"""aPromptGuardian 插件入口。

把每次 LLM 请求前的提示词加工收拢成一条流水线，身份、防护、感知三个阶段按固定顺序执行；
优化分区不走流水线，在插件异步初始化时按需深覆盖人设本体。
另外暴露一组管理命令，方便运行时改配置、封禁、查黑白名单和统计。
"""
from astrbot.api.star import Context, Star, register
from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.core import AstrBotConfig

from .core.pipeline import Pipeline
from .core.context import PipelineContext
from .core.ban import BanManager
from .core.incident_log import IncidentLogger
from .core.webui import WebUIServer
from .stages.identity import IdentityStage
from .stages.defense import DefenseStage, BLOCK_MESSAGE
from .stages.perception import PerceptionStage
from .stages.optimizer import optimize_personas, rollback_personas
from .rules.persona import PersonaMatcher


@register("aPromptGuardian", "Sea", "开箱即用的流式提示词框架：优化→审查→过滤→复核→防护→核验→感知。维护优化系统优化提示词、屏蔽注入攻击、身份核验、信息感知、黑白名单与 WebUi 管理", "v1.1.0")
class aPromptGuardian(Star):
    """插件主类，持有流水线、封禁管理器和拦截日志三个核心组件。"""

    def __init__(self, context: Context, config: AstrBotConfig = None):
        super().__init__(context)
        self.config = config or {}

        # 封禁状态是内存态，带过期时间；拦截日志是固定容量队列，超了就丢最旧的
        self.ban_manager = BanManager(self.config)
        self.incident_log = IncidentLogger()

        # 人设一致性匹配器：画像在 initialize 时从 AstrBot 当前人设抓取
        self.persona_matcher = PersonaMatcher()

        # WebUI 服务在 initialize 阶段按需启动，这里先建实例
        self.webui = WebUIServer(
            self.config, self.ban_manager, self.incident_log,
            password=self.config.get("webui_password") or "promptguardian",
            context=self.context,
        )

        # 请求时流水线的阶段顺序是固定的：先校验身份，再做防护，最后注入感知信息
        self.pipeline = Pipeline([
            IdentityStage(self.config, self.context),
            DefenseStage(self.config, self.context, self.ban_manager, self.incident_log, self.persona_matcher),
            PerceptionStage(self.config, self.context),
        ])

    async def initialize(self):
        """优化分区要调当前对话模型，只能等异步环境就绪后再跑深覆盖。"""
        # 抓取 AstrBot 当前人设的 system_prompt，加载到人设匹配器
        pname, psys = self._fetch_current_persona()
        self.persona_matcher.load_persona(pname, psys)

        if self.config.get("enable_optimize"):
            await optimize_personas(self.context, self.config)

        # WebUI 默认开，可配置关掉；端口冲突时只记日志不崩
        if self.config.get("enable_webui", True):
            try:
                port = int(self.config.get("webui_port") or 6187)
            except (TypeError, ValueError):
                port = 6187
            try:
                await self.webui.start(port=port)
            except Exception as exc:
                import logging
                logging.getLogger(__name__).error("[aPromptGuardian] WebUI 启动失败: %s", exc)

    async def terminate(self):
        """插件卸载时关掉 WebUI，释放端口。"""
        try:
            await self.webui.stop()
        except Exception:
            pass

    @filter.on_llm_request()
    async def on_request(self, event: AstrMessageEvent, req):
        """请求钩子：跑一遍流水线，防护命中且处置为拦截时终止本次请求。"""
        ctx = PipelineContext(
            event=event,
            req=req,
            session_id=self._get_session_id(event),
        )
        await self.pipeline.run(ctx)

        # 拦截动作统一在这里收口：发一条提示，然后停掉事件
        if ctx.risky and ctx.extra.get("defense_action") == "block":
            try:
                await event.send(event.plain_result(BLOCK_MESSAGE))
            except Exception:
                pass
            event.stop_event()

        # 防御后保护：强制刷新（切新会话，隔离被污染的连续对话）
        if ctx.extra.get("reset_conversation"):
            await self._reset_conversation(event, req)

    # ==================== 管理命令 ====================

    @filter.command("pg帮助")
    async def cmd_help(self, event: AstrMessageEvent) -> MessageEventResult:
        """把当前支持的命令列一遍，方便随时查用法。"""
        help_text = (
            "aPromptGuardian 管理命令：\n"
            "/pg统计 - 查看拦截统计\n"
            "/切换力度 低|中|高 - 切换防御力度（灵敏度）\n"
            "/切换等级 观察|标注|仅去除危险内容|拦截 - 切换防御等级\n"
            "/复核 一直|判危险时|从不 - 切换 LLM 复核\n"
            "/拉黑 ID [分钟] - 拉黑用户（0=永久）\n"
            "/解封 ID - 解封用户\n"
            "/黑名单 - 查看黑名单\n"
            "/白名单 - 查看白名单\n"
            "/加白 ID - 添加白名单\n"
            "/移白 ID - 移除白名单\n"
            "/优化 开|关 - 切换提示词优化辅助"
        )
        yield event.plain_result(help_text)

    @filter.command("pg统计", is_admin=True)
    async def cmd_stats(self, event: AstrMessageEvent) -> MessageEventResult:
        """拦截次数按处置方式聚合后展示。"""
        s = self.incident_log.stats()
        yield event.plain_result(
            f"总拦截次数：{s['total_intercepts']}\n按处置方式：{s['by_action']}"
        )

    @filter.command("pg日志", is_admin=True)
    async def cmd_logs(self, event: AstrMessageEvent, limit: str = "20") -> MessageEventResult:
        """导出最近若干条拦截日志，默认 20 条。"""
        try:
            n = int(limit or "20")
        except ValueError:
            n = 20
        recent = self.incident_log.recent(n)
        if not recent:
            yield event.plain_result("暂无拦截日志")
            return
        lines = [f"最近 {len(recent)} 条拦截日志："]
        for e in recent:
            import datetime
            t = datetime.datetime.fromtimestamp(e["time"]).strftime("%m-%d %H:%M:%S")
            lines.append(f"[{t}] {e['user_id']} | {e['action']} | {e['reason']}")
        yield event.plain_result("\n".join(lines))

    @filter.command("pg配置", is_admin=True)
    async def cmd_config(self, event: AstrMessageEvent) -> MessageEventResult:
        """把防护相关的配置项汇总成一段文本，方便确认当前状态。"""
        sens = {"low": "低", "medium": "中", "high": "高"}.get(self.config.get("defense_sensitivity"), "中")
        action = {"block": "拦截", "rewrite": "仅去除危险内容", "mark": "标注", "observe": "观察"}.get(self.config.get("defense_action"), "拦截")
        review = {"always": "一直", "risk": "判危险时", "never": "从不"}.get(self.config.get("llm_review"), "判危险时")
        text = (
            f"当前配置：\n"
            f"防御力度：{sens}\n"
            f"防御等级：{action}\n"
            f"LLM 复核：{review}\n"
            f"自动拉黑：{'开' if self.config.get('auto_ban') else '关'}"
            f"（{self.config.get('ban_duration', 0)} 分钟）\n"
            f"优化辅助：{'开' if self.config.get('enable_optimize') else '关'}"
        )
        yield event.plain_result(text)

    @filter.command("防骚扰", is_admin=True)
    async def cmd_abuse(self, event: AstrMessageEvent, on: str = "") -> MessageEventResult:
        """仇恨 / 骚扰辱骂霸凌检测开关，参数只认「开」或「关」。"""
        if on not in ("开", "关"):
            yield event.plain_result("用法：/防骚扰 开|关")
            return
        self.config["enable_hate_detection"] = (on == "开")
        self.config["enable_harassment_detection"] = (on == "开")
        self._persist_config()
        yield event.plain_result(f"仇恨与骚扰辱骂霸凌检测已{'开启' if on == '开' else '关闭'}")

    @filter.command("切换力度", is_admin=True)
    async def cmd_sensitivity(self, event: AstrMessageEvent, level: str = "") -> MessageEventResult:
        """切防御灵敏度，低/中/高对应不同的风险阈值。"""
        valid = {"低": "low", "中": "medium", "高": "high"}
        if level not in valid:
            yield event.plain_result("用法：/切换力度 低|中|高")
            return
        self.config["defense_sensitivity"] = valid[level]
        self._persist_config()
        yield event.plain_result(f"防御力度已切换为：{level}")

    @filter.command("切换等级", is_admin=True)
    async def cmd_action(self, event: AstrMessageEvent, action: str = "") -> MessageEventResult:
        """切命中后的处置方式，观察/标注/仅去除危险内容/拦截四选一。"""
        valid = {"观察": "observe", "标注": "mark", "仅去除危险内容": "rewrite", "拦截": "block"}
        if action not in valid:
            yield event.plain_result("用法：/切换等级 观察|标注|仅去除危险内容|拦截")
            return
        self.config["defense_action"] = valid[action]
        self._persist_config()
        yield event.plain_result(f"防御等级已切换为：{action}")

    @filter.command("复核", is_admin=True)
    async def cmd_review(self, event: AstrMessageEvent, mode: str = "") -> MessageEventResult:
        """切 LLM 二次复核的触发时机：一直 / 判危险时 / 从不。"""
        valid = {"一直": "always", "判危险时": "risk", "从不": "never"}
        if mode not in valid:
            yield event.plain_result("用法：/复核 一直|判危险时|从不")
            return
        self.config["llm_review"] = valid[mode]
        self._persist_config()
        yield event.plain_result(f"LLM 复核已切换为：{mode}")

    @filter.command("拉黑", is_admin=True)
    async def cmd_ban(self, event: AstrMessageEvent, user_id: str = "", minutes: str = "0") -> MessageEventResult:
        """拉黑用户，分钟传 0 或不传表示永久封禁。"""
        if not user_id:
            yield event.plain_result("用法：/拉黑 ID [分钟]")
            return
        try:
            mins = int(minutes or "0")
        except ValueError:
            mins = 0
        self.ban_manager.ban(user_id, mins)
        yield event.plain_result(f"已拉黑 {user_id}（{'永久' if mins <= 0 else str(mins) + ' 分钟'}）")

    @filter.command("解封", is_admin=True)
    async def cmd_unban(self, event: AstrMessageEvent, user_id: str = "") -> MessageEventResult:
        """解封用户，不在封禁列表里时会提示。"""
        if not user_id:
            yield event.plain_result("用法：/解封 ID")
            return
        ok = self.ban_manager.unban(user_id)
        yield event.plain_result(f"已解封 {user_id}" if ok else f"{user_id} 不在封禁列表中")

    @filter.command("黑名单", is_admin=True)
    async def cmd_blacklist(self, event: AstrMessageEvent) -> MessageEventResult:
        """列出当前封禁列表，含剩余时长或永久标记。"""
        bans = self.ban_manager.list_bans()
        if not bans:
            yield event.plain_result("黑名单为空")
            return
        lines = ["当前封禁列表："]
        for b in bans:
            rem = "永久" if b["remaining"] == -1 else f"剩 {b['remaining'] // 60} 分钟"
            lines.append(f"- {b['user_id']}（{rem}）")
        yield event.plain_result("\n".join(lines))

    @filter.command("白名单", is_admin=True)
    async def cmd_whitelist(self, event: AstrMessageEvent) -> MessageEventResult:
        """查看白名单用户 ID。"""
        wl = self.config.get("whitelist") or []
        yield event.plain_result("白名单：" + (", ".join(wl) if wl else "空"))

    @filter.command("加白", is_admin=True)
    async def cmd_add_white(self, event: AstrMessageEvent, user_id: str = "") -> MessageEventResult:
        """把用户加进白名单，白名单内跳过防护检测。"""
        if not user_id:
            yield event.plain_result("用法：/加白 ID")
            return
        wl = list(self.config.get("whitelist") or [])
        if user_id not in wl:
            wl.append(user_id)
            self.config["whitelist"] = wl
            self._persist_config()
        yield event.plain_result(f"已添加白名单：{user_id}")

    @filter.command("移白", is_admin=True)
    async def cmd_remove_white(self, event: AstrMessageEvent, user_id: str = "") -> MessageEventResult:
        """把用户移出白名单。"""
        if not user_id:
            yield event.plain_result("用法：/移白 ID")
            return
        wl = list(self.config.get("whitelist") or [])
        if user_id in wl:
            wl.remove(user_id)
            self.config["whitelist"] = wl
            self._persist_config()
        yield event.plain_result(f"已移除白名单：{user_id}")

    @filter.command("优化", is_admin=True)
    async def cmd_optimize(self, event: AstrMessageEvent, on: str = "") -> MessageEventResult:
        """提示词优化辅助开关，开启后初始化阶段会用模型重写人设本体。"""
        if on not in ("开", "关"):
            yield event.plain_result("用法：/优化 开|关")
            return
        self.config["enable_optimize"] = (on == "开")
        self._persist_config()
        if on == "开":
            await optimize_personas(self.context, self.config)
            yield event.plain_result("优化辅助已开启，并立即执行了一次优化；结果不理想可用 /回滚人设 恢复")
        else:
            yield event.plain_result("优化辅助已关闭")

    @filter.command("回滚人设", is_admin=True)
    async def cmd_rollback(self, event: AstrMessageEvent) -> MessageEventResult:
        """把优化过的人设恢复到备份的初始提示词。"""
        rolled = rollback_personas(self.context)
        if rolled:
            yield event.plain_result(f"已回滚 {rolled} 个人设到备份的初始提示词")
        else:
            yield event.plain_result("没有可回滚的备份（可能未开启自动备份或尚未优化过）")

    # ==================== 内部工具 ====================

    async def _reset_conversation(self, event, req=None) -> None:
        """防御后保护：切换新会话，隔离被污染的连续对话。

        注意 AstrBot 的时序：on_llm_request 触发时 req.conversation 已经指向旧会话，
        本次请求的历史最终仍会写回 req.conversation.cid（旧会话）；这里切新会话只是
        改变「当前选中会话」的指针，让下一次请求从干净的新会话开始。为免丢人设，
        新建会话时继承旧会话的 persona_id。
        """
        try:
            cm = getattr(self.context, "conversation_manager", None)
            if cm is None:
                return
            umo = getattr(event, "unified_msg_origin", None)
            if not umo:
                return
            persona_id = None
            conv = getattr(req, "conversation", None) if req is not None else None
            if conv is not None:
                persona_id = getattr(conv, "persona_id", None) or None
            await cm.new_conversation(umo, persona_id=persona_id)
        except Exception:
            pass

    def _persist_config(self):
        """把内存里的配置改动写回磁盘；AstrBotConfig 才有 save_config，普通 dict 跳过。"""
        save = getattr(self.config, "save_config", None)
        if callable(save):
            save()

    def _fetch_current_persona(self):
        """从 AstrBot 抓取当前人设的名称和 system_prompt，抓不到返回空。"""
        try:
            pm = getattr(self.context, "provider_manager", None)
            if pm is None:
                return "", ""
            personas = getattr(pm, "personas", None) or []
            for p in personas:
                if isinstance(p, dict):
                    name = p.get("persona_id") or p.get("name") or ""
                    sp = p.get("system_prompt") or p.get("prompt") or ""
                    if sp.strip():
                        return str(name), str(sp)
        except Exception:
            pass
        return "", ""

    @staticmethod
    def _get_session_id(event) -> str:
        """会话 ID 的兜底读取，拿不到就返回空串。"""
        try:
            getter = getattr(event, "get_session_id", None)
            if getter is None:
                return ""
            return str(getter() or "")
        except Exception:
            return ""
