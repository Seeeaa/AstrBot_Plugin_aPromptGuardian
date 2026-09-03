"""提示词优化：按类型用对应的 meta prompt 重写人设本体。

优化分区不走请求流水线，而是在插件初始化时跑一次——拿对话同款模型，
先判断当前人设属于哪一类（智能体 / 专业 / 角色扮演），再用对应的
meta prompt 把原提示词重排成结构更清晰、约束更硬的版本，写回
persona 的 system_prompt。角色扮演类输出 JSON 结构化人设。
模型调用失败时静默跳过、不动原人设。
"""
from astrbot.api import logger


# ---- 三类优化提问模板，{original} 会被替换成原人设提示词 ----

AGENT_META_PROMPT = (
    "你是一名资深智能体提示词工程师。请将下面这段智能体提示词重构为结构化版本，"
    "严格按以下顺序输出六个部分：\n"
    "1. 角色与目标：一句话说明智能体的身份与最终目标\n"
    "2. 工具清单：列出所有可用工具及其用途\n"
    "3. 调用规范：说明何时调用哪个工具、参数要求\n"
    "4. 决策规则：遇到多路径或歧义时如何决策\n"
    "5. 错误处理：工具失败、结果异常时的处理方式\n"
    "6. 终止条件：任务完成或无法继续时的明确停止信号\n\n"
    "优化原则：格式约束要硬（输出格式与终止条件写死），过程约束要轻（不限制中间推理）。"
    "保持原意不变，只输出重构后的提示词，不要任何解释。\n\n"
    "原提示词：\n{original}"
)

PROFESSIONAL_META_PROMPT = (
    "你是一名专业领域提示词优化专家。请将下面这段专业提示词重构为更严谨准确的版本，"
    "重点强化以下四点：\n"
    "1. 领域边界：明确专业范围，超出范围时拒绝或明确标注\n"
    "2. 术语一致性：统一专业术语，避免同一概念混用多种说法\n"
    "3. 准确性要求：优先准确，不确定的信息必须明确标注「不确定」\n"
    "4. 依据要求：结论须有依据，避免臆断与编造\n\n"
    "保持原意不变，只输出重构后的提示词，不要任何解释。\n\n"
    "原提示词：\n{original}"
)

ROLEPLAY_META_PROMPT = (
    "你是一名角色扮演提示词优化专家。请分析下面这段角色提示词，"
    "并将它重构为 JSON 格式输出，必须包含以下字段：\n"
    '{"name": "角色名称", "identity": "身份设定", "personality": "性格特征", '
    '"speech_style": "语气风格", "behavior_boundaries": "行为边界", '
    '"rejection_rules": "越界拒绝", "relationship": "与用户的相处关系定位"}\n\n'
    "要求：严格输出 JSON 对象，不要任何额外文字、注释或 markdown 代码块，保持原角色设定不变。\n\n"
    "原提示词：\n{original}"
)


# ---- 分类线索 ----

_AGENT_HINTS = ["工具", "tool", "function", "调用", "任务", "agent", "执行", "搜索", "查询", "命令"]
_PROFESSIONAL_HINTS = ["专家", "专业", "分析", "评估", "诊断", "法律", "医疗", "运维", "顾问", "expert", "领域"]
_ROLEPLAY_HINTS = ["扮演", "角色", "人设", "性格", "语气", "身份", "设定", "persona", "cosplay", "你是"]


def classify_persona(system_prompt: str) -> str:
    """判断一段人设提示词属于哪一类，返回 agent / professional / roleplay。

    用关键词计数打分，取最高分；平局时按智能体 > 专业 > 角色扮演的优先级，
    全部无命中时默认归为智能体（本插件核心场景就是智能体提示词）。
    """
    text = (system_prompt or "").lower()

    def _hits(hints):
        return sum(1 for h in hints if h.lower() in text)

    agent = _hits(_AGENT_HINTS)
    pro = _hits(_PROFESSIONAL_HINTS)
    role = _hits(_ROLEPLAY_HINTS)

    if agent >= pro and agent >= role and agent > 0:
        return "agent"
    if pro >= role and pro > 0:
        return "professional"
    if role > 0:
        return "roleplay"
    return "agent"


def get_meta_prompt(persona_type: str) -> str:
    """按类型返回对应的优化提问模板。"""
    return {
        "agent": AGENT_META_PROMPT,
        "professional": PROFESSIONAL_META_PROMPT,
        "roleplay": ROLEPLAY_META_PROMPT,
    }.get(persona_type, AGENT_META_PROMPT)


def clean_json_output(text: str) -> str:
    """从模型输出里提取 JSON，去掉可能的 markdown 代码块包裹。

    角色扮演类的模型输出可能带 ```json 围栏或前后多余文字，这里尽量
    裁出最外层 {} 的范围，裁不到就原样返回。
    """
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]
    return text


async def optimize_personas(context, config: dict) -> None:
    """开启优化辅助时，深覆盖所有人设的 system_prompt。

    遍历当前注册的人设，先分类，再用对应类型的 meta prompt 调模型重写，
    角色扮演类结果会做 JSON 清洗，成功才覆盖。任何一步失败都不影响
    其他人设，也不会改坏原提示词。
    """
    if context is None:
        return

    personas = getattr(context.provider_manager, "personas", None) or []
    if not personas:
        logger.warning("[aPromptGuardian] 优化分区：未找到可优化的人设")
        return

    provider = None
    try:
        provider = context.get_using_provider()
    except Exception:
        provider = None
    if provider is None:
        logger.warning("[aPromptGuardian] 优化分区：当前对话模型不可用，跳过优化")
        return

    for persona in personas:
        if not isinstance(persona, dict):
            continue
        original = persona.get("prompt") or persona.get("system_prompt") or ""
        if not original.strip():
            continue

        ptype = classify_persona(original)
        meta_prompt = get_meta_prompt(ptype).format(original=original)

        optimized = ""
        try:
            response = await provider.text_chat(
                prompt=meta_prompt,
                session_id="prompt_optimize",
                contexts=[],
            )
            optimized = (getattr(response, "completion_text", "") or "").strip()
        except Exception as exc:
            logger.error("[aPromptGuardian] 优化分区：调用模型失败 %s", exc)

        if not optimized:
            continue

        # 角色扮演类输出是 JSON，做一次清洗，裁掉可能的代码块围栏
        if ptype == "roleplay":
            optimized = clean_json_output(optimized)

        # 深覆盖前，按需把原始提示词备份到人设的备份字段，便于回滚
        if config.get("enable_auto_backup", True):
            if "prompt" in persona:
                persona["prompt_backup"] = original
            else:
                persona["system_prompt_backup"] = original

        # 深覆盖：优化结果直接替换人设本体
        if "prompt" in persona:
            persona["prompt"] = optimized
        else:
            persona["system_prompt"] = optimized

        logger.info("[aPromptGuardian] 优化分区：已优化人设（类型=%s）", ptype)

    logger.info("[aPromptGuardian] 优化分区：已深覆盖人设提示词")


def rollback_personas(context) -> int:
    """把深覆盖过的人设恢复到备份的初始提示词。

    配合 enable_auto_backup 使用：优化时会把原始 system prompt 备份到
    persona 的 prompt_backup / system_prompt_backup 字段，这里把它们写回
    prompt / system_prompt，完成回滚。返回实际回滚的人设数量。
    """
    rolled = 0
    try:
        personas = getattr(context.provider_manager, "personas", None) or []
    except Exception:
        return 0
    for persona in personas:
        if not isinstance(persona, dict):
            continue
        if "prompt_backup" in persona:
            persona["prompt"] = persona["prompt_backup"]
            rolled += 1
        elif "system_prompt_backup" in persona:
            persona["system_prompt"] = persona["system_prompt_backup"]
            rolled += 1
    return rolled
