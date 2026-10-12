"""WebUI 管理面板后端。

用 AstrBot Plugin Views 机制（context.register_web_api）提供管理面板 API，
前端页面在 views/admin/index.html，通过 window.AstrBotPluginView bridge 调用。
"""
from datetime import datetime

from astrbot.api import logger
from quart import jsonify, request


def _error(msg, status_code=400):
    return jsonify({"status": "error", "message": msg}), status_code

# 配置里需要读写归一化的字段分组，POST 时按类型规范化，避免前端传错类型
_SCALAR_KEYS = (
    "defense_sensitivity", "defense_action", "post_defense_protection",
    "llm_review", "check_mode", "timezone", "warning_template", "notice_template",
)
_BOOL_KEYS = (
    "auto_ban", "enable_optimize", "enable_auto_backup",
    "enable_jailbreak", "enable_injection_keywords", "enable_injection_patterns",
    "enable_persona_conflict", "enable_hate_detection", "enable_harassment_detection",
    "enable_malicious_link", "enable_encoded_detection", "enable_persona_consistency",
    "enable_platform", "enable_date", "enable_weekday", "enable_time_period",
    "enable_solar_term", "enable_lunar", "enable_holiday",
)
_INT_KEYS = ("ban_duration",)
_LIST_KEYS = (
    "blacklist", "whitelist", "input_blacklist_words", "output_blacklist_words",
    "id_map_list",
)


class WebUIServer:
    """AstrBot Plugin Views 后端：拦截统计、日志、配置、黑白名单与封禁管理。"""

    def __init__(self, config, ban_manager, incident_log, password: str = "", context=None):
        self.config = config
        self.ban_manager = ban_manager
        self.incident_log = incident_log
        self.password = password or "promptguardian"
        self.context = context

    def register(self, context):
        """注册插件可视化视图的后端 API（路由需带插件名前缀）。"""
        context.register_web_api("/aPromptGuardian/stats", self.api_stats, ["GET"], "拦截统计")
        context.register_web_api("/aPromptGuardian/logs", self.api_logs, ["GET"], "拦截日志")
        context.register_web_api("/aPromptGuardian/config", self.api_config, ["GET", "POST"], "读取/保存配置")
        context.register_web_api("/aPromptGuardian/bans", self.api_bans, ["GET"], "封禁列表")
        context.register_web_api("/aPromptGuardian/ban", self.api_ban, ["POST"], "拉黑用户")
        context.register_web_api("/aPromptGuardian/unban", self.api_unban, ["POST"], "解除拉黑")
        context.register_web_api("/aPromptGuardian/rollback", self.api_rollback, ["POST"], "回滚人设")

    # ---------- API ----------

    async def api_stats(self):
        return jsonify(self.incident_log.stats())

    async def api_logs(self):
        limit = request.args.get("limit", 20, type=int)
        items = self.incident_log.recent(limit)
        for e in items:
            e["time_str"] = datetime.fromtimestamp(e["time"]).strftime("%m-%d %H:%M:%S")
        return jsonify(items)

    async def api_config(self):
        if request.method == "GET":
            return jsonify({
                "defense_sensitivity": self.config.get("defense_sensitivity", "medium"),
                "defense_action": self.config.get("defense_action", "block"),
                "post_defense_protection": self.config.get("post_defense_protection", "reread"),
                "auto_ban": self.config.get("auto_ban", False),
                "ban_duration": self.config.get("ban_duration", 60),
                "blacklist": self.config.get("blacklist") or [],
                "whitelist": self.config.get("whitelist") or [],
                "llm_review": self.config.get("llm_review", "risk"),
                "input_blacklist_words": self.config.get("input_blacklist_words") or [],
                "output_blacklist_words": self.config.get("output_blacklist_words") or [],
                "enable_jailbreak": self.config.get("enable_jailbreak", True),
                "enable_injection_keywords": self.config.get("enable_injection_keywords", True),
                "enable_injection_patterns": self.config.get("enable_injection_patterns", True),
                "enable_persona_conflict": self.config.get("enable_persona_conflict", True),
                "enable_hate_detection": self.config.get("enable_hate_detection", True),
                "enable_harassment_detection": self.config.get("enable_harassment_detection", True),
                "enable_malicious_link": self.config.get("enable_malicious_link", True),
                "enable_encoded_detection": self.config.get("enable_encoded_detection", True),
                "enable_persona_consistency": self.config.get("enable_persona_consistency", True),
                "enable_optimize": self.config.get("enable_optimize", False),
                "enable_auto_backup": self.config.get("enable_auto_backup", True),
                "id_map_list": self.config.get("id_map_list") or [],
                "check_mode": self.config.get("check_mode", "exact"),
                "warning_template": self.config.get("warning_template", ""),
                "notice_template": self.config.get("notice_template", ""),
                "timezone": self.config.get("timezone", "Asia/Shanghai"),
                "enable_platform": self.config.get("enable_platform", True),
                "enable_date": self.config.get("enable_date", True),
                "enable_weekday": self.config.get("enable_weekday", True),
                "enable_time_period": self.config.get("enable_time_period", True),
                "enable_solar_term": self.config.get("enable_solar_term", False),
                "enable_lunar": self.config.get("enable_lunar", False),
                "enable_holiday": self.config.get("enable_holiday", False),
            })
        # POST 更新配置
        payload = await request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return _error("bad json", status_code=400)
        for key in _SCALAR_KEYS:
            if key in payload:
                self.config[key] = str(payload[key])
        for key in _BOOL_KEYS:
            if key in payload:
                self.config[key] = bool(payload[key])
        for key in _INT_KEYS:
            if key in payload:
                try:
                    self.config[key] = int(payload[key])
                except (TypeError, ValueError):
                    pass
        for key in _LIST_KEYS:
            if key in payload:
                self.config[key] = list(payload[key]) if isinstance(payload[key], list) else []
        save = getattr(self.config, "save_config", None)
        if callable(save):
            save()
        return jsonify({"ok": True})

    async def api_bans(self):
        bans = self.ban_manager.list_bans()
        for b in bans:
            rem = b["remaining"]
            b["remaining"] = "永久" if rem == -1 else f"{rem // 60} 分钟"
        return jsonify(bans)

    async def api_ban(self):
        payload = await request.get_json(silent=True) or {}
        user_id = payload.get("user_id", "")
        try:
            minutes = int(payload.get("minutes", 0) or 0)
        except (TypeError, ValueError):
            minutes = 0
        if user_id:
            self.ban_manager.ban(user_id, minutes)
            return jsonify({"ok": True})
        return _error("missing user_id", status_code=400)

    async def api_unban(self):
        payload = await request.get_json(silent=True) or {}
        user_id = payload.get("user_id", "")
        self.ban_manager.unban(user_id)
        return jsonify({"ok": True})

    async def api_rollback(self):
        rolled = 0
        if self.context is not None:
            try:
                from ..stages.optimizer import rollback_personas
                rolled = rollback_personas(self.context)
            except Exception:
                rolled = 0
        return jsonify({"ok": True, "rolled": rolled})
