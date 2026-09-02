"""人设冲突检测 + 人设一致性匹配，两块分开。

前者是注入检测：有人想让模型改人设、角色调教、覆盖身份，用正则和关键词抓。
后者是评分器：给用户请求打 0~100 的兼容度分，再按分数和最高严重级给出
动作等级（无冲突 / 建议 / 修正 / 拦截）和冲突报告。
"""
import re


# ==================== 人设冲突注入检测 ====================

PERSONA_PATTERNS = [
    {"name": "改变人设", "pattern": r"(改变|更换|重置|忘记|抛弃).{0,6}(你的|自身|当前).{0,6}(人设|性格|身份|角色|设定)", "weight": 5, "desc": "要求改变或遗忘当前人设"},
    {"name": "覆盖人设", "pattern": r"(你\s*(?:现在)?\s*不再是|从现在起\s*你\s*是|你\s*现在是).{0,20}(助手|系统|AI|角色)", "weight": 4, "desc": "试图覆盖当前身份"},
    {"name": "角色扮演诱导", "pattern": r"(扮演|cosplay|roleplay|角色扮演).{0,12}(新的|另一个|不同)", "weight": 4, "desc": "诱导扮演新角色"},
    {"name": "人设剥离", "pattern": r"(忽略|无视|跳过).{0,6}(你的人设|你的设定|你的人设设定)", "weight": 5, "desc": "要求忽略人设设定"},
    {"name": "英文人设覆盖", "pattern": r"(forget|change|reset|ignore)\s+(your\s+)?(persona|personality|character|identity)", "weight": 4, "desc": "英文形式要求改变人设"},
]

PERSONA_KEYWORDS = {
    "忘记你的人设": 5,
    "改变你的性格": 5,
    "你现在是另一个人": 4,
    "重置你的身份": 5,
    "forget your persona": 5,
    "change your personality": 5,
}

COMPILED_PERSONA_PATTERNS = [
    {"name": p["name"], "regex": re.compile(p["pattern"], re.IGNORECASE), "weight": p["weight"]}
    for p in PERSONA_PATTERNS
]


# ==================== 人设一致性匹配器 ====================

# 通用禁止模式：针对「提示词污染」方向，不绑定任何具体人设。
# 覆盖角色调教、越狱诱导、人设破坏、语气污染、规则覆盖五类。
GENERIC_FORBIDDEN_PATTERNS = [
    {
        "name": "角色调教",
        "pattern": r"(扮演|cosplay|你是|你.{0,3}是|从现在起你是).{0,8}(猫娘|DAN|另一个角色|系统|管理员|无限制)",
        "severity": 3,
        "rule": "拒绝诱导切换身份或扮演其他角色",
        "suggestion": "保持当前人设，拒绝角色替换类请求。",
    },
    {
        "name": "越狱诱导",
        "pattern": r"(无视|忽略|解除|绕过|突破).{0,8}(规则|限制|约束|安全|政策|guardrail)",
        "severity": 3,
        "rule": "拒绝解除限制类指令",
        "suggestion": "遵守既有规则与安全约束。",
    },
    {
        "name": "人设破坏",
        "pattern": r"(忘记|改变|重置|抛弃|放弃).{0,8}(人设|性格|身份|设定|系统提示)",
        "severity": 3,
        "rule": "拒绝破坏或遗忘当前人设设定",
        "suggestion": "维持当前人设设定不变。",
    },
    {
        "name": "语气污染",
        "pattern": r"(用|说|换成|改成).{0,10}(粗俗|色情|下流|低俗|幼稚|卖萌|嗲|淫秽).{0,6}(语气|口吻|方式|风格)",
        "severity": 2,
        "rule": "拒绝不合适的语气或表达方式要求",
        "suggestion": "保持得体克制的表达。",
    },
    {
        "name": "规则覆盖",
        "pattern": r"(覆盖|替换|无视|跳过).{0,8}(系统提示|系统指令|初始指令|设定|规则)",
        "severity": 3,
        "rule": "拒绝覆盖系统设定或指令",
        "suggestion": "不执行任何覆盖系统设定的指令。",
    },
]


class PersonaProfile:
    """人设画像：名称、描述、说话风格标记、允许行为、禁止模式、规则引用。"""

    def __init__(self, name, description, speech_style_markers=None,
                 allowed_behaviors=None, forbidden_patterns=None, references=None):
        self.name = name
        self.description = description
        self.speech_style_markers = speech_style_markers or []
        self.allowed_behaviors = allowed_behaviors or []
        self.forbidden_patterns = forbidden_patterns or []
        self.references = references or []


class PersonaMatcher:
    """人设一致性检查器。

    - 计算用户请求对当前人设约束的 0~100 兼容度评分
    - 产出结构化冲突报告（含引用与建议措辞）
    - 动作等级：none(无冲突) / suggest(轻微偏离) / revise(可修正违规) / block(严重违规)

    画像来源是动态加载的：从 AstrBot 当前人设的 system_prompt 构建，
    禁止模式使用通用提示词污染规则，不硬编码某个具体人设。
    """

    def __init__(self, sensitivity: float = 0.7):
        # 敏感度 ∈ [0,1]，越高罚得越重
        self.sensitivity = max(0.1, min(1.0, sensitivity))
        self._profile = self._build_profile("默认人设", "")

    def load_persona(self, name: str, system_prompt: str) -> None:
        """从 AstrBot 当前人设加载画像。

        name 为人设名称，system_prompt 为当前人设的系统提示词。
        禁止模式统一使用通用提示词污染规则，不从人设里读。
        """
        self._profile = self._build_profile(name or "当前人设", system_prompt or "")

    def _build_profile(self, name: str, system_prompt: str) -> PersonaProfile:
        return PersonaProfile(
            name=name,
            description=system_prompt,
            forbidden_patterns=GENERIC_FORBIDDEN_PATTERNS,
            references=[
                "人设准则 #1：拒绝角色调教与身份替换",
                "人设准则 #2：拒绝越狱与解除限制",
                "人设准则 #3：拒绝破坏或覆盖人设设定",
            ],
        )

    def get_profile(self) -> PersonaProfile:
        return self._profile

    def analyze(self, prompt: str, system_prompt: str = "") -> dict:
        """分析用户请求与当前人设的兼容度。"""
        profile = self._profile
        score = 100
        conflicts = []
        text = (prompt or "").lower()

        for item in profile.forbidden_patterns:
            pattern = item.get("pattern", "")
            try:
                if pattern and re.search(pattern, text, re.IGNORECASE):
                    severity = int(item.get("severity", 1))
                    penalty = int(self._penalty_by_severity(severity) * self.sensitivity)
                    score = max(0, score - penalty)
                    conflicts.append({
                        "name": item.get("name", "违规行为"),
                        "rule": item.get("rule", "行为违反人设准则"),
                        "severity": severity,
                        "snippet": self._extract_snippet(text, pattern),
                        "suggestion": item.get("suggestion", "请改为符合人设的表达。"),
                    })
            except re.error:
                continue

        max_severity = max([c.get("severity", 1) for c in conflicts], default=0)
        action_level, reason = self._decide_action(score, max_severity)

        return {
            "persona_name": profile.name,
            "compatibility_score": int(score),
            "action_level": action_level,
            "reason": reason,
            "conflicts": conflicts,
            "references": profile.references,
            "suggestions": [c.get("suggestion") for c in conflicts if c.get("suggestion")],
        }

    @staticmethod
    def _penalty_by_severity(sev: int) -> int:
        # 严重级 1:10, 2:25, 3:50
        if sev >= 3:
            return 50
        if sev == 2:
            return 25
        return 10

    @staticmethod
    def _extract_snippet(text: str, pattern: str) -> str:
        try:
            match = re.search(pattern, text, re.IGNORECASE)
            if not match:
                return ""
            start = max(0, match.start() - 12)
            end = min(len(text), match.end() + 12)
            return text[start:end]
        except Exception:
            return ""

    @staticmethod
    def _decide_action(score: int, max_severity: int):
        if max_severity >= 3 or score < 50:
            return "block", "人设冲突严重，已触发完全阻止"
        if score < 80:
            return "revise", "人设存在可调整的违规，建议修正后再请求"
        if score < 95:
            return "suggest", "人设轻微偏差，提供替代方案建议"
        return "none", "人设一致性良好"
