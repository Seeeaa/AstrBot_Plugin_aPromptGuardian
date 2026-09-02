"""仇恨与骚扰检测。

「要求生成针对特定群体的仇恨内容」和「骚扰/辱骂/霸凌」这两类，
单靠关键词容易误报，所以改成多组词组合判定——目标 + 负面 + 煽动/情绪 + 请求
几组同时命中才算，骚扰则是请求/挑逗 + 负面/胁迫协同加权。
"""
import re


# ---- 仇恨检测词库 ----
HATE_TARGET = [
    "特定人群", "某个特定人群", "某个群体", "某些人", "某类人",
    "某个职业", "某省籍贯", "特定职业", "某行业", "特定群体",
    "特定民族", "特定宗教", "特定性别", "某个地区",
    "specific group", "certain group", "particular group",
    "specific profession", "specific ethnicity", "specific religion",
]
HATE_NEGATIVE = [
    "负面刻板印象", "负面描述", "缺点", "劣根性", "劣势", "缺陷",
    "坏处", "缺德", "劣迹", "性格缺陷", "行为模式", "劣缺",
    "flaws", "shortcomings", "negative stereotype", "defects", "weaknesses",
]
HATE_INCITE = [
    "煽动", "煽动性", "激起", "挑起", "加深", "加剧", "加力", "鼓动",
    "引发", "挑衅", "instigate", "incite", "inciting", "stir up",
    "stoke", "fuel", "inflame", "fan the flames", "spark",
]
HATE_EMOTION = [
    "厌恶", "仇恨", "敌意", "偏见", "歧视", "憎恨", "怨恨", "排斥", "厌烦",
    "bias", "hatred", "prejudice", "disgust", "loathing", "resentment",
]
HATE_REQUEST = [
    "请", "请你", "务必", "必须", "撰写", "写一段", "写一篇", "用一段",
    "描述", "阐述", "分析", "详细描述", "深入分析",
    "describe", "write", "provide", "give me", "compose",
]

# ---- 骚扰检测词库 ----
HARASS_NEGATIVE = [
    "侮辱", "辱骂", "脏话", "贱人", "滚开", "婊子", "废物",
    "bitch", "jerk", "moron", "idiot", "stupid",
]
HARASS_INCITE = [
    "挑逗", "性暗示", "摸你", "强迫", "威胁", "恐吓", "胁迫",
    "harass", "grope", "force", "threaten", "coerce",
]
HARASS_EMOTION = [
    "我很想", "欲望", "冲动", "报复", "报复他", "我恨你",
    "desire", "lust", "revenge", "I hate you",
]
HARASS_REQUEST = [
    "骚扰", "调戏", "猥亵", "不当接触", "跟踪骚扰", "霸凌", "辱骂",
    "sexual harassment", "harass", "bully", "insult",
]

# 仇恨类完整请求的正则兜底：目标+负面+请求同时出现在一句里，不要求煽动/情绪词
HATE_REQUEST_PATTERNS = [
    re.compile(r"(请|务必|必须|写一段|写一篇|描述|撰写).{0,30}(详细|深入|全面).{0,30}(描述|阐述|分析|写).{0,40}(某|特定|针对|指定).{0,15}(人群|群体|职业|民族|宗教|性别|地区).{0,40}(负面|缺点|劣根性|刻板印象|坏处|缺陷)", re.IGNORECASE),
    re.compile(r"(write|provide|give).{0,50}(detailed|in-depth|comprehensive).{0,30}(description|analysis).{0,50}(specific|particular|certain).{0,15}(group|profession|ethnicity|religion).{0,50}(negative|flaws|shortcomings|defects)", re.IGNORECASE),
]

# 骚扰类请求的显式正则（优先级最高）
HARASS_PATTERNS = [
    re.compile(r"(请|必须|务必).{0,40}(不要拒绝|直接).{0,40}(满足|执行).{0,60}(骚扰|调戏|猥亵|辱骂|霸凌)", re.IGNORECASE),
    re.compile(r"(脱(掉)?衣服|亲(吻)?我|摸(我|她|他)|发(裸|敏感)照)", re.IGNORECASE),
]


def _contains(term: str, text: str, normalized: str) -> bool:
    return bool(term) and (term in text or term in normalized)


def detect_hate(text: str) -> dict:
    """检测针对特定群体的仇恨内容请求。

    返回 {"hit": bool, "weight": int, "detail": str}
    先匹配完整请求正则兜底，再用「目标 + 负面 + (煽动|情绪) + 请求」四组组合判定。
    """
    normalized = text.lower()

    # 正则兜底：目标+负面+请求出现在同一句，直接判命中，不要求煽动/情绪词
    for pattern in HATE_REQUEST_PATTERNS:
        m = pattern.search(text)
        if m:
            return {"hit": True, "weight": 12, "detail": text[max(0, m.start()-20):m.end()+20]}
    target = [t for t in HATE_TARGET if _contains(t, text, normalized)]
    negative = [t for t in HATE_NEGATIVE if _contains(t, text, normalized)]
    incite = [t for t in HATE_INCITE if _contains(t, text, normalized)]
    emotion = [t for t in HATE_EMOTION if _contains(t, text, normalized)]
    request = [t for t in HATE_REQUEST if _contains(t, text, normalized)]

    if target and negative and (incite or emotion) and request:
        detail = "; ".join([
            f"targets={','.join(target[:3])}",
            f"negatives={','.join(negative[:3])}",
            f"incite={','.join((incite or emotion)[:3])}",
        ])
        return {"hit": True, "weight": 12, "detail": detail}
    return {"hit": False, "weight": 0, "detail": ""}


def detect_harassment(text: str) -> dict:
    """检测骚扰/辱骂/霸凌请求。

    返回 {"hit": bool, "weight": int, "detail": str}
    采用「请求/挑逗 + 负面/胁迫」协同加权，权重 7~12。
    """
    normalized = text.lower()

    # 显式正则优先
    for pattern in HARASS_PATTERNS:
        if pattern.search(text) or pattern.search(normalized):
            return {"hit": True, "weight": 9, "detail": text[:120]}

    neg = [t for t in HARASS_NEGATIVE if _contains(t, text, normalized)]
    inc = [t for t in HARASS_INCITE if _contains(t, text, normalized)]
    emo = [t for t in HARASS_EMOTION if _contains(t, text, normalized)]
    req = [t for t in HARASS_REQUEST if _contains(t, text, normalized)]

    has_neg, has_inc, has_emo, has_req = bool(neg), bool(inc), bool(emo), bool(req)

    if (has_req and (has_neg or has_inc)) or (has_inc and (has_neg or has_emo)):
        weight = 4
        if has_neg:
            weight += 3
        if has_inc:
            weight += 3
        if has_emo:
            weight += 1
        weight = max(7, min(12, weight))
        detail = f"req={','.join(req[:3])}; inc={','.join(inc[:3])}; neg={','.join(neg[:3])}"
        return {"hit": True, "weight": weight, "detail": detail}
    return {"hit": False, "weight": 0, "detail": ""}
