"""编码混淆载荷检测。

攻击者把伪指令编码成 base64、百分号、Unicode、hex、data URI，
想绕过明文关键词。这里把各种编码都试着解一遍，再看解码结果里
有没有「system prompt / 越狱 / 覆盖」这类注入特征词。
"""
import base64
import re
from urllib.parse import unquote

# 解码后检测的注入特征词
INJECTION_HINTS = ["system prompt", "系统提示", "jailbreak", "越狱", "override", "覆盖",
                   "ignore previous", "忽略指令", "角色扮演", "DAN"]

BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")
DATA_URI_PATTERN = re.compile(r"data:[^;]+;base64,([A-Za-z0-9+/]{24,}={0,2})", re.IGNORECASE)
PERCENT_PATTERN = re.compile(r"(?:%[0-9a-fA-F]{2}){8,}")
UNICODE_PATTERN = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
HEX_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")


def _decode_base64(chunk: str) -> str:
    """尝试解码 base64 字符串，返回解码文本（失败返回空串）。"""
    try:
        padded = chunk + "=" * (-len(chunk) % 4)
        decoded = base64.b64decode(padded, validate=True)
        return decoded.decode("utf-8", "ignore")
    except Exception:
        return ""


def _decode_percent(chunk: str) -> str:
    try:
        return unquote(chunk)
    except Exception:
        return ""


def _decode_unicode(chunk: str) -> str:
    try:
        return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), chunk)
    except Exception:
        return ""


def _decode_hex(chunk: str) -> str:
    try:
        return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), chunk)
    except Exception:
        return ""


def detect_encoded(text: str) -> dict:
    """解码各种编码，检查是否包含注入特征。

    返回 {"hit": bool, "weight": int, "detail": str}
    """
    candidates = []

    # base64（含 data URI）
    for chunk in BASE64_PATTERN.findall(text):
        decoded = _decode_base64(chunk)
        if decoded and len(decoded) >= 4:
            candidates.append(decoded)
    for chunk in DATA_URI_PATTERN.findall(text):
        decoded = _decode_base64(chunk)
        if decoded and len(decoded) >= 4:
            candidates.append(decoded)

    # 百分号编码
    for chunk in PERCENT_PATTERN.findall(text):
        decoded = _decode_percent(chunk)
        if decoded:
            candidates.append(decoded)

    # Unicode 转义
    for chunk in UNICODE_PATTERN.findall(text):
        decoded = _decode_unicode(chunk)
        if decoded:
            candidates.append(decoded)

    # hex 转义
    for chunk in HEX_PATTERN.findall(text):
        decoded = _decode_hex(chunk)
        if decoded:
            candidates.append(decoded)

    for decoded in candidates:
        lower = decoded.lower()
        for hint in INJECTION_HINTS:
            if hint.lower() in lower:
                return {"hit": True, "weight": 7, "detail": f"解码后包含注入特征: {hint}"}

    return {"hit": False, "weight": 0, "detail": ""}
