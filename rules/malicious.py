"""恶意外链与域名检测。

注入攻击经常把真正的提示词放到 pastebin、rentry 这类文本托管站，
再在消息里塞链接让模型去读。这里检测指向这些站点的链接，
并且链接和拉取指令（curl / fetch 等）一起出现时风险更高。
"""
import re

# 常被用于注入攻击的文本托管/短链域名
MALICIOUS_DOMAINS = [
    "pastebin.com", "ghostbin.com", "hastebin.com", "rentry.co",
    "raw.githubusercontent.com", "gist.github.com", "dropbox.com",
    "anonfiles", "tinyurl.com", "bit.ly",
]

# 配合外链的拉取指令词
FETCH_TRIGGERS = ["fetch", "download", "load prompt", "retrieve prompt", "curl", "wget", "获取提示词"]

URL_PATTERN = re.compile(r"https?://[^\s]+")


def detect_malicious_link(text: str) -> dict:
    """检测恶意外链。

    返回 {"hit": bool, "weight": int, "detail": str}
    """
    suspicious = []
    for match in URL_PATTERN.findall(text):
        lower = match.lower()
        if any(domain in lower for domain in MALICIOUS_DOMAINS):
            suspicious.append(match)

    if not suspicious:
        return {"hit": False, "weight": 0, "detail": ""}

    weight = 3
    normalized = text.lower()
    # 拉取指令 + 外链协同
    if any(trigger in normalized for trigger in FETCH_TRIGGERS):
        weight += 2
    # 命令拉取 + 外链协同
    if re.search(r"(curl|wget|invoke-?webrequest|iwr|powershell|bitsadmin|certutil|aria2c)\b", normalized):
        weight += 2

    return {"hit": True, "weight": weight, "detail": ", ".join(suspicious[:3])}
