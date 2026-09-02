"""拦截事件日志：记录防护命中与处置动作。

记录内存中的拦截事件列表，供统计与导出。
"""
import time
from collections import deque


class IncidentLogger:
    """记录防护拦截事件。"""

    def __init__(self, max_entries: int = 500):
        # 固定容量的队列，超出丢弃最旧记录
        self._entries = deque(maxlen=max_entries)

    def record(self, user_id: str, reason: str, action: str, prompt: str = "") -> None:
        """记录一条拦截事件。"""
        self._entries.append({
            "time": int(time.time()),
            "user_id": user_id or "",
            "reason": reason or "",
            "action": action or "",
            "prompt_preview": (prompt or "")[:120],
        })

    def stats(self) -> dict:
        """返回拦截统计。"""
        total = len(self._entries)
        actions = {}
        for e in self._entries:
            a = e["action"]
            actions[a] = actions.get(a, 0) + 1
        return {"total_intercepts": total, "by_action": actions}

    def recent(self, limit: int = 50) -> list:
        """返回最近的拦截事件（时间倒序）。"""
        items = list(self._entries)
        items.reverse()
        return items[:limit]
