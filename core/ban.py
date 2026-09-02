"""封禁管理：拉黑、解封、时长控制、自动解封。

维护内存中的封禁状态（用户 ID → 解封时间戳），
0 表示永久封禁；支持过期自动解封。
"""
import time


class BanManager:
    """管理被拦截用户的封禁状态。"""

    def __init__(self, config: dict):
        self.config = config or {}
        # user_id -> 解封时间戳（0 表示永久）
        self._bans = {}

    def ban(self, user_id: str, minutes: int) -> None:
        """拉黑用户。minutes=0 表示永久。"""
        if not user_id:
            return
        if minutes <= 0:
            self._bans[user_id] = 0
        else:
            self._bans[user_id] = time.time() + minutes * 60

    def unban(self, user_id: str) -> bool:
        """解封用户，返回是否成功。"""
        return self._bans.pop(user_id, None) is not None

    def is_banned(self, user_id: str) -> bool:
        """判断用户当前是否处于封禁状态（含自动解封检查）。"""
        if not user_id or user_id not in self._bans:
            return False
        expiry = self._bans[user_id]
        if expiry != 0 and time.time() >= expiry:
            # 已过期，自动解封
            self._bans.pop(user_id, None)
            return False
        return True

    def remaining(self, user_id: str) -> int:
        """返回剩余封禁秒数；永久封禁返回 -1；未封禁返回 0。"""
        if not self.is_banned(user_id):
            return 0
        expiry = self._bans[user_id]
        if expiry == 0:
            return -1
        return max(0, int(expiry - time.time()))

    def list_bans(self) -> list:
        """列出所有封禁记录（含过期清理）。"""
        for uid in list(self._bans.keys()):
            self.is_banned(uid)  # 触发过期清理
        return [
            {"user_id": uid, "remaining": self.remaining(uid)}
            for uid in self._bans
        ]
