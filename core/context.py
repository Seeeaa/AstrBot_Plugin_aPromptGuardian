"""流水线上下文。

在一条流水线的各阶段之间传递数据。
"""
from typing import Any


class PipelineContext:
    """一条流水线执行期间的共享上下文。"""

    def __init__(self, event: Any = None, req: Any = None, session_id: str = None):
        self.event = event            # 原始消息事件（可能为 None，各阶段需判空）
        self.req = req                # 当前 LLM 请求对象（可能为 None）
        self.session_id = session_id or ""   # 会话 ID，供调模型时使用
        self.risky = False            # 是否被判定为危险
        self.risk_reason = ""         # 危险判定原因
        self.extra = {}               # 阶段之间传递的附加数据
