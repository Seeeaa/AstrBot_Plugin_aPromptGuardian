"""流水线阶段基类。

所有处理阶段继承本类，实现统一的 process 接口，
由流水线（pipeline）按顺序调用。
"""
from abc import ABC, abstractmethod


class Stage(ABC):
    """提示词加工流水线的一个阶段。"""

    name: str = "stage"

    def __init__(self, config: dict = None, context=None):
        # config 统一兜底为空 dict，context 供需要调模型的阶段使用
        self.config = config or {}
        self.context = context

    @abstractmethod
    async def process(self, ctx) -> None:
        """处理当前阶段，修改流水线上下文 ctx。"""
        raise NotImplementedError
