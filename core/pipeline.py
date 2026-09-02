"""提示词加工流水线。

把多个处理阶段按顺序串起来，逐阶段执行，
阶段之间通过 PipelineContext 共享数据、互不调用。
"""
import logging

logger = logging.getLogger(__name__)


class Pipeline:
    """按顺序执行一组提示词加工阶段。"""

    def __init__(self, stages=None):
        self._stages = list(stages) if stages else []

    def add_stage(self, stage) -> "Pipeline":
        """追加一个阶段到流水线末尾。"""
        self._stages.append(stage)
        return self

    async def run(self, ctx) -> None:
        """按顺序执行所有阶段，修改传入的上下文。"""
        for stage in self._stages:
            try:
                await stage.process(ctx)
            except Exception as exc:
                # 单个阶段异常不中断整条流水线，记录后继续
                logger.error("[aPromptGuardian] 阶段 %s 执行失败: %s", stage.name, exc)
