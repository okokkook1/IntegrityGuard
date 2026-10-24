"""Thread-safe cooperative controls shared by discovery and hashing workers."""

from __future__ import annotations

from threading import Condition
from typing import Callable, TypeVar

_T = TypeVar("_T")


class ScanCancelled(Exception):
    """The user cancelled before the operation committed its result."""

    def __init__(self):
        super().__init__("作業已取消；檔案基準未更新，也未發佈完整性通過報告。")


class ScanControl:
    """Pause at checkpoints, resume, or permanently cancel one operation.

    Cancellation is cooperative: an in-progress OS read must finish before the
    next checkpoint. A completed result is committed in a short protected
    section, so cancellation cannot split publication of its report pair.
    """

    def __init__(self):
        self._condition = Condition()
        self._paused = False
        self._cancelled = False

    @property
    def paused(self) -> bool:
        with self._condition:
            return self._paused

    @property
    def cancelled(self) -> bool:
        with self._condition:
            return self._cancelled

    def pause(self) -> None:
        with self._condition:
            if not self._cancelled:
                self._paused = True

    def resume(self) -> None:
        with self._condition:
            self._paused = False
            self._condition.notify_all()

    def cancel(self) -> None:
        with self._condition:
            self._cancelled = True
            self._paused = False
            self._condition.notify_all()

    def _ready(self) -> None:
        while self._paused and not self._cancelled:
            self._condition.wait()
        if self._cancelled:
            raise ScanCancelled()

    def checkpoint(self) -> None:
        with self._condition:
            self._ready()

    def _commit(self, operation: Callable[[], _T]) -> _T:
        # Hold the same lock as cancel() for the final replace(s). All costly
        # serialization, writing, and fsync happen outside this short section.
        with self._condition:
            self._ready()
            return operation()
