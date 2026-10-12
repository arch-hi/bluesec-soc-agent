import json
from typing import Any


class CountingSession:
    # в финале сервер не отдаёт число вызовов, а оно нужно для дедлайна

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        self.calls += 1
        return await self._inner.call_tool(tool_name, arguments)


class HiddenMetricsSession:
    # имитация финала, агент не видит наград, настоящие пишутся в файл

    def __init__(self, inner: Any, truth_path: str) -> None:
        self._inner = inner
        self._truth_path = truth_path

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        response = await self._inner.call_tool(tool_name, arguments)
        record = {
            "task_id": self._inner.task_id,
            "tool": tool_name,
            "reward": response.reward,
            "task_result": (
                response.task_result.model_dump(mode="json") if response.task_result else None
            ),
        }
        with open(self._truth_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        return response.model_copy(update={"reward": 0.0, "task_result": None})
