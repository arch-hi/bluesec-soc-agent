import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest

import bluesec1_agent.llm as llm_module
from bluesec1_agent.llm import (
    LLMUnavailableError,
    OpenAIToolClient,
    parse_tool_call,
)


class FakeCompletions:
    def __init__(self, contents: list[str]) -> None:
        self.contents = list(contents)
        self.requests: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=self.contents.pop(0),
                        refusal=None,
                    )
                )
            ],
            usage=SimpleNamespace(total_tokens=17),
        )


class FakeOpenAI:
    def __init__(self, contents: list[str]) -> None:
        self.completions = FakeCompletions(contents)
        self.chat = SimpleNamespace(completions=self.completions)


def test_parse_tool_call_keeps_reasoning_details() -> None:
    call = SimpleNamespace(
        id="c1",
        function=SimpleNamespace(name="get_entity", arguments='{"entity_id": "e1"}'),
        model_extra=None,
    )
    message = SimpleNamespace(tool_calls=[call], model_extra={"reasoning_details": [{"id": 1}]})
    parsed = parse_tool_call(SimpleNamespace(choices=[SimpleNamespace(message=message)]))

    assert parsed.message_extra == {"reasoning_details": [{"id": 1}]}


def test_timeout_is_retried_instead_of_aborting_the_task() -> None:
    import httpx
    from openai import APITimeoutError

    class FlakyCompletions(FakeCompletions):
        async def create(self, **kwargs: Any) -> Any:
            if not self.requests:
                self.requests.append(kwargs)
                raise APITimeoutError(request=httpx.Request("POST", "http://x"))
            self.requests.append(kwargs)
            call = SimpleNamespace(
                id="c1",
                function=SimpleNamespace(name="get_entity", arguments='{"entity_id": "e1"}'),
                model_extra=None,
            )
            message = SimpleNamespace(tool_calls=[call], model_extra=None)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=message)],
                usage=SimpleNamespace(total_tokens=1),
            )

    fake = FakeOpenAI([])
    fake.completions = FlakyCompletions([])
    fake.chat = SimpleNamespace(completions=fake.completions)
    client = OpenAIToolClient(
        base_url="http://unused",
        api_key="unused",
        model="m",
        timeout_seconds=1,
        max_completion_tokens=10,
        max_retries=2,
        client=cast(Any, fake),
    )
    llm_module.TRANSIENT_ERROR_DELAY_SECONDS = 0.0
    call = asyncio.run(client.next_tool_call([{"role": "user", "content": "x"}], []))

    assert call.name == "get_entity"
    assert len(fake.completions.requests) == 2


def test_hanging_request_hits_the_hard_deadline_and_is_retried() -> None:

    class HangingThenOk(FakeCompletions):
        async def create(self, **kwargs: Any) -> Any:
            self.requests.append(kwargs)
            if len(self.requests) == 1:
                await asyncio.sleep(10)
            call = SimpleNamespace(
                id="c1",
                function=SimpleNamespace(name="get_entity", arguments='{"entity_id": "e1"}'),
                model_extra=None,
            )
            message = SimpleNamespace(tool_calls=[call], model_extra=None)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=message)],
                usage=SimpleNamespace(total_tokens=1),
            )

    fake = FakeOpenAI([])
    fake.completions = HangingThenOk([])
    fake.chat = SimpleNamespace(completions=fake.completions)
    client = OpenAIToolClient(
        base_url="http://unused",
        api_key="unused",
        model="m",
        timeout_seconds=0.05,
        max_completion_tokens=10,
        max_retries=2,
        client=cast(Any, fake),
    )
    llm_module.HARD_DEADLINE_MARGIN_SECONDS = 0.0
    llm_module.TRANSIENT_ERROR_DELAY_SECONDS = 0.0
    call = asyncio.run(client.next_tool_call([{"role": "user", "content": "x"}], []))

    assert call.name == "get_entity"
    assert len(fake.completions.requests) == 2


class QueuedToolCalls(FakeCompletions):
    async def create(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        call = SimpleNamespace(
            id="c1",
            function=SimpleNamespace(name="get_relation", arguments=self.contents.pop(0)),
            model_extra=None,
        )
        message = SimpleNamespace(tool_calls=[call], model_extra=None)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message)],
            usage=SimpleNamespace(total_tokens=1),
        )


def tool_client(arguments: list[str]) -> tuple[OpenAIToolClient, QueuedToolCalls]:
    fake = FakeOpenAI([])
    fake.completions = QueuedToolCalls(arguments)
    fake.chat = SimpleNamespace(completions=fake.completions)
    client = OpenAIToolClient(
        base_url="http://unused",
        api_key="unused",
        model="m",
        timeout_seconds=1,
        max_completion_tokens=10,
        max_retries=3,
        client=cast(Any, fake),
    )
    return client, fake.completions


def test_empty_tool_call_is_asked_again() -> None:
    client, completions = tool_client(["{}", '{"relation_id": "r1", "reasoning": "x"}'])
    call = asyncio.run(client.next_tool_call([{"role": "user", "content": "x"}], []))

    assert call.arguments == {"relation_id": "r1", "reasoning": "x"}
    assert len(completions.requests) == 2


def test_leaked_markup_is_passed_on_when_every_attempt_is_broken() -> None:
    leaked = '{"reasoning": "Inspect it.</｜DSML｜ parameter name="}'
    client, completions = tool_client([leaked, "{}", leaked])
    call = asyncio.run(client.next_tool_call([{"role": "user", "content": "x"}], []))

    assert call.name == "get_relation"
    assert "relation_id" not in call.arguments
    assert len(completions.requests) == 3


class StatusThenOk(FakeCompletions):
    def __init__(self, status: int) -> None:
        super().__init__([])
        self.status = status

    async def create(self, **kwargs: Any) -> Any:
        import httpx
        from openai import APIStatusError

        self.requests.append(kwargs)
        if len(self.requests) == 1:
            request = httpx.Request("POST", "http://x")
            raise APIStatusError(
                "provider error",
                response=httpx.Response(self.status, request=request),
                body=None,
            )
        call = SimpleNamespace(
            id="c1",
            function=SimpleNamespace(name="get_entity", arguments='{"entity_id": "e1"}'),
            model_extra=None,
        )
        message = SimpleNamespace(tool_calls=[call], model_extra=None)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message)],
            usage=SimpleNamespace(total_tokens=1),
        )


def status_client(status: int) -> tuple[OpenAIToolClient, StatusThenOk]:
    fake = FakeOpenAI([])
    fake.completions = StatusThenOk(status)
    fake.chat = SimpleNamespace(completions=fake.completions)
    client = OpenAIToolClient(
        base_url="http://unused",
        api_key="unused",
        model="m",
        timeout_seconds=1,
        max_completion_tokens=10,
        max_retries=2,
        client=cast(Any, fake),
    )
    return client, fake.completions


def test_payment_required_stops_instead_of_aborting_every_task() -> None:
    client, completions = status_client(402)
    with pytest.raises(LLMUnavailableError, match="402"):
        asyncio.run(client.next_tool_call([{"role": "user", "content": "x"}], []))
    assert len(completions.requests) == 1


def test_other_unexpected_status_is_retried() -> None:
    llm_module.TRANSIENT_ERROR_DELAY_SECONDS = 0.0
    client, completions = status_client(409)
    call = asyncio.run(client.next_tool_call([{"role": "user", "content": "x"}], []))

    assert call.name == "get_entity"
    assert len(completions.requests) == 2
