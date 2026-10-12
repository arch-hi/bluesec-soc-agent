import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, Self, cast

from loguru import logger
from openai import (
    APIConnectionError,
    APIStatusError,
    AsyncOpenAI,
    BadRequestError,
    InternalServerError,
    RateLimitError,
)
from openai.types.chat import ChatCompletionMessageParam, ChatCompletionToolParam

RATE_LIMIT_BASE_DELAY_SECONDS = 10.0
TRANSIENT_ERROR_DELAY_SECONDS = 5.0
# таймаут клиента сбрасывается при каждом полученном байте, нужен общий предел на запрос
HARD_DEADLINE_MARGIN_SECONDS = 10.0
BAD_REQUEST_DUMP = Path("runs/last_bad_request.json")
# ошибки ключа, баланса, доступа и модели, повтор не поможет
FATAL_STATUS_CODES = {401, 402, 403, 404}
# DeepSeek иногда вставляет служебную разметку вызова в аргументы
LEAKED_MARKUP = ("DSML", "\uff5c")
MESSAGE_EXTRA_KEYS = ("reasoning_details",)


class LLMUnavailableError(RuntimeError):
    pass


class NextStepRequestError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    extra: dict[str, Any] | None = None
    message_extra: dict[str, Any] | None = None


class MalformedToolCallError(ValueError):
    # вызов сохраняем, чтобы агент отклонил его локально без прерывания задачи

    def __init__(self, message: str, call: ToolCall) -> None:
        super().__init__(message)
        self.call = call


class ToolCallingClient(Protocol):
    async def next_tool_call(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ToolCall: ...


def dump_request(
    path: Path, model: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"model": model, "messages": messages, "tools": tools}
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not save the rejected request: {}", exc)


class OpenAIToolClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_completion_tokens: int,
        max_retries: int,
        client: AsyncOpenAI | None = None,
    ) -> None:
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_completion_tokens = max_completion_tokens
        self.max_retries = max_retries
        self._owns_client = client is None
        self._client = client or AsyncOpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout_seconds,
            max_retries=0,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.close()

    async def next_tool_call(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ToolCall:
        last_error: Exception | None = None
        malformed: ToolCall | None = None

        for attempt in range(1, self.max_retries + 1):
            started_at = time.perf_counter()
            try:
                response = await asyncio.wait_for(
                    self._client.chat.completions.create(
                        model=self.model,
                        messages=cast(list[ChatCompletionMessageParam], messages),
                        tools=cast(list[ChatCompletionToolParam], tools),
                        tool_choice="required",
                        max_completion_tokens=self.max_completion_tokens,
                    ),
                    timeout=self.timeout_seconds + HARD_DEADLINE_MARGIN_SECONDS,
                )
            except BadRequestError as exc:
                dump_request(BAD_REQUEST_DUMP, self.model, messages, tools)
                raise LLMUnavailableError(
                    f"Provider rejected the request: {exc}. Saved to {BAD_REQUEST_DUMP}."
                ) from exc
            except RateLimitError as exc:
                last_error = exc
                delay = RATE_LIMIT_BASE_DELAY_SECONDS * attempt
                logger.warning(
                    "Rate limited on attempt {}/{}; waiting {} s.", attempt, self.max_retries, delay
                )
                await asyncio.sleep(delay)
                continue
            except (APIConnectionError, InternalServerError, TimeoutError) as exc:
                last_error = exc
                delay = TRANSIENT_ERROR_DELAY_SECONDS * attempt
                logger.warning(
                    "Provider error on attempt {}/{} ({}); waiting {} s.",
                    attempt,
                    self.max_retries,
                    type(exc).__name__,
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            except APIStatusError as exc:
                if exc.status_code in FATAL_STATUS_CODES:
                    raise LLMUnavailableError(
                        f"Provider refused the request (HTTP {exc.status_code}): {exc}"
                    ) from exc
                last_error = exc
                delay = TRANSIENT_ERROR_DELAY_SECONDS * attempt
                logger.warning(
                    "Provider error on attempt {}/{} (HTTP {}); waiting {} s.",
                    attempt,
                    self.max_retries,
                    exc.status_code,
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            latency_ms = int((time.perf_counter() - started_at) * 1000)

            try:
                call = parse_tool_call(response)
            except MalformedToolCallError as exc:
                last_error = exc
                malformed = exc.call
                logger.warning(
                    "Malformed tool call on attempt {}/{}: {}", attempt, self.max_retries, exc
                )
                continue
            except ValueError as exc:
                last_error = exc
                logger.warning(
                    "Invalid tool call on attempt {}/{}: {}", attempt, self.max_retries, exc
                )
                continue

            logger.info(
                "LLM selected {} in {} ms using {} tokens.",
                call.name,
                latency_ms,
                response_total_tokens(response),
            )
            return call

        if malformed is not None:
            logger.warning("Every attempt was malformed; passing the last call on.")
            return malformed
        raise NextStepRequestError(str(last_error or "Unable to get a tool call.")) from last_error


def parse_tool_call(response: Any) -> ToolCall:
    choices = getattr(response, "choices", None)
    if not choices:
        raise ValueError("Model response is missing choices.")
    message = getattr(choices[0], "message", None)
    tool_calls = getattr(message, "tool_calls", None)
    if not tool_calls:
        raise ValueError("Model returned no tool call.")

    call = tool_calls[0]
    raw_arguments = call.function.arguments or "{}"
    try:
        arguments = json.loads(raw_arguments)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Tool arguments are not valid JSON: {raw_arguments[:200]}") from exc
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be a JSON object.")

    message_fields = getattr(message, "model_extra", None) or {}
    message_extra = {
        key: message_fields[key] for key in MESSAGE_EXTRA_KEYS if message_fields.get(key)
    }
    parsed = ToolCall(
        id=call.id,
        name=call.function.name,
        arguments=arguments,
        extra=getattr(call, "model_extra", None) or None,
        message_extra=message_extra or None,
    )
    if not arguments:
        raise MalformedToolCallError("Tool arguments are empty.", parsed)
    if any(isinstance(value, str) and not value.strip(" ,.;:") for value in arguments.values()):
        raise MalformedToolCallError(
            f"Tool arguments contain empty placeholder values: {raw_arguments[:200]}", parsed
        )
    if any(marker in text for text in _strings(arguments) for marker in LEAKED_MARKUP):
        raise MalformedToolCallError(
            f"Tool arguments contain leaked markup: {raw_arguments[:200]}", parsed
        )
    return parsed


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    return []


def response_total_tokens(response: Any) -> int:
    usage = getattr(response, "usage", None)
    total_tokens = getattr(usage, "total_tokens", 0)
    return total_tokens if isinstance(total_tokens, int) and total_tokens >= 0 else 0


def render_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str)
