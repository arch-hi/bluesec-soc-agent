import asyncio
import json
import math
import time
from dataclasses import dataclass
from statistics import median
from typing import Any, cast

from loguru import logger
from pydantic import BaseModel, ConfigDict, Field

from bluesec1_agent.evidence import Evidence, harvest_queries
from bluesec1_agent.llm import (
    LLMUnavailableError,
    NextStepRequestError,
    ToolCall,
    ToolCallingClient,
    render_json,
)
from bluesec1_agent.prompts import (
    ARTIFACT_SWEEP,
    BUDGET_WARNING,
    EMPTY_BENIGN_REVIEW,
    FINISH_NOW,
    NO_FINDINGS,
    SYSTEM_PROMPT,
    UNKNOWN_ID,
    VERDICT_SLIP,
)
from bluesec1_agent.report import (
    drop_items_with_ids,
    filter_by_kind,
    fix_false_positive_slip,
    normalize_finish,
    verdict_of,
    verdict_slip,
)
from bluesec1_agent.scenarios import (
    BUDGET_NOTE,
    OPEN_BUDGET_CAP,
    alert_type,
    call_budget,
    open_budget,
    scenario_notes,
)
from bluesec1_agent.schemas import argument_problems, simplify_tool
from bluesec1_agent.sessions import CountingSession, HiddenMetricsSession
from bluesec1_agent.trajectory import TrajectoryLogger
from bluesec1_client import (
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)

FINISH = "finish_investigation"

MAX_LLM_FAILURES_IN_A_ROW = 2
LLM_FAILURE_PAUSE_SECONDS = 60.0
MAX_LLM_FAILURE_PAUSE_SECONDS = 300.0
BUDGET_WARNING_STEPS = 3
# локально отклонённые вызовы не тратят бюджет сервера, но занимают ход
MAX_LOCAL_REJECTIONS = 8
NO_FINDINGS_STREAK = 6
EMPTY_BENIGN_MIN_STEPS = 3
HARVEST_DRY_STOP = 2
# после ошибок с подсказками на стольких типах отключаем все подсказки
NOTE_FAILURES_TO_DROP_ALL = 2
RAISE_STEP = 4
MIN_DEADLINE_STEPS = 6
FIRST_GUESS_SECONDS_PER_CALL = 8.0

# эти запросы чаще других находили эталонные сущности, короче 5 символов сервер не принимает
SWEEP_QUERIES = ("Downloads", "powershell.exe")
SWEEP_SHOWN_CHARS = 3_000
NOISY_FIELDS = {
    "sha1",
    "md5",
    "sha256",
    "imphash",
    "file_version",
    "company",
    "product",
    "file_description",
    "original_filename",
    "loaded_modules",
    "token_privileges",
    "boot_time",
    "mac_addresses",
    "architecture",
    "is_virtual_machine",
    "powershell_version",
    "current_page_id",
    "next_page_id",
    "log_sources",
    "script_block_number",
    "script_block_count",
}


class AgentRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    successful_tasks: int
    failed_tasks: int
    task_results: list[TaskResult] = Field(default_factory=list)


@dataclass
class TaskState:
    session: RemoteBenchmarkSession
    evidence: Evidence
    parameters: dict[str, Any]
    available: set[str]
    max_steps: int
    calls: int = 0
    model_scored: bool = False
    swept: bool = False
    empty_benign_reviewed: bool = False
    slip_reviewed: bool = False
    finish_retry_used: bool = False
    unrewarded_streak: int = 0
    nudge_no_findings: bool = False


def _compact(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in "{[":
        try:
            return _compact(json.loads(value))
        except json.JSONDecodeError:
            return value
    if isinstance(value, dict):
        return {
            key: _compact(item)
            for key, item in value.items()
            if key not in NOISY_FIELDS and item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [_compact(item) for item in value]
    return value


class InvestigationAgent:
    def __init__(
        self,
        llm: ToolCallingClient,
        *,
        max_steps: int = 100,
        max_tasks: int | None = None,
        total_cap: int | None = None,
        type_budgets: bool = False,
        deadline_minutes: float | None = None,
        harvest_calls: int = 1,
        scenario_notes: bool = True,
        complete_report_share: float | None = None,
        empty_benign_review: bool = False,
        artifact_sweep: bool = False,
        keep_going: bool = False,
        simplify_tool_schemas: bool = False,
        simulate_hidden: str | None = None,
        trajectory: TrajectoryLogger | None = None,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.llm = llm
        self.max_steps = max_steps
        self.max_tasks = max_tasks
        self.total_cap = total_cap
        self.type_budgets = type_budgets
        self.deadline_minutes = deadline_minutes
        self.harvest_calls = harvest_calls
        self.use_notes = scenario_notes
        self.complete_report_share = complete_report_share
        self.empty_benign_review = empty_benign_review
        self.artifact_sweep = artifact_sweep
        self.keep_going = keep_going
        self.simplify_tool_schemas = simplify_tool_schemas
        self.simulate_hidden = simulate_hidden
        self.trajectory = trajectory or TrajectoryLogger(None)

        # пока наград не было, считаем, что они скрыты, как в финале
        self.reward_signal_seen = False

        self._run_budgets: dict[tuple[str, str], list[float]] = {}
        self._run_floors: dict[tuple[str, str], int] = {}
        self._task_type: tuple[str, str] | None = None
        self._task_notes: list[str] = []
        self._notes_off: set[str] = set()
        self._failed_note_types: set[tuple[str, str]] = set()
        self._all_notes_off = False
        self._types_seen = 0
        self._types_known = 0
        self._clock = time.monotonic
        self._spent_seconds = 0.0
        self._spent_calls = 0

    async def run(self, client: RemoteBenchmarkClient) -> AgentRunResult:
        remote_run = client.run
        if remote_run is None:
            raise RuntimeError("RemoteBenchmarkClient must be open before running the agent.")

        task_results: list[TaskResult] = []
        llm_failures_in_a_row = 0
        started_at = self._clock()
        while (self.max_tasks is None or len(task_results) < self.max_tasks) and (
            session := await client.start_task()
        ) is not None:
            if self.simulate_hidden:
                session = cast(
                    RemoteBenchmarkSession, HiddenMetricsSession(session, self.simulate_hidden)
                )
            session = cast(RemoteBenchmarkSession, CountingSession(session))
            logger.info("Task {}: starting investigation.", session.task_id)
            llm_failed = False
            step_cap = self._deadline_step_cap(started_at, len(task_results))
            task_started = self._clock()
            try:
                task_result = await self._investigate(session, step_cap=step_cap)
            except Exception as exc:
                llm_failed = isinstance(exc, (LLMUnavailableError, NextStepRequestError))
                logger.error("Task {} failed in the agent: {}", session.task_id, exc)
                error_message = f"{type(exc).__name__}: {exc}"[:2_000]
                self.trajectory.log("task_error", task_id=session.task_id, error=error_message)
                try:
                    aborted = await session.abort_task(error_message=error_message)
                    task_result = TaskResult.model_validate(aborted)
                except Exception as abort_exc:
                    # сервер тоже бывает недоступен, тогда завершаем только эту задачу
                    logger.error("Abort of task {} failed: {}", session.task_id, abort_exc)
                    task_result = TaskResult(task_id=session.task_id, completion_reason="error")

            task_results.append(task_result)
            self._learn_from_result(task_result)
            self._spent_seconds += self._clock() - task_started
            self._spent_calls += max(1, task_result.tool_calls, getattr(session, "calls", 0))
            self.trajectory.log(
                "task_end", task_id=session.task_id, result=task_result.model_dump(mode="json")
            )

            llm_failures_in_a_row = llm_failures_in_a_row + 1 if llm_failed else 0
            if llm_failures_in_a_row >= MAX_LLM_FAILURES_IN_A_ROW and not self.keep_going:
                logger.error(
                    "The LLM provider failed {} tasks in a row; stopping the run.",
                    llm_failures_in_a_row,
                )
                break
            if llm_failed:
                # сбой провайдера обычно короткий, увеличиваем паузу вместо остановки
                pause = (
                    min(
                        MAX_LLM_FAILURE_PAUSE_SECONDS,
                        LLM_FAILURE_PAUSE_SECONDS * llm_failures_in_a_row,
                    )
                    if self.keep_going
                    else LLM_FAILURE_PAUSE_SECONDS
                )
                logger.warning(
                    "Task lost to the LLM provider; waiting {} s before the next one.", pause
                )
                await asyncio.sleep(pause)

        successful = sum(r.completion_reason in {"terminated", "truncated"} for r in task_results)
        return AgentRunResult(
            run_id=remote_run.run_id,
            successful_tasks=successful,
            failed_tasks=len(task_results) - successful,
            task_results=task_results,
        )

    def _deadline_step_cap(self, started_at: float, done: int) -> int | None:
        # если прогон отстаёт от графика, урезаем вызовы, чтобы успеть все задачи
        if not self.deadline_minutes or not self.max_tasks:
            return None
        tasks_left = max(1, self.max_tasks - done)
        seconds_left = self.deadline_minutes * 60 - (self._clock() - started_at)
        per_call = (
            self._spent_seconds / self._spent_calls
            if self._spent_calls
            else FIRST_GUESS_SECONDS_PER_CALL
        )
        affordable = int(seconds_left / tasks_left / per_call)
        if affordable >= self.max_steps:
            return None
        cap = max(MIN_DEADLINE_STEPS, affordable)
        logger.warning(
            "Behind schedule: {:.0f} s left for {} tasks at {:.1f} s per call; capping the "
            "next task at {} calls.",
            seconds_left,
            tasks_left,
            per_call,
            cap,
        )
        return cap

    async def _investigate(
        self, session: RemoteBenchmarkSession, *, step_cap: int | None = None
    ) -> TaskResult:
        observation = session.task.observation
        alert = observation.get("alert_text")
        logger.info("Alert: {}", alert)
        self.trajectory.log("task_start", task_id=session.task_id, alert=alert)

        tools = self._function_schemas(self._tool_specs(observation))
        parameters = {
            tool["function"]["name"]: tool["function"].get("parameters") for tool in tools
        }
        if self.simplify_tool_schemas:
            tools = [simplify_tool(tool) for tool in tools]
        available = {tool["function"]["name"] for tool in tools}
        if FINISH not in available:
            raise ValueError("The runtime did not advertise finish_investigation.")
        finish_only = [tool for tool in tools if tool["function"]["name"] == FINISH]

        self._task_type = alert_type(alert)
        budget, max_steps = self._plan_calls(alert)
        if step_cap:
            max_steps = min(max_steps, step_cap)

        known = bool(call_budget(alert) or open_budget(alert) or scenario_notes(alert))
        self._types_seen += 1
        self._types_known += known
        logger.info(
            "Alert type {} practice runs ({} of {} so far).",
            "seen in" if known else "new to",
            self._types_known,
            self._types_seen,
        )

        notes: list[str] = []
        if self.use_notes and not self._all_notes_off:
            notes = [note for note in scenario_notes(alert) if note not in self._notes_off]
        self._task_notes = notes
        if budget:
            notes = [*notes, BUDGET_NOTE.format(budget=budget)]
            logger.info("Known budget for this alert type: {} calls (cap {}).", budget, max_steps)

        task_message: dict[str, Any] = {
            "instruction": "Investigate this alert and submit the correct response.",
            "observation": {k: v for k, v in observation.items() if k != "available_tools"},
            "step_budget": max_steps,
        }
        if notes:
            task_message["notes_for_this_alert"] = notes
            self.trajectory.log("scenario_notes", task_id=session.task_id, notes=notes)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": render_json(task_message)},
        ]

        task = TaskState(
            session=session,
            evidence=Evidence(alert),
            parameters=parameters,
            available=available,
            max_steps=max_steps,
        )
        if self.harvest_calls and "search" in available and max_steps > 2:
            task.calls += await self._harvest(
                task, messages, max_calls=min(self.harvest_calls, max_steps - 2)
            )

        max_turns = max_steps + MAX_LOCAL_REJECTIONS
        for turn in range(1, max_turns + 1):
            if task.calls >= task.max_steps:
                break
            steps_left = min(task.max_steps - task.calls, max_turns - turn + 1)
            step_tools = tools
            if steps_left == 1:
                messages.append({"role": "user", "content": FINISH_NOW})
                step_tools = finish_only
            elif steps_left == BUDGET_WARNING_STEPS:
                messages.append({"role": "user", "content": BUDGET_WARNING.format(left=steps_left)})
            elif task.nudge_no_findings:
                messages.append(
                    {"role": "user", "content": NO_FINDINGS.format(count=NO_FINDINGS_STREAK)}
                )
                task.nudge_no_findings = False

            call = await self.llm.next_tool_call(messages, step_tools)
            if call.name == FINISH:
                normalize_finish(call.arguments)
            call_id = call.id or f"call_{turn}"
            messages.append(self._assistant_message(call, call_id))

            feedback, terminal = await self._handle(task, call, turn, steps_left)
            if feedback.get("status") in {"ok", "error"} and call.name != FINISH:
                self._note_reward(task, feedback)
            self.trajectory.log(
                "step",
                task_id=session.task_id,
                step=turn,
                tool=call.name,
                arguments=call.arguments,
                feedback=feedback,
            )
            if terminal is not None:
                return TaskResult.model_validate(terminal)
            if feedback.get("terminated"):
                # метрики скрыты, задача закрыта без результата
                return TaskResult(
                    task_id=session.task_id, completion_reason="terminated", tool_calls=task.calls
                )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": render_json(self._for_model(feedback)),
                }
            )

        raise RuntimeError(f"Agent hit the {task.max_steps}-step limit without {FINISH}.")

    async def _handle(
        self, task: TaskState, call: ToolCall, turn: int, steps_left: int
    ) -> tuple[dict[str, Any], Any]:
        if call.name == FINISH:
            held, steps_left = await self._hold_back(task, call.arguments, turn, steps_left)
            if held:
                return held, None
        last_step = steps_left <= 1
        if not last_step and (rejection := self._reject_locally(task, call, turn)):
            return rejection, None
        if call.name not in task.available:
            logger.warning("Rejected unavailable tool {} locally.", call.name)
            return {
                "status": "error",
                "error": (
                    f"Tool {call.name!r} is not advertised for this task. "
                    f"Available tools: {sorted(task.available)}"
                ),
            }, None
        return await self._send(task, call, turn, last_step)

    async def _hold_back(
        self, task: TaskState, arguments: dict[str, Any], turn: int, steps_left: int
    ) -> tuple[dict[str, Any] | None, int]:
        verdict = verdict_of(arguments)
        slip = verdict_slip(arguments)

        # benign без находок часто оказывался пропущенной атакой, перед отправкой ищем артефакты
        if (
            self.artifact_sweep
            and self.reward_signal_seen
            and not task.swept
            and not slip
            and verdict == "benign"
            and not task.model_scored
            and steps_left > len(SWEEP_QUERIES)
            and "search" in task.available
        ):
            task.swept = True
            task.empty_benign_reviewed = True
            calls, earned, objection = await self._artifact_sweep(task)
            task.calls += calls
            steps_left -= calls
            if earned > 0:
                task.model_scored = True
            if objection:
                logger.warning("Step {}: verdict held back for a second look.", turn)
                return {"status": "not_submitted", "error": objection}, steps_left

        if slip and not task.slip_reviewed and steps_left > 1:
            task.slip_reviewed = True
            logger.warning("Step {}: report held back, {}", turn, slip)
            return {
                "status": "not_submitted",
                "error": VERDICT_SLIP.format(problem=slip),
            }, steps_left

        if (
            verdict == "benign"
            and self.empty_benign_review
            and not task.empty_benign_reviewed
            and self.reward_signal_seen
            and steps_left >= EMPTY_BENIGN_MIN_STEPS
            and not task.model_scored
        ):
            task.empty_benign_reviewed = True
            logger.info("Step {}: benign verdict with nothing scored held back.", turn)
            return {"status": "not_submitted", "error": EMPTY_BENIGN_REVIEW}, steps_left

        return None, steps_left

    def _reject_locally(self, task: TaskState, call: ToolCall, turn: int) -> dict[str, Any] | None:
        evidence = task.evidence
        if problems := argument_problems(task.parameters.get(call.name) or {}, call.arguments):
            logger.warning("Step {}: rejected invalid arguments locally: {}", turn, problems)
            return {"status": "not_sent", "error": "Not sent: " + "; ".join(problems)}
        if unknown := evidence.unknown_ids(call.arguments):
            hints = [
                f"{value!r} (did you mean {closest!r}?)"
                if (closest := evidence.closest_id(value))
                else repr(value)
                for value in unknown
            ]
            logger.warning("Step {}: rejected unknown ids locally: {}", turn, unknown)
            return {"status": "not_sent", "error": UNKNOWN_ID.format(ids=", ".join(hints))}
        if misused := evidence.wrong_kind(call.arguments):
            logger.warning("Step {}: rejected misused ids locally: {}", turn, misused)
            return {"status": "not_sent", "error": "Not sent: " + " ".join(misused)}
        return None

    async def _send(
        self, task: TaskState, call: ToolCall, turn: int, last_step: bool
    ) -> tuple[dict[str, Any], Any]:
        evidence = task.evidence
        if call.name == FINISH:
            if last_step:
                # на последнем шаге исправляем отчёт без участия модели
                drop_items_with_ids(call.arguments, evidence.bad_ids(call.arguments))
                fix_false_positive_slip(call.arguments)
            self._prune_report(task, call.arguments)

        task.calls += 1
        response = await task.session.call_tool(call.name, call.arguments)
        feedback = self._tool_feedback(response)
        status = feedback.get("status")
        if status != "error":
            evidence.add_result(feedback.get("result"))
        if status == "ok" and call.name != FINISH:
            evidence.add_reward(feedback.get("result"), feedback.get("reward"))
        logger.info("Step {}: {} returned status {}.", turn, call.name, status or "unknown")
        if status == "error":
            logger.warning(
                "Tool error: {} | arguments: {}",
                feedback.get("error") or feedback.get("result"),
                render_json(call.arguments),
            )
            if (
                call.name == FINISH
                and response.task_result is None
                and task.calls >= task.max_steps
                and not task.finish_retry_used
            ):
                # отчёт отклонён на последнем шаге, разрешаем ещё одну попытку
                task.finish_retry_used = True
                task.max_steps += 1
                logger.warning("Report rejected on the last step: one more try.")
        return feedback, response.task_result

    def _note_reward(self, task: TaskState, feedback: dict[str, Any]) -> None:
        rewarded = (feedback.get("reward") or 0) > 0
        self.reward_signal_seen = self.reward_signal_seen or rewarded
        task.model_scored = task.model_scored or rewarded
        task.unrewarded_streak = 0 if rewarded else task.unrewarded_streak + 1
        if task.unrewarded_streak >= NO_FINDINGS_STREAK and self.reward_signal_seen:
            task.nudge_no_findings = True
            task.unrewarded_streak = 0

    def _for_model(self, feedback: dict[str, Any]) -> dict[str, Any]:
        # иначе модель видит нулевую награду и считает результат пустым
        if self.reward_signal_seen or "reward" not in feedback:
            return feedback
        return {key: value for key, value in feedback.items() if key != "reward"}

    async def _harvest(
        self, task: TaskState, messages: list[dict[str, Any]], *, max_calls: int
    ) -> int:
        # поиски до первого хода модели, учётки и хосты из алерта
        if max_calls <= 1:
            names = task.evidence.accounts_to_open()
            if not names:
                return 0
            return int(await self._seeded_search(task, messages, names[0], 0) is not None)

        searched: set[str] = set()
        calls = 0
        dry = 0
        while calls < max_calls and dry < HARVEST_DRY_STOP:
            queries = harvest_queries(task.evidence, searched)
            if not queries:
                break
            searched.add(queries[0].lower())
            reward = await self._seeded_search(task, messages, queries[0], calls)
            if reward is None:
                continue
            calls += 1
            dry = 0 if reward > 0 else dry + 1
        logger.info("Harvest: {} searches before the model's first turn.", calls)
        return calls

    async def _seeded_search(
        self, task: TaskState, messages: list[dict[str, Any]], query: str, index: int
    ) -> float | None:
        # поиск добавляется в диалог как вызов модели, None если запрос не отправлен
        arguments = {
            "query": query,
            "reasoning": "Open the account of the alerted process and what it touched.",
        }
        if argument_problems(task.parameters.get("search") or {}, arguments):
            return None
        response = await task.session.call_tool("search", arguments)
        feedback = self._tool_feedback(response)
        reward = float(feedback.get("reward") or 0)
        if feedback.get("status") == "ok":
            task.evidence.add_result(feedback.get("result"))
            task.evidence.add_reward(feedback.get("result"), feedback.get("reward"))
            self.reward_signal_seen = self.reward_signal_seen or reward > 0
        logger.info(
            "Seed search for {} returned status {} (reward {}).",
            query,
            feedback.get("status"),
            feedback.get("reward"),
        )
        self.trajectory.log(
            "step",
            task_id=task.session.task_id,
            step=-index,
            tool="search",
            arguments=arguments,
            feedback=feedback,
        )
        call_id = f"seed_search_{index}"
        messages.append(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "type": "function",
                        "id": call_id,
                        "function": {"name": "search", "arguments": render_json(arguments)},
                    }
                ],
            }
        )
        messages.append(
            {
                "role": "tool",
                "tool_call_id": call_id,
                "content": render_json(self._for_model(feedback)),
            }
        )
        return reward

    async def _artifact_sweep(self, task: TaskState) -> tuple[int, float, str | None]:
        calls = 0
        earned = 0.0
        found: list[str] = []
        schema = task.parameters.get("search") or {}
        for query in SWEEP_QUERIES:
            arguments = {"query": query, "reasoning": "Look for attack artifacts before closing."}
            if argument_problems(schema, arguments):
                continue
            response = await task.session.call_tool("search", arguments)
            calls += 1
            feedback = self._tool_feedback(response)
            reward = float(feedback.get("reward") or 0)
            self.trajectory.log(
                "step",
                task_id=task.session.task_id,
                step=0,
                tool="search",
                arguments=arguments,
                feedback=feedback,
            )
            if feedback.get("status") != "ok":
                continue
            task.evidence.add_result(feedback.get("result"))
            task.evidence.add_reward(feedback.get("result"), feedback.get("reward"))
            if reward > 0:
                earned += reward
                shown = json.dumps(_compact(feedback), ensure_ascii=False, separators=(",", ":"))
                found.append(f"search {query!r} (reward {reward:g}): {shown[:SWEEP_SHOWN_CHARS]}")
        logger.info("Artifact sweep: {} searches, reward {:g}.", calls, earned)
        if not earned:
            return calls, 0.0, None
        return calls, earned, ARTIFACT_SWEEP.format(found="\n".join(found))

    def _plan_calls(self, alert: Any) -> tuple[int | None, int]:
        # бюджет для модели и лимит вызовов, измеренный в прогоне бюджет важнее таблицы
        if not self.type_budgets:
            return None, min(self.max_steps, self.total_cap or self.max_steps)
        key = alert_type(alert) or ("", "")
        if measured := self._run_budgets.get(key):
            budget = max(1, math.ceil(median(measured)))
            return budget, min(self.max_steps, budget)
        if open_budget(alert):
            return None, min(self.max_steps, OPEN_BUDGET_CAP)
        table = call_budget(alert)
        cap = table or self.total_cap or self.max_steps
        if self._run_floors.get(key, 0) >= cap:
            # эффективность осталась 1 на лимите, значит бюджет больше
            raised = min(self.max_steps, OPEN_BUDGET_CAP, self._run_floors[key] + RAISE_STEP)
            return (raised if table else None), raised
        return table, min(self.max_steps, cap)

    def _learn_from_result(self, result: TaskResult) -> None:
        key, self._task_type = self._task_type, None
        notes, self._task_notes = self._task_notes, []
        finished = result.completion_reason == "terminated"
        hidden = not self.reward_signal_seen or (
            result.total_reward == 0 and result.efficiency_score == 0
        )

        # нулевое качество задачи с подсказкой означает смену сценария, подсказку отключаем
        if notes and finished and result.quality_score <= 0 and not hidden:
            self._notes_off.update(notes)
            if key is not None:
                self._failed_note_types.add(key)
            logger.warning(
                "A noted task scored 0: dropping its note ({} alert types failed).",
                len(self._failed_note_types),
            )
            if (
                len(self._failed_note_types) >= NOTE_FAILURES_TO_DROP_ALL
                and not self._all_notes_off
            ):
                self._all_notes_off = True
                logger.warning("Notes failed on several alert types: dropping every note.")

        if key is None or not finished or result.tool_calls <= 0:
            return
        # при эффективности меньше 1 бюджет равен эффективности, умноженной на число вызовов
        if 0 < result.efficiency_score < 1:
            budget = result.efficiency_score * result.tool_calls
            self._run_budgets.setdefault(key, []).append(budget)
            logger.info("Measured budget for {} <- {}: {:.1f} calls.", key[0], key[1], budget)
        elif result.efficiency_score >= 1:
            self._run_floors[key] = max(self._run_floors.get(key, 0), result.tool_calls)

    def _prune_report(self, task: TaskState, arguments: dict[str, Any]) -> None:
        submission = arguments.get("submission")
        if not isinstance(submission, dict):
            return
        verdict = submission.get("verdict")
        if verdict == "benign":
            key = "legitimacy_evidence"
        elif verdict == "malicious":
            key = "ir_artifacts"
        else:
            return
        items = submission.get(key)
        if not isinstance(items, list):
            return

        evidence = task.evidence
        if not self.reward_signal_seen:
            kept = filter_by_kind(items, verdict, evidence)
            if kept != items:
                submission[key] = kept
                logger.info(
                    "{} report filtered by type (no rewards shown): {} items -> {}.",
                    verdict,
                    len(items),
                    len(kept),
                )
                self.trajectory.log(
                    "report_pruned", task_id=task.session.task_id, before=items, after=kept
                )
            return

        if verdict == "benign":
            # без подтверждённых пунктов список пустой, догадки снижают оценку
            pruned = evidence.prune_benign(items)
            if pruned is None:
                pruned = []
        else:
            pruned = evidence.prune_malicious(items)
            if self.complete_report_share is not None:
                base = items if pruned is None else pruned
                additions = evidence.report_additions(base, min_share=self.complete_report_share)
                if additions:
                    pruned = [*base, *additions]
                    logger.info("Malicious report completed by reward: +{} items.", len(additions))
        if pruned is None or pruned == items:
            return
        submission[key] = pruned
        logger.info("{} report pruned by reward: {} items -> {}.", verdict, len(items), len(pruned))
        self.trajectory.log(
            "report_pruned", task_id=task.session.task_id, before=items, after=pruned
        )

    @staticmethod
    def _assistant_message(call: ToolCall, call_id: str) -> dict[str, Any]:
        tool_call: dict[str, Any] = {
            "type": "function",
            "id": call_id,
            "function": {"name": call.name, "arguments": render_json(call.arguments)},
        }
        if call.extra:
            tool_call.update(call.extra)
        message: dict[str, Any] = {"role": "assistant", "content": None, "tool_calls": [tool_call]}
        if call.message_extra:
            message.update(call.message_extra)
        return message

    @staticmethod
    def _tool_specs(observation: dict[str, Any]) -> list[dict[str, Any]]:
        raw = observation.get("available_tools")
        if not isinstance(raw, str):
            raise ValueError("Observation has no JSON-encoded available_tools field.")
        try:
            specs = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("available_tools is not valid JSON.") from exc
        if not isinstance(specs, list) or not all(isinstance(spec, dict) for spec in specs):
            raise ValueError("available_tools must encode a list of tool specifications.")
        return [dict(spec) for spec in specs]

    @staticmethod
    def _function_schemas(tool_specs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        schemas: list[dict[str, Any]] = []
        for spec in tool_specs:
            schema = spec.get("function_schema")
            if isinstance(schema, dict) and isinstance(schema.get("function"), dict):
                schemas.append(schema)
            elif isinstance(spec.get("name"), str):
                schemas.append(
                    {
                        "type": "function",
                        "function": {
                            "name": spec["name"],
                            "description": spec.get("description", ""),
                            "parameters": spec.get("parameters", {"type": "object"}),
                        },
                    }
                )
        return schemas

    @staticmethod
    def _tool_feedback(response: ToolCallResult) -> dict[str, Any]:
        result = response.info.get("tool_result")
        if result is None:
            result = response.observation.get("last_tool_result")
        return {
            "tool_name": response.tool_name,
            "status": response.info.get("tool_status", "unknown"),
            "result": result,
            "error": response.info.get("error"),
            "reward": response.reward,
            "terminated": response.terminated,
            "truncated": response.truncated,
        }
