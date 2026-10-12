import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import bluesec1_agent.agent as agent_module
from bluesec1_agent.agent import InvestigationAgent
from bluesec1_agent.llm import (
    LLMUnavailableError,
    NextStepRequestError,
    ToolCall,
)
from bluesec1_agent.trajectory import TrajectoryLogger
from bluesec1_client import (
    PublicTask,
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)

ENTITY_ID = "11111111-1111-1111-1111-111111111111"
PROCESS_ID = "22222222-2222-2222-2222-222222222222"


class FakeToolClient:
    def __init__(self, calls: list[ToolCall]) -> None:
        self.calls = list(calls)
        self.requests: list[list[dict[str, Any]]] = []
        self.tools: list[list[dict[str, Any]]] = []

    async def next_tool_call(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ToolCall:
        self.requests.append([dict(message) for message in messages])
        self.tools.append(tools)
        return self.calls.pop(0)


class FakeSession:
    def __init__(self) -> None:
        self.task = PublicTask(
            task_id="task-1",
            observation={
                "alert_text": {"trigger_entities": [{"id": ENTITY_ID, "type": "host"}]},
                "available_tools": json.dumps(
                    [
                        {"name": "get_entity", "parameters": {"type": "object"}},
                        {"name": "finish_investigation", "parameters": {"type": "object"}},
                    ]
                ),
            },
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def task_id(self) -> str:
        return self.task.task_id

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolCallResult:
        self.calls.append((tool_name, arguments))
        terminal = tool_name == "finish_investigation"
        task_result = None
        if terminal:
            task_result = TaskResult(
                task_id="task-1",
                completion_reason="terminated",
            )
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            reward=1.0,
            terminated=terminal,
            info={
                "tool_status": "ok",
                "tool_result": (
                    [{"entity_id": PROCESS_ID, "pid": 42}] if not terminal else "Report accepted"
                ),
            },
            task_result=task_result,
        )

    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        raise AssertionError(f"Unexpected abort: {error_message}")


class FakeClient:
    def __init__(self, session: FakeSession) -> None:
        self.run = SimpleNamespace(run_id="run-1")
        self.session: FakeSession | None = session

    async def start_task(self) -> RemoteBenchmarkSession | None:
        if self.session is None:
            return None
        session = self.session
        self.session = None
        return cast(RemoteBenchmarkSession, session)


def test_agent_executes_fresh_task_via_native_tool_calls() -> None:
    llm = FakeToolClient(
        [
            ToolCall(
                id="call_a",
                name="get_entity",
                arguments={"entity_id": ENTITY_ID, "reasoning": "Inspect the alert process."},
            ),
            ToolCall(
                id="call_b",
                name="finish_investigation",
                arguments={
                    "submission": {
                        "verdict": "malicious",
                        "ir_artifacts": [{"entity_id": PROCESS_ID, "kind": "process_observed"}],
                        "reasoning": "The alert process is part of a suspicious chain.",
                    }
                },
            ),
        ]
    )
    session = FakeSession()
    client = FakeClient(session)

    result = asyncio.run(InvestigationAgent(llm).run(cast(RemoteBenchmarkClient, client)))

    assert result.run_id == "run-1"
    assert result.successful_tasks == 1
    assert result.failed_tasks == 0
    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    assert session.calls[0][1] == {
        "entity_id": ENTITY_ID,
        "reasoning": "Inspect the alert process.",
    }
    assert [tool["function"]["name"] for tool in llm.tools[0]] == [
        "get_entity",
        "finish_investigation",
    ]
    tool_messages = [message for message in llm.requests[1] if message["role"] == "tool"]
    assert tool_messages[0]["tool_call_id"] == "call_a"
    assert PROCESS_ID in tool_messages[0]["content"]
    assert "available_tools" not in llm.requests[0][1]["content"]


def test_provider_extra_fields_are_echoed_back() -> None:
    signature = {"extra_content": {"google": {"thought_signature": "SIG"}}}
    llm = FakeToolClient(
        [
            ToolCall(
                id="call_a",
                name="get_entity",
                arguments={"entity_id": ENTITY_ID, "reasoning": "Inspect."},
                extra=signature,
                message_extra={"reasoning_details": [{"type": "reasoning.encrypted"}]},
            ),
            ToolCall(
                id="call_b",
                name="finish_investigation",
                arguments={
                    "submission": {
                        "verdict": "malicious",
                        "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                        "reasoning": "r",
                    }
                },
            ),
        ]
    )
    asyncio.run(InvestigationAgent(llm).run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    assistant = [message for message in llm.requests[1] if message["role"] == "assistant"]
    assert assistant[0]["tool_calls"][0]["extra_content"] == signature["extra_content"]
    assert assistant[0]["reasoning_details"] == [{"type": "reasoning.encrypted"}]


def test_trajectory_records_every_step_and_the_result(tmp_path: Path) -> None:
    llm = FakeToolClient(
        [
            ToolCall(
                id="call_a",
                name="get_entity",
                arguments={"entity_id": ENTITY_ID, "reasoning": "Inspect."},
            ),
            ToolCall(
                id="call_b",
                name="finish_investigation",
                arguments={
                    "submission": {
                        "verdict": "malicious",
                        "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                        "reasoning": "r",
                    }
                },
            ),
        ]
    )
    trajectory = TrajectoryLogger(tmp_path, run_label="test run")
    agent = InvestigationAgent(llm, trajectory=trajectory)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    assert trajectory.path is not None
    assert trajectory.path.name.startswith("test_run_")
    events = [json.loads(line) for line in trajectory.path.read_text().splitlines()]
    assert [event["event"] for event in events] == ["task_start", "step", "step", "task_end"]
    assert events[1]["arguments"]["reasoning"] == "Inspect."
    assert PROCESS_ID in json.dumps(events[1]["feedback"])
    assert events[2]["tool"] == "finish_investigation"
    assert events[3]["result"]["completion_reason"] == "terminated"


def test_last_step_offers_only_finish_investigation() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {"verdict": "benign", "legitimacy_evidence": [], "reasoning": "r"}
        },
    )
    llm = FakeToolClient([explore, explore, finish])
    session = FakeSession()
    agent = InvestigationAgent(llm, max_steps=3)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [len(tools) for tools in llm.tools] == [2, 2, 1]
    assert llm.tools[2][0]["function"]["name"] == "finish_investigation"
    assert "budget is exhausted" in llm.requests[2][-1]["content"]
    assert "Only 3 tool calls remain" in llm.requests[0][-1]["content"]
    assert [name for name, _ in session.calls][-1] == "finish_investigation"


class BrokenLLM:
    def __init__(self) -> None:
        self.requests = 0

    async def next_tool_call(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ToolCall:
        self.requests += 1
        raise LLMUnavailableError("Provider rejected the request")


class AbortableSession(FakeSession):
    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        return TaskResult(task_id=self.task_id, completion_reason="aborted")


class EndlessClient:
    def __init__(self) -> None:
        self.run = SimpleNamespace(run_id="run-1")
        self.started = 0

    async def start_task(self) -> RemoteBenchmarkSession:
        self.started += 1
        return cast(RemoteBenchmarkSession, AbortableSession())


def test_run_stops_when_llm_provider_keeps_failing() -> None:
    agent_module.LLM_FAILURE_PAUSE_SECONDS = 0.0
    client = EndlessClient()
    agent = InvestigationAgent(cast(Any, BrokenLLM()), max_tasks=20)
    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, client)))

    assert client.started == 2
    assert result.failed_tasks == 2


class ExhaustedLLM(BrokenLLM):
    async def next_tool_call(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ToolCall:
        self.requests += 1
        raise NextStepRequestError("Error code: 503")


def test_provider_outage_also_stops_the_run() -> None:
    agent_module.LLM_FAILURE_PAUSE_SECONDS = 0.0
    client = EndlessClient()
    agent = InvestigationAgent(cast(Any, ExhaustedLLM()), max_tasks=20)
    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, client)))

    assert client.started == 2
    assert result.failed_tasks == 2


def test_unknown_id_is_rejected_locally_without_server_call() -> None:
    typo = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID[:-2] + "_1", "reasoning": "r"}
    )
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )
    llm = FakeToolClient([typo, finish])
    session = FakeSession()
    asyncio.run(InvestigationAgent(llm).run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == ["finish_investigation"]
    rejection = [m for m in llm.requests[1] if m["role"] == "tool"][-1]["content"]
    assert "never appeared" in rejection
    assert ENTITY_ID in rejection


def test_misused_id_is_rejected_locally_with_tool_hint() -> None:
    misuse = ToolCall(
        id="", name="get_relation", arguments={"relation_id": ENTITY_ID, "reasoning": "r"}
    )
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )
    llm = FakeToolClient([misuse, finish])
    session = FakeSession()
    session.task.observation["alert_text"]["trigger_entities"][0]["properties"] = {}
    asyncio.run(InvestigationAgent(llm).run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == ["finish_investigation"]
    rejection = [m for m in llm.requests[1] if m["role"] == "tool"][-1]["content"]
    assert "get_entity" in rejection


def test_last_step_finish_drops_bad_ids_instead_of_aborting() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [
                    {"entity_id": ENTITY_ID, "kind": "host_to_isolate"},
                    {"entity_id": "99999999-9999-9999-9999-999999999999", "kind": "other"},
                ],
                "reasoning": "r",
            }
        },
    )
    llm = FakeToolClient([finish])
    session = FakeSession()
    asyncio.run(
        InvestigationAgent(llm, max_steps=1).run(cast(RemoteBenchmarkClient, FakeClient(session)))
    )

    assert [name for name, _ in session.calls] == ["finish_investigation"]
    sent = session.calls[0][1]["submission"]["ir_artifacts"]
    assert sent == [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}]


def test_benign_report_loses_empty_artifact_list() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "benign",
                "ir_artifacts": [],
                "legitimacy_evidence": [],
                "reasoning": "r",
            }
        },
    )
    llm = FakeToolClient([finish])
    session = FakeSession()
    asyncio.run(
        InvestigationAgent(llm, max_steps=1).run(cast(RemoteBenchmarkClient, FakeClient(session)))
    )

    assert "ir_artifacts" not in session.calls[0][1]["submission"]


def test_misnamed_reasoning_field_is_repaired() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "benign",
                "legitimacy_evidence": [],
                "reasoning_filtered": "Routine backup job.",
            }
        },
    )
    llm = FakeToolClient([finish])
    session = FakeSession()
    asyncio.run(
        InvestigationAgent(llm, max_steps=1).run(cast(RemoteBenchmarkClient, FakeClient(session)))
    )

    sent = session.calls[0][1]["submission"]
    assert sent["reasoning"] == "Routine backup job."
    assert "reasoning_filtered" not in sent


def test_top_level_reasoning_moves_into_the_report() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "reasoning": "Phishing chain on NB79.",
            "submission": {"verdict": "malicious", "ir_artifacts": []},
        },
    )
    llm = FakeToolClient([finish])
    session = FakeSession()
    asyncio.run(
        InvestigationAgent(llm, max_steps=1).run(cast(RemoteBenchmarkClient, FakeClient(session)))
    )

    sent = session.calls[0][1]
    assert list(sent) == ["submission"]
    assert sent["submission"]["reasoning"] == "Phishing chain on NB79."


def test_benign_evidence_loses_metadata_fields() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "benign",
                "reasoning": "r",
                "legitimacy_evidence": [
                    {
                        "anchor": "entity",
                        "entity_id": ENTITY_ID,
                        "property_fields": ["user", "type"],
                    },
                    {"anchor": "relation", "relation_id": PROCESS_ID, "property_fields": ["type"]},
                ],
            }
        },
    )
    llm = FakeToolClient([finish])
    session = FakeSession()
    agent = InvestigationAgent(llm, max_steps=1)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    evidence = session.calls[0][1]["submission"]["legitimacy_evidence"]
    # наград не было, работает фильтр по типам, сущность из алерта и связь удаляются
    assert evidence == []


class ZeroRewardSession(FakeSession):
    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        if tool_name == "finish_investigation":
            return await super().call_tool(tool_name, arguments)
        self.calls.append((tool_name, arguments))
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            reward=0.0,
            terminated=False,
            info={"tool_status": "ok", "tool_result": json.dumps({"id": ENTITY_ID})},
        )


def test_streak_without_reward_triggers_one_hint() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )
    llm = FakeToolClient([explore] * 8 + [finish])
    agent = InvestigationAgent(llm, max_steps=25)
    agent.reward_signal_seen = True  # в прошлых задачах прогона награды были
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(ZeroRewardSession()))))

    hints = [
        sum("opened nothing the scorer counts" in str(m.get("content")) for m in r)
        for r in llm.requests
    ]
    assert hints == [0, 0, 0, 0, 0, 0, 1, 1, 1]


def test_no_findings_hint_waits_until_the_run_has_seen_a_reward() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )
    llm = FakeToolClient([explore] * 8 + [finish])
    agent = InvestigationAgent(llm, max_steps=25)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(ZeroRewardSession()))))

    assert not any("opened nothing the scorer counts" in str(r) for r in llm.requests)


def test_report_without_submission_wrapper_is_wrapped() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "verdict": "benign",
            "legitimacy_evidence": [
                {"anchor": "entity", "entity_id": ENTITY_ID, "property_fields": ["role"]}
            ],
            "reasoning": "Admin console on the admin workstation.",
        },
    )
    llm = FakeToolClient([finish])
    session = FakeSession()
    asyncio.run(
        InvestigationAgent(llm, max_steps=1).run(cast(RemoteBenchmarkClient, FakeClient(session)))
    )

    sent = session.calls[0][1]
    assert list(sent) == ["submission"]
    assert sent["submission"]["verdict"] == "benign"
    assert sent["submission"]["reasoning"] == "Admin console on the admin workstation."


def test_local_rejections_do_not_use_the_server_budget() -> None:
    broken = ToolCall(
        id="",
        name="get_entity",
        arguments={"entity_id": "99999999-9999-9999-9999-999999999999", "reasoning": "r"},
    )
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )
    llm = FakeToolClient([broken, broken, broken, explore, finish])
    session = FakeSession()
    asyncio.run(
        InvestigationAgent(llm, max_steps=2).run(cast(RemoteBenchmarkClient, FakeClient(session)))
    )

    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    offered = [[tool["function"]["name"] for tool in tools] for tools in llm.tools]
    assert offered[-1] == ["finish_investigation"]


USER_ID = "33333333-3333-3333-3333-333333333333"
FILE_ID = "44444444-4444-4444-4444-444444444444"


class RewardSession(FakeSession):
    def __init__(self) -> None:
        super().__init__()
        self.task.observation["alert_text"]["trigger_relations"] = [
            {"id": "r1", "type": "x", "source_id": USER_ID, "target_id": FILE_ID}
        ]

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        if tool_name == "finish_investigation":
            return await super().call_tool(tool_name, arguments)
        self.calls.append((tool_name, arguments))
        found = {
            USER_ID: ({"type": "windows_user", "properties": {"username": "bob"}}, 1.0),
            FILE_ID: ({"type": "windows_file", "properties": {"path": "C:\\a.txt"}}, 0.0),
        }
        body, reward = found[arguments["entity_id"]]
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            reward=reward,
            terminated=False,
            info={
                "tool_status": "ok",
                "tool_result": json.dumps({"id": arguments["entity_id"], **body}),
            },
        )


def test_benign_report_is_pruned_to_rewarded_entities() -> None:
    session = RewardSession()
    opened = [
        ToolCall(id="", name="get_entity", arguments={"entity_id": entity, "reasoning": "r"})
        for entity in (USER_ID, FILE_ID)
    ]
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "benign",
                "reasoning": "r",
                "legitimacy_evidence": [
                    {"anchor": "entity", "entity_id": ENTITY_ID, "property_fields": ["role"]},
                    {"anchor": "entity", "entity_id": FILE_ID, "property_fields": ["path"]},
                ],
            }
        },
    )
    llm = FakeToolClient([*opened, finish])
    agent = InvestigationAgent(llm, max_steps=25)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    evidence = session.calls[-1][1]["submission"]["legitimacy_evidence"]
    assert evidence == [{"anchor": "entity", "entity_id": USER_ID, "property_fields": ["username"]}]


def unconfirmed_benign_finish() -> tuple[FakeToolClient, list[dict[str, Any]]]:
    opened = ToolCall(id="", name="get_entity", arguments={"entity_id": FILE_ID, "reasoning": "r"})
    items = [{"anchor": "entity", "entity_id": FILE_ID, "property_fields": ["path"]}]
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {"verdict": "benign", "reasoning": "r", "legitimacy_evidence": items}
        },
    )
    return FakeToolClient([opened, finish]), items


def test_benign_report_with_nothing_confirmed_goes_out_empty() -> None:
    llm, _ = unconfirmed_benign_finish()
    session = RewardSession()
    agent = InvestigationAgent(llm, max_steps=25)
    agent.reward_signal_seen = True  # в прошлых задачах прогона награды были
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert session.calls[-1][1]["submission"]["legitimacy_evidence"] == []


def test_benign_report_is_kept_while_no_reward_was_ever_seen() -> None:
    llm, items = unconfirmed_benign_finish()
    session = RewardSession()
    agent = InvestigationAgent(llm, max_steps=25)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert session.calls[-1][1]["submission"]["legitimacy_evidence"] == items


def test_malicious_report_drops_entities_opened_without_reward() -> None:
    opened = ToolCall(id="", name="get_entity", arguments={"entity_id": FILE_ID, "reasoning": "r"})
    artifacts = [
        {"entity_id": ENTITY_ID, "kind": "host_to_isolate"},
        {"entity_id": FILE_ID, "kind": "file_to_delete"},
    ]
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {"verdict": "malicious", "reasoning": "r", "ir_artifacts": artifacts}
        },
    )
    account = ToolCall(id="", name="get_entity", arguments={"entity_id": USER_ID, "reasoning": "r"})
    llm = FakeToolClient([account, opened, finish])
    session = RewardSession()
    asyncio.run(
        InvestigationAgent(llm, max_steps=25).run(cast(RemoteBenchmarkClient, FakeClient(session)))
    )

    sent = session.calls[-1][1]["submission"]["ir_artifacts"]
    assert sent == [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}]


def test_scenario_note_reaches_the_first_message() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )
    session = FakeSession()
    session.task.observation["alert_text"]["trigger_entities"].append(
        {
            "id": PROCESS_ID,
            "type": "windows_process",
            "properties": {
                "image_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "parent_image": "C:\\Windows\\explorer.exe",
            },
        }
    )
    llm = FakeToolClient([finish, finish])
    asyncio.run(InvestigationAgent(llm).run(cast(RemoteBenchmarkClient, FakeClient(session))))
    plain = FakeToolClient([finish])
    asyncio.run(
        InvestigationAgent(plain).run(cast(RemoteBenchmarkClient, FakeClient(FakeSession())))
    )

    assert "wrote_file relations" in str(llm.requests[0][1]["content"])
    assert "notes_for_this_alert" not in str(plain.requests[0][1]["content"])


class SearchSession(FakeSession):
    def __init__(self, user: str) -> None:
        super().__init__()
        self.task.observation["available_tools"] = json.dumps(
            [
                {"name": "get_entity", "parameters": {"type": "object"}},
                {
                    "name": "search",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string", "minLength": 5}},
                        "required": ["query"],
                    },
                },
                {"name": "finish_investigation", "parameters": {"type": "object"}},
            ]
        )
        self.task.observation["alert_text"]["trigger_entities"].append(
            {"id": PROCESS_ID, "type": "windows_process", "properties": {"user": user}}
        )

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        if tool_name != "search":
            return await super().call_tool(tool_name, arguments)
        self.calls.append((tool_name, arguments))
        account = {"id": USER_ID, "type": "windows_user", "properties": {"username": "x"}}
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            reward=1.0,
            terminated=False,
            info={"tool_status": "ok", "tool_result": json.dumps({"results": [account]})},
        )


def test_account_of_alerted_process_is_searched_before_the_first_turn() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )
    llm = FakeToolClient([finish])
    session = SearchSession("CORP\\alice.smith")
    asyncio.run(InvestigationAgent(llm).run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert session.calls[0][0] == "search"
    assert session.calls[0][1]["query"] == "alice.smith"
    first_request = llm.requests[0]
    assert first_request[2]["tool_calls"][0]["function"]["name"] == "search"
    assert first_request[3]["role"] == "tool" and USER_ID in first_request[3]["content"]


def test_no_seed_search_for_built_in_or_short_accounts() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )
    for user in ("NT AUTHORITY\\SYSTEM", "CORP\\bob"):
        session = SearchSession(user)
        llm = FakeToolClient([finish])
        asyncio.run(InvestigationAgent(llm).run(cast(RemoteBenchmarkClient, FakeClient(session))))

        assert [name for name, _ in session.calls] == ["finish_investigation"]


def test_alert_type_with_known_budget_is_capped_and_told() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {"verdict": "benign", "legitimacy_evidence": [], "reasoning": "r"}
        },
    )
    session = FakeSession()
    session.task.observation["alert_text"]["trigger_entities"].append(
        {
            "id": PROCESS_ID,
            "type": "windows_process",
            "properties": {
                "image_path": "C:\\Windows\\System32\\mmc.exe",
                "parent_image": "C:\\Windows\\explorer.exe",
            },
        }
    )
    llm = FakeToolClient([explore] * 6 + [finish])
    agent = InvestigationAgent(llm, max_steps=25, type_budgets=True)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert "budget of about 7 tool calls" in str(llm.requests[0][1]["content"])
    assert len(session.calls) == 7
    assert [tool["function"]["name"] for tool in llm.tools[-1]] == ["finish_investigation"]


def test_run_deadline_caps_calls_when_time_is_short() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )
    llm = FakeToolClient([explore] * 5 + [finish])
    session = FakeSession()
    agent = InvestigationAgent(llm, max_steps=25, max_tasks=2, deadline_minutes=1.0)
    agent._clock = lambda: 0.0
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert len(session.calls) == 6
    assert [tool["function"]["name"] for tool in llm.tools[-1]] == ["finish_investigation"]
    assert json.loads(llm.requests[0][1]["content"])["step_budget"] == 6


def test_no_deadline_cap_when_there_is_time() -> None:
    agent = InvestigationAgent(FakeToolClient([]), max_steps=25, max_tasks=2, deadline_minutes=180)
    agent._clock = lambda: 0.0

    assert agent._deadline_step_cap(0.0, 0) is None


def test_malicious_report_that_calls_itself_a_false_positive_is_held_back() -> None:
    slip = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [],
                "reasoning": "Scheduled inventory script, so the alert is a false positive.",
            }
        },
    )
    benign = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {"verdict": "benign", "legitimacy_evidence": [], "reasoning": "r"}
        },
    )
    llm = FakeToolClient([slip, benign])
    session = FakeSession()
    agent = InvestigationAgent(llm, max_steps=25)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert "verdict does not match the report" in str(llm.requests[1][-1]["content"])
    assert session.calls[-1][1]["submission"]["verdict"] == "benign"


def test_false_positive_slip_on_the_last_step_is_sent_as_benign() -> None:
    slip = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [],
                "reasoning": "Nothing attacker-only, so the alert is a false positive.",
            }
        },
    )
    session = FakeSession()
    asyncio.run(
        InvestigationAgent(FakeToolClient([slip]), max_steps=1).run(
            cast(RemoteBenchmarkClient, FakeClient(session))
        )
    )

    sent = session.calls[0][1]["submission"]
    assert sent["verdict"] == "benign"
    assert "ir_artifacts" not in sent


class UnavailableSession(FakeSession):
    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        raise ConnectionError("The remote runtime is temporarily unavailable.")

    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        raise ConnectionError("The remote runtime is temporarily unavailable.")


def test_failed_abort_loses_the_task_but_not_the_run() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    agent = InvestigationAgent(FakeToolClient([explore] * 3), max_steps=25, harvest_calls=0)
    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(UnavailableSession()))))

    assert [task.completion_reason for task in result.task_results] == ["error"]


def test_open_budget_type_gets_more_calls_than_the_total_cap() -> None:
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {"verdict": "benign", "legitimacy_evidence": [], "reasoning": "r"}
        },
    )
    session = FakeSession()
    session.task.observation["alert_text"]["trigger_entities"].append(
        {
            "id": PROCESS_ID,
            "type": "windows_process",
            "properties": {"image_path": "C:\\Windows\\System32\\svchost.exe"},
        }
    )
    llm = FakeToolClient([finish])
    agent = InvestigationAgent(llm, max_steps=30, type_budgets=True, total_cap=20, harvest_calls=0)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert json.loads(llm.requests[0][1]["content"])["step_budget"] == 30


def _process_alert(image: str, parent: str) -> dict[str, Any]:
    return {
        "trigger_entities": [
            {
                "id": PROCESS_ID,
                "type": "windows_process",
                "properties": {"image_path": image, "parent_image": parent},
            }
        ]
    }


def _finished(calls: int, efficiency: float) -> TaskResult:
    return TaskResult(
        task_id="t", completion_reason="terminated", tool_calls=calls, efficiency_score=efficiency
    )


def test_measured_budget_replaces_the_training_table() -> None:
    agent = InvestigationAgent(FakeToolClient([]), max_steps=30, type_budgets=True, total_cap=20)
    console = _process_alert("C:\\Windows\\System32\\mmc.exe", "C:\\Windows\\explorer.exe")
    unknown = _process_alert("C:\\Tools\\new.exe", "C:\\Windows\\explorer.exe")

    assert agent._plan_calls(console) == (7, 7)
    assert agent._plan_calls(unknown) == (None, 20)

    agent._task_type = ("new.exe", "explorer.exe")
    agent._learn_from_result(_finished(20, 0.6))
    agent._task_type = ("mmc.exe", "explorer.exe")
    agent._learn_from_result(_finished(10, 0.9))

    assert agent._plan_calls(unknown) == (12, 12)
    assert agent._plan_calls(console) == (9, 9)


def test_type_that_kept_efficiency_at_its_cap_gets_more_calls() -> None:
    agent = InvestigationAgent(FakeToolClient([]), max_steps=30, type_budgets=True, total_cap=20)
    console = _process_alert("C:\\Windows\\System32\\mmc.exe", "C:\\Windows\\explorer.exe")
    unknown = _process_alert("C:\\Tools\\new.exe", "C:\\Windows\\explorer.exe")

    agent._task_type = ("mmc.exe", "explorer.exe")
    agent._learn_from_result(_finished(7, 1.0))
    agent._task_type = ("new.exe", "explorer.exe")
    agent._learn_from_result(_finished(20, 1.0))

    assert agent._plan_calls(console) == (11, 11)
    assert agent._plan_calls(unknown) == (None, 24)


def test_aborted_task_teaches_nothing() -> None:
    agent = InvestigationAgent(FakeToolClient([]), max_steps=30, type_budgets=True, total_cap=20)
    agent._task_type = ("mmc.exe", "explorer.exe")
    agent._learn_from_result(TaskResult(task_id="t", completion_reason="aborted", tool_calls=3))

    assert agent._run_budgets == {} and agent._run_floors == {}


def _scored(quality: float) -> TaskResult:
    return TaskResult(
        task_id="t",
        completion_reason="terminated",
        tool_calls=8,
        efficiency_score=1.0,
        quality_score=quality,
    )


def test_note_that_led_to_a_wrong_verdict_is_dropped() -> None:
    from bluesec1_agent.scenarios import ADMIN_CONSOLE, WSUS_SERVER

    agent = InvestigationAgent(FakeToolClient([]), type_budgets=True)
    agent.reward_signal_seen = True
    agent._task_type, agent._task_notes = ("w3wp.exe", ""), [WSUS_SERVER]
    agent._learn_from_result(_scored(0.6))
    agent._task_type, agent._task_notes = ("mmc.exe", "explorer.exe"), [ADMIN_CONSOLE]
    agent._learn_from_result(_scored(0.0))

    assert agent._notes_off == {ADMIN_CONSOLE}
    assert not agent._all_notes_off


def test_notes_failing_on_two_alert_types_drop_every_note() -> None:
    from bluesec1_agent.scenarios import ADMIN_CONSOLE, WSUS_SERVER

    agent = InvestigationAgent(FakeToolClient([]), type_budgets=True)
    agent.reward_signal_seen = True
    agent._task_type, agent._task_notes = ("mmc.exe", "explorer.exe"), [ADMIN_CONSOLE]
    agent._learn_from_result(_scored(0.0))
    agent._task_type, agent._task_notes = ("w3wp.exe", ""), [WSUS_SERVER]
    agent._learn_from_result(_scored(0.0))

    assert agent._all_notes_off


def test_dropped_note_is_not_sent_again() -> None:
    from bluesec1_agent.scenarios import ADMIN_CONSOLE

    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {"verdict": "benign", "legitimacy_evidence": [], "reasoning": "r"}
        },
    )
    session = FakeSession()
    session.task.observation["alert_text"]["trigger_entities"].append(
        {
            "id": PROCESS_ID,
            "type": "windows_process",
            "properties": {
                "image_path": "C:\\Windows\\System32\\mmc.exe",
                "parent_image": "C:\\Windows\\explorer.exe",
            },
        }
    )
    llm = FakeToolClient([finish])
    agent = InvestigationAgent(llm, harvest_calls=0)
    agent._notes_off.add(ADMIN_CONSOLE)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert ADMIN_CONSOLE not in str(llm.requests[0][1]["content"])


class UnrewardedSession(FakeSession):
    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        result = await super().call_tool(tool_name, arguments)
        if tool_name != "finish_investigation":
            result = result.model_copy(update={"reward": 0.0})
        return result


class RewardedEntitySession(FakeSession):
    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        result = await super().call_tool(tool_name, arguments)
        if tool_name != "finish_investigation":
            entity = {"id": PROCESS_ID, "type": "windows_process", "properties": {"pid": 42}}
            result = result.model_copy(
                update={"info": {"tool_status": "ok", "tool_result": entity}}
            )
        return result


def _benign_finish() -> ToolCall:
    return ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {"verdict": "benign", "legitimacy_evidence": [], "reasoning": "r"}
        },
    )


def test_benign_verdict_with_nothing_scored_is_held_back_once() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    session = UnrewardedSession()
    llm = FakeToolClient([explore, _benign_finish(), explore, _benign_finish()])
    agent = InvestigationAgent(llm, max_steps=10, harvest_calls=0, empty_benign_review=True)
    agent.reward_signal_seen = True
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == [
        "get_entity",
        "get_entity",
        "finish_investigation",
    ]
    assert "None of your calls in this task has earned a reward" in str(llm.requests[2])


def test_benign_verdict_after_a_scored_find_goes_straight_out() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    session = RewardedEntitySession()
    llm = FakeToolClient([explore, _benign_finish()])
    agent = InvestigationAgent(llm, max_steps=10, harvest_calls=0, empty_benign_review=True)
    agent.reward_signal_seen = True
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]


def _malicious_finish() -> ToolCall:
    return ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": ENTITY_ID, "kind": "host_to_isolate"}],
                "reasoning": "r",
            }
        },
    )


def test_artifact_sweep_shows_scored_artifacts_before_an_unsupported_benign() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )

    class SearchPays(UnrewardedSession):
        async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
            result = await super().call_tool(tool_name, arguments)
            if tool_name == "search" and arguments.get("query") == "Downloads":
                result = result.model_copy(update={"reward": 2.0})
            return result

    session = SearchPays()
    session.task.observation["available_tools"] = json.dumps(
        [
            {"name": "get_entity", "parameters": {"type": "object"}},
            {"name": "search", "parameters": {"type": "object"}},
            {"name": "finish_investigation", "parameters": {"type": "object"}},
        ]
    )
    llm = FakeToolClient([explore, _benign_finish(), _benign_finish()])
    agent = InvestigationAgent(llm, max_steps=10, harvest_calls=0, artifact_sweep=True)
    agent.reward_signal_seen = True
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    names = [name for name, _ in session.calls]
    assert names == ["get_entity", "search", "search", "finish_investigation"]
    held_back = str(llm.requests[2])
    assert "typical attack artifacts" in held_back and "(reward 2)" in held_back


def test_artifact_sweep_with_nothing_found_lets_benign_out() -> None:
    session = UnrewardedSession()
    session.task.observation["available_tools"] = json.dumps(
        [
            {"name": "search", "parameters": {"type": "object"}},
            {"name": "finish_investigation", "parameters": {"type": "object"}},
        ]
    )
    llm = FakeToolClient([_benign_finish()])
    agent = InvestigationAgent(
        llm,
        max_steps=10,
        harvest_calls=0,
        artifact_sweep=True,
        empty_benign_review=True,
    )
    agent.reward_signal_seen = True
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == ["search", "search", "finish_investigation"]


def test_report_string_with_a_field_after_the_closing_brace_is_repaired() -> None:
    from bluesec1_agent.report import normalize_finish

    broken = (
        '{"verdict": "malicious", "ir_artifacts": [{"entity_id": "e1", "kind": "other"}], '
        '"reasoning": "short"}, "reasoning": "long version"}'
    )
    arguments: dict[str, Any] = {"submission": broken}
    normalize_finish(arguments)

    assert arguments["submission"]["verdict"] == "malicious"
    assert arguments["submission"]["reasoning"] == "short"
    assert arguments["submission"]["ir_artifacts"] == [{"entity_id": "e1", "kind": "other"}]


class RejectFirstFinish(FakeSession):
    def __init__(self) -> None:
        super().__init__()
        self.finishes = 0

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        if tool_name == "finish_investigation":
            self.finishes += 1
            if self.finishes == 1:
                self.calls.append((tool_name, arguments))
                return ToolCallResult(
                    task_id="task-1",
                    tool_name=tool_name,
                    reward=-0.5,
                    terminated=False,
                    info={"tool_status": "error", "tool_result": "validation failed"},
                )
        return await super().call_tool(tool_name, arguments)


def test_rejected_report_on_the_last_step_gets_one_more_try() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    session = RejectFirstFinish()
    llm = FakeToolClient([explore, _malicious_finish(), _malicious_finish()])
    agent = InvestigationAgent(llm, max_steps=2, harvest_calls=0)
    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == [
        "get_entity",
        "finish_investigation",
        "finish_investigation",
    ]
    assert result.task_results[0].completion_reason == "terminated"


def test_keep_going_waits_instead_of_stopping_after_provider_failures() -> None:
    from bluesec1_agent.llm import LLMUnavailableError

    class DeadLLM:
        async def next_tool_call(self, messages: Any, tools: Any) -> ToolCall:
            raise LLMUnavailableError("provider down")

    class ManyTasks:
        def __init__(self, count: int) -> None:
            self.run = SimpleNamespace(run_id="run-1")
            self.left = count

        async def start_task(self) -> RemoteBenchmarkSession | None:
            if not self.left:
                return None
            self.left -= 1

            class Aborting(FakeSession):
                async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
                    return TaskResult(task_id="task-1", completion_reason="aborted")

            return cast(RemoteBenchmarkSession, Aborting())

    pauses: list[float] = []

    async def no_sleep(seconds: float) -> None:
        pauses.append(seconds)

    original = agent_module.asyncio.sleep
    agent_module.asyncio.sleep = no_sleep  # type: ignore[assignment]
    try:
        stopping = InvestigationAgent(cast(Any, DeadLLM()), harvest_calls=0)
        stopped = asyncio.run(stopping.run(cast(RemoteBenchmarkClient, ManyTasks(4))))
        going = InvestigationAgent(cast(Any, DeadLLM()), harvest_calls=0, keep_going=True)
        went = asyncio.run(going.run(cast(RemoteBenchmarkClient, ManyTasks(4))))
    finally:
        agent_module.asyncio.sleep = original  # type: ignore[assignment]

    assert len(stopped.task_results) == 2
    assert len(went.task_results) == 4
    assert max(pauses) <= agent_module.MAX_LLM_FAILURE_PAUSE_SECONDS


def test_hidden_metrics_end_the_task_and_filter_reports_by_kind() -> None:

    class HiddenSession(FakeSession):
        async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
            self.calls.append((tool_name, arguments))
            terminal = tool_name == "finish_investigation"
            entity = {"id": "u1", "type": "windows_user", "properties": {"username": "ann"}}
            other = {"id": "c1", "type": "network_connection", "properties": {"dst_port": 443}}
            return ToolCallResult(
                task_id="task-1",
                tool_name=tool_name,
                reward=0.0,
                terminated=terminal,
                info={"tool_status": "ok", "tool_result": {"results": [entity, other]}},
                task_result=None,
            )

    explore = ToolCall(id="", name="search", arguments={"query": "ann", "reasoning": "r"})
    finish = ToolCall(
        id="",
        name="finish_investigation",
        arguments={
            "submission": {
                "verdict": "benign",
                "reasoning": "r",
                "legitimacy_evidence": [
                    {"anchor": "entity", "entity_id": "u1", "property_fields": ["username"]},
                    {"anchor": "entity", "entity_id": "c1", "property_fields": ["dst_port"]},
                ],
            }
        },
    )
    session = HiddenSession()
    session.task.observation["available_tools"] = json.dumps(
        [
            {"name": "search", "parameters": {"type": "object"}},
            {"name": "finish_investigation", "parameters": {"type": "object"}},
        ]
    )
    llm = FakeToolClient([explore, finish])
    agent = InvestigationAgent(llm, max_steps=10, harvest_calls=0, artifact_sweep=True)
    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == ["search", "finish_investigation"]
    sent = session.calls[1][1]["submission"]["legitimacy_evidence"]
    assert [item["entity_id"] for item in sent] == ["u1"]
    assert result.task_results[0].completion_reason == "terminated"
    assert agent._spent_calls == 2


def test_hidden_metrics_simulator_hides_rewards_and_results(tmp_path: Any) -> None:
    truth = tmp_path / "truth.jsonl"
    llm = FakeToolClient([_malicious_finish()])
    agent = InvestigationAgent(llm, max_steps=5, harvest_calls=0, simulate_hidden=str(truth))
    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    assert result.task_results[0].completion_reason == "terminated"
    assert not agent.reward_signal_seen
    record = json.loads(truth.read_text().splitlines()[-1])
    assert record["tool"] == "finish_investigation" and record["task_result"] is not None


def test_model_does_not_see_a_zero_reward_before_any_reward_is_shown(tmp_path: Any) -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    llm = FakeToolClient([explore, _malicious_finish()])
    agent = InvestigationAgent(
        llm,
        max_steps=5,
        harvest_calls=0,
        simulate_hidden=str(tmp_path / "truth.jsonl"),
    )
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    tool_message = next(m for m in llm.requests[1] if m.get("role") == "tool")
    assert '"reward"' not in tool_message["content"]


def test_model_sees_rewards_when_the_runtime_shows_them() -> None:
    explore = ToolCall(
        id="", name="get_entity", arguments={"entity_id": ENTITY_ID, "reasoning": "r"}
    )
    llm = FakeToolClient([explore, _malicious_finish()])
    agent = InvestigationAgent(llm, max_steps=5, harvest_calls=0)
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    tool_message = next(m for m in llm.requests[1] if m.get("role") == "tool")
    assert '"reward": 1.0' in tool_message["content"]
