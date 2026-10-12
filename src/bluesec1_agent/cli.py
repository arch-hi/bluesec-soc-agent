import argparse
import asyncio
import json
import sys

import truststore
from pydantic import ValidationError

from bluesec1_agent.agent import InvestigationAgent
from bluesec1_agent.llm import OpenAIToolClient
from bluesec1_agent.settings import Settings
from bluesec1_agent.trajectory import TrajectoryLogger
from bluesec1_client import (
    CompetitionClosedError,
    RemoteAuthenticationError,
    RemoteBenchmarkClient,
    RemoteRateLimitError,
    RemoteUnavailableError,
    RetryPolicy,
    RunCapacityExceededError,
)

# по умолчанию клиент прекращает попытки через 1.5 с, а сервер бывал недоступен до пары минут
RUNTIME_RETRY_POLICY = RetryPolicy(
    max_attempts=10,
    initial_backoff_seconds=1.0,
    max_backoff_seconds=30.0,
    backoff_multiplier=2.0,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Investigate BlueSec alerts with an LLM agent.")
    parser.add_argument("--endpoint", help="Override SCENARIO_RUNTIME_ENDPOINT.")
    parser.add_argument("--token", help="Override SCENARIO_RUNTIME_TOKEN.")
    parser.add_argument("--run-label", help="Override REMOTE_RUN_LABEL.")
    parser.add_argument("--agent-name", help="Override AGENT_NAME.")
    parser.add_argument("--arena", help="Override SCENARIO_RUNTIME_ARENA.")
    parser.add_argument(
        "--verify-tls",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Override SCENARIO_RUNTIME_VERIFY_TLS.",
    )
    return parser


async def run(args: argparse.Namespace) -> None:
    truststore.inject_into_ssl()
    settings = _load_settings()
    llm = OpenAIToolClient(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key.get_secret_value(),
        model=settings.llm_default_model,
        timeout_seconds=settings.llm_timeout_seconds,
        max_completion_tokens=settings.llm_max_completion_tokens,
        max_retries=settings.llm_max_step_retries,
    )
    agent_name = args.agent_name or settings.agent_name
    trajectory = TrajectoryLogger(
        settings.agent_log_dir or None,
        run_label=args.run_label or settings.remote_run_label,
    )
    if trajectory.path is not None:
        print(f"Trajectory log: {trajectory.path}", file=sys.stderr)
    verify_tls = (
        settings.scenario_runtime_verify_tls if args.verify_tls is None else args.verify_tls
    )
    async with (
        llm,
        RemoteBenchmarkClient(
            endpoint=args.endpoint or settings.scenario_runtime_endpoint,
            token=args.token or settings.scenario_runtime_token.get_secret_value(),
            verify_tls=verify_tls,
            run_label=args.run_label or settings.remote_run_label,
            agent_name=agent_name,
            model_name=settings.llm_default_model,
            arena=args.arena or settings.scenario_runtime_arena,
            retry_policy=RUNTIME_RETRY_POLICY,
            metadata={
                "agent": agent_name,
                "implementation": "bluesec-soc-agent",
                "model": settings.llm_default_model,
            },
        ) as client,
    ):
        result = await InvestigationAgent(
            llm,
            max_steps=settings.agent_max_steps,
            max_tasks=settings.agent_max_tasks,
            total_cap=settings.agent_total_cap,
            type_budgets=settings.agent_type_budgets,
            deadline_minutes=settings.agent_deadline_minutes,
            harvest_calls=settings.agent_harvest_calls,
            scenario_notes=settings.agent_scenario_notes,
            complete_report_share=settings.agent_complete_report_share,
            empty_benign_review=settings.agent_empty_benign_review,
            artifact_sweep=settings.agent_artifact_sweep,
            keep_going=settings.agent_keep_going,
            simplify_tool_schemas=settings.llm_simplify_tool_schemas,
            simulate_hidden=settings.agent_simulate_hidden,
            trajectory=trajectory,
        ).run(client)

    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


def main() -> None:
    try:
        asyncio.run(run(build_parser().parse_args()))
    except RunCapacityExceededError as error:
        print(_run_capacity_message(error), file=sys.stderr)
        raise SystemExit(1) from error
    except CompetitionClosedError as error:
        print(
            "The selected competition arena is closed. Check SCENARIO_RUNTIME_ARENA or retry "
            "when the arena opens.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteRateLimitError as error:
        print(
            "Run starts are temporarily rate-limited. Wait before starting another run.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteAuthenticationError as error:
        print(
            "The runtime rejected your key. Check SCENARIO_RUNTIME_TOKEN in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteUnavailableError as error:
        print(
            "Cannot reach the runtime. Check SCENARIO_RUNTIME_ENDPOINT and "
            "SCENARIO_RUNTIME_VERIFY_TLS in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _load_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as error:
        missing = [str(item["loc"][0]) for item in error.errors() if item["type"] == "missing"]
        if not missing:
            raise
        print("Missing configuration: " + ", ".join(missing), file=sys.stderr)
        print(
            "Copy .env.example to .env and fill it in. "
            "Runtime address and key: https://bluesec.team/",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _run_capacity_message(error: RunCapacityExceededError) -> str:
    if getattr(error, "reason", None) == "PROCESS_ACTIVE_RUN_LIMIT_REACHED":
        lines = ["The runtime is at its overall capacity right now. This is not your limit."]
    else:
        lines = [
            "You have reached your limit of concurrent runs.",
            "Wait for a running one to finish. If an agent was killed mid-run, its run stays "
            "open until it is released.",
        ]
    return "\n".join(lines)
