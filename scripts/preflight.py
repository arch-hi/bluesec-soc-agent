# проверка перед запуском, прогон на сервере не создаётся

import asyncio
import socket
import subprocess
import sys
import time

from dotenv import dotenv_values
from openai import AsyncOpenAI

EXPECTED = {
    "BLUESEC_AGENT_MAX_TASKS": "40",
    "BLUESEC_AGENT_TYPE_BUDGETS": "true",
    "BLUESEC_AGENT_KEEP_GOING": "true",
}
PING = [{"role": "user", "content": "Reply with the word ok."}]


def check(
    problems: list[str], warnings: list[str], ok: bool, text: str, *, fatal: bool = True
) -> None:
    print(("  ok    " if ok else ("  FAIL  " if fatal else "  WARN  ")) + text)
    if not ok:
        (problems if fatal else warnings).append(text)


async def ping(base_url: str, key: str, model: str) -> tuple[bool, str]:
    client = AsyncOpenAI(base_url=base_url, api_key=key, timeout=60, max_retries=1)
    started = time.perf_counter()
    try:
        reply = await client.chat.completions.create(
            model=model, messages=PING, max_completion_tokens=200
        )
    except Exception as exc:  # любая ошибка означает NO-GO
        return False, f"refused: {str(exc)[:160]}"
    finally:
        await client.close()
    seconds = time.perf_counter() - started
    return bool(reply.choices), f"{seconds:.1f} s"


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else ".env"
    env = {**dotenv_values(".env"), **dotenv_values(path)}
    problems: list[str] = []
    warnings: list[str] = []

    print(f"Settings ({path}):")
    for key, value in EXPECTED.items():
        check(problems, warnings, env.get(key) == value, f"{key}={env.get(key)} (want {value})")
    deadline = int(env.get("BLUESEC_AGENT_DEADLINE_MINUTES") or 0)
    check(
        problems,
        warnings,
        60 <= deadline <= 170,
        f"deadline {deadline} min (start late: cut it by the delay)",
    )
    for key in ("SCENARIO_RUNTIME_ENDPOINT", "SCENARIO_RUNTIME_TOKEN", "LLM_API_KEY", "AGENT_NAME"):
        check(problems, warnings, bool(env.get(key)), f"{key} set")

    print("Code:")
    described = subprocess.run(
        ["git", "describe", "--tags", "--always", "--dirty"], capture_output=True, text=True
    ).stdout.strip()
    check(problems, warnings, "dirty" not in described, f"version {described}", fatal=False)

    print("Competition endpoint (TCP only, no run is created):")
    host, _, port = str(env.get("SCENARIO_RUNTIME_ENDPOINT") or "").partition(":")
    try:
        with socket.create_connection((host, int(port or 443)), timeout=10):
            reachable = True
    except OSError:
        reachable = False
    check(problems, warnings, reachable, f"{host}:{port or 443} reachable")

    print("Models (one tiny request each):")
    base, key = str(env.get("LLM_BASE_URL")), str(env.get("LLM_API_KEY"))
    good, note = asyncio.run(ping(base, key, str(env.get("LLM_DEFAULT_MODEL"))))
    check(problems, warnings, good, f"main {env.get('LLM_DEFAULT_MODEL')}: {note}")
    print("Power:")
    battery = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True).stdout
    check(problems, warnings, "AC Power" in battery, "charger connected (AC power)", fatal=False)

    print()
    print("NO-GO: " + "; ".join(problems) if problems else "GO")
    if warnings:
        print("Warnings: " + "; ".join(warnings))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
