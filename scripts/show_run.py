# просмотр лога прогона, по задачам или одна задача по шагам

import argparse
import contextlib
import json
from pathlib import Path
from typing import Any

RESULT_PREVIEW_CHARS = 700


def load(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def group_by_task(events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    tasks: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        tasks.setdefault(event.get("task_id", "?"), []).append(event)
    return list(tasks.values())


def finish_attempts(task: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event
        for event in task
        if event["event"] == "step" and event["tool"] == "finish_investigation"
    ]


def submission_of(task: list[dict[str, Any]]) -> dict[str, Any]:
    sent = [
        event
        for event in finish_attempts(task)
        if (event.get("feedback") or {}).get("status") not in {"not_submitted", "not_sent"}
    ]
    attempts = sent or finish_attempts(task)
    return attempts[-1]["arguments"].get("submission", {}) if attempts else {}


def review_note(task: list[dict[str, Any]]) -> str:
    verdicts = [
        str(event["arguments"].get("submission", {}).get("verdict", "?"))[:1]
        for event in finish_attempts(task)
    ]
    return ">".join(verdicts) if len(verdicts) > 1 else ""


def summarize(tasks: list[list[dict[str, Any]]]) -> None:
    header = f"{'#':>2}  {'verdict':<10}{'items':>5}{'calls':>6}{'quality':>9}{'effic':>7}"
    header += f"{'reward':>8}  {'end':<11}tries"
    print(header)
    print("-" * len(header))
    totals = {"quality_score": 0.0, "efficiency_score": 0.0, "total_reward": 0.0}
    for number, task in enumerate(tasks, start=1):
        result = next((e["result"] for e in task if e["event"] == "task_end"), {})
        submission = submission_of(task)
        items = submission.get("ir_artifacts") or submission.get("legitimacy_evidence") or []
        print(
            f"{number:>2}  {submission.get('verdict', '-'):<10}{len(items):>5}"
            f"{result.get('tool_calls', 0):>6}{result.get('quality_score', 0):>9.2f}"
            f"{result.get('efficiency_score', 0):>7.2f}{result.get('total_reward', 0):>8.1f}"
            f"  {result.get('completion_reason', '?'):<11}{review_note(task)}"
        )
        for key in totals:
            totals[key] += float(result.get(key) or 0)
    count = max(len(tasks), 1)
    print("-" * len(header))
    print(
        f"tasks: {len(tasks)}   mean quality: {totals['quality_score'] / count:.2f}   "
        f"mean efficiency: {totals['efficiency_score'] / count:.2f}   "
        f"mean reward: {totals['total_reward'] / count:.1f}"
    )


def show_task(task: list[dict[str, Any]]) -> None:
    for event in task:
        kind = event["event"]
        if kind == "task_start":
            alert = event.get("alert")
            with contextlib.suppress(TypeError, ValueError, AttributeError):
                alert = json.loads(alert).get("alert_description", alert)
            print(f"ALERT: {alert}\n")
        elif kind == "step":
            arguments = dict(event["arguments"])
            reasoning = arguments.pop("reasoning", "")
            feedback = event["feedback"]
            print(f"[{event['step']}] {event['tool']} {json.dumps(arguments, ensure_ascii=False)}")
            if reasoning:
                print(f"    why: {reasoning}")
            status = feedback.get("status")
            reward = feedback.get("reward")
            print(f"    -> status={status} reward={reward}")
            if feedback.get("error"):
                print(f"    error: {feedback['error']}")
            elif event["tool"] != "finish_investigation":
                text = json.dumps(feedback.get("result"), ensure_ascii=False)
                if len(text) > RESULT_PREVIEW_CHARS:
                    text = text[:RESULT_PREVIEW_CHARS] + " ..."
                print(f"    result: {text}")
            print()
        elif kind == "task_error":
            print(f"AGENT ERROR: {event['error']}\n")
        elif kind == "task_end":
            submission = submission_of(task)
            if submission:
                print("SUBMISSION:")
                print(json.dumps(submission, indent=2, ensure_ascii=False))
            print("\nRESULT:", json.dumps(event["result"], ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--task", type=int, help="Show task number N (from the summary).")
    args = parser.parse_args()
    tasks = group_by_task(load(args.log))
    if args.task:
        show_task(tasks[args.task - 1])
    else:
        summarize(tasks)


if __name__ == "__main__":
    main()
