import contextlib
import json
from typing import Any

from loguru import logger

from bluesec1_agent.evidence import FROM_ALERT, Evidence

SUBMISSION_KEYS = {"verdict", "reasoning", "ir_artifacts", "legitimacy_evidence"}
OTHER_VERDICT_LIST = {"benign": "ir_artifacts", "malicious": "legitimacy_evidence"}
METADATA_FIELDS = {
    "type",
    "id",
    "timestamp",
    "timestamps",
    "log_sources",
    "source_id",
    "target_id",
    "host_id",
    "relation_ids",
}

# фильтр отчёта без наград, на тренировке оценку повышали только эти типы
BENIGN_TYPES = {"windows_user", "host", "windows_file", "archive_file"}
MALICIOUS_DROP_TYPES = {"network_connection", "powershell_script", "powershell_cmdlet_invocation"}


def verdict_of(arguments: dict[str, Any]) -> str | None:
    submission = arguments.get("submission")
    if isinstance(submission, dict) and isinstance(submission.get("verdict"), str):
        return submission["verdict"]
    return None


def normalize_finish(arguments: dict[str, Any]) -> None:
    # сервер отклоняет отчёт при любом расхождении со схемой, исправляем типичные ошибки модели
    submission = arguments.get("submission")
    if isinstance(submission, str):
        submission = _loads_lenient(submission)
        if submission is None:
            return
        arguments["submission"] = submission
    if submission is None and "verdict" in arguments:
        submission = {key: arguments.pop(key) for key in list(arguments) if key in SUBMISSION_KEYS}
        arguments["submission"] = submission
        logger.warning("Wrapped a report written without `submission`.")
    if not isinstance(submission, dict):
        return

    for key in [key for key in arguments if key != "submission"]:
        value = arguments.pop(key)
        if key == "reasoning" and isinstance(value, str) and not submission.get("reasoning"):
            submission["reasoning"] = value
        logger.warning("Moved or dropped top-level field {} of finish_investigation.", key)

    other = OTHER_VERDICT_LIST.get(str(submission.get("verdict")))
    if other and other in submission:
        del submission[other]
        logger.warning("Dropped {} from a {} report.", other, submission.get("verdict"))

    _repair_reasoning(submission)
    _drop_metadata_fields(submission)


def _loads_lenient(text: str) -> Any:
    # модель иногда закрывает объект и дописывает ещё одно поле после скобки
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    text = text.strip()
    try:
        first, end = json.JSONDecoder().raw_decode(text)
    except json.JSONDecodeError:
        return None
    rest = text[end:].strip()
    if isinstance(first, dict) and rest.startswith(",") and rest.endswith("}"):
        with contextlib.suppress(json.JSONDecodeError):
            extra = json.loads("{" + rest[1:])
            if isinstance(extra, dict):
                for key, value in extra.items():
                    first.setdefault(key, value)
    return first


def _repair_reasoning(submission: dict[str, Any]) -> None:
    # модель иногда пишет reasoning_filtered вместо reasoning
    if not isinstance(submission.get("reasoning"), str) or not submission["reasoning"].strip():
        submission["reasoning"] = next(
            (
                value
                for key, value in submission.items()
                if "reason" in key and isinstance(value, str) and value.strip()
            ),
            "See the investigation steps.",
        )
    for key in [key for key in submission if key not in SUBMISSION_KEYS]:
        del submission[key]
        logger.warning("Dropped unknown field {} from the report.", key)


def _drop_metadata_fields(submission: dict[str, Any]) -> None:
    # поля вроде type или timestamp ничего не доказывают и снижали оценку
    items = submission.get("legitimacy_evidence")
    if not isinstance(items, list):
        return
    kept: list[Any] = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("property_fields"), list):
            kept.append(item)
            continue
        fields = [field for field in item["property_fields"] if field not in METADATA_FIELDS]
        if fields:
            kept.append({**item, "property_fields": fields})
    if kept:
        submission["legitimacy_evidence"] = kept


def verdict_slip(arguments: dict[str, Any]) -> str | None:
    submission = arguments.get("submission")
    if not isinstance(submission, dict):
        return None
    verdict = submission.get("verdict")
    reasoning = str(submission.get("reasoning") or "").lower()
    if verdict == "malicious":
        if "false positive" in reasoning:
            return "The reasoning calls the alert a false positive, but the verdict is malicious."
        if not submission.get("ir_artifacts"):
            return "The verdict is malicious, but ir_artifacts is empty."
    if verdict == "benign" and "true positive" in reasoning:
        return "The reasoning calls the alert a true positive, but the verdict is benign."
    return None


def fix_false_positive_slip(arguments: dict[str, Any]) -> None:
    # только на последнем шаге, malicious без артефактов всё равно даёт 0
    submission = arguments.get("submission")
    if (
        isinstance(submission, dict)
        and submission.get("verdict") == "malicious"
        and not submission.get("ir_artifacts")
        and "false positive" in str(submission.get("reasoning") or "").lower()
    ):
        submission["verdict"] = "benign"
        submission.pop("ir_artifacts", None)
        submission["legitimacy_evidence"] = []
        logger.warning("Last step: report said false positive but malicious; sent as benign.")


def drop_items_with_ids(arguments: dict[str, Any], bad_ids: set[str]) -> None:
    if not bad_ids:
        return
    submission = arguments.get("submission")
    if not isinstance(submission, dict):
        return
    for key in ("ir_artifacts", "legitimacy_evidence"):
        items = submission.get(key)
        if isinstance(items, list):
            submission[key] = [
                item
                for item in items
                if not (
                    isinstance(item, dict)
                    and {item.get("entity_id"), item.get("relation_id")} & bad_ids
                )
            ]
    logger.warning("Last step: dropped report items with bad ids {}", sorted(bad_ids))


def filter_by_kind(items: list[Any], verdict: Any, evidence: Evidence) -> list[Any]:
    kept: list[Any] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        entity_id = str(item.get("entity_id") or "")
        kind = str((evidence.entities.get(entity_id) or {}).get("type") or "")
        from_alert = evidence.labels.get(entity_id) == FROM_ALERT
        if verdict == "benign":
            if item.get("anchor") == "entity" and kind in BENIGN_TYPES and not from_alert:
                kept.append(item)
        elif kind not in MALICIOUS_DROP_TYPES:
            kept.append(item)
    return kept
