import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class TrajectoryLogger:
    # один JSONL на прогон, по событию на строку, без папки лог выключен

    def __init__(self, directory: Path | str | None, run_label: str = "run") -> None:
        self.path: Path | None = None
        if directory is None:
            return
        folder = Path(directory)
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        safe_label = "".join(char if char.isalnum() or char in "-_" else "_" for char in run_label)
        self.path = folder / f"{safe_label}_{stamp}.jsonl"

    def log(self, event: str, **payload: Any) -> None:
        if self.path is None:
            return
        record = {"time": datetime.now(UTC).isoformat(), "event": event, **payload}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
