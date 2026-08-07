from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from app.config import OBSERVATORY_DIR, OT_EXPORT_DIR
from app.state import get_event_queue_size, get_recent_events, get_serialized_sessions


def _read_jsonl_tail(path: Path, limit: int) -> list[Dict[str, object]]:
    if not path.exists() or limit <= 0:
        return []

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    tail = lines[-limit:]
    output: list[Dict[str, object]] = []
    for line in tail:
        line = line.strip()
        if not line:
            continue
        try:
            output.append(json.loads(line))
        except json.JSONDecodeError:
            output.append({"raw": line, "decode_error": True})
    return output


def _latest_report_files(limit: int = 5) -> list[Dict[str, object]]:
    reports_dir = OBSERVATORY_DIR / "reports"
    if not reports_dir.exists():
        return []

    files = sorted(
        [p for p in reports_dir.glob("soc_report_*.md") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:limit]

    return [
        {
            "path": str(path),
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "mtime": path.stat().st_mtime,
        }
        for path in files
    ]


def _latest_ot_snapshots(limit: int = 5) -> list[Dict[str, object]]:
    if not OT_EXPORT_DIR.exists():
        return []

    files = sorted(
        [p for p in OT_EXPORT_DIR.glob("conpot_forensics_*.json") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:limit]

    return [
        {
            "path": str(path),
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "mtime": path.stat().st_mtime,
        }
        for path in files
    ]


def build_dashboard_summary(log_tail: int = 20, event_tail: int = 20) -> Dict[str, object]:
    it_commands_file = OBSERVATORY_DIR / "it" / "it_commands.jsonl"
    prediction_file = OBSERVATORY_DIR / "it" / "prediction_events.jsonl"
    ot_events_file = OBSERVATORY_DIR / "ot" / "ot_events.jsonl"

    it_commands = _read_jsonl_tail(it_commands_file, log_tail)
    predictions = _read_jsonl_tail(prediction_file, log_tail)
    ot_events = _read_jsonl_tail(ot_events_file, log_tail)

    return {
        "sessions": get_serialized_sessions(),
        "queue_size": get_event_queue_size(),
        "recent_queue_events": get_recent_events(event_tail),
        "it_commands_tail": it_commands,
        "prediction_tail": predictions,
        "ot_events_tail": ot_events,
        "latest_reports": _latest_report_files(),
        "latest_ot_snapshots": _latest_ot_snapshots(),
    }


def latest_report_content() -> Dict[str, object]:
    reports = _latest_report_files(limit=1)
    if not reports:
        return {
            "status": "missing",
            "detail": "No SOC report file found yet.",
        }

    report_path = Path(reports[0]["path"])
    content = report_path.read_text(encoding="utf-8", errors="replace")
    return {
        "status": "ok",
        "report": reports[0],
        "content": content,
    }
