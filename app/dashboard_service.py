from __future__ import annotations

import json
from datetime import datetime
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


def _parse_shell_state(metadata: Dict[str, object]) -> Dict[str, object]:
    raw_state = metadata.get("shell_state")
    if not isinstance(raw_state, str) or not raw_state.strip():
        return {}

    try:
        parsed = json.loads(raw_state)
    except json.JSONDecodeError:
        return {}

    if not isinstance(parsed, dict):
        return {}

    transcript = parsed.get("transcript")
    if not isinstance(transcript, list):
        transcript = []

    return {
        "session_key": session_key,
        "shell_family": parsed.get("shell_family"),
        "hostname": parsed.get("hostname"),
        "username": parsed.get("username"),
        "cwd": parsed.get("cwd"),
        "banner": parsed.get("banner"),
        "prompt": parsed.get("prompt"),
        "last_command": parsed.get("last_command"),
        "last_output": parsed.get("last_output"),
        "last_exit_code": parsed.get("last_exit_code"),
        "history": parsed.get("history", []),
        "transcript": transcript,
    }


def _latest_terminal_session(sessions: Dict[str, object]) -> Dict[str, object]:
    parsed_sessions: list[Dict[str, object]] = []
    for session_key, payload in sessions.items():
        if not isinstance(payload, dict):
            continue
        metadata = payload.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        shell_state = _parse_shell_state(metadata)
        if not shell_state:
            continue

        started_at = payload.get("started_at") or ""
        last_activity = payload.get("last_activity") or started_at
        parsed_sessions.append(
            {
                "session_key": session_key,
                "started_at": started_at,
                "last_activity": last_activity,
                **shell_state,
            }
        )

    if not parsed_sessions:
        return {
            "status": "idle",
            "detail": "No live fake terminal session yet.",
            "sessions": [],
            "transcript": [],
        }

    parsed_sessions.sort(
        key=lambda item: datetime.fromisoformat(str(item.get("last_activity")))
        if str(item.get("last_activity"))
        else datetime.min,
        reverse=True,
    )
    latest = parsed_sessions[0]
    latest_transcript = latest.get("transcript") or []
    if isinstance(latest_transcript, list):
        latest_transcript = [str(line) for line in latest_transcript[-20:]]
    else:
        latest_transcript = []

    return {
        "status": "live",
        "detail": "Latest decoy terminal session with persisted shell state.",
        "latest_session": latest,
        "sessions": parsed_sessions[:5],
        "transcript": latest_transcript,
    }


def _honeynet_live_state(sessions: Dict[str, object], ot_events: list[Dict[str, object]]) -> Dict[str, object]:
    ot_sessions = []
    for session_key, payload in sessions.items():
        if not isinstance(payload, dict):
            continue
        if payload.get("target_domain") != "OT":
            continue
        ot_sessions.append(
            {
                "session_key": session_key,
                "trap": payload.get("trap"),
                "target_domain": payload.get("target_domain"),
                "started_at": payload.get("started_at"),
                "last_activity": payload.get("last_activity"),
                "metadata": payload.get("metadata", {}),
            }
        )

    recent_ot_events = ot_events[-10:]
    last_ot_event = recent_ot_events[-1] if recent_ot_events else {}
    latest_activity = ot_sessions[-1] if ot_sessions else {}

    return {
        "status": "live" if ot_sessions or recent_ot_events else "idle",
        "active_ot_sessions": ot_sessions,
        "recent_ot_events": recent_ot_events,
        "last_ot_event": last_ot_event,
        "latest_activity": latest_activity,
    }


def build_dashboard_summary(log_tail: int = 20, event_tail: int = 20) -> Dict[str, object]:
    it_commands_file = OBSERVATORY_DIR / "it" / "it_commands.jsonl"
    prediction_file = OBSERVATORY_DIR / "it" / "prediction_events.jsonl"
    ot_events_file = OBSERVATORY_DIR / "ot" / "ot_events.jsonl"

    it_commands = _read_jsonl_tail(it_commands_file, log_tail)
    predictions = _read_jsonl_tail(prediction_file, log_tail)
    ot_events = _read_jsonl_tail(ot_events_file, log_tail)

    sessions = get_serialized_sessions()

    return {
        "sessions": sessions,
        "live_terminal": _latest_terminal_session(sessions),
        "honeynet": _honeynet_live_state(sessions, ot_events),
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
