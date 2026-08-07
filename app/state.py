from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Dict, Literal, Optional

from app.models import TrapSession

session_state_lock = threading.Lock()
session_state: Dict[str, TrapSession] = {}
event_queue_lock = threading.Lock()
event_queue: list[Dict[str, object]] = []


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def touch_session(
    session_key: str,
    trap: str,
    target_domain: Literal["IT", "OT"],
    metadata: Optional[Dict[str, str]] = None,
) -> None:
    now = utcnow()
    with session_state_lock:
        existing = session_state.get(session_key)
        if existing:
            existing.last_activity = now
            if metadata:
                existing.metadata.update(metadata)
            return

        session_state[session_key] = TrapSession(
            trap=trap,
            target_domain=target_domain,
            started_at=now,
            last_activity=now,
            metadata=metadata or {},
        )


def get_serialized_sessions() -> Dict[str, object]:
    with session_state_lock:
        return {k: v.model_dump(mode="json") for k, v in session_state.items()}


def get_expired_session_keys(timeout_seconds: int) -> list[str]:
    now = utcnow()
    expired: list[str] = []
    with session_state_lock:
        for key, session in session_state.items():
            idle_seconds = (now - session.last_activity).total_seconds()
            if idle_seconds >= timeout_seconds:
                expired.append(key)
    return expired


def remove_session(session_key: str) -> None:
    with session_state_lock:
        session_state.pop(session_key, None)


def get_session_snapshot(session_key: str) -> Optional[TrapSession]:
    with session_state_lock:
        session = session_state.get(session_key)
        if not session:
            return None
        return session.model_copy(deep=True)


def update_session_metadata(session_key: str, metadata: Dict[str, str]) -> None:
    if not metadata:
        return

    with session_state_lock:
        session = session_state.get(session_key)
        if not session:
            return
        session.metadata.update(metadata)


def append_event(event: Dict[str, object]) -> int:
    with event_queue_lock:
        event_queue.append(event)
        return len(event_queue)


def get_event_queue_size() -> int:
    with event_queue_lock:
        return len(event_queue)


def get_recent_events(limit: int = 50) -> list[Dict[str, object]]:
    with event_queue_lock:
        chunk = event_queue[-max(limit, 1) :]

    # Convert datetime/object fields to JSON-safe values.
    return json.loads(json.dumps(chunk, default=str))
