from __future__ import annotations

import threading
from typing import Optional

from app.config import (
    CLEANUP_INTERVAL_SECONDS,
    INACTIVITY_TIMEOUT_SECONDS,
    SESSION_KEY_OT,
)
from app.orchestrator import stop_conpot_if_running
from app.state import get_expired_session_keys, remove_session

cleanup_stop_event = threading.Event()
cleanup_thread: Optional[threading.Thread] = None


def cleanup_worker_loop() -> None:
    while not cleanup_stop_event.is_set():
        expired_keys = get_expired_session_keys(INACTIVITY_TIMEOUT_SECONDS)

        for key in expired_keys:
            if key == SESSION_KEY_OT:
                stop_conpot_if_running()
            remove_session(key)

        cleanup_stop_event.wait(CLEANUP_INTERVAL_SECONDS)


def start_cleanup_worker() -> None:
    global cleanup_thread
    if cleanup_thread and cleanup_thread.is_alive():
        return
    cleanup_stop_event.clear()
    cleanup_thread = threading.Thread(target=cleanup_worker_loop, daemon=True)
    cleanup_thread.start()


def stop_cleanup_worker() -> None:
    cleanup_stop_event.set()
