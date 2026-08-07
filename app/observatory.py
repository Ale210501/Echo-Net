from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, Optional
from uuid import uuid4

import docker
from docker.errors import DockerException, NotFound

from app.behavior import classify_attacker_behavior
from app.config import (
    CONPOT_CONTAINER_NAME,
    CONPOT_VOLUME_HOST_DIR,
    IT_LOG_FILE,
    OBSERVATORY_DIR,
    OT_EVENT_LOG_FILE,
    OT_EXPORT_DIR,
    PREDICTION_LOG_FILE,
)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_observatory_paths() -> None:
    (OBSERVATORY_DIR / "it").mkdir(parents=True, exist_ok=True)
    OT_EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    CONPOT_VOLUME_HOST_DIR.mkdir(parents=True, exist_ok=True)


def _append_jsonl(file_path: Path, payload: Dict[str, object]) -> None:
    ensure_observatory_paths()
    with file_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True, default=str) + "\n")


def command_features(command: str) -> Dict[str, object]:
    words = [chunk for chunk in command.strip().split() if chunk]
    unique_words = len(set(words))
    char_count = len(command)
    features: Dict[str, object] = {
        "sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
        "char_count": char_count,
        "word_count": len(words),
        "unique_word_count": unique_words,
        "uppercase_ratio": (
            round(sum(1 for c in command if c.isupper()) / char_count, 4)
            if char_count
            else 0
        ),
        "digit_ratio": (
            round(sum(1 for c in command if c.isdigit()) / char_count, 4)
            if char_count
            else 0
        ),
        "contains_pipe": "|" in command,
        "contains_redirect": (">" in command) or ("<" in command),
        "contains_url": ("http://" in command) or ("https://" in command),
        "contains_encoded_hint": any(
            token in command.lower()
            for token in ["base64", "frombase64", "-enc", "decode", "certutil"]
        ),
    }
    return features


def request_metadata(request: Any) -> Dict[str, object]:
    headers = getattr(request, "headers", {}) or {}
    client = getattr(request, "client", None)
    url = getattr(request, "url", None)

    return {
        "timestamp": utcnow_iso(),
        "method": getattr(request, "method", "unknown"),
        "path": str(getattr(url, "path", "")),
        "query": str(getattr(url, "query", "")),
        "client_ip": getattr(client, "host", None),
        "client_port": getattr(client, "port", None),
        "x_forwarded_for": headers.get("x-forwarded-for"),
        "user_agent": headers.get("user-agent"),
        "content_type": headers.get("content-type"),
        "accept_language": headers.get("accept-language"),
        "referer": headers.get("referer"),
    }


def start_timer() -> float:
    return perf_counter()


def elapsed_ms(started: float) -> float:
    return round((perf_counter() - started) * 1000.0, 3)


def log_it_command(
    command: str,
    model: str,
    metadata: Optional[Dict[str, object]] = None,
    event_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> str:
    record_id = str(uuid4())
    features = command_features(command)
    behavior = classify_attacker_behavior(command=command, features=features)
    _append_jsonl(
        IT_LOG_FILE,
        {
            "record_id": record_id,
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": utcnow_iso(),
            "event": "attacker_command_received",
            "model": model,
            "command": command,
            "features": features,
            "behavior": behavior,
            "request": metadata or {},
        },
    )
    return record_id


def log_it_result(
    record_id: str,
    event_id: Optional[str],
    correlation_id: Optional[str],
    status: str,
    detail: str,
    base_url: Optional[str] = None,
    error: Optional[object] = None,
    duration_ms: Optional[float] = None,
    ollama_metrics: Optional[Dict[str, object]] = None,
) -> None:
    _append_jsonl(
        IT_LOG_FILE,
        {
            "record_id": record_id,
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": utcnow_iso(),
            "event": "attacker_command_processed",
            "status": status,
            "detail": detail,
            "ollama_base_url": base_url,
            "duration_ms": duration_ms,
            "ollama_metrics": ollama_metrics or {},
            "error": error,
        },
    )


def log_prediction_received(
    event_id: str,
    payload: Dict[str, object],
    request_info: Dict[str, object],
) -> None:
    _append_jsonl(
        PREDICTION_LOG_FILE,
        {
            "event": "prediction_received",
            "event_id": event_id,
            "timestamp": utcnow_iso(),
            "request": request_info,
            "payload": payload,
        },
    )


def log_prediction_outcome(
    event_id: str,
    reaction: Dict[str, object],
    queue_status: str,
    processing_ms: float,
) -> None:
    _append_jsonl(
        PREDICTION_LOG_FILE,
        {
            "event": "prediction_processed",
            "event_id": event_id,
            "timestamp": utcnow_iso(),
            "reaction": reaction,
            "queue_status": queue_status,
            "processing_ms": processing_ms,
        },
    )


def log_ot_event(event_name: str, payload: Dict[str, object]) -> None:
    _append_jsonl(
        OT_EVENT_LOG_FILE,
        {
            "event": event_name,
            "timestamp": utcnow_iso(),
            **payload,
        },
    )


def _safe_container_stats(container: Any) -> Dict[str, object]:
    try:
        stats = container.stats(stream=False)
        cpu_total = (
            stats.get("cpu_stats", {})
            .get("cpu_usage", {})
            .get("total_usage", 0)
        )
        memory_usage = stats.get("memory_stats", {}).get("usage", 0)
        memory_limit = stats.get("memory_stats", {}).get("limit", 0)
        networks = stats.get("networks", {})
        return {
            "cpu_total_usage": cpu_total,
            "memory_usage": memory_usage,
            "memory_limit": memory_limit,
            "networks": networks,
        }
    except Exception as exc:
        return {"error": str(exc)}


def _volume_tree_snapshot(root: Path, max_files: int = 200) -> Dict[str, object]:
    if not root.exists():
        return {"exists": False, "files": []}

    files: list[Dict[str, object]] = []
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        rel_path = file_path.relative_to(root).as_posix()
        files.append(
            {
                "path": rel_path,
                "size_bytes": file_path.stat().st_size,
                "mtime": datetime.fromtimestamp(
                    file_path.stat().st_mtime, tz=timezone.utc
                ).isoformat(),
            }
        )
        if len(files) >= max_files:
            break

    return {
        "exists": True,
        "root": str(root),
        "file_count_sample": len(files),
        "max_files": max_files,
        "files": files,
    }


def export_conpot_forensics_snapshot(tail: int = 2000) -> Dict[str, object]:
    ensure_observatory_paths()
    try:
        docker_client = docker.from_env()
        container = docker_client.containers.get(CONPOT_CONTAINER_NAME)
        container.reload()

        raw_logs = container.logs(tail=tail, timestamps=True)
        logs_text = raw_logs.decode("utf-8", errors="replace")

        snapshot = {
            "timestamp": utcnow_iso(),
            "container_name": container.name,
            "container_id": container.short_id,
            "status": container.status,
            "image": container.image.tags,
            "inspect": {
                "created": container.attrs.get("Created"),
                "state": container.attrs.get("State", {}),
                "config": {
                    "env": container.attrs.get("Config", {}).get("Env", []),
                    "cmd": container.attrs.get("Config", {}).get("Cmd", []),
                    "labels": container.attrs.get("Config", {}).get("Labels", {}),
                },
                "network_settings": container.attrs.get("NetworkSettings", {}),
                "mounts": container.attrs.get("Mounts", []),
            },
            "stats": _safe_container_stats(container),
            "volume_snapshot": _volume_tree_snapshot(CONPOT_VOLUME_HOST_DIR),
            "runtime_log_tail_lines": logs_text.splitlines(),
        }

        file_path = OT_EXPORT_DIR / (
            f"conpot_forensics_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        )
        file_path.write_text(json.dumps(snapshot, ensure_ascii=True, indent=2), encoding="utf-8")

        log_ot_event(
            "ot_forensics_snapshot_exported",
            {
                "export_file": str(file_path),
                "tail": tail,
                "container_id": container.short_id,
            },
        )

        return {
            "status": "exported",
            "export_file": str(file_path),
            "container_name": container.name,
            "tail": tail,
            "log_line_count": len(snapshot["runtime_log_tail_lines"]),
        }
    except NotFound:
        return {
            "status": "container_missing",
            "detail": "Conpot container was not found.",
        }
    except DockerException as exc:
        return {
            "status": "docker_error",
            "detail": "Could not export Conpot forensics snapshot.",
            "error": str(exc),
        }


def export_conpot_runtime_logs(tail: int = 1000) -> Dict[str, object]:
    ensure_observatory_paths()
    try:
        docker_client = docker.from_env()
        container = docker_client.containers.get(CONPOT_CONTAINER_NAME)
        raw_logs = container.logs(tail=tail, timestamps=True)
        text_logs = raw_logs.decode("utf-8", errors="replace")

        export_file = OT_EXPORT_DIR / (
            f"conpot_runtime_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.log"
        )
        export_file.write_text(text_logs, encoding="utf-8")

        line_count = 0 if not text_logs else len(text_logs.splitlines())
        log_ot_event(
            "ot_runtime_logs_exported",
            {
                "export_file": str(export_file),
                "tail": tail,
                "line_count": line_count,
            },
        )
        return {
            "status": "exported",
            "container_name": CONPOT_CONTAINER_NAME,
            "tail": tail,
            "line_count": line_count,
            "export_file": str(export_file),
        }
    except NotFound:
        return {
            "status": "container_missing",
            "detail": "Conpot container was not found.",
        }
    except DockerException as exc:
        return {
            "status": "docker_error",
            "detail": "Could not export Conpot logs.",
            "error": str(exc),
        }
