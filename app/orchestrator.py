from __future__ import annotations

from typing import Dict, Optional
from time import perf_counter
from uuid import uuid4

import docker
import requests
from docker.errors import APIError, DockerException, ImageNotFound, NotFound

from app.config import (
    CONPOT_CONTAINER_LOG_DIR,
    CONPOT_CONTAINER_NAME,
    CONPOT_IMAGE,
    CONPOT_VOLUME_HOST_DIR,
    HONEYPOT_NETWORK,
    OLLAMA_BASE_URL,
    OLLAMA_FALLBACK_URLS,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT_SECONDS,
    SESSION_KEY_IT,
    SESSION_KEY_OT,
)
from app.decoy_shell import simulate_terminal_response
from app.observatory import ensure_observatory_paths, log_it_command, log_it_result, log_ot_event
from app.state import touch_session


def _build_ollama_urls() -> list[str]:
    urls = [OLLAMA_BASE_URL, *OLLAMA_FALLBACK_URLS]
    # Deduplicate while preserving order.
    return list(dict.fromkeys(urls))


def route_to_ollama_decoy(
    command: Optional[str],
    metadata: Optional[Dict[str, object]] = None,
    event_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, object]:
    touch_session(SESSION_KEY_IT, trap="ollama_decoy", target_domain="IT")
    correlation_id = correlation_id or event_id or str(uuid4())

    if not command:
        return {
            "status": "armed",
            "detail": "IT decoy is armed. No attacker command was provided.",
            "terminal_profile": "linux",
        }

    started = perf_counter()
    record_id = log_it_command(
        command=command,
        model=OLLAMA_MODEL,
        metadata=metadata,
        event_id=event_id,
        correlation_id=correlation_id,
    )

    shell_response = simulate_terminal_response(
        command,
        metadata=metadata,
        event_id=event_id,
        correlation_id=correlation_id,
    )
    detail = "Attacker command rendered through a stateful fake terminal decoy."
    failure = {
        "status": "routed",
        "detail": detail,
        "model": OLLAMA_MODEL,
        "terminal_profile": shell_response.get("terminal_profile"),
        "intent": shell_response.get("intent"),
        "session_key": shell_response.get("session_key"),
        "correlation_id": correlation_id,
        "prompt": shell_response.get("prompt"),
        "current_directory": shell_response.get("current_directory"),
        "last_exit_code": shell_response.get("last_exit_code"),
        "command_history_tail": shell_response.get("command_history_tail"),
        "banner": shell_response.get("banner"),
        "ollama_response": "\n".join(shell_response.get("transcript", [])),
        "terminal_transcript": shell_response.get("transcript", []),
        "output_lines": shell_response.get("output", []),
    }
    log_it_result(
        record_id=record_id,
        event_id=event_id,
        correlation_id=correlation_id,
        status="routed",
        detail=detail,
        duration_ms=round((perf_counter() - started) * 1000.0, 3),
    )
    return failure


def _conpot_volume_bindings() -> Dict[str, Dict[str, str]]:
    ensure_observatory_paths()
    return {
        str(CONPOT_VOLUME_HOST_DIR): {
            "bind": CONPOT_CONTAINER_LOG_DIR,
            "mode": "rw",
        }
    }


def _container_has_observatory_mount(container: object) -> bool:
    mount_source = str(CONPOT_VOLUME_HOST_DIR)
    mount_target = CONPOT_CONTAINER_LOG_DIR
    mounts = getattr(container, "attrs", {}).get("Mounts", [])
    for mount in mounts:
        if mount.get("Source") == mount_source and mount.get("Destination") == mount_target:
            return True
    return False


def _run_new_conpot_container(docker_client: object) -> object:
    return docker_client.containers.run(
        CONPOT_IMAGE,
        name=CONPOT_CONTAINER_NAME,
        detach=True,
        network=HONEYPOT_NETWORK,
        volumes=_conpot_volume_bindings(),
        environment={
            "CONPOT_CONFIG": "/etc/conpot/conpot.cfg",
            "CONPOT_JSON_LOG": f"{CONPOT_CONTAINER_LOG_DIR}/conpot.json",
            "CONPOT_LOG": f"{CONPOT_CONTAINER_LOG_DIR}/conpot.log",
            "CONPOT_TEMPLATE": "default",
            "CONPOT_TMP": "/tmp",
        },
        labels={
            "echo_net": "true",
            "role": "ot_honeypot",
        },
    )


def start_or_touch_conpot(correlation_id: Optional[str] = None) -> Dict[str, object]:
    ensure_observatory_paths()
    try:
        docker_client = docker.from_env()
        docker_client.ping()
    except DockerException as exc:
        failure = {
            "status": "docker_unavailable",
            "detail": "Docker daemon is not reachable.",
            "error": str(exc),
            "correlation_id": correlation_id,
        }
        log_ot_event("ot_container_start_failed", failure)
        return failure

    try:
        network = docker_client.networks.get(HONEYPOT_NETWORK)
        if not getattr(network, "attrs", {}).get("Internal", False):
            failure = {
                "status": "network_not_internal",
                "detail": (
                    f"Docker network '{HONEYPOT_NETWORK}' must be internal=true for safety."
                ),
                "correlation_id": correlation_id,
            }
            log_ot_event("ot_container_start_failed", failure)
            return failure
    except NotFound:
        failure = {
            "status": "network_missing",
            "detail": (
                f"Docker network '{HONEYPOT_NETWORK}' not found. "
                "Create it with: docker network create --driver bridge --internal "
                f"{HONEYPOT_NETWORK}"
            ),
            "correlation_id": correlation_id,
        }
        log_ot_event("ot_container_start_failed", failure)
        return failure
    except DockerException as exc:
        failure = {
            "status": "docker_error",
            "detail": "Unable to inspect Docker network.",
            "error": str(exc),
            "correlation_id": correlation_id,
        }
        log_ot_event("ot_container_start_failed", failure)
        return failure

    try:
        container = docker_client.containers.get(CONPOT_CONTAINER_NAME)
        container.reload()

        if not _container_has_observatory_mount(container):
            was_running = container.status == "running"
            if was_running:
                container.stop(timeout=10)
            container.remove()
            container = _run_new_conpot_container(docker_client)
            container.reload()
            touch_session(
                SESSION_KEY_OT,
                trap="conpot",
                target_domain="OT",
                metadata={"container_name": container.name},
            )
            result = {
                "status": "recreated",
                "detail": "Conpot container recreated with persistent observatory volume.",
                "container_name": container.name,
                "container_id": container.short_id,
                "volume_host_dir": str(CONPOT_VOLUME_HOST_DIR),
                "volume_container_dir": CONPOT_CONTAINER_LOG_DIR,
                "correlation_id": correlation_id,
            }
            log_ot_event("ot_container_recreated", result)
            return result

        if container.status != "running":
            container.start()
            container.reload()
            status = "started"
        else:
            status = "already_running"

        touch_session(
            SESSION_KEY_OT,
            trap="conpot",
            target_domain="OT",
            metadata={"container_name": container.name},
        )
        result = {
            "status": status,
            "detail": "Conpot OT ambush is active.",
            "container_name": container.name,
            "container_id": container.short_id,
            "volume_host_dir": str(CONPOT_VOLUME_HOST_DIR),
            "volume_container_dir": CONPOT_CONTAINER_LOG_DIR,
            "correlation_id": correlation_id,
        }
        log_ot_event("ot_container_status", result)
        return result
    except NotFound:
        try:
            container = _run_new_conpot_container(docker_client)
            touch_session(
                SESSION_KEY_OT,
                trap="conpot",
                target_domain="OT",
                metadata={"container_name": container.name},
            )
            result = {
                "status": "started",
                "detail": "Conpot OT ambush container started.",
                "container_name": container.name,
                "container_id": container.short_id,
                "image": CONPOT_IMAGE,
                "volume_host_dir": str(CONPOT_VOLUME_HOST_DIR),
                "volume_container_dir": CONPOT_CONTAINER_LOG_DIR,
                "correlation_id": correlation_id,
            }
            log_ot_event("ot_container_started", result)
            return result
        except ImageNotFound:
            try:
                docker_client.images.pull(CONPOT_IMAGE)
                container = _run_new_conpot_container(docker_client)
                touch_session(
                    SESSION_KEY_OT,
                    trap="conpot",
                    target_domain="OT",
                    metadata={"container_name": container.name},
                )
                result = {
                    "status": "started",
                    "detail": "Conpot image pulled and OT ambush container started.",
                    "container_name": container.name,
                    "container_id": container.short_id,
                    "image": CONPOT_IMAGE,
                    "volume_host_dir": str(CONPOT_VOLUME_HOST_DIR),
                    "volume_container_dir": CONPOT_CONTAINER_LOG_DIR,
                    "correlation_id": correlation_id,
                }
                log_ot_event("ot_container_started", result)
                return result
            except (DockerException, APIError) as exc:
                failure = {
                    "status": "start_failed",
                    "detail": "Could not pull/start Conpot container.",
                    "error": str(exc),
                    "correlation_id": correlation_id,
                }
                log_ot_event("ot_container_start_failed", failure)
                return failure
        except (DockerException, APIError) as exc:
            failure = {
                "status": "start_failed",
                "detail": "Could not start Conpot container.",
                "error": str(exc),
                "correlation_id": correlation_id,
            }
            log_ot_event("ot_container_start_failed", failure)
            return failure
    except (DockerException, APIError) as exc:
        failure = {
            "status": "docker_error",
            "detail": "Error while managing Conpot container.",
            "error": str(exc),
            "correlation_id": correlation_id,
        }
        log_ot_event("ot_container_start_failed", failure)
        return failure


def stop_conpot_if_running() -> Dict[str, object]:
    try:
        docker_client = docker.from_env()
        docker_client.ping()
        container = docker_client.containers.get(CONPOT_CONTAINER_NAME)
        if container.status == "running":
            container.stop(timeout=10)
            result = {
                "status": "stopped",
                "detail": "Conpot container stopped after inactivity timeout.",
                "container_name": container.name,
            }
            log_ot_event("ot_container_stopped", result)
            return result
        result = {
            "status": "already_stopped",
            "detail": "Conpot container was already stopped.",
        }
        log_ot_event("ot_container_stopped", result)
        return result
    except NotFound:
        result = {
            "status": "missing",
            "detail": "Conpot container not found.",
        }
        log_ot_event("ot_container_stopped", result)
        return result
    except DockerException as exc:
        result = {
            "status": "docker_error",
            "detail": "Could not stop Conpot container.",
            "error": str(exc),
        }
        log_ot_event("ot_container_stopped", result)
        return result
