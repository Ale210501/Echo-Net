from __future__ import annotations

import asyncio
from typing import Dict
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect

from app.config import (
    CLEANUP_INTERVAL_SECONDS,
    INACTIVITY_TIMEOUT_SECONDS,
    IT_LOG_FILE,
    OT_EVENT_LOG_FILE,
    OT_EXPORT_DIR,
    PREDICTION_LOG_FILE,
)
from app.dashboard_service import build_dashboard_summary, latest_report_content
from app.mitre_execution_ta0002 import (
    TA0002_ALLOWED_SUBTECHNIQUES,
    TA0002_TOP_LEVEL_TECHNIQUES,
    resolve_reaction,
)
from app.models import AttackerCommandIn, PredictionAccepted, PredictionIn, SocReportRequest
from app.observatory import (
    elapsed_ms,
    export_conpot_forensics_snapshot,
    export_conpot_runtime_logs,
    log_prediction_outcome,
    log_prediction_received,
    request_metadata,
    start_timer,
)
from app.orchestrator import route_to_ollama_decoy, start_or_touch_conpot
from app.soc_reporting import generate_soc_report
from app.state import append_event, get_serialized_sessions, utcnow

router = APIRouter()


@router.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@router.get("/ta0002/catalog")
def ta0002_catalog() -> Dict[str, object]:
    return {
        "tactic_id": "TA0002",
        "top_level_techniques": sorted(TA0002_TOP_LEVEL_TECHNIQUES),
        "allowed_subtechniques": sorted(TA0002_ALLOWED_SUBTECHNIQUES),
    }


@router.get("/orchestrator/state")
def orchestrator_state() -> Dict[str, object]:
    return {
        "inactivity_timeout_seconds": INACTIVITY_TIMEOUT_SECONDS,
        "cleanup_interval_seconds": CLEANUP_INTERVAL_SECONDS,
        "sessions": get_serialized_sessions(),
    }


@router.get("/observatory/state")
def observatory_state() -> Dict[str, object]:
    return {
        "it_log_file": str(IT_LOG_FILE),
        "prediction_log_file": str(PREDICTION_LOG_FILE),
        "ot_event_log_file": str(OT_EVENT_LOG_FILE),
        "ot_export_dir": str(OT_EXPORT_DIR),
        "it_log_exists": IT_LOG_FILE.exists(),
        "prediction_log_exists": PREDICTION_LOG_FILE.exists(),
        "ot_event_log_exists": OT_EVENT_LOG_FILE.exists(),
        "ot_export_dir_exists": OT_EXPORT_DIR.exists(),
    }


@router.post("/ot/logs/export")
def export_ot_logs(tail: int = 2000) -> Dict[str, object]:
    return export_conpot_runtime_logs(tail=tail)


@router.post("/ot/forensics/snapshot")
def export_ot_forensics_snapshot(tail: int = 2000) -> Dict[str, object]:
    return export_conpot_forensics_snapshot(tail=tail)


@router.post("/soc/report/generate")
def soc_report_generate(payload: SocReportRequest) -> Dict[str, object]:
    return generate_soc_report(attack_label=payload.attack_label, model=payload.model)


@router.get("/dashboard/summary")
def dashboard_summary(log_tail: int = 20, event_tail: int = 20) -> Dict[str, object]:
    return build_dashboard_summary(log_tail=log_tail, event_tail=event_tail)


@router.get("/dashboard/report/latest")
def dashboard_report_latest() -> Dict[str, object]:
    return latest_report_content()


@router.websocket("/ws/dashboard")
async def dashboard_ws(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            await websocket.send_json(build_dashboard_summary(log_tail=60, event_tail=60))
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        return


@router.post("/attacker/command")
def attacker_command(payload: AttackerCommandIn, request: Request) -> Dict[str, object]:
    return route_to_ollama_decoy(payload.command, metadata=request_metadata(request))


@router.post("/prediction", response_model=PredictionAccepted, status_code=202)
def receive_prediction(payload: PredictionIn, request: Request) -> PredictionAccepted:
    processing_started = start_timer()
    if payload.tactic_id != "TA0002":
        raise HTTPException(
            status_code=422,
            detail="Only alerts with tactic_id TA0002 are accepted in this phase.",
        )

    event_id = str(uuid4())
    req_meta = request_metadata(request)
    log_prediction_received(
        event_id=event_id,
        payload=payload.model_dump(),
        request_info=req_meta,
    )

    reaction = resolve_reaction(
        matrix=payload.matrix,
        target_domain=payload.target_domain,
        technique_id=payload.technique_id,
    )

    runtime_result: Dict[str, object]
    if reaction["action"] == "ROUTE_TO_LLM_DECOY":
        runtime_result = route_to_ollama_decoy(
            payload.attacker_command,
            metadata=req_meta,
            event_id=event_id,
        )
    else:
        runtime_result = start_or_touch_conpot()

    reaction_with_runtime: Dict[str, object] = {**reaction, **runtime_result}

    if payload.end_of_attack:
        reaction_with_runtime["soc_report"] = generate_soc_report(
            attack_label=(
                f"Echo-Net incident ending at {utcnow().isoformat()} "
                f"technique={payload.technique_id}"
            )
        )

    queue_size = append_event(
        {
            "event_id": event_id,
            "received_at": utcnow(),
            "payload": payload.model_dump(),
            "reaction": reaction_with_runtime,
        }
    )

    accepted = PredictionAccepted(
        event_id=event_id,
        accepted_at=utcnow(),
        reaction=reaction_with_runtime,
        queue_status=f"queued:{queue_size}",
    )

    log_prediction_outcome(
        event_id=event_id,
        reaction=reaction_with_runtime,
        queue_status=accepted.queue_status,
        processing_ms=elapsed_ms(processing_started),
    )

    return accepted
