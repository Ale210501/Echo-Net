from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from statistics import mean, median
from typing import Dict, List, Tuple

from app.config import KPI_DIR, KPI_FALSE_TRIGGER_THRESHOLD, PREDICTION_LOG_FILE


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _percentile(sorted_data: List[float], pct: float) -> float:
    """Linear-interpolation percentile (equivalent to numpy percentile default)."""
    if not sorted_data:
        return 0.0
    n = len(sorted_data)
    index = (pct / 100.0) * (n - 1)
    lo = math.floor(index)
    hi = math.ceil(index)
    if lo == hi:
        return sorted_data[lo]
    return sorted_data[lo] * (1.0 - (index - lo)) + sorted_data[hi] * (index - lo)


def _read_prediction_events() -> Tuple[Dict[str, dict], Dict[str, dict]]:
    received: Dict[str, dict] = {}
    processed: Dict[str, dict] = {}

    if not PREDICTION_LOG_FILE.exists():
        return received, processed

    with PREDICTION_LOG_FILE.open(encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            eid = rec.get("event_id")
            if not eid:
                continue
            evt = rec.get("event")
            if evt == "prediction_received":
                received[eid] = rec
            elif evt == "prediction_processed":
                processed[eid] = rec

    return received, processed


def compute_kpi_report() -> Dict[str, object]:
    """
    Reads observatory/it/prediction_events.jsonl and returns a structured KPI dict.

    Metrics:
      - activation_time_ms: time from prediction receipt to action taken (ms)
      - false_trigger: events where confidence < threshold OR action errored
    """
    received_by_id, processed_by_id = _read_prediction_events()

    total_received = len(received_by_id)
    total_processed = len(processed_by_id)

    activation_ms_values: List[float] = []
    confidence_values: List[float] = []
    false_trigger_count = 0
    domain_split: Dict[str, int] = {"IT": 0, "OT": 0}
    action_counts: Dict[str, int] = {}
    error_count = 0
    timestamps: List[str] = []

    _ERROR_STATUSES = {"error", "docker_unavailable", "docker_error", "connection_error"}

    for event_id, proc in processed_by_id.items():
        recv = received_by_id.get(event_id, {})
        payload = recv.get("payload") or {}

        # --- activation time --------------------------------------------------
        act_ms = proc.get("activation_ms") or proc.get("processing_ms")
        if isinstance(act_ms, (int, float)):
            activation_ms_values.append(float(act_ms))

        # --- confidence -------------------------------------------------------
        confidence = payload.get("confidence") if isinstance(payload, dict) else None
        if isinstance(confidence, (int, float)):
            confidence_values.append(float(confidence))

        # --- false trigger ----------------------------------------------------
        # Prefer the stored flag; fall back to confidence-threshold for old records.
        stored_flag = proc.get("is_false_trigger")
        if stored_flag is True:
            false_trigger_count += 1
        elif stored_flag is None:
            # backward-compat: infer from confidence
            if isinstance(confidence, (int, float)) and confidence < KPI_FALSE_TRIGGER_THRESHOLD:
                false_trigger_count += 1

        # --- domain -----------------------------------------------------------
        if isinstance(payload, dict):
            domain = payload.get("target_domain", "")
            if domain in domain_split:
                domain_split[domain] += 1

        # --- action outcomes & errors -----------------------------------------
        reaction = proc.get("reaction") or {}
        if isinstance(reaction, dict):
            action = str(reaction.get("action", "unknown"))
            action_counts[action] = action_counts.get(action, 0) + 1
            if str(reaction.get("status", "")) in _ERROR_STATUSES:
                error_count += 1

        ts = proc.get("timestamp")
        if ts:
            timestamps.append(str(ts))

    # --- compute distribution stats ------------------------------------------
    sorted_ms = sorted(activation_ms_values)
    activation_stats: Dict[str, object] = {
        "samples": len(sorted_ms),
        "min_ms": round(sorted_ms[0], 3) if sorted_ms else None,
        "max_ms": round(sorted_ms[-1], 3) if sorted_ms else None,
        "mean_ms": round(mean(sorted_ms), 3) if sorted_ms else None,
        "median_ms": round(median(sorted_ms), 3) if sorted_ms else None,
        "p95_ms": round(_percentile(sorted_ms, 95), 3) if sorted_ms else None,
        "p99_ms": round(_percentile(sorted_ms, 99), 3) if sorted_ms else None,
    }

    sorted_conf = sorted(confidence_values)
    confidence_stats: Dict[str, object] = {
        "samples": len(sorted_conf),
        "min": round(sorted_conf[0], 4) if sorted_conf else None,
        "max": round(sorted_conf[-1], 4) if sorted_conf else None,
        "mean": round(mean(sorted_conf), 4) if sorted_conf else None,
        "threshold": KPI_FALSE_TRIGGER_THRESHOLD,
        "below_threshold_count": sum(
            1 for c in sorted_conf if c < KPI_FALSE_TRIGGER_THRESHOLD
        ),
    }

    false_trigger_rate_pct = (
        round((false_trigger_count / total_processed) * 100.0, 2)
        if total_processed
        else 0.0
    )

    return {
        "generated_at": _utcnow_iso(),
        "period": {
            "from": min(timestamps) if timestamps else None,
            "to": max(timestamps) if timestamps else None,
        },
        "total_predictions_received": total_received,
        "total_predictions_processed": total_processed,
        "activation_time_ms": activation_stats,
        "false_trigger": {
            "count": false_trigger_count,
            "rate_pct": false_trigger_rate_pct,
            "confidence_threshold": KPI_FALSE_TRIGGER_THRESHOLD,
        },
        "domain_split": domain_split,
        "confidence_stats": confidence_stats,
        "action_outcomes": action_counts,
        "error_count": error_count,
    }


def save_kpi_report() -> Dict[str, object]:
    """Persist a KPI report JSON to observatory/reports/kpi/ and return metadata."""
    KPI_DIR.mkdir(parents=True, exist_ok=True)
    report = compute_kpi_report()
    out_path = KPI_DIR / f"kpi_report_{_now_stamp()}.json"
    out_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=True, default=str),
        encoding="utf-8",
    )
    return {
        "status": "saved",
        "path": str(out_path),
        "report": report,
    }
