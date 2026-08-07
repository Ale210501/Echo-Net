from __future__ import annotations

from time import perf_counter
from typing import Dict
from uuid import uuid4

from app.mitre_execution_ta0002 import resolve_reaction
from app.orchestrator import route_to_ollama_decoy, start_or_touch_conpot
from app.soc_reporting import generate_soc_report
from app.state import utcnow


def run_basic_scenario(
    source_ip: str,
    user_agent: str,
    commands: list[str],
    trigger_ot: bool,
    generate_report: bool,
    attack_label: str,
) -> Dict[str, object]:
    scenario_started = perf_counter()
    scenario_correlation_id = str(uuid4())
    metadata = {
        "client_ip": source_ip,
        "user_agent": user_agent,
        "path": "/scenario/run/basic",
        "method": "POST",
        "correlation_id": scenario_correlation_id,
    }

    step_results: list[Dict[str, object]] = []
    it_routed = 0
    it_failed = 0
    response_ms: list[float] = []

    for index, command in enumerate(commands, start=1):
        step_started = perf_counter()
        result = route_to_ollama_decoy(
            command=command,
            metadata=metadata,
            event_id=f"{scenario_correlation_id}-it-{index}",
            correlation_id=scenario_correlation_id,
        )
        duration_ms = round((perf_counter() - step_started) * 1000.0, 3)
        response_ms.append(duration_ms)
        if result.get("status") == "routed":
            it_routed += 1
        else:
            it_failed += 1
        step_results.append(
            {
                "phase": "IT",
                "command": command,
                "duration_ms": duration_ms,
                "result": result,
            }
        )

    ot_result: Dict[str, object] = {
        "status": "skipped",
        "detail": "OT trigger disabled by request.",
    }
    if trigger_ot:
        ot_reaction = resolve_reaction(
            matrix="ics",
            target_domain="OT",
            technique_id="T1610",
        )
        ot_result = {
            **ot_reaction,
            **start_or_touch_conpot(correlation_id=scenario_correlation_id),
        }
        step_results.append(
            {
                "phase": "OT",
                "command": "trigger_conpot_t1610",
                "duration_ms": None,
                "result": ot_result,
            }
        )

    report_result: Dict[str, object] = {
        "status": "skipped",
        "detail": "SOC report generation disabled by request.",
    }
    if generate_report:
        report_result = generate_soc_report(
            attack_label=f"{attack_label} @ {utcnow().isoformat()}"
        )

    total_ms = round((perf_counter() - scenario_started) * 1000.0, 3)
    avg_response_ms = round(sum(response_ms) / len(response_ms), 3) if response_ms else 0.0
    route_rate = round((it_routed / max(len(commands), 1)) * 100.0, 2)

    return {
        "status": "completed",
        "started_at": utcnow().isoformat(),
        "source_ip": source_ip,
        "user_agent": user_agent,
        "correlation_id": scenario_correlation_id,
        "steps": step_results,
        "kpi": {
            "it_commands_total": len(commands),
            "it_commands_routed": it_routed,
            "it_commands_failed": it_failed,
            "it_route_success_rate_pct": route_rate,
            "it_avg_response_ms": avg_response_ms,
            "ot_triggered": trigger_ot,
            "ot_status": ot_result.get("status"),
            "scenario_duration_ms": total_ms,
        },
        "ot_result": ot_result,
        "report": report_result,
    }