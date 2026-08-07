from __future__ import annotations

from typing import Dict, Set

# Top-level Enterprise ATT&CK techniques for tactic TA0002 (Execution).
# Source: https://attack.mitre.org/tactics/TA0002/
TA0002_TOP_LEVEL_TECHNIQUES: Set[str] = {
    "T1047",  # Windows Management Instrumentation
    "T1053",  # Scheduled Task/Job
    "T1059",  # Command and Scripting Interpreter
    "T1072",  # Software Deployment Tools
    "T1106",  # Native API
    "T1127",  # Trusted Developer Utilities Proxy Execution
    "T1129",  # Shared Modules
    "T1197",  # BITS Jobs
    "T1203",  # Exploitation for Client Execution
    "T1204",  # User Execution
    "T1559",  # Inter-Process Communication
    "T1569",  # System Services
    "T1574",  # Hijack Execution Flow
    "T1609",  # Container Administration Command
    "T1610",  # Deploy Container
    "T1648",  # Serverless Execution
    "T1651",  # Cloud Administration Command
    "T1674",  # Input Injection
    "T1675",  # ESXi Administration Command
    "T1677",  # Poisoned Pipeline Execution
}

# Sub-techniques currently accepted for TA0002 in this project.
# Keep this list explicit to accept only real MITRE IDs used in your phase.
TA0002_ALLOWED_SUBTECHNIQUES: Set[str] = {
    "T1053.002",
    "T1053.003",
    "T1053.005",
    "T1053.006",
    "T1053.007",
    "T1059.001",
    "T1059.002",
    "T1059.003",
    "T1059.004",
    "T1059.005",
    "T1059.006",
    "T1059.007",
    "T1059.008",
    "T1059.009",
    "T1059.010",
    "T1059.011",
    "T1059.012",
    "T1059.013",
    "T1127.001",
    "T1127.002",
    "T1127.003",
    "T1204.001",
    "T1204.002",
    "T1204.003",
    "T1204.004",
    "T1204.005",
    "T1559.001",
    "T1559.002",
    "T1559.003",
    "T1569.001",
    "T1569.002",
    "T1569.003",
    "T1574.001",
    "T1574.004",
    "T1574.005",
    "T1574.006",
    "T1574.007",
    "T1574.008",
    "T1574.009",
    "T1574.010",
    "T1574.011",
    "T1574.012",
    "T1574.013",
    "T1574.014",
}

# Optional overrides for techniques strongly linked to cloud/container/infra execution.
# If target_domain is not provided or is ambiguous, these default to OT-style trap.
OT_BIASED_TECHNIQUES: Set[str] = {
    "T1609",
    "T1610",
    "T1651",
    "T1675",
    "T1677",
}


def is_allowed_ta0002_technique(technique_id: str) -> bool:
    if "." in technique_id:
        return technique_id in TA0002_ALLOWED_SUBTECHNIQUES
    return technique_id in TA0002_TOP_LEVEL_TECHNIQUES


def get_base_technique_id(technique_id: str) -> str:
    return technique_id.split(".", 1)[0]


def resolve_reaction(
    matrix: str,
    target_domain: str,
    technique_id: str,
) -> Dict[str, str]:
    """Map a validated TA0002 prediction to the trap to activate."""
    normalized_matrix = matrix.lower()
    normalized_domain = target_domain.upper()
    base_id = get_base_technique_id(technique_id)

    # Base routing by domain (requested architecture).
    if normalized_domain == "IT":
        action = "ROUTE_TO_LLM_DECOY"
        trap = "ollama_decoy"
    else:
        action = "START_OT_HONEYPOT"
        trap = "conpot"

    # Optional override for infra/container-heavy execution techniques.
    if normalized_domain not in {"IT", "OT"} and base_id in OT_BIASED_TECHNIQUES:
        action = "START_OT_HONEYPOT"
        trap = "conpot"

    return {
        "matrix": normalized_matrix,
        "target_domain": normalized_domain,
        "action": action,
        "trap": trap,
    }
