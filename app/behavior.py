from __future__ import annotations

from typing import Dict


def classify_attacker_behavior(command: str, features: Dict[str, object]) -> Dict[str, object]:
    lowered = command.lower()
    indicators: list[str] = []
    score = 0.0

    suspicious_keywords = [
        "whoami",
        "ipconfig",
        "ifconfig",
        "net user",
        "wmic",
        "powershell",
        "curl",
        "wget",
        "certutil",
        "base64",
        "invoke-",
        "sc ",
        "reg ",
        "schtasks",
        "systeminfo",
    ]

    for keyword in suspicious_keywords:
        if keyword in lowered:
            score += 0.08
            indicators.append(f"keyword:{keyword}")

    if bool(features.get("contains_pipe")):
        score += 0.12
        indicators.append("pipeline_used")

    if bool(features.get("contains_redirect")):
        score += 0.1
        indicators.append("redirection_used")

    if bool(features.get("contains_encoded_hint")):
        score += 0.22
        indicators.append("encoded_payload_hint")

    char_count = int(features.get("char_count", 0) or 0)
    word_count = int(features.get("word_count", 0) or 0)
    unique_word_count = int(features.get("unique_word_count", 0) or 0)

    if char_count > 120:
        score += 0.12
        indicators.append("long_command")

    if word_count > 20:
        score += 0.08
        indicators.append("high_word_count")

    if word_count > 0 and unique_word_count / max(word_count, 1) < 0.45:
        score += 0.1
        indicators.append("high_repetition_ratio")

    if bool(features.get("contains_url")):
        score += 0.12
        indicators.append("external_resource_reference")

    automation_score = max(0.0, min(1.0, round(score, 4)))

    if automation_score >= 0.65:
        profile = "scripted_or_automated"
    elif automation_score >= 0.35:
        profile = "mixed_or_assisted"
    else:
        profile = "interactive_or_human_like"

    return {
        "profile": profile,
        "automation_score": automation_score,
        "indicators": indicators,
        "confidence": "heuristic",
    }
