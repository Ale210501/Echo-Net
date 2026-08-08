from __future__ import annotations

from typing import Dict, List


def _build_explanation(
    profile: str,
    automation_score: float,
    indicators: List[str],
    char_count: int,
    word_count: int,
    unique_word_count: int,
    features: Dict[str, object],
) -> str:
    parts: list[str] = []

    kw_found = [ind.split("keyword:")[1] for ind in indicators if ind.startswith("keyword:")]
    if kw_found:
        parts.append(
            f"{len(kw_found)} reconnaissance/execution keyword(s) matched "
            f"({', '.join(kw_found[:4])}{'...' if len(kw_found) > 4 else ''}), "
            f"each contributing +0.08 to the score."
        )

    if "encoded_payload_hint" in indicators:
        parts.append(
            "Obfuscation/encoding pattern detected (base64, certutil, -enc): "
            "strong indicator of an automated payload (+0.22)."
        )

    if "pipeline_used" in indicators:
        parts.append("Pipe operator '|' present: typical of chained script commands (+0.12).")

    if "redirection_used" in indicators:
        parts.append("I/O redirection (>, <) detected: common in automated enumeration scripts (+0.10).")

    if "external_resource_reference" in indicators:
        parts.append("External URL reference found: frequent pattern in droppers or C2 beacons (+0.12).")

    if "long_command" in indicators:
        parts.append(
            f"Command length ({char_count} chars) exceeds threshold of 120: "
            f"unusual for an interactive human operator (+0.12)."
        )

    if "high_word_count" in indicators:
        parts.append(
            f"High token count ({word_count} words > threshold 20): "
            f"suggests programmatically generated command (+0.08)."
        )

    if "high_repetition_ratio" in indicators:
        rep_ratio = round(unique_word_count / max(word_count, 1), 2)
        parts.append(
            f"Low lexical diversity (unique/total tokens = {rep_ratio} < 0.45): "
            f"typical of payloads with repeated arguments (+0.10)."
        )

    # profile sentence
    profile_labels = {
        "scripted_or_automated": "SCRIPTED/AUTOMATED",
        "mixed_or_assisted": "MIXED/SEMI-ASSISTED",
        "interactive_or_human_like": "INTERACTIVE/HUMAN-LIKE",
    }
    label = profile_labels.get(profile, profile.upper())
    verdict = f"Final score {automation_score:.2f} → profile {label}. "
    if not parts:
        verdict += "No significant indicators detected; behaviour consistent with a human operator."
    else:
        verdict += "Contributing factors: " + " | ".join(parts)

    return verdict


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

    explanation = _build_explanation(
        profile=profile,
        automation_score=automation_score,
        indicators=indicators,
        char_count=char_count,
        word_count=word_count,
        unique_word_count=unique_word_count,
        features=features,
    )

    return {
        "profile": profile,
        "automation_score": automation_score,
        "indicators": indicators,
        "decision_explanation": explanation,
        "confidence": "heuristic",
    }
