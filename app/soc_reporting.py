from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import requests

from app.config import (
    OBSERVATORY_DIR,
    OLLAMA_BASE_URL,
    OLLAMA_FALLBACK_URLS,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT_SECONDS,
)

REPORTS_DIR = OBSERVATORY_DIR / "reports"
MAX_TOTAL_CONTEXT_CHARS = 1_500_000


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _build_ollama_urls() -> list[str]:
    urls = [OLLAMA_BASE_URL, *OLLAMA_FALLBACK_URLS]
    return list(dict.fromkeys(urls))


def _collect_json_artifacts() -> Dict[str, object]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    candidates: list[Path] = []
    for ext in ("*.json", "*.jsonl"):
        candidates.extend(OBSERVATORY_DIR.rglob(ext))

    candidates = [p for p in candidates if p.is_file() and REPORTS_DIR not in p.parents]
    candidates = sorted(candidates)

    artifacts: list[Dict[str, object]] = []
    total_chars = 0

    for file_path in candidates:
        text = file_path.read_text(encoding="utf-8", errors="replace")
        remaining = MAX_TOTAL_CONTEXT_CHARS - total_chars
        if remaining <= 0:
            artifacts.append(
                {
                    "path": str(file_path),
                    "size_bytes": file_path.stat().st_size,
                    "truncated": True,
                    "content": "",
                }
            )
            continue

        if len(text) > remaining:
            artifacts.append(
                {
                    "path": str(file_path),
                    "size_bytes": file_path.stat().st_size,
                    "truncated": True,
                    "content": text[:remaining],
                }
            )
            total_chars += remaining
        else:
            artifacts.append(
                {
                    "path": str(file_path),
                    "size_bytes": file_path.stat().st_size,
                    "truncated": False,
                    "content": text,
                }
            )
            total_chars += len(text)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact_count": len(artifacts),
        "total_chars": total_chars,
        "artifacts": artifacts,
    }


def _build_soc_prompt(bundle: Dict[str, object], attack_label: str) -> str:
    return (
        "You are a SOC analyst assistant. "
        "Produce a complete SOC incident report in English based ONLY on the provided JSON artifacts.\n\n"
        "Report requirements:\n"
        "1) Executive Summary\n"
        "2) Attack Timeline (UTC)\n"
        "3) MITRE ATT&CK mapping with tactic/technique IDs\n"
        "4) IT behavior analysis (human vs automated indicators)\n"
        "5) OT behavior analysis (industrial protocol manipulation attempts)\n"
        "6) Evidence inventory (file paths and key log excerpts)\n"
        "7) Containment and eradication actions\n"
        "8) Detection and hardening recommendations\n"
        "9) Confidence and limitations\n"
        "10) Appendix with machine-readable IOC list\n\n"
        f"Attack label: {attack_label}\n\n"
        "JSON artifacts:\n"
        f"{json.dumps(bundle, ensure_ascii=True)}"
    )


def generate_soc_report(
    attack_label: str = "Echo-Net simulated incident",
    model: Optional[str] = None,
) -> Dict[str, object]:
    bundle = _collect_json_artifacts()
    bundle_file = REPORTS_DIR / f"attack_bundle_{_now_stamp()}.json"
    bundle_file.write_text(json.dumps(bundle, ensure_ascii=True, indent=2), encoding="utf-8")

    prompt = _build_soc_prompt(bundle=bundle, attack_label=attack_label)
    chosen_model = model or OLLAMA_MODEL

    attempted_errors: list[str] = []
    for base_url in _build_ollama_urls():
        try:
            response = requests.post(
                f"{base_url}/api/generate",
                json={
                    "model": chosen_model,
                    "stream": False,
                    "keep_alive": "30m",
                    "prompt": prompt,
                },
                timeout=max(OLLAMA_TIMEOUT_SECONDS, 300),
            )

            if response.status_code >= 400:
                attempted_errors.append(
                    f"{base_url} -> HTTP {response.status_code}: {response.text.strip() or response.reason}"
                )
                continue

            data = response.json()
            report_text = data.get("response", "").strip()
            if not report_text:
                attempted_errors.append(f"{base_url} -> empty LLM output")
                continue

            report_file = REPORTS_DIR / f"soc_report_{_now_stamp()}.md"
            report_file.write_text(report_text, encoding="utf-8")
            return {
                "status": "generated",
                "model": chosen_model,
                "ollama_base_url": base_url,
                "artifact_count": bundle.get("artifact_count", 0),
                "bundle_file": str(bundle_file),
                "report_file": str(report_file),
            }
        except requests.RequestException as exc:
            attempted_errors.append(f"{base_url} -> {exc}")

    return {
        "status": "generation_failed",
        "model": chosen_model,
        "bundle_file": str(bundle_file),
        "errors": attempted_errors,
    }
