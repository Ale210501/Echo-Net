from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OBSERVATORY_DIR = Path(os.getenv("OBSERVATORY_DIR", str(PROJECT_ROOT / "observatory")))
IT_LOG_FILE = OBSERVATORY_DIR / "it" / "it_commands.jsonl"
PREDICTION_LOG_FILE = OBSERVATORY_DIR / "it" / "prediction_events.jsonl"
OT_LOG_DIR = OBSERVATORY_DIR / "ot"
OT_EXPORT_DIR = OT_LOG_DIR / "exports"
OT_EVENT_LOG_FILE = OT_LOG_DIR / "ot_events.jsonl"
CONPOT_VOLUME_HOST_DIR = OT_LOG_DIR / "conpot_volume"
CONPOT_CONTAINER_LOG_DIR = os.getenv("CONPOT_CONTAINER_LOG_DIR", "/var/log/conpot")

HONEYPOT_NETWORK = os.getenv("HONEYPOT_NETWORK", "honeynet_net")
CONPOT_IMAGE = os.getenv("CONPOT_IMAGE", "dtagdevsec/conpot:24.04.1")
CONPOT_CONTAINER_NAME = os.getenv("CONPOT_CONTAINER_NAME", "conpot_dynamic")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "tinyllama")
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "240"))
OLLAMA_FALLBACK_URLS = [
	url.strip()
	for url in os.getenv(
		"OLLAMA_FALLBACK_URLS",
		"http://ollama:11434,http://host.docker.internal:11434",
	).split(",")
	if url.strip()
]
INACTIVITY_TIMEOUT_SECONDS = int(os.getenv("INACTIVITY_TIMEOUT_SECONDS", "1800"))
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "30"))

SESSION_KEY_IT = "it_decoy"
SESSION_KEY_OT = "ot_conpot"

# Confidence thresholds for human-in-the-loop guardrails
CONFIDENCE_AUTO_THRESHOLD: float = float(os.getenv("CONFIDENCE_AUTO_THRESHOLD", "0.80"))
CONFIDENCE_REVIEW_THRESHOLD: float = float(os.getenv("CONFIDENCE_REVIEW_THRESHOLD", "0.50"))

KPI_DIR = OBSERVATORY_DIR / "reports" / "kpi"
KPI_FALSE_TRIGGER_THRESHOLD: float = float(
    os.getenv("KPI_FALSE_TRIGGER_THRESHOLD", "0.5")
)
