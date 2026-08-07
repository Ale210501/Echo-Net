from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import router
from app.config import PROJECT_ROOT
from app.cleanup import start_cleanup_worker, stop_cleanup_worker
from app.observatory import ensure_observatory_paths

app = FastAPI(
    title="Echo-Net Listener API",
    description=(
        "Receives Next-Step Prediction JSON and maps TA0002 (Execution) "
        "MITRE ATT&CK techniques to IT/OT deception actions."
    ),
    version="0.1.0",
)

app.include_router(router)

UI_DIR = PROJECT_ROOT / "ui"

if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")


def _serve_ui_page(file_name: str) -> FileResponse:
    return FileResponse(str(UI_DIR / file_name))


@app.get("/soc/dashboard")
def soc_dashboard() -> FileResponse:
    return _serve_ui_page("index.html")


@app.get("/soc/terminal")
def soc_terminal() -> FileResponse:
    return _serve_ui_page("terminal.html")


@app.get("/soc/scenario")
def soc_scenario() -> FileResponse:
    return _serve_ui_page("scenario.html")


@app.get("/soc/honeynet")
def soc_honeynet() -> FileResponse:
    return _serve_ui_page("honeynet.html")


@app.on_event("startup")
def on_startup() -> None:
    ensure_observatory_paths()
    start_cleanup_worker()


@app.on_event("shutdown")
def on_shutdown() -> None:
    stop_cleanup_worker()
