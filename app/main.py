import os
import secrets
from pathlib import Path
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from app import store

load_dotenv()
app = FastAPI(title="Sentinel Windows Monitor", version="1.0.0", description="Windows endpoint behavior monitoring API")
store.initialize()
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class Snapshot(BaseModel):
    schema_version: str = "1.0"
    endpoint: str = Field(min_length=1, max_length=128)
    hostname: str = Field(default="", max_length=255)
    captured_at: str
    processes: list[dict] = Field(default_factory=list)
    services: list[dict] = Field(default_factory=list)
    alerts: list[dict] = Field(default_factory=list)


def authenticate(authorization: str | None = Header(default=None)):
    expected = os.getenv("API_TOKEN", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="API_TOKEN is not configured")
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid bearer token")


@app.get("/")
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


@app.get("/api/summary")
def get_summary():
    return store.summary()


@app.get("/api/alerts")
def get_alerts(limit: int = Query(default=100, ge=1, le=500)):
    return store.recent_alerts(limit)


@app.get("/api/snapshots/latest")
def get_latest(_: None = Depends(authenticate)):
    return store.latest_snapshots()


@app.post("/api/snapshots", status_code=202)
def ingest(snapshot: Snapshot, _: None = Depends(authenticate)):
    store.save_snapshot(snapshot.model_dump())
    return {"accepted": True, "endpoint": snapshot.endpoint, "alert_count": len(snapshot.alerts)}
