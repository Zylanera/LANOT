import hmac
import time

from fastapi import APIRouter, Header, HTTPException, Request
from lanot_common.protocol import LogBatch, MetricsReport, StateReport

router = APIRouter(prefix="/api/v1")


def _authorize(request: Request, host: str, authorization: str | None) -> None:
    expected = request.app.state.settings.agent_tokens.get(host)
    scheme, _, token = (authorization or "").partition(" ")
    if expected is None or scheme.lower() != "bearer" or not hmac.compare_digest(
        token.encode(), expected.encode()
    ):
        raise HTTPException(status_code=401, detail="invalid token for host")


def _db(request: Request):
    return request.app.state.db


# Handlers are plain `def` so FastAPI runs them in its threadpool and the
# blocking SQLite writes never stall the event loop.
@router.get("/health")
def health() -> dict:
    return {"ok": True}


@router.post("/metrics")
def post_metrics(
    report: MetricsReport, request: Request, authorization: str | None = Header(default=None)
) -> dict:
    _authorize(request, report.host, authorization)
    _db(request).insert_metrics(report, time.time())
    return {"ok": True}


@router.post("/state")
def post_state(
    report: StateReport, request: Request, authorization: str | None = Header(default=None)
) -> dict:
    _authorize(request, report.host, authorization)
    _db(request).insert_state(report, time.time())
    return {"ok": True}


@router.post("/logs")
def post_logs(
    batch: LogBatch, request: Request, authorization: str | None = Header(default=None)
) -> dict:
    _authorize(request, batch.host, authorization)
    return {"ok": True, "stored": _db(request).insert_logs(batch, time.time())}
