"""Local non-root API. No privileged commands, capture execution or model uploads."""
import asyncio
import logging
import re
import tempfile
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import ValidationError, Field
from backend.core import config
from backend.core.security_policy import POLICIES, hardening
from backend.database.store import Store
from backend.ml.classifier import model_info
from backend.protocol.pcap import CaptureError
from backend.reporting.html import render
from backend.schemas.models import (Analysis, ProtocolSummary, SecurityAssociation, Prediction,
                                    Finding, Score, StrictModel, PolicyName)
from backend.services.analysis import build_analysis
from backend.services.policy import assess
from backend.telemetry.importer import Telemetry, apply_telemetry

log = logging.getLogger(__name__)


class IntakeLimits:
    """Bound actual body bytes before multipart parsing; at most two intake requests.
    Disk-backed spool avoids unbounded upload memory and catches lying Content-Length.
    """
    def __init__(self, app):
        self.app = app
        self.slots = asyncio.Semaphore(2)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        origin = headers.get(b"origin", b"").decode(errors="replace")
        if origin and origin not in ("http://127.0.0.1:5173", "http://localhost:5173",
                                     "http://127.0.0.1:18760", "http://localhost:18760"):
            return await JSONResponse({"detail": "Origin not permitted"}, status_code=403)(scope, receive, send)
        if self.slots.locked():
            return await JSONResponse({"detail": "Analysis capacity busy; retry shortly"}, status_code=503)(scope, receive, send)
        limit = config.MAX_TELEMETRY if scope["path"].endswith("/telemetry") else config.MAX_UPLOAD + config.MAX_TELEMETRY
        async with self.slots:
            with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as spool:
                total = 0
                while True:
                    try:
                        message = await asyncio.wait_for(receive(), timeout=30)
                    except TimeoutError:
                        return await JSONResponse({"detail": "Upload timed out"}, status_code=408)(scope, receive, send)
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    total += len(chunk)
                    if total > limit:
                        return await JSONResponse({"detail": "Request body exceeds configured limit"},
                                                  status_code=413)(scope, receive, send)
                    spool.write(chunk)
                    if not message.get("more_body", False):
                        break
                spool.seek(0)
                async def replay():
                    body = spool.read(65536)
                    return {"type": "http.request", "body": body, "more_body": spool.tell() < total}
                await self.app(scope, replay, send)


class AnalysisSummary(StrictModel):
    analysis_id: str
    created_at: str
    label: str
    capture_filename: str
    packet_count: int
    policy: PolicyName
    score: Score


class Health(StrictModel):
    status: str
    service: str


class Hardening(StrictModel):
    status: Literal["RECOMMENDATION"] = "RECOMMENDATION"
    snippet: str


class TelemetryRequest(Telemetry):
    expected_revision: int = Field(ge=1)


def create_app(data_dir: Path | None = None):
    directory = data_dir or config.DATA_DIR
    store = Store(directory)
    app = FastAPI(title="IPsecLens AI", version="0.1.0", docs_url=None, redoc_url=None, description=(
        "Local evidence-aware IPsec analyzer. UNKNOWN != SECURE. IKE proposals are not ESP transforms."))
    app.add_middleware(IntakeLimits)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"] if data_dir else ["127.0.0.1", "localhost"])
    app.state.store = store

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        return JSONResponse({"detail": "Request validation failed; check field types and required values"}, status_code=422)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception):
        log.error("Analysis service error: %s", type(exc).__name__)
        return JSONResponse({"detail": "Analysis service error; inspect local service logs"}, status_code=500)

    @app.get("/api/health", response_model=Health)
    def health():
        return Health(status="ok", service="IPsecLens AI")

    def get(identity: str):
        if not re.fullmatch(r"[0-9a-f]{32}", identity):
            raise HTTPException(404, "Analysis not found")
        result = store.get(identity)
        if result is None:
            raise HTTPException(404, "Analysis not found")
        return result

    @app.post("/api/analyses", response_model=Analysis, status_code=201)
    def upload(capture: UploadFile = File(...), policy: PolicyName = Form("MODERN"),
               label: str = Form("", max_length=160), retain_capture: bool = Form(False),
               telemetry: str | None = Form(None, max_length=config.MAX_TELEMETRY)):
        identity = uuid.uuid4().hex
        filename = re.sub(r"[^A-Za-z0-9._-]", "_", (capture.filename or "capture.pcap").replace("\\", "/").split("/")[-1])[:120]
        imported = None
        try:
            if telemetry:
                imported = Telemetry.model_validate_json(telemetry, strict=True)
            work_root = directory / "work"
            work_root.mkdir(exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix=identity + "-", dir=work_root) as work:
                path = Path(work) / "input.capture"
                size = 0
                with path.open("wb") as output:
                    while chunk := capture.file.read(65536):
                        size += len(chunk)
                        if size > config.MAX_UPLOAD:
                            raise HTTPException(413, "Capture exceeds configured upload limit")
                        output.write(chunk)
                result = build_analysis(path, identity, filename, label, policy, retain_capture, imported)
                if retain_capture:
                    retained = directory / "captures"
                    retained.mkdir(exist_ok=True, mode=0o700)
                    path.replace(retained / (identity + ".pcap"))
                try:
                    store.save(result)
                except Exception:
                    if retain_capture:
                        (directory / "captures" / (identity + ".pcap")).unlink(missing_ok=True)
                    raise
                return result
        except (CaptureError, ValidationError, ValueError) as exc:
            message = str(exc) if isinstance(exc, CaptureError) else "Invalid telemetry or analysis input"
            raise HTTPException(422, message) from None
        finally:
            capture.file.close()

    @app.get("/api/analyses", response_model=list[AnalysisSummary])
    def history(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return store.list(limit, offset)

    @app.get("/api/analyses/{identity}", response_model=Analysis)
    def detail(identity: str):
        return get(identity)

    @app.get("/api/analyses/{identity}/protocol", response_model=ProtocolSummary)
    def protocol(identity: str):
        return get(identity).protocol_observations

    @app.get("/api/analyses/{identity}/sas", response_model=list[SecurityAssociation])
    def sas(identity: str):
        return get(identity).security_associations

    @app.get("/api/analyses/{identity}/traffic", response_model=list[Prediction])
    def traffic(identity: str):
        return get(identity).traffic_predictions

    @app.get("/api/analyses/{identity}/findings", response_model=list[Finding])
    def findings(identity: str):
        return get(identity).findings

    @app.get("/api/analyses/{identity}/score", response_model=Score)
    def score(identity: str):
        return get(identity).score

    @app.post("/api/analyses/{identity}/telemetry", response_model=Analysis)
    def telemetry(identity: str, body: TelemetryRequest):
        result = get(identity)
        if result.revision != body.expected_revision:
            raise HTTPException(409, "Analysis changed; reload before importing telemetry")
        clean = Telemetry.model_validate(body.model_dump(exclude={"expected_revision"}))
        try:
            provenance = apply_telemetry(result.security_associations, clean, result.capture_sha256)
            result.telemetry_provenance.extend(provenance)
            result.findings, result.score, result.threat_matrix = assess(
                result.protocol_observations, result.security_associations, result.policy, result.analysis_status == "PARTIAL")
            result.revision += 1
            store.replace(result, body.expected_revision)
        except ValueError:
            raise HTTPException(422, "Telemetry identity conflict or concurrent update") from None
        return result

    @app.get("/api/analyses/{identity}/report/{kind}", response_class=HTMLResponse)
    def report(identity: str, kind: Literal["executive", "technical"]):
        return HTMLResponse(render(get(identity), kind), headers={
            "Content-Disposition": f'attachment; filename="ipseclens-{identity}-{kind}.html"',
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff"})

    @app.get("/api/analyses/{identity}/hardening", response_model=Hardening)
    def harden(identity: str):
        return Hardening(snippet=hardening(get(identity).policy))

    @app.get("/api/policies")
    def policies():
        return [asdict(p) for p in POLICIES.values()]

    @app.get("/api/model/info")
    def model():
        return model_info()

    return app


app = create_app()
