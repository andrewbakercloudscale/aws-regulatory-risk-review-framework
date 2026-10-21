"""The web console: a local FastAPI app serving the dashboard and a small JSON API.

The console runs on the analyst's machine with the analyst's AWS credentials, so it is
locked to loopback by default and defends against the two ways a web page in the same
browser could reach it:

* DNS rebinding - requests whose Host header is not a loopback name are refused;
* cross-site requests - every state-changing request must carry ``X-ExitRisk: 1``, a
  custom header a foreign origin cannot send without a CORS preflight, which we never grant.
"""

from __future__ import annotations

import contextvars
import json
import os
import queue
import threading
import time
import uuid
from importlib import resources
from typing import Annotated

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, preflight, sso, store
from .aws_session import available_profiles, make_session, profile_accounts
from .catalog import load_catalog
from .collectors import organizations
from .compare import compare_scans
from .demo import create_demo_scan
from .estimate import CICD_LABELS, DC_FACILITY_LABELS, IAC_LABELS, TARGET_LABELS, TARGET_PATTERN, Questionnaire
from .filtering import AccountFilter, FilterError
from .issues import describe_exception
from .logging_config import configure_logging, get_logger, tail_log
from .multiregion import MultiRegionAnswers, build_multiregion
from .scanner import ScanParams, get_job, running_scans, start_scan
from .scoring import build_report

log = get_logger("server")


def _aws_error(exc: Exception) -> bool:
    """AWS errors are expected (expired sign-in, missing permission); anything else is logged with a traceback."""
    return isinstance(exc, (ClientError, BotoCoreError))


WEB_DIR = resources.files("exitrisk").joinpath("web")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}


class OUQuery(BaseModel):
    profile: str | None = None
    refresh: bool = False  # bypass the cache (the ↻ button)


class AccessCheckRequest(BaseModel):
    profile: str | None = Field(None, max_length=128)
    role_name: str | None = Field(None, max_length=64, pattern=r"^[\w+=,.@-]*$")


class ScanRequest(BaseModel):
    profile: str | None = None
    ou_id: str | None = Field(None, max_length=80)
    ou_ids: list[Annotated[str, Field(max_length=80)]] | None = Field(None, max_length=100)
    months: int = Field(12, ge=1, le=12)
    role_name: str | None = Field(None, max_length=64, pattern=r"^[\w+=,.@-]*$")
    inventory: bool = False
    regions: list[str] | None = None
    label: str = Field("", max_length=120)
    target: str = Field("azure", pattern=TARGET_PATTERN)


class SSOSessionRequest(BaseModel):
    name: str = Field(..., max_length=64)
    start_url: str = Field(..., max_length=300)
    region: str | None = Field(None, max_length=30, pattern=r"^[a-z0-9-]*$")


class SSOLoginRequest(BaseModel):
    session: str = Field(..., max_length=64)


class SSOProfileRequest(BaseModel):
    session: str = Field(..., max_length=64)
    account_id: str = Field(..., pattern=r"^\d{12}$")
    role: str = Field(..., max_length=64)


class FilterModel(BaseModel):
    include: str = Field("", max_length=200)
    exclude: str = Field("", max_length=200)
    mode: str = "contains"
    case_sensitive: bool = False


class ReportRequest(BaseModel):
    scan_id: str
    filter: FilterModel = FilterModel()
    questionnaire: Questionnaire = Questionnaire()
    weighting: str = Field("spend", pattern=r"^(balanced|spend|equal)$")


class CompareRequest(BaseModel):
    before_id: str
    after_id: str
    filter: FilterModel = FilterModel()
    questionnaire: Questionnaire = Questionnaire()


class MultiRegionRequest(BaseModel):
    scan_id: str
    filter: FilterModel = FilterModel()
    questionnaire: Questionnaire = Questionnaire()
    multiregion: MultiRegionAnswers = MultiRegionAnswers()


def _host_name(header: str) -> str:
    """'localhost:8765' -> 'localhost', '[::1]:8765' -> '[::1]'."""
    if header.startswith("["):
        return header.split("]")[0] + "]"
    return header.rsplit(":", 1)[0]


def create_app(allow_remote: bool = False) -> FastAPI:
    configure_logging()
    app = FastAPI(title="AWS Exit Risk Review", version=__version__, docs_url="/api/docs", redoc_url=None)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        req_id = uuid.uuid4().hex[:8]
        started = time.perf_counter()
        host = _host_name(request.headers.get("host") or "")
        if not allow_remote and host not in LOOPBACK_HOSTS:
            log.warning("refused request with Host %r", host)
            return JSONResponse({"error": "host not allowed"}, status_code=403)
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-exitrisk") != "1":
            log.warning("refused %s %s without X-ExitRisk header", request.method, request.url.path)
            return JSONResponse({"error": "missing X-ExitRisk header"}, status_code=403)
        try:
            response = await call_next(request)
        except Exception:
            log.exception("unhandled error on %s %s (req %s)", request.method, request.url.path, req_id)
            return JSONResponse({"error": "internal error - see the log", "request_id": req_id}, status_code=500)
        ms = (time.perf_counter() - started) * 1000
        if request.url.path.startswith("/api/"):
            log.info("%s %s -> %d (%.0f ms)", request.method, request.url.path, response.status_code, ms)
        response.headers["X-Request-Id"] = req_id
        if request.url.path.startswith("/static/"):
            # Revalidate on every load so an upgraded console never runs stale JS/CSS.
            response.headers.setdefault("Cache-Control", "no-cache")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'"
        )
        return response

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "version": __version__,
            "catalog_version": load_catalog().version,
            "pid": os.getpid(),
            "scans_running": running_scans(),
        }

    @app.get("/api/profiles")
    def profiles():
        return {"profiles": available_profiles(), "accounts": profile_accounts()}

    def sso_call(fn, *args):
        try:
            return fn(*args)
        except sso.SSOFailure as exc:
            raise HTTPException(400, str(exc)) from exc
        except Exception as exc:
            code, msg, hint = describe_exception(exc)
            log.warning("SSO call %s failed: %s %s", fn.__name__, code, msg, exc_info=not _aws_error(exc))
            return JSONResponse({"error": msg, "code": code, "hint": hint}, status_code=502)

    @app.get("/api/sso/sessions")
    def sso_sessions():
        return {"sessions": sso_call(sso.list_sessions)}

    @app.post("/api/sso/sessions")
    def sso_add_session(req: SSOSessionRequest):
        return sso_call(sso.add_session, req.name, req.start_url, req.region or None)

    @app.post("/api/sso/login")
    def sso_login(req: SSOLoginRequest):
        return sso_call(sso.start_login, req.session).snapshot()

    @app.get("/api/sso/login/{login_id}")
    def sso_login_status(login_id: str):
        login = sso.get_login(login_id)
        if not login:
            raise HTTPException(404, "sign-in not found")
        return login.snapshot()

    @app.get("/api/sso/{session}/accounts")
    def sso_accounts(session: str):
        return sso_call(sso.list_accounts, session)

    @app.get("/api/sso/{session}/accounts/{account_id}/roles")
    def sso_roles(session: str, account_id: str):
        return {"roles": sso_call(sso.list_roles, session, account_id)}

    @app.post("/api/sso/profile")
    def sso_profile(req: SSOProfileRequest):
        return {"profile": sso_call(sso.ensure_profile, req.session, req.account_id, req.role)}

    @app.get("/api/options")
    def options():
        return {
            "cicd": CICD_LABELS,
            "iac": IAC_LABELS,
            "target": TARGET_LABELS,
            "dc_facility": DC_FACILITY_LABELS,
            "defaults": Questionnaire().model_dump(),
        }

    @app.post("/api/org")
    def org(q: OUQuery):
        """Read the OU tree. With aws-cli-zsp this call is where Touch ID is first requested."""
        try:
            hit = None if q.refresh else organizations.cached_org_and_tree(q.profile)
            if hit:
                return {"org": hit[0], "tree": hit[1]}
            session = make_session(q.profile)
            out = {"tree": organizations.list_ou_tree(session), "org": organizations.describe_org(session)}
            organizations.remember_org_and_tree(q.profile, out["org"], out["tree"])
            return out
        except Exception as exc:
            code, msg, hint = describe_exception(exc)
            log.warning("OU tree unavailable for profile %s: %s %s", q.profile, code, msg, exc_info=not _aws_error(exc))
            return JSONResponse({"error": msg, "code": code, "hint": hint}, status_code=502)

    @app.post("/api/access-check")
    def access_check(req: AccessCheckRequest, stream: bool = False):
        """Make each read-only call a scan needs and say what to fix. Never raises: failures are results.

        With ?stream=1 the answer is NDJSON: {"steps": [...]}, then {"check": {...}} as each call returns,
        then {"result": {...}}, so the console can show which call it is waiting on.
        """
        if not stream:
            return preflight.run_checks(req.profile, req.role_name or None)
        q: queue.Queue = queue.Queue()

        def work() -> None:
            try:
                q.put(
                    {
                        "result": preflight.run_checks(
                            req.profile, req.role_name or None, on_check=lambda c: q.put({"check": c})
                        )
                    }
                )
            except Exception as exc:
                log.exception("access check failed")
                q.put({"error": describe_exception(exc)[1]})

        threading.Thread(target=contextvars.copy_context().run, args=(work,), daemon=True).start()

        def lines():
            yield json.dumps({"steps": [{"id": i, "label": label} for i, label in preflight.STEPS]}) + "\n"
            while True:
                item = q.get()
                yield json.dumps(item) + "\n"
                if "check" not in item:
                    return

        return StreamingResponse(lines(), media_type="application/x-ndjson")

    @app.post("/api/scans")
    def create_scan(req: ScanRequest):
        try:
            job = start_scan(ScanParams(**req.model_dump()))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return job.snapshot()

    @app.post("/api/scans/demo")
    def demo():
        scan = create_demo_scan()
        log.info("created demo scan %s", scan["id"])
        return {"id": scan["id"], "status": "complete"}

    @app.get("/api/scans")
    def scans():
        return {"scans": store.list_scans(), "running": running_scans()}

    @app.get("/api/scans/{scan_id}/status")
    def scan_status(scan_id: str):
        job = get_job(scan_id)
        if job:
            return job.snapshot()
        try:
            s = store.load_scan(scan_id)
        except store.ScanNotFound as exc:
            raise HTTPException(404, "scan not found") from exc
        return {
            "id": scan_id,
            "phase": s["status"],
            "pct": 100,
            "status": s["status"],
            "message": "",
            "issues": len(s.get("issues", [])),
        }

    @app.delete("/api/scans/{scan_id}")
    def delete(scan_id: str):
        try:
            store.delete_scan(scan_id)
        except store.ScanNotFound as exc:
            raise HTTPException(404, "scan not found") from exc
        return {"deleted": scan_id}

    @app.post("/api/report")
    def report(req: ReportRequest):
        try:
            scan = store.load_scan(req.scan_id)
        except store.ScanNotFound as exc:
            raise HTTPException(404, "scan not found") from exc
        try:
            flt = AccountFilter(**req.filter.model_dump())
        except FilterError as exc:
            raise HTTPException(400, str(exc)) from exc
        return build_report(scan, flt, req.questionnaire, weighting=req.weighting)

    @app.post("/api/compare")
    def compare(req: CompareRequest):
        try:
            before, after = store.load_scan(req.before_id), store.load_scan(req.after_id)
        except store.ScanNotFound as exc:
            raise HTTPException(404, "scan not found") from exc
        try:
            flt = AccountFilter(**req.filter.model_dump())
        except FilterError as exc:
            raise HTTPException(400, str(exc)) from exc
        return compare_scans(before, after, flt, req.questionnaire)

    @app.post("/api/multiregion")
    def multiregion(req: MultiRegionRequest):
        try:
            scan = store.load_scan(req.scan_id)
        except store.ScanNotFound as exc:
            raise HTTPException(404, "scan not found") from exc
        try:
            flt = AccountFilter(**req.filter.model_dump())
        except FilterError as exc:
            raise HTTPException(400, str(exc)) from exc
        return build_multiregion(scan, flt, req.questionnaire, req.multiregion)

    @app.get("/api/catalog")
    def catalog():
        return load_catalog().to_dict()

    @app.get("/api/logs")
    def logs(lines: int = 200, run_id: str | None = None):
        return {"records": tail_log(min(max(lines, 1), 2000), run_id)}

    @app.get("/")
    def index():
        return FileResponse(str(WEB_DIR.joinpath("index.html")), headers={"Cache-Control": "no-store"})

    @app.get("/favicon.ico")
    def favicon():
        # Browsers that ignore <link rel="icon"> still ask for /favicon.ico; give them the same SVG.
        return FileResponse(str(WEB_DIR.joinpath("favicon.svg")), media_type="image/svg+xml")

    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
    return app
