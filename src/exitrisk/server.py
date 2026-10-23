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
from contextlib import asynccontextmanager
from importlib import resources
from typing import Annotated

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, preflight, schedule, sso, store
from .ai import providers as ai_providers
from .ai import review as ai_review
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


class UpstreamError(Exception):
    """An AWS call behind an API route failed; answered as 502 with the code and hint the console shows."""

    def __init__(self, exc: Exception):
        self.code, self.msg, self.hint = describe_exception(exc)
        super().__init__(self.msg)


WEB_DIR = resources.files("exitrisk").joinpath("web")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}


PROFILE = Field(None, max_length=128)
REGION = Annotated[str, Field(max_length=30, pattern=r"^[a-z]{2}(-[a-z]+)+-\d+$")]


class OUQuery(BaseModel):
    profile: str | None = PROFILE
    refresh: bool = False  # bypass the cache (the ↻ button)


class AccessCheckRequest(BaseModel):
    profile: str | None = PROFILE
    role_name: str | None = Field(None, max_length=64, pattern=r"^[\w+=,.@-]*$")


class ScanRequest(BaseModel):
    profile: str | None = PROFILE
    ou_id: str | None = Field(None, max_length=80)
    ou_ids: list[Annotated[str, Field(max_length=80)]] | None = Field(None, max_length=100)
    months: int = Field(12, ge=1, le=12)
    role_name: str | None = Field(None, max_length=64, pattern=r"^[\w+=,.@-]*$")
    inventory: bool = False
    dependencies: bool = False
    inventory_scope: str = Field("all", pattern="^(all|material)$")
    regions: list[REGION] | None = Field(None, max_length=40)
    region_scope: str = Field("all", pattern="^(all|spend)$")
    label: str = Field("", max_length=120)
    target: str = Field("azure", pattern=TARGET_PATTERN)
    # Set to run the AI review on the finished scan, with the report as the console will show it.
    ai_review: AIAfterScanRequest | None = None


class SSOSessionRequest(BaseModel):
    name: str = Field(..., max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
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


class AISettingsRequest(BaseModel):
    provider: str = Field("bedrock", pattern="^(bedrock|anthropic|together|openrouter|gateway)$")
    model: str = Field("", max_length=200)
    region: str = Field("us-east-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    profile: str = Field("", max_length=200)
    mask_names: bool = True
    api_key: str | None = Field(None, max_length=500)  # None keeps the saved key; "" removes it
    base_url: str | None = Field(None, max_length=300, pattern=r"^(https://\S+)?$")  # gateway; None keeps it
    key_header: str | None = Field(None, pattern="^(authorization|x-portkey-api-key|api-key|x-api-key)$")
    headers: str | None = Field(None, max_length=4000)  # gateway: "Name: value" lines; None keeps the saved ones


class AIKeyRequest(BaseModel):
    provider: str = Field(..., pattern="^(bedrock|anthropic|together|openrouter|gateway)$")


class AIRunRequest(ReportRequest):
    pass


class AIAfterScanRequest(BaseModel):
    filter: FilterModel = FilterModel()
    questionnaire: Questionnaire = Questionnaire()
    weighting: str = Field("spend", pattern=r"^(balanced|spend|equal)$")


ScanRequest.model_rebuild()


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


def create_app(allow_remote: bool = False, scheduler: bool = False) -> FastAPI:
    """`scheduler` runs the monthly scan while the console is up; the PDF export's private server does not."""
    configure_logging()

    @asynccontextmanager
    async def lifespan(_app):
        stop = threading.Event()
        if scheduler:
            schedule.start_runner(stop)
        yield
        stop.set()

    app = FastAPI(
        title="AWS Exit Risk Review", version=__version__, docs_url="/api/docs", redoc_url=None, lifespan=lifespan
    )

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

    @app.exception_handler(UpstreamError)
    async def upstream_error(_request: Request, exc: UpstreamError):
        return JSONResponse({"error": exc.msg, "code": exc.code, "hint": exc.hint}, status_code=502)

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "version": __version__,
            "catalog_version": load_catalog().version,
            "pid": os.getpid(),
            "scans_running": running_scans(),
            "reviews_running": ai_review.running_reviews(),
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
            err = UpstreamError(exc)
            log.warning("SSO call %s failed: %s %s", fn.__name__, err.code, err.msg, exc_info=not _aws_error(exc))
            raise err from exc

    @app.get("/api/sso/sessions")
    def sso_sessions():
        return {"sessions": sso_call(sso.list_sessions)}

    @app.post("/api/sso/sessions")
    def sso_add_session(req: SSOSessionRequest):
        return sso_call(sso.add_session, req.name, req.start_url, req.region or None)

    @app.post("/api/sso/login")
    def sso_login(req: SSOLoginRequest):
        return sso_call(sso.start_login, req.session).snapshot()

    @app.post("/api/sso/logout")
    def sso_logout(req: SSOLoginRequest):
        sso_call(sso._session_config, req.session)  # 400 for an unknown portal
        sso_call(sso.logout, req.session)
        return {"signed_out": req.session}

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
                            req.profile,
                            req.role_name or None,
                            on_check=lambda c: q.put({"check": c}),
                            on_progress=lambda pr: q.put({"progress": pr}),
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
                if "check" not in item and "progress" not in item:
                    return

        return StreamingResponse(lines(), media_type="application/x-ndjson")

    @app.post("/api/scans")
    def create_scan(req: ScanRequest):
        if req.ai_review is not None:
            # On billing alone the model sees spend, not resources or integrations: not worth a review.
            if not req.inventory:
                raise HTTPException(
                    400, "the Agentic Risk Review needs a deep scan: choose a dependency (or inventory) scan"
                )
            # Fail before the scan, not half an hour later, if the AI review is not set up.
            if not ai_providers.settings_saved():
                raise HTTPException(400, "the AI review is not set up yet: open Settings, AI configuration")
            try:
                ai_providers.Client(ai_providers.load_settings())
            except (ValueError, ai_providers.AIError) as exc:
                raise HTTPException(400, f"AI review: {exc}") from exc
        # An ended IAM Identity Center sign-in fails the scan at its first call: ask for a new one now.
        pair = sso.profile_permission_set(req.profile)
        if pair and not sso.load_token(pair[0]):
            raise HTTPException(401, f"Your AWS sign-in ({pair[0]}) has ended. Sign in again, then start the scan.")
        try:
            job = start_scan(ScanParams(**req.model_dump(exclude={"ai_review"})))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if req.ai_review is not None:
            ai_review.expect(job.id)
            threading.Thread(
                target=contextvars.copy_context().run,
                args=(_ai_after_scan, job.id, req.ai_review),
                daemon=True,
                name=f"ai-wait-{job.id}",
            ).start()
        return job.snapshot()

    def _ai_after_scan(scan_id: str, want: AIAfterScanRequest) -> None:
        """Wait for the scan, then start the AI review it was asked for with."""
        while (job := get_job(scan_id)) and job.status == "running":
            time.sleep(2)
        if not ai_review.waiting(scan_id):
            return  # stopped from the console while the scan ran
        if not job or job.status == "failed":
            ai_review.give_up(scan_id, "the scan failed, so there is no report to review")
            return
        try:
            _start_ai(scan_id, want)
        except HTTPException as exc:
            ai_review.give_up(scan_id, str(exc.detail))
        except Exception as exc:
            log.exception("AI review after scan %s could not start", scan_id)
            ai_review.give_up(scan_id, f"could not start: {exc}")
        else:
            ai_review.started(scan_id)

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
        job = get_job(scan_id)
        if job and job.status == "running":
            raise HTTPException(409, "the scan is still running; wait for it to finish, then delete it")
        try:
            store.delete_scan(scan_id)
        except store.ScanNotFound as exc:
            raise HTTPException(404, "scan not found") from exc
        return {"deleted": scan_id}

    @app.get("/api/schedule")
    def get_schedule():
        return schedule.status(schedule.load())

    @app.put("/api/schedule")
    def put_schedule(req: schedule.ScheduleRequest):
        try:
            scan = store.load_scan(req.from_scan)
        except store.ScanNotFound as exc:
            raise HTTPException(404, "scan not found") from exc
        try:
            schedule.create(req, scan)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return schedule.status(schedule.load())

    @app.delete("/api/schedule")
    def delete_schedule():
        schedule.clear()
        log.info("monthly scan turned off")
        return schedule.status(None)

    @app.post("/api/schedule/run")
    def run_schedule():
        if not schedule.load():
            raise HTTPException(404, "no monthly scan is set")
        scan_id = schedule.run_in_console(force=True)
        if not scan_id:
            raise HTTPException(409, "the monthly scan is already running")
        return {"scan_id": scan_id, **schedule.status(schedule.load())}

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

    # ------------------------------------------------------------------ AI review (optional)
    def _ai_settings(req: AISettingsRequest | None = None) -> ai_providers.AISettings:
        s = ai_providers.load_settings()
        if req is not None:
            s.provider, s.model, s.region, s.profile, s.mask_names = (
                req.provider,
                req.model.strip(),
                req.region,
                req.profile,
                req.mask_names,
            )
            if req.api_key is not None:
                if req.api_key.strip():
                    s.keys[req.provider] = req.api_key.strip()
                else:
                    s.keys.pop(req.provider, None)
            if req.provider == "gateway" and s.model:
                s.gateway_model = s.model
            if req.base_url is not None:
                s.base_url = req.base_url.strip()
            if req.key_header is not None:
                s.key_header = req.key_header
            if req.headers is not None:
                try:
                    s.headers = ai_providers.parse_headers(req.headers)
                except ai_providers.AIError as exc:
                    raise HTTPException(400, str(exc)) from exc
        return s

    @app.get("/api/ai/settings")
    def ai_settings():
        providers = [
            {
                "key": p.key,
                "label": p.label,
                "note": p.note,
                "key_url": p.key_url,
                "key_env": p.key_env,
                "third_party": p.third_party,
                "recommended": [{"id": m, "label": label} for m, label in p.recommended],
            }
            for p in ai_providers.PROVIDERS.values()
        ]
        return {
            "settings": ai_providers.load_settings().public(),
            "providers": providers,
            "configured": ai_providers.settings_saved(),
        }

    @app.put("/api/ai/settings")
    def ai_save(req: AISettingsRequest):
        s = _ai_settings(req)
        ai_providers.save_settings(s)
        return {"settings": s.public()}

    @app.post("/api/ai/models")
    def ai_models(req: AISettingsRequest):
        return {"models": ai_providers.list_models(_ai_settings(req))}

    @app.post("/api/ai/test")
    def ai_test(req: AISettingsRequest):
        try:
            return ai_providers.test_connection(_ai_settings(req))
        except ai_providers.AIError as exc:
            return {"ok": False, "error": str(exc)}

    @app.post("/api/ai/test-all")
    def ai_test_all():
        """Each provider with a key (Bedrock: the AWS profile), on its saved or recommended model."""
        saved = ai_providers.load_settings()

        def one(key: str) -> dict:
            s = ai_providers.AISettings(**{**saved.__dict__, "provider": key})
            if key != saved.provider:
                s.model = ""
            label = ai_providers.PROVIDERS[key].label
            if key == "gateway" and not s.base_url:
                return {"provider": key, "label": label, "ok": None, "error": "Not set up"}
            if key not in ("bedrock", "gateway") and not s.api_key():
                return {"provider": key, "label": label, "ok": None, "error": "No key saved"}
            try:
                return {**ai_providers.test_connection(s), "label": label}
            except ai_providers.AIError as exc:
                return {"provider": key, "label": label, "ok": False, "model": s.model_id(), "error": str(exc)}
            except Exception as exc:  # e.g. no AWS credentials for Bedrock
                return {"provider": key, "label": label, "ok": False, "model": s.model_id(), "error": str(exc)}

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=len(ai_providers.PROVIDERS)) as pool:
            return {"results": list(pool.map(one, ai_providers.PROVIDERS))}

    def _start_ai(scan_id: str, req: AIAfterScanRequest) -> dict:
        try:
            scan = store.load_scan(scan_id)
        except store.ScanNotFound as exc:
            raise HTTPException(404, "scan not found") from exc
        try:
            flt = AccountFilter(**req.filter.model_dump())
        except FilterError as exc:
            raise HTTPException(400, str(exc)) from exc
        rep = build_report(scan, flt, req.questionnaire, weighting=req.weighting)
        basis = {
            "filter": flt.to_dict()["description"],
            "accounts": rep["summary"]["accounts_in_scope"],
            "provisional": rep["estimate"].get("provisional"),
        }
        try:
            return ai_review.start(scan_id, rep, ai_providers.load_settings(), basis)
        except (ValueError, ai_providers.AIError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/ai/review")
    def ai_start(req: AIRunRequest):
        return _start_ai(req.scan_id, req)

    @app.post("/api/ai/key")
    def ai_key(req: AIKeyRequest):
        """The saved key for one provider, for the Show button. The console listens on this computer only
        and every POST needs the X-ExitRisk header, so another site cannot read it."""
        s = ai_providers.load_settings()
        return {"key": s.keys.get(req.provider) or os.environ.get(ai_providers.PROVIDERS[req.provider].key_env, "")}

    @app.get("/api/ai/review/{scan_id}")
    def ai_get(scan_id: str):
        try:
            result = ai_review.load_result(scan_id)
            if result and "cost_usd" not in result:  # reviews saved before the cost was recorded
                ai_review.save_result(ai_review.add_cost(result, ai_providers.load_settings()))
            return {"run": ai_review.status(scan_id), "result": result}
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.delete("/api/ai/review/{scan_id}")
    def ai_stop(scan_id: str, remove: bool = False):
        try:
            stopped = ai_review.cancel(scan_id)
            if remove:
                ai_review.delete_result(scan_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"stopped": stopped, "removed": remove}

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
