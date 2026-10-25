"""AI insights for the Multi-Region Report and the Cloud Assurance Report.

Each report has its own audience, so each gets its own short AI read: a model is given a compact summary
of that report (never resource names, ARNs or configuration) and writes a headline, key points, risks,
actions and the questions management should ask. The deterministic report stays the source of record.
One call, asked again once if the reply is cut off or is not JSON; account ids the model invents are
dropped. With ``mask_names`` account names, ids and owners are swapped for codes before sending.

The exit risk report has its own, deeper three-pass review in ``review.py``.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from ..config import settings
from ..logging_config import get_logger
from .providers import PROVIDERS, AIError, AISettings, Client
from .review import Masker, _ids_to_names, add_cost, parse_json

log = get_logger("ai")

KINDS = ("multiregion", "assurance")
LABELS = {"multiregion": "Multi-Region Report", "assurance": "Cloud Assurance Report"}
MAX_ACCOUNTS = 40  # the accounts that matter most; the rest are in the totals
MAX_TOKENS = 12000

AUDIENCE = {
    "multiregion": """You are a principal AWS resilience architect advising a bank's CIO, chief risk officer and \
head of infrastructure. They are deciding which accounts need a second AWS region: what it costs to run, what \
it does to each team's headcount, how long each service would take to recover, which region to use, and what \
the regulator will ask. This is about surviving the loss of one AWS region while staying on AWS, not about \
leaving AWS.""",
    "assurance": """You are a cloud security and governance adviser to a bank's CISO, chief risk officer, internal \
audit and the team that answers the regulator. They want to know how well AWS accounts are controlled: \
internet exposure, access, audit trail, threat detection, data protection, change management, resilience and \
ownership, which accounts carry the most risk, and what to fix first.""",
}

RULES = """Rules:
- Use only the data provided. Figures in FACTS are measured or computed by a deterministic model and are \
authoritative; do not recompute them, but you may judge them and say where they look optimistic or thin.
- Where evidence is missing, say so; never invent accounts, services or numbers.
- Refer to accounts only by the id given.
- Write for executives: short, specific, plain English. No em dashes or en dashes.
- Reply with one JSON object only, exactly in the requested shape, with no text before or after it."""

SHAPE = """{
  "headline": "one sentence: the single most important thing",
  "key_points": ["3 to 6 short points a reader must take away"],
  "risks": [{"title": "short", "why": "one or two sentences", "accounts": ["account ids, if any"]}],
  "actions": [{"title": "short", "detail": "what to do and how", "owner": "which team",
               "when": "first 30 days | this quarter | this year"}],
  "questions": ["3 to 5 questions management should ask the team"],
  "confidence": {"level": "Low | Medium | High", "why": "what the view rests on and what is missing"}
}"""


def _r(x, nd=0):
    return round(x, nd) if isinstance(x, (int, float)) else x


def _multiregion_facts(rep: dict) -> tuple[dict, list[dict]]:
    s = rep["summary"]
    rec = s.get("recovery") or {}
    chosen = [a for a in rep["accounts"] if a["selected"]]
    chosen.sort(key=lambda a: -a["monthly_spend"])
    accounts = [
        {
            "id": a["id"],
            "name": a["name"],
            "ou": a["ou_path"],
            "monthly_spend": _r(a["monthly_spend"]),
            "readiness": a["readiness"],
            "risks": [
                {"service": r["service"], "severity": r["severity"], "failover": r["failover"]} for r in a["risks"][:5]
            ],
        }
        for a in chosen[:MAX_ACCOUNTS]
    ]
    facts = {
        "answers": {k: rep["answers"][k] for k in ("recovery", "residency", "support_plan", "regulated")},
        "recovery_target": rep["labels"]["recovery"][rep["answers"]["recovery"]],
        "primary_region": s["primary_name"],
        "second_region": s["secondary_name"],
        "recommended_region": s["recommended_name"],
        "accounts_chosen": s["accounts_selected"],
        "accounts_in_scope": s["accounts_in_scope"],
        "accounts_not_listed": max(len(chosen) - MAX_ACCOUNTS, 0),
        "monthly_spend_chosen": _r(s["monthly_spend_selected"]),
        "ranges": s["ranges"],
        "teams": [{k: t[k] for k in ("team", "today", "extra", "after", "pct")} for t in s["staff"]["teams"]],
        "recovery": {
            "strategy": rec.get("strategy_label"),
            "target": rec.get("target"),
            "services_missing_target": rec.get("missing_target"),
            "worst": [
                {k: r[k] for k in ("service", "failover", "monthly_spend", "needs")}
                | {"rto": r["strategies"][rec["strategy"]]["rto"], "rpo": r["strategies"][rec["strategy"]]["rpo"]}
                for r in (rec.get("services") or [])[:15]
            ],
        },
        "build": {"parts": s["build"]["parts"], "constrained_by": s["build"]["constrained_by"]},
        "failover_risks": s["severity_counts"],
        "accounts_with_failover_risk": s["accounts_blocked"],
        "regulation": [r["name"] for r in s.get("regulation") or []],
        "no_second_region_in_country": s.get("no_second_region_in_country"),
        "candidates": [
            {
                "region": c["name"],
                "latency_ms": c["latency_ms"],
                "parity_pct": c["parity_pct"],
                "missing": [x["display"] for x in c["missing"]],
                "price_index": c["price_index"],
            }
            for c in rep["candidates"]
            if c["residency_ok"]
        ][:5],
        "report_findings": s["executive"]["findings"],
        "provisional": rep.get("provisional"),
    }
    return facts, accounts


def _assurance_facts(rep: dict) -> tuple[dict, list[dict]]:
    titles = {r["id"]: r["title"] for r in rep["rules"]}
    ranked = sorted(rep["accounts"], key=lambda a: (-a["score"], -a["monthly_spend"]))
    accounts = [
        {
            "id": a["id"],
            "name": a["name"],
            "ou": a["ou_path"],
            "owner": a.get("owner") or "",
            "rating": a["rating"],
            "score": a["score"],
            "production": a["production"],
            "critical": a["critical"],
            "monthly_spend": _r(a["monthly_spend"]),
            "fails": a["fails"],
            "top_findings": [
                f"{f['severity']}: {titles.get(f['id'], f['id'])}" for f in a["findings"] if f["status"] == "fail"
            ][:6],
        }
        for a in ranked[:MAX_ACCOUNTS]
    ]
    failing = sorted(
        (r for r in rep["rules"] if r["fail"]),
        key=lambda r: (-{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(r["severity"], 0), -r["fail"]),
    )
    org = rep.get("organisation") or {}
    facts = {
        "ruleset": (rep.get("ruleset") or {}).get("name")
        if isinstance(rep.get("ruleset"), dict)
        else rep.get("ruleset"),
        "summary": rep["summary"],
        "areas": [
            {k: a[k] for k in ("label", "fails", "unknown", "accounts_failing", "pass_rate")} for a in rep["areas"]
        ],
        "failing_rules": [
            {k: r[k] for k in ("title", "area", "severity", "fail", "unknown")} | {"refs": r.get("refs", [])[:3]}
            for r in failing[:25]
        ],
        "accounts_not_listed": max(len(ranked) - MAX_ACCOUNTS, 0),
        "accounts_not_checked": len(rep.get("not_checked") or []),
        "ownership": {
            s: sum(1 for x in (rep.get("ownership") or {}).get("rows", []) if x["status"] == s)
            for s in ("missing", "proposed", "ok")
        },
        "organisation": {
            "read": org.get("read"),
            "admin_permission_sets": len(org.get("admin_permission_sets") or []),
            "delegated_admins": [d["services"] for d in org.get("delegated") or []],
            "org_trails": [t.get("logging") for t in org.get("trails") or []],
            "trusted_advisor_org_view": org.get("trusted_advisor_org"),
        },
    }
    return facts, accounts


FACTS = {"multiregion": _multiregion_facts, "assurance": _assurance_facts}


def _prompt(kind: str, facts: dict, accounts: list[dict]) -> str:
    return (
        f"Give your view of this {LABELS[kind]}.\n\nFACTS:\n{json.dumps(facts, separators=(',', ':'))}\n\n"
        f"ACCOUNTS (the ones that matter most):\n{json.dumps(accounts, separators=(',', ':'))}\n\n"
        f"Reply in this shape:\n{SHAPE}"
    )


def _clean(view: dict, ids: set[str]) -> dict:
    """Keep the requested shape; drop account ids the model made up."""
    out = {
        "headline": str(view.get("headline") or ""),
        "key_points": [str(x) for x in view.get("key_points") or [] if x][:8],
        "risks": [],
        "actions": [],
        "questions": [str(x) for x in view.get("questions") or [] if x][:6],
        "confidence": view.get("confidence") if isinstance(view.get("confidence"), dict) else {},
    }
    for r in view.get("risks") or []:
        if isinstance(r, dict) and r.get("title"):
            out["risks"].append(
                {
                    "title": str(r["title"]),
                    "why": str(r.get("why") or ""),
                    "accounts": [a for a in r.get("accounts") or [] if a in ids],
                }
            )
    for a in view.get("actions") or []:
        if isinstance(a, dict) and a.get("title"):
            out["actions"].append({k: str(a.get(k) or "") for k in ("title", "detail", "owner", "when")})
    return out


class Run:
    """One AI read of one report, in a background thread."""

    def __init__(self, scan_id: str, kind: str, report: dict, s: AISettings, basis: dict):
        self.scan_id, self.kind, self.report, self.s, self.basis = scan_id, kind, report, s, basis
        self.cancel = threading.Event()
        self.state = {
            "scan_id": scan_id,
            "kind": kind,
            "status": "running",
            "stage": "Asking the model",
            "message": "",
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "provider": s.provider,
            "model": s.model_id(),
        }
        self.usage = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "retries": 0}
        self._lock = threading.Lock()

    def snapshot(self) -> dict:
        with self._lock:
            return {**self.state, "usage": dict(self.usage)}

    def running(self) -> bool:
        with self._lock:
            return self.state["status"] == "running"

    def finish(self, **fields) -> None:
        with self._lock:
            self.state.update(fields, usage=dict(self.usage))

    def run(self) -> dict:
        started = time.perf_counter()
        mask = Masker(self.s.mask_names)
        mask.register(self.report["accounts"])
        facts, accounts = FACTS[self.kind](self.report)
        ids = {mask.code(a["id"], "A") for a in accounts}
        prompt = mask.mask(_prompt(self.kind, facts, accounts))
        client = Client(self.s)
        system = f"{AUDIENCE[self.kind]}\n\n{RULES}"
        notes: list[str] = []
        view, last, extra, max_tokens = None, "", "", MAX_TOKENS
        for attempt in range(3):
            if self.cancel.is_set():
                raise Cancelled()
            reply = client.complete(system, prompt + extra, max_tokens=max_tokens)
            with self._lock:
                self.usage["calls"] += 1
                self.usage["input_tokens"] += reply.input_tokens
                self.usage["output_tokens"] += reply.output_tokens
                self.usage["retries"] += 1 if attempt else 0
            if reply.truncated:
                last = f"the answer was cut off at {max_tokens:,} output tokens"
                notes.append(f"{last}; asked again with more room.")
                max_tokens *= 2
                continue
            try:
                view = parse_json(reply.text)
                break
            except ValueError as exc:
                last = f"the reply was not valid JSON ({exc})"
                notes.append(f"{last}; asked again.")
                extra = "\n\nYour previous reply was not one valid JSON object. Reply with JSON only."
        if view is None:
            raise AIError(f"{LABELS[self.kind]} insights: {last}. Nothing was saved; try again.")
        if self.cancel.is_set():
            raise Cancelled()
        names = {a["id"]: a["name"] for a in self.report["accounts"]}
        final = _ids_to_names(mask.unmask(_clean(view, ids)), names)
        for r in final["risks"]:
            r["account_names"] = [names.get(x, x) for x in r["accounts"]]
        result = {
            "scan_id": self.scan_id,
            "kind": self.kind,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "provider": self.s.provider,
            "provider_label": PROVIDERS[self.s.provider].label,
            "model": client.model,
            "masked": self.s.mask_names,
            "basis": self.basis,
            "accounts_sent": len(accounts),
            "final": final,
            "usage": dict(self.usage),
            "notes": notes,
            "seconds": round(time.perf_counter() - started),
        }
        add_cost(result, self.s)
        save_result(result)
        return result


class Cancelled(Exception):
    pass


# ---------------------------------------------------------------------------- storage and jobs
def _key(scan_id: str, kind: str) -> str:
    if not re.fullmatch(r"[\w-]{1,80}", scan_id) or kind not in KINDS:
        raise ValueError("bad scan id or report")
    return f"{scan_id}.{kind}"


def _path(scan_id: str, kind: str) -> Path:
    return settings.data_dir / "ai" / f"{_key(scan_id, kind)}.json"


def save_result(result: dict) -> None:
    path = _path(result["scan_id"], result["kind"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(result, fh, indent=1)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_result(scan_id: str, kind: str) -> dict | None:
    try:
        return json.loads(_path(scan_id, kind).read_text())
    except FileNotFoundError:
        return None


def delete_result(scan_id: str, kind: str) -> None:
    _path(scan_id, kind).unlink(missing_ok=True)


_RUNS: dict[str, Run] = {}
_PENDING: dict[str, dict] = {}  # asked for with a scan that is still running
_LOCK = threading.Lock()


def expect(scan_id: str, kind: str) -> None:
    with _LOCK:
        _PENDING[_key(scan_id, kind)] = {
            "scan_id": scan_id,
            "kind": kind,
            "status": "running",
            "stage": "Waiting for the scan",
            "message": "The AI insights start when the scan finishes",
            "usage": {"calls": 0},
        }


def waiting(scan_id: str, kind: str) -> bool:
    with _LOCK:
        return (_PENDING.get(_key(scan_id, kind)) or {}).get("status") == "running"


def give_up(scan_id: str, kind: str, message: str) -> None:
    log.warning("AI insights (%s) of %s not started: %s", kind, scan_id, message)
    with _LOCK:
        p = _PENDING.get(_key(scan_id, kind))
        if p:
            p.update(status="failed", stage="Not started", message=message)


def start(scan_id: str, kind: str, report: dict, s: AISettings, basis: dict) -> dict:
    key = _key(scan_id, kind)
    with _LOCK:
        cur = _RUNS.get(key)
        if cur and cur.running():
            raise ValueError(f"AI insights for the {LABELS[kind]} of this scan are already running")
        Client(s)  # fail now on a missing key, not in the background
        run = Run(scan_id, kind, report, s, basis)
        _RUNS[key] = run
        _PENDING.pop(key, None)

    def work():
        try:
            run.run()
            run.finish(status="complete", stage="Done")
        except Cancelled:
            run.finish(status="cancelled", stage="Stopped", message="Stopped")
        except AIError as exc:
            run.finish(status="failed", message=str(exc))
            log.warning("AI insights (%s) of %s failed: %s", kind, scan_id, exc)
        except Exception as exc:
            run.finish(status="failed", message=f"Unexpected error: {exc}. See the log.")
            log.exception("AI insights (%s) of %s failed", kind, scan_id)

    log.info("AI insights (%s) of %s started with %s %s", kind, scan_id, s.provider, s.model_id())
    threading.Thread(target=work, daemon=True, name=f"ai-{key}").start()
    return run.snapshot()


def running() -> list[str]:
    """'scan.kind' keys whose insights run, or wait for their scan, in this process."""
    with _LOCK:
        return sorted(
            {
                *(k for k, v in _PENDING.items() if v["status"] == "running"),
                *(k for k, r in _RUNS.items() if r.running()),
            }
        )


def status(scan_id: str, kind: str) -> dict | None:
    key = _key(scan_id, kind)
    run = _RUNS.get(key)
    if run:
        return run.snapshot()
    with _LOCK:
        p = _PENDING.get(key)
        return dict(p) if p else None


def cancel(scan_id: str, kind: str) -> bool:
    key = _key(scan_id, kind)
    run = _RUNS.get(key)
    if run and run.running():
        run.cancel.set()
        return True
    with _LOCK:
        p = _PENDING.get(key)
        if p and p["status"] == "running":
            p.update(status="cancelled", stage="Stopped", message="Stopped")
            return True
    return False
