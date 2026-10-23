"""The optional AI review: a model reads the whole report and gives its own view of the exit.

The deterministic report stays the source of record. The AI review is a second opinion, in three passes
so that no single answer goes unchecked:

1. **Account analysis** - the material accounts in batches: how entrenched each is, the model's own
   effort range against ours, the risks, and how to tackle it in the project.
2. **Estate synthesis** - one pass over every account analysis and the estate facts: an overall view
   of cost, effort and duration, the areas of focus, programme risks and sequencing.
3. **Review** - the synthesis goes back to the model with the facts, the account analyses and the
   findings of automated checks (unknown accounts, ranges that contradict each other, figures far from
   the model's). It corrects what is inconsistent and lists what it changed. The checks run again on
   the result, and anything still open is shown with the review.

Only a summary of the report is sent: per account its name, spend, services, effort, data size and
counts of integrations; never resource names, ARNs or configuration. With ``mask_names`` the account
names, ids and owners are replaced by codes before sending and restored in the answer.
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from ..catalog import Catalog, load_catalog
from ..config import settings
from ..logging_config import get_logger
from ..scoring import SERVICES_USED_MAX
from .providers import PROVIDERS, AIError, AISettings, Client, cost, price

log = get_logger("ai")

BATCH_ACCOUNTS = 12  # small enough that the first answers, and the progress, come back quickly
MAX_ACCOUNTS = 400
WORKERS = 8  # batches in flight at once; providers answer 429 when busy and the call waits and retries
MAX_OUTPUT_TOKENS = 64000  # a reply cut off at max_tokens is asked again with double, up to this
PASSES = {"Analysing accounts": 1, "Estate view": 2, "Reviewing for consistency": 3}
PHASES = ("Before mobilisation", "Mobilise", "Wave 1", "Wave 2", "Wave 3", "Cutover")
LEVELS = ("Low", "Moderate", "High", "Very high")
# The automated check flags an AI estimate this far from the deterministic one, either way.
FAR_FACTOR = 2.5

SYSTEM = """You are a principal cloud migration architect and a regulatory risk adviser to a bank's \
executive committee. You are assessing how hard, how costly and how long it would be to exit AWS, as a \
regulator expects in an exit plan.

Rules:
- Use only the data provided. Figures in FACTS are measured or computed by a deterministic model and \
are authoritative; your estimates are your own professional view and may differ from the model's, but \
say why in plain words.
- Where evidence is missing (no deep scan, no dependency scan, untagged owners), say so; never fill \
gaps with invented detail. Never invent accounts, services or numbers.
- Refer to accounts only by the id given.
- Write for executives: short, specific, plain English. No em dashes or en dashes.
- Reply with one JSON object only, exactly in the requested shape, with no text before or after it."""


# ---------------------------------------------------------------------------- masking
class Masker:
    """Swap account ids, names and owners for codes, and back again in the answer."""

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.fwd: dict[str, str] = {}

    def code(self, value: str, prefix: str) -> str:
        if not self.enabled or not value:
            return value
        if value not in self.fwd:
            n = sum(1 for v in self.fwd.values() if v.startswith(prefix)) + 1
            self.fwd[value] = f"{prefix}{n:03d}"
        return self.fwd[value]

    def register(self, accounts: list[dict]) -> None:
        """Give every account, name and owner a code up front, so free text can be scrubbed too."""
        for a in accounts:
            self.code(a["id"], "A")
            self.code(a["name"], "acct-")
            for who in (a.get("owner"), a.get("executive")):
                if who:
                    self.code(who, "owner-")

    def mask(self, obj):
        """Replace every registered value inside any string (sentences in the facts name accounts too)."""
        return self._swap(obj, self.fwd)

    def unmask(self, obj):
        return self._swap(obj, {v: k for k, v in self.fwd.items()})

    def _swap(self, obj, table: dict):
        if not self.enabled or not table:
            return obj
        alt = "|".join(re.escape(k) for k in sorted(table, key=len, reverse=True))
        pat = re.compile(r"(?<![\w-])(" + alt + r")(?![\w-])")

        def walk(o):
            if isinstance(o, str):
                return pat.sub(lambda m: table[m.group(1)], o)
            if isinstance(o, list):
                return [walk(x) for x in o]
            if isinstance(o, dict):
                return {k: walk(v) for k, v in o.items()}
            return o

        return walk(obj)


# ---------------------------------------------------------------------------- context
def _r(x, nd=0):
    return round(x, nd) if isinstance(x, (int, float)) else x


def build_context(report: dict, mask: Masker, catalog: Catalog | None = None) -> tuple[dict, list[dict]]:
    """FACTS for the estate, and one compact row per account to analyse (largest effort first)."""
    catalog = catalog or load_catalog()
    mask.register(report["accounts"])
    s, e, res, t = report["summary"], report["estimate"], report["resilience"], report["timing"]
    accounts = [a for a in report["accounts"] if a["monthly_spend"] > 0]
    accounts.sort(key=lambda a: -(a.get("effort_weeks") or 0) - a["monthly_spend"] / 1e6)
    rows = []
    for a in accounts[:MAX_ACCOUNTS]:
        rows.append(
            {
                "id": mask.code(a["id"], "A"),
                "name": mask.code(a["name"], "acct-"),
                "ou": a.get("ou_path", ""),
                "monthly_spend": _r(a["monthly_spend"]),
                "risk_score": _r(a.get("score"), 1),
                "risk_rating": a.get("rating"),
                "aws_only_spend_pct": _r(a.get("high_risk_pct"), 1),
                "model_effort_weeks": _r(a.get("effort_weeks"), 1),
                "effort_by_tier": {k: _r(v, 1) for k, v in (a.get("effort_by_tier") or {}).items() if v},
                "effort_basis": a.get("effort_basis"),
                "portability": _r(a.get("portability"), 1),
                "deep_scanned": a.get("deep_scanned", False),
                "dependency_scanned": a.get("dependency_scanned", False),
                "integrations": a.get("integrations", 0),
                "integrations_aws_only": a.get("integrations_hard", 0),
                "data_tb": _r(a.get("data_tb") or 0, 1),
                "critical": bool(a.get("critical")),
                "owner": mask.code(a.get("owner") or a.get("executive") or "", "owner-") or None,
                # Every service in use, with the model's effort for it: nothing is left out of the evidence.
                "services": [
                    {
                        "service": x["service"],
                        "tier": x["tier"],
                        "monthly": _r(x["monthly_spend"]),
                        "model_effort_weeks": x.get("effort_weeks", 0),
                    }
                    for x in (a.get("services_used") or a.get("top_services") or [])
                ],
                **(
                    {"services_note": f"the {SERVICES_USED_MAX} services with the most effort or spend are listed"}
                    if len(a.get("services_used") or []) >= SERVICES_USED_MAX
                    else {}
                ),
                "aws_only_services": [x["service"] for x in (a.get("top_lockin") or [])],
            }
        )
    rest = accounts[MAX_ACCOUNTS:]
    services = []
    for x in report["services"][:40]:
        info = catalog.lookup(x["service"])
        services.append(
            {
                "service": x["display"],
                "tier": x["tier"],
                "tier_label": x["tier_label"],
                "monthly": _r(x["monthly_spend"]),
                "accounts": x["accounts"],
                "model_effort_weeks": _r(x.get("effort_weeks"), 1),
                "growth_pct": x.get("change_pct"),
                **(
                    {"why_hard": info.why, "migration_path": info.migration, "typical_duration": info.duration}
                    if x["tier"] >= 3 and info.classified
                    else {}
                ),
            }
        )
    d = res.get("data") or {}
    c = (t or {}).get("commitments") or {}
    focus = report.get("focus") or {}
    facts = {
        "scope": {
            "ou": (report["meta"].get("ou") or {}).get("path"),
            "accounts_in_scope": s.get("accounts_in_scope"),
            "accounts_analysed": len(rows),
            "accounts_not_analysed": len(rest),
            "monthly_spend_not_analysed": _r(sum(a["monthly_spend"] for a in rest)),
            "months_of_billing": len(report["meta"].get("months_in_data") or []),
            "scan_depth": s.get("scan_depth_label") or s.get("scan_depth"),
            "deep_scan_pct_of_spend": s.get("deep_scan_pct"),
            "target": report["meta"].get("target_label"),
        },
        "spend": {
            "monthly": _r(s.get("total_monthly")),
            "annual": _r(s.get("annual_run_rate") or (s.get("total_monthly") or 0) * 12),
            "currency": (e.get("cost") or {}).get("currency", "USD"),
            "by_tier": [
                {"tier": x["tier"], "label": x["label"], "monthly": _r(x["monthly_spend"]), "pct": x["pct"]}
                for x in report["tiers"]
            ],
        },
        "risk_score": {
            "by_spend": s.get("score_by_spend"),
            "rating": s.get("rating_by_spend"),
            "by_accounts": s.get("score_by_accounts"),
        },
        "measures": s.get("measures"),
        "dimensions": [
            {k: x.get(k) for k in ("label", "value", "detail", "measured")} for x in s.get("dimensions") or []
        ],
        "integrations": {k: v for k, v in (s.get("integrations") or {}).items() if k != "top"},
        "critical_readiness": s.get("critical_readiness"),
        "model_estimate": {
            "answers": e.get("inputs"),
            "provisional": e.get("provisional"),
            "factors": e.get("factors"),
            "effort_weeks": e.get("effort"),
            "team": e.get("team"),
            "duration": e.get("duration"),
            "cost": e.get("cost"),
            "ranges": e.get("ranges"),
            "waves": e.get("waves"),
            "assumptions": e.get("assumptions"),
        },
        "data": {
            k: d.get(k)
            for k in ("total_tb", "live_tb", "archive_tb", "copy_tb", "move_tb", "critical_tb", "dynamodb_tb")
            if d.get(k) is not None
        }
        | (
            {
                "copy_options": [
                    {k: o[k] for k in ("label", "links", "gbps", "days")} for o in d["migration_links"]["options"]
                ]
            }
            if (d.get("migration_links") or {}).get("options")
            else {}
        ),
        "concentration": {k: (res.get("concentration") or {}).get(k) for k in ("level", "region_name", "pct")},
        "stressed_exit": [
            {"bucket": b["label"], "pct": b["pct"]} for b in (res.get("stressed_exit") or {}).get("buckets", [])
        ],
        "ownership": {
            k: (res.get("owners") or {}).get(k) for k in ("tagged_accounts", "accounts_with_spend", "untagged_monthly")
        },
        "commitments": {
            k: c.get(k) for k in ("remaining", "stranded_range", "last_end", "pct_runs_off_before_exit") if c.get(k)
        },
        "exit_window": {"ends": t.get("exit_end"), "deadline": t.get("deadline")},
        "top_services": services,
        "rule_based_areas_of_focus": {
            "themes": [{"title": x["title"], "detail": x["detail"]} for x in focus.get("themes", [])],
            "accounts": [
                {"id": mask.code(a["id"], "A"), "concerns": [c["title"] for c in a["concerns"]]}
                for a in focus.get("accounts", [])
            ],
        },
        "coverage_gaps": s.get("coverage"),
    }
    # Sentences in the facts (dimension details, readiness) name accounts: scrub them as well.
    return mask.mask(facts), rows


# ---------------------------------------------------------------------------- prompts
ACCOUNT_SHAPE = """{"accounts": [{
  "id": "<account id as given>",
  "entrenchment": "Low | Moderate | High | Very high",
  "effort_engineer_weeks": [<low>, <high>],
  "vs_model": "lower | agree | higher",
  "why": "<one or two sentences: what makes this account easy or hard to move>",
  "key_risks": ["<specific risk>", "..."],
  "approach": "<how to tackle it in the project: target pattern, order, what to do first>",
  "phase": "Before mobilisation | Mobilise | Wave 1 | Wave 2 | Wave 3 | Cutover",
  "confidence": "low | medium | high",
  "evidence_gaps": ["<what we would need to know to be sure>"]
}]}"""

ESTATE_SHAPE = """{
  "headline": "<two sentences for the executive committee: how entrenched we are and what decides the exit>",
  "key_points": ["<the 5 to 8 most important points of the whole report for the executive committee, most important \
first, each one sentence carrying its number: risk score, spend on AWS-only services, cost and time, critical \
accounts, data to move, commitments and the deadline, and how far the evidence can be trusted>"],
  "entrenchment": {"level": "Low | Moderate | High | Very high", "summary": "<why, in three or four sentences>"},
  "estimate": {
    "effort_engineer_days": [<low>, <high>],
    "duration_months": [<low>, <high>],
    "cost": [<low>, <high>],
    "confidence": "low | medium | high",
    "compared_with_model": "<how and why your view differs from the model's estimate, or why it agrees>",
    "drivers": ["<what drives the cost and time most>"],
    "adjustments": [{"item": "<what>", "direction": "up | down", "reason": "<why>"}],
    "not_included": ["<costs outside this estimate>"]
  },
  "areas_of_focus": [{
    "title": "<short>",
    "accounts": ["<account ids>"],
    "concern": "<what the complexity or risk is>",
    "how_to_tackle": "<concrete guidance for the project>",
    "phase": "Before mobilisation | Mobilise | Wave 1 | Wave 2 | Wave 3 | Cutover",
    "priority": "high | medium"
  }],
  "programme_risks": [{"risk": "<risk>", "impact": "<impact>", "mitigation": "<mitigation>"}],
  "sequencing": [{"phase": "<phase>", "what": "<what happens and why in this order>"}],
  "quick_wins": ["<low-cost actions that reduce lock-in or risk now>"],
  "questions_to_validate": ["<questions for account owners or architects that would change the estimate>"],
  "evidence_to_collect": ["<scans, data or documents that would make the estimate firmer>"]
}"""


def _account_prompt(facts: dict, batch: list[dict]) -> str:
    brief = {k: facts[k] for k in ("scope", "spend", "measures", "model_estimate")}
    brief["model_estimate"] = {k: brief["model_estimate"][k] for k in ("answers", "factors", "assumptions")}
    services = {x["service"]: x for x in facts["top_services"] if "why_hard" in x}
    used = {s for a in batch for s in a["aws_only_services"] + [x["service"] for x in a["services"]]}
    notes = [v for k, v in services.items() if k in used]
    return (
        "Assess each account below for an exit from AWS.\n"
        "model_effort_weeks is the deterministic model's engineer-weeks for the account's services before "
        "delivery-maturity factors, programme management and contingency; give your own range on the same basis, "
        "using the services, their tiers, the integrations, the data size and whether a deep scan ran.\n\n"
        f"ESTATE BRIEF:\n{json.dumps(brief, separators=(',', ':'))}\n\n"
        f"SERVICE NOTES (hard services in these accounts):\n{json.dumps(notes, separators=(',', ':'))}\n\n"
        f"ACCOUNTS:\n{json.dumps(batch, separators=(',', ':'))}\n\n"
        f"Reply with JSON in exactly this shape, one entry per account:\n{ACCOUNT_SHAPE}"
    )


def _estate_prompt(facts: dict, analyses: list[dict]) -> str:
    return (
        "Using the FACTS and the ACCOUNT ANALYSES (one per account, from an earlier pass), give the estate view.\n"
        "The estimate covers the whole exit programme on the model's basis (all accounts, landing zone, "
        "programme management, contingency, parallel run) in the currency of FACTS.spend.currency. Areas of focus "
        "should be the 6 to 12 things that will decide whether the exit succeeds, each naming the accounts "
        "concerned; the rule-based list in FACTS is a starting point, not a limit.\n\n"
        f"FACTS:\n{json.dumps(facts, separators=(',', ':'))}\n\n"
        f"ACCOUNT ANALYSES:\n{json.dumps(analyses, separators=(',', ':'))}\n\n"
        f"Reply with JSON in exactly this shape:\n{ESTATE_SHAPE}"
    )


def _review_prompt(facts: dict, analyses: list[dict], draft: dict, checks: list[str]) -> str:
    found = "\n".join(f"- {c}" for c in checks) or "- none"
    return (
        "You are now the independent reviewer of the DRAFT estate view below, written from the FACTS and "
        "ACCOUNT ANALYSES. Check it line by line:\n"
        "1. Every number agrees with FACTS, or the difference from the model is explained.\n"
        "2. The estimate is internally consistent: effort, duration and cost fit together and with the team "
        "size and day rate in FACTS; the sum of account effort supports the estate effort.\n"
        "3. Every account named exists and the concern matches its analysis; nothing material is missing "
        "(critical accounts, the largest effort, AWS-only blockers, large data).\n"
        "4. Phases are in a sensible order and the guidance is specific and actionable.\n"
        "5. Nothing is claimed that the data does not support.\n"
        f"Automated checks found:\n{found}\n\n"
        f"FACTS:\n{json.dumps(facts, separators=(',', ':'))}\n\n"
        f"ACCOUNT ANALYSES:\n{json.dumps(analyses, separators=(',', ':'))}\n\n"
        f"DRAFT:\n{json.dumps(draft, separators=(',', ':'))}\n\n"
        'Reply with JSON: {"changes": [{"issue": "<what was wrong>", "fix": "<what you changed>"}], '
        f'"final": <the corrected estate view, in exactly the DRAFT shape>}}\nDRAFT shape:\n{ESTATE_SHAPE}'
    )


# ---------------------------------------------------------------------------- parsing and checks
def parse_json(text: str) -> dict:
    """The JSON object in a reply, tolerating a code fence or a sentence around it."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in the reply")
    return json.loads(text[start : end + 1])


def _pair(x) -> tuple[float, float] | None:
    if isinstance(x, (list, tuple)) and len(x) == 2 and all(isinstance(v, (int, float)) for v in x):
        return float(x[0]), float(x[1])
    return None


def check_estate(view: dict, facts: dict, ids: set[str]) -> list[str]:
    """Automated consistency checks on an estate view. Each finding is a sentence for the reviewer."""
    out = []
    est = view.get("estimate") or {}
    model = facts["model_estimate"]
    explained = len(str(est.get("compared_with_model") or "")) >= 40  # a far estimate needs a reason
    m_days = (model.get("effort_weeks") or {}).get("total_weeks", 0) * 5
    m_months = (model.get("duration") or {}).get("calendar_months", 0)
    m_cost = (model.get("cost") or {}).get("total", 0)
    for key, label, ref in (
        ("effort_engineer_days", "effort", m_days),
        ("duration_months", "duration", m_months),
        ("cost", "cost", m_cost),
    ):
        p = _pair(est.get(key))
        if not p:
            out.append(f"estimate.{key} is missing or not a [low, high] pair of numbers.")
            continue
        lo, hi = p
        if lo <= 0 or hi < lo:
            out.append(f"estimate.{key} [{lo:,.0f}, {hi:,.0f}] is not a valid range (low must be > 0 and <= high).")
        elif ref and (hi < ref / FAR_FACTOR or lo > ref * FAR_FACTOR) and not explained:
            out.append(
                f"estimate.{key} [{lo:,.0f}, {hi:,.0f}] is more than {FAR_FACTOR}x away from the model's {label} "
                f"({ref:,.0f}) and compared_with_model does not explain why."
            )
    team = (model.get("team") or {}).get("capacity_fte") or 0
    eff, dur = _pair(est.get("effort_engineer_days")), _pair(est.get("duration_months"))
    if team and eff and dur and dur[1] > 0:
        # Engineer-days over the duration, at about 21 working days a month, implies an average team size.
        implied = eff[0] / (dur[1] * 21)
        if implied > team * 4:
            out.append(
                f"The estimate implies an average team of about {implied:,.0f} people, over four times the "
                f"{team:,.0f} full-time people the answers provide; reconcile effort, duration and team."
            )
    for i, a in enumerate(view.get("areas_of_focus") or []):
        unknown = [x for x in a.get("accounts") or [] if x not in ids]
        if unknown:
            out.append(f"areas_of_focus[{i}] ({a.get('title')}) names unknown accounts: {', '.join(unknown[:5])}.")
        if a.get("phase") not in PHASES:
            out.append(f"areas_of_focus[{i}] ({a.get('title')}) has phase {a.get('phase')!r}, not one of {PHASES}.")
    if not view.get("areas_of_focus"):
        out.append("areas_of_focus is empty.")
    if not view.get("key_points"):
        out.append("key_points is empty: give the most important points of the whole report.")
    if (view.get("entrenchment") or {}).get("level") not in LEVELS:
        out.append(f"entrenchment.level must be one of {LEVELS}.")
    return out


# ---------------------------------------------------------------------------- the run
class Cancelled(Exception):
    pass


class Run:
    """One AI review of one report, in a background thread, with progress the console polls."""

    def __init__(self, scan_id: str, report: dict, s: AISettings, basis: dict):
        self.scan_id, self.report, self.s, self.basis = scan_id, report, s, basis
        self.cancel = threading.Event()
        self.state = {
            "scan_id": scan_id,
            "status": "running",
            "stage": "Preparing",
            "done": 0,
            "total": 0,
            "message": "",
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "provider": s.provider,
            "model": s.model_id(),
        }
        self.usage = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "retries": 0}
        self.notes: list[str] = []  # anything that went less than perfectly, shown with the result
        self._lock = threading.Lock()

    def _note(self, text: str) -> None:
        log.warning("AI review of %s: %s", self.scan_id, text)
        with self._lock:
            self.notes.append(text)

    def _step(self, stage: str, done: int, total: int, message: str = "") -> None:
        with self._lock:
            self.state.update(stage=stage, done=done, total=total, message=message, **{"pass": PASSES.get(stage)})

    def _ask(self, client: Client, prompt: str, max_tokens: int, what: str) -> dict:
        """One call, parsed. A reply cut off at max_tokens is asked again with more room, and a reply that
        is not valid JSON once more; a reply that is still cut off or unreadable fails the run loudly,
        so a truncated answer is never used as if it were whole."""
        last = ""
        extra = ""
        for attempt in range(3):
            if self.cancel.is_set():
                raise Cancelled()
            reply = client.complete(SYSTEM, prompt + extra, max_tokens=max_tokens)
            with self._lock:
                self.usage["calls"] += 1
                self.usage["input_tokens"] += reply.input_tokens
                self.usage["output_tokens"] += reply.output_tokens
                self.usage["retries"] += 1 if attempt else 0
            log.info(
                "AI %s: %d tokens in, %d out, stop %r (%d characters of prompt)",
                what,
                reply.input_tokens,
                reply.output_tokens,
                reply.stop,
                len(prompt),
            )
            if reply.truncated:
                last = f"the answer was cut off at {max_tokens:,} output tokens"
                if max_tokens >= MAX_OUTPUT_TOKENS:
                    break
                self._note(f"{what}: {last}; asked again with {min(max_tokens * 2, MAX_OUTPUT_TOKENS):,}.")
                max_tokens = min(max_tokens * 2, MAX_OUTPUT_TOKENS)
                continue
            try:
                return parse_json(reply.text)
            except ValueError as exc:
                last = f"the reply was not valid JSON ({exc})"
                self._note(f"{what}: {last}; asked again.")
                extra = "\n\nYour previous reply was not one valid JSON object. Reply with JSON only."
        raise AIError(f"{what}: {last}. Nothing was saved; try again, or a model with a longer output limit.")

    def run(self) -> dict:
        started = time.perf_counter()
        mask = Masker(self.s.mask_names)
        facts, rows = build_context(self.report, mask)
        ids = {r["id"] for r in rows}
        client = Client(self.s)
        asked_reasoning = client.reasoning
        batches = [rows[i : i + BATCH_ACCOUNTS] for i in range(0, len(rows), BATCH_ACCOUNTS)]
        total = len(batches) + 2
        analyses: list[dict] = []
        done = 0
        at_once = f"{min(WORKERS, len(batches))} batches of up to {BATCH_ACCOUNTS} at a time"
        self._step("Analysing accounts", 0, total, f"0 of {len(rows)} accounts read · {at_once}")

        def one(batch: list[dict]) -> list[dict]:
            want = {a["id"] for a in batch}
            what = f"accounts {batch[0]['name']} to {batch[-1]['name']}"
            got = [
                a
                for a in self._ask(client, _account_prompt(facts, batch), 16000, what).get("accounts", [])
                if a.get("id") in want
            ]
            missing = [a for a in batch if a["id"] not in {g["id"] for g in got}]
            if missing:  # ask once more for any account the model skipped
                self._note(f"{what}: the model skipped {len(missing)} account(s); asked again for them.")
                got += [
                    a
                    for a in self._ask(client, _account_prompt(facts, missing), 16000, what).get("accounts", [])
                    if a.get("id") in want
                ]
            return got

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for fut in as_completed([pool.submit(one, b) for b in batches]):
                got = fut.result()
                analyses.extend(got)
                done += 1
                self._step(
                    "Analysing accounts", done, total, f"{len(analyses)} of {len(rows)} accounts read · {at_once}"
                )
        by_id = {a["id"]: a for a in analyses}
        analyses = [by_id[r["id"]] for r in rows if r["id"] in by_id]
        skipped = [r["name"] for r in rows if r["id"] not in by_id]
        if skipped:
            self._note(
                f"{len(skipped)} account(s) still have no analysis after asking twice: {', '.join(skipped[:10])}"
                + (" and more" if len(skipped) > 10 else "")
            )
        if facts["scope"]["accounts_not_analysed"]:
            self._note(
                f"Only the {MAX_ACCOUNTS} accounts with the most effort were analysed one by one; "
                f"{facts['scope']['accounts_not_analysed']} smaller ones are in the estate totals only."
            )

        self._step("Estate view", done, total, "Weighing the whole estate")
        draft = self._ask(client, _estate_prompt(facts, analyses), 32000, "estate view")
        done += 1
        checks = check_estate(draft, facts, ids)
        self._step("Reviewing for consistency", done, total, f"{len(checks)} automated finding(s) to resolve")
        reviewed = self._ask(client, _review_prompt(facts, analyses, draft, checks), 32000, "review")
        if isinstance(reviewed.get("final"), dict):
            final = reviewed["final"]
        else:
            final = draft
            self._note("The review pass returned no corrected view, so the estate view is shown unreviewed.")
        open_checks = check_estate(final, facts, ids)
        done += 1

        if client.reasoning != asked_reasoning:
            self._note(
                f"{client.model} refused the {asked_reasoning} reasoning setting, so it ran with "
                f"{client.reasoning or 'no extended reasoning'}."
            )
        result = {
            "scan_id": self.scan_id,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "provider": self.s.provider,
            "provider_label": PROVIDERS[self.s.provider].label,
            "model": client.model,
            "masked": self.s.mask_names,
            "basis": self.basis,
            "accounts_analysed": len(analyses),
            "accounts_sent": len(rows),
            "final": mask.unmask(final),
            "draft": mask.unmask(draft),
            "changes": mask.unmask(reviewed.get("changes") or []),
            "checks_before_review": mask.unmask(checks),
            "open_checks": mask.unmask(open_checks),
            "accounts": mask.unmask(analyses),
            "model_reference": {
                "effort_engineer_days": round(facts["model_estimate"]["effort_weeks"]["total_weeks"] * 5),
                "duration_months": facts["model_estimate"]["duration"]["calendar_months"],
                "cost": facts["model_estimate"]["cost"]["total"],
                "currency": facts["spend"]["currency"],
            },
            "usage": dict(self.usage),
            "notes": mask.unmask(self.notes),
            "reasoning": client.reasoning,
            "seconds": round(time.perf_counter() - started),
        }
        # The model names accounts by id; readers know them by name. Lists of ids stay ids.
        names = {a["id"]: a["name"] for a in self.report["accounts"]}
        for key in ("final", "draft", "changes", "accounts"):
            result[key] = _ids_to_names(result[key], names)
        result["account_names"] = {a["id"]: names.get(a["id"], a["id"]) for a in result["accounts"]}
        for a in result["final"].get("areas_of_focus") or []:
            a["account_names"] = [names.get(x, x) for x in a.get("accounts") or []]
        add_cost(result, self.s)
        save_result(result)
        self._step("Done", total, total, "")
        return result


def add_cost(result: dict, s: AISettings) -> dict:
    """The approximate dollar cost of a review, from its token counts and the model's list price."""
    p = price(AISettings(**{**s.__dict__, "provider": result["provider"], "model": result["model"]}))
    result["price"] = p
    result["cost_usd"] = cost(result.get("usage") or {}, p)
    return result


def _ids_to_names(obj, names: dict, key: str = ""):
    """Account ids inside sentences become names; the "id" and "accounts" fields keep the ids."""
    if key in ("id", "accounts"):
        return obj
    if isinstance(obj, str):
        return re.sub(r"\b\d{12}\b", lambda m: names.get(m.group(0), m.group(0)), obj)
    if isinstance(obj, list):
        return [_ids_to_names(x, names) for x in obj]
    if isinstance(obj, dict):
        return {k: _ids_to_names(v, names, k) for k, v in obj.items()}
    return obj


# ---------------------------------------------------------------------------- storage and jobs
def _path(scan_id: str):
    if not re.fullmatch(r"[\w-]{1,80}", scan_id):
        raise ValueError("bad scan id")
    return settings.data_dir / "ai" / f"{scan_id}.json"


def save_result(result: dict) -> None:
    path = _path(result["scan_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(result, indent=1))
    tmp.replace(path)


def load_result(scan_id: str) -> dict | None:
    try:
        return json.loads(_path(scan_id).read_text())
    except FileNotFoundError:
        return None


def delete_result(scan_id: str) -> None:
    _path(scan_id).unlink(missing_ok=True)


_RUNS: dict[str, Run] = {}
_RUNS_LOCK = threading.Lock()
# Reviews asked for with a new scan, shown as running until the scan finishes and the review starts.
_PENDING: dict[str, dict] = {}


def expect(scan_id: str) -> None:
    """Show a review as on its way while the scan it was asked for with is still running."""
    with _RUNS_LOCK:
        _PENDING[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "stage": "Waiting for the scan",
            "done": 0,
            "total": 0,
            "message": "The review starts when the scan finishes",
            "pass": None,
            "usage": {"calls": 0},
        }


def waiting(scan_id: str) -> bool:
    """True while a review asked for with this scan is still wanted (not stopped)."""
    with _RUNS_LOCK:
        return (_PENDING.get(scan_id) or {}).get("status") == "running"


def give_up(scan_id: str, message: str) -> None:
    """The review asked for with a scan could not start: say why where the console looks."""
    log.warning("AI review of %s not started: %s", scan_id, message)
    with _RUNS_LOCK:
        if scan_id in _PENDING:
            _PENDING[scan_id].update(status="failed", stage="Not started", message=message)


def started(scan_id: str) -> None:
    with _RUNS_LOCK:
        _PENDING.pop(scan_id, None)


def start(scan_id: str, report: dict, s: AISettings, basis: dict) -> dict:
    with _RUNS_LOCK:
        cur = _RUNS.get(scan_id)
        if cur and cur.state["status"] == "running":
            raise ValueError("an AI review of this scan is already running")
        Client(s)  # fail now on a missing key, not in the background
        run = Run(scan_id, report, s, basis)
        _RUNS[scan_id] = run

    def work():
        try:
            run.run()
            run.state["status"] = "complete"
        except Cancelled:
            run.state.update(status="cancelled", message="Stopped")
            log.info("AI review of %s cancelled", scan_id)
        except AIError as exc:
            run.state.update(status="failed", message=str(exc))
            log.warning("AI review of %s failed: %s", scan_id, exc)
        except Exception as exc:
            run.state.update(status="failed", message=f"Unexpected error: {exc}. See the log.")
            log.exception("AI review of %s failed", scan_id)
        run.state["usage"] = dict(run.usage)

    log.info("AI review of %s started with %s %s", scan_id, s.provider, s.model_id())
    threading.Thread(target=work, daemon=True, name=f"ai-{scan_id}").start()
    return dict(run.state)


def status(scan_id: str) -> dict | None:
    run = _RUNS.get(scan_id)
    if not run:
        with _RUNS_LOCK:
            pending = _PENDING.get(scan_id)
            return dict(pending) if pending else None
    return {**run.state, "usage": dict(run.usage)}


def cancel(scan_id: str) -> bool:
    run = _RUNS.get(scan_id)
    if run and run.state["status"] == "running":
        run.cancel.set()
        return True
    with _RUNS_LOCK:
        pending = _PENDING.get(scan_id)
        if pending and pending["status"] == "running":
            pending.update(status="cancelled", stage="Stopped", message="Stopped")
            return True
    return False
