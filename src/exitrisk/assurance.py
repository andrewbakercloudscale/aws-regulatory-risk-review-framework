"""The Cloud Assurance Framework Report: every account scored against the selected rules.

The scan reads each account's controls (collectors/assurance.py) and the organisation's own
(collectors/assurance_org.py). This module applies the answers given in the report (which accounts
are production, internet edge or hold sensitive data, the allowed data locations, the ruleset) and
scores each account:

* each failing rule adds its severity's points (critical 40, high 15, medium 5, low 1) once,
  however many resources fail it; points combine with diminishing returns, so the score stays
  within 0 to 100: score = 100 x (1 - product of (1 - points / 100));
* a critical account (tagged, or named in the answers) counts its points 1.5 times;
* any failing critical rule sets the score to at least 80;
* a rule that could not be measured scores nothing but lowers the account's coverage, which is
  shown next to the score: a high coverage and a low score is assurance, a low coverage is not.

Nothing here calls AWS. Changing an answer or the ruleset needs no new scan.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from . import rulesets
from .collectors.assurance import catalog
from .filtering import AccountFilter
from .logging_config import get_logger
from .multiregion import load_region_data
from .resilience import _patterns, classify, owner_of

log = get_logger("assurance")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CRITICAL_FLOOR = 80
CRITICAL_ACCOUNT_WEIGHT = 1.5
RATINGS = ((80, "Critical"), (50, "High"), (20, "Medium"), (0, "Low"))
# Bucket classification tag values (lowercased) that mark sensitive data.
SENSITIVE_VALUES = ("confidential", "restricted", "sensitive", "secret", "pci", "pii", "highly", "internal-only")
# Account name parts that say non-production.
NON_PROD_MARKS = ("dev", "test", "uat", "sandbox", "sbx", "nonprod", "non-prod", "qa", "staging", "stg", "sit", "poc")
ENV_SUFFIX = re.compile(r"[-_ ]?(prd|prod|production|dev|develop|test|tst|uat|qa|sit|stg|staging|nonprod|np|sbx)$")
# Spend that means data is stored in a region.
DATA_SERVICES = (
    "Amazon Simple Storage Service", "Amazon Relational Database Service", "Amazon DynamoDB", "EC2 - Other",
    "Amazon Elastic File System", "Amazon FSx", "AWS Backup", "Amazon Redshift", "Amazon ElastiCache",
    "Amazon OpenSearch Service", "Amazon DocumentDB (with MongoDB compatibility)", "Amazon Neptune",
    "Amazon Kinesis", "Amazon Simple Queue Service", "Amazon S3 Glacier", "AWS Glue",
)  # fmt: skip
AI_MARKS = ("Bedrock", "SageMaker", "Comprehend", "Rekognition", "Textract", "Transcribe", "Polly", "Translate",
            "Lex", "Kendra", "Amazon Q", "Personalize", "Forecast", "Fraud Detector", "Lookout")  # fmt: skip
STATES = ("fail", "unknown", "pass", "na")


class AssuranceAnswers(BaseModel):
    """The questions answered in the report, all optional. Patterns are comma-separated, matched
    case-insensitively against the account name (and OU path for production)."""

    ruleset: str = Field("All rules", max_length=60)
    production_patterns: str = Field("prod,prd", max_length=200)
    edge_patterns: str = Field("edge,network,ingress,egress,dmz,perimeter", max_length=200)
    sensitive_patterns: str = Field("payment,card,pci,eft,pii,customer,statement", max_length=300)
    critical_patterns: str = Field("", max_length=200)
    admin_limit: int = Field(5, ge=1, le=500)
    # Countries or jurisdictions (ISO codes, EU, UK...) where data may sit; empty: the jurisdiction
    # of the busiest region.
    allowed_locations: str = Field("", max_length=200)
    required_tags: str = Field("", max_length=200)
    ai_approved: str = Field("", max_length=200)


def _rating(score: float) -> str:
    return next(label for floor, label in RATINGS if score >= floor)


def _matches(text: str, patterns: list[str]) -> bool:
    text = text.lower()
    return any(p in text for p in patterns)


def _tag_env(account: dict) -> str:
    tags = {re.sub(r"[^a-z]", "", k.lower()): str(v).strip().lower() for k, v in (account.get("tags") or {}).items()}
    return tags.get("environment") or tags.get("env") or tags.get("stage") or ""


def _sensitive_bucket(b: dict, patterns: list[str]) -> str:
    """Why the bucket counts as sensitive ("" if it does not)."""
    for k, v in (b.get("tags") or {}).items():
        if any(m in str(v).lower() for m in SENSITIVE_VALUES):
            return f"tag {k}={v}"
    if _matches(b.get("name", ""), patterns):
        return "name"
    return ""


def _covered(name: str, cover: dict | None) -> bool | None:
    if cover is None:
        return None
    if cover.get("all"):
        return True
    arn = f"arn:aws:s3:::{name}"
    return any(p.rstrip("/") == arn or p.startswith(arn + "/") for p in cover["prefixes"])


class _Account:
    """One account's rule results as the report applies them."""

    def __init__(self, raw: dict):
        self.checks: dict[str, dict] = {k: dict(v) for k, v in (raw.get("checks") or {}).items()}
        self.facts: dict = raw.get("facts") or {}

    def set(self, cid: str, status: str, items: list | None = None, note: str = "") -> None:
        out = {"status": status, "note": note}
        if status == "fail":
            items = list(items or [])
            out.update(n=len(items) or 1, ev=[str(i) for i in items[:25]])
        self.checks[cid] = out

    def fail_or_pass(self, cid: str, items: list, note: str = "") -> None:
        self.set(cid, "fail" if items else "pass", items, note)


def build_assurance(scan: dict, account_filter: AccountFilter | None = None, a: AssuranceAnswers | None = None) -> dict:
    started = time.perf_counter()
    account_filter = account_filter or AccountFilter()
    a = a or AssuranceAnswers()
    cat = catalog()
    rules = {c["id"]: c for c in cat["checks"]}
    points = cat["points"]
    ruleset = rulesets.get(a.ruleset)
    enabled = [r for r in ruleset["rules"] if r in rules]
    severity = {r: ruleset.get("severity", {}).get(r) or rules[r]["severity"] for r in enabled}
    data = scan.get("assurance") or {}
    checked = data.get("accounts") or {}
    org = data.get("org") or {}
    accounts = [x for x in scan.get("accounts", []) if account_filter.matches(x["name"])]
    base = {
        "scan_id": scan.get("id"),
        "label": scan.get("label", ""),
        "scan_at": scan.get("created_at"),
        "ou": scan.get("ou"),
        "answers": a.model_dump(),
        "ruleset": {k: ruleset[k] for k in ("name", "description", "builtin")} | {"rules": len(enabled)},
        "catalog_version": cat.get("version"),
        "scan_catalog_version": data.get("catalog_version"),
        "filter": account_filter.describe() if account_filter.active else "",
    }
    if not checked:
        return {**base, "available": False, "accounts": [], "reason": _why_empty(scan)}

    prod_p, edge_p = _patterns(a.production_patterns), _patterns(a.edge_patterns)
    sens_p, crit_p = _patterns(a.sensitive_patterns), _patterns(a.critical_patterns)
    spend = _monthly_spend(scan)
    allowed = _allowed_locations(scan, a)
    regions = load_region_data()["regions"]

    rows = []
    for acct in accounts:
        raw = checked.get(acct["id"])
        if raw is None:
            continue
        ax = _Account(raw)
        name, path = acct.get("name", ""), acct.get("ou_path", "")
        env = _tag_env(acct)
        production = env in ("prod", "production", "prd") or _matches(name, prod_p) or _matches(path, prod_p)
        if env and env not in ("prod", "production", "prd"):
            production = False
        edge = _matches(name, edge_p)
        critical = classify(acct, crit_p)[0]
        buckets = ax.facts.get("buckets") or []
        sensitive = [(b, why) for b in buckets if (why := _sensitive_bucket(b, sens_p))]
        _report_time(ax, acct, a, org, scan, sensitive, production, prod_p, allowed, regions)

        results = []
        for cid in enabled:
            rule = rules[cid]
            scope = rule.get("scope", "all")
            res = ax.checks.get(cid) or {"status": "unknown", "note": "not read by this scan"}
            if scope == "production" and not production:
                res = {"status": "na", "note": "not a production account"}
            elif scope == "non_edge" and edge:
                res = {"status": "na", "note": "internet edge account"}
            elif scope == "sensitive" and not sensitive:
                res = {"status": "na", "note": "no sensitive buckets"}
            results.append({"id": cid, **res})
        rows.append(_score(acct, results, severity, points, critical, production, edge, sensitive, spend))

    rows.sort(key=lambda r: (-r["score"], -r["monthly_spend"], r["name"].lower()))
    not_checked = [
        {"id": x["id"], "name": x["name"]}
        for x in accounts
        if x["id"] not in checked and x.get("status", "ACTIVE") in ("ACTIVE", "UNKNOWN")
    ]
    out = {
        **base,
        "available": True,
        "summary": _summary(rows, not_checked),
        "areas": _areas(rows, rules, cat["areas"], severity),
        "rules": _rules(rows, rules, severity),
        "accounts": rows,
        "not_checked": not_checked,
        "ownership": _ownership(accounts, checked, org),
        "organisation": _org_summary(org),
        "allowed_locations": sorted(allowed),
        "points": points,
        "build_ms": round((time.perf_counter() - started) * 1000),
    }
    return out


def _why_empty(scan: dict) -> str:
    if (scan.get("params") or {}).get("assurance"):
        return "The assurance checks ran but no account could be read: see the scan's issues."
    return "This scan did not run the Cloud Assurance Framework checks. Start a new scan with them turned on."


def _monthly_spend(scan: dict) -> dict[str, float]:
    months = len({r["month"] for r in scan.get("costs") or []}) or 1
    out: dict[str, float] = defaultdict(float)
    for r in scan.get("costs") or []:
        out[r["account_id"]] += float(r.get("amount") or 0) / months
    return out


def _allowed_locations(scan: dict, a: AssuranceAnswers) -> set[str]:
    given = {p.strip().upper() for p in a.allowed_locations.split(",") if p.strip()}
    if given:
        return given
    regions = load_region_data()["regions"]
    by: dict[str, float] = defaultdict(float)
    for r in scan.get("region_costs") or []:
        if r.get("region") in regions:
            by[r["region"]] += float(r.get("monthly") or 0)
    if not by:
        return set()
    top = max(by, key=by.get)
    return {regions[top].get("jurisdiction", ""), regions[top].get("country", "")} - {""}


def _report_time(ax: _Account, acct, a, org, scan, sensitive, production, prod_p, allowed, regions) -> None:
    """Rules judged from the answers and the organisation's facts, not read in the account itself."""
    aid, f = acct["id"], ax.facts
    unavailable = org.get("unavailable") or {}

    # Ownership.
    owner, _ = owner_of(acct)
    ax.fail_or_pass("owner_missing", [] if owner else ["no owner tag"])
    ic = org.get("identity_center")
    if not owner:
        ax.set("owner_not_found", "na", note="no owner tagged")
    elif "@" not in owner:
        ax.set("owner_not_found", "unknown", note="the owner tag is a name, not an email, so it cannot be looked up")
    elif not ic:
        ax.set("owner_not_found", "unknown", note=unavailable.get("identity_center", "Identity Center not read"))
    else:
        found = ic.get("owners", {}).get(owner.strip().lower())
        if found is None:
            ax.set("owner_not_found", "unknown", note="owner not looked up")
        else:
            ax.fail_or_pass("owner_not_found", [] if found else [owner])
    name = acct.get("name", "").lower()
    in_prod_ou = _matches(acct.get("ou_path", ""), prod_p)
    marks = [m for m in NON_PROD_MARKS if re.search(rf"(^|[-_ ]){re.escape(m)}($|[-_ \d])", name)]
    ax.fail_or_pass(
        "misplaced_account", [f"named {marks[0]} in {acct.get('ou_path', '')}"] if in_prod_ou and marks else []
    )
    required = _patterns(a.required_tags)
    if required:
        have = {re.sub(r"[^a-z0-9]", "", k.lower()) for k in (acct.get("tags") or {})}
        ax.fail_or_pass("account_tags_missing", [t for t in required if re.sub(r"[^a-z0-9]", "", t) not in have])
    else:
        ax.set("account_tags_missing", "na", note="no required tags set in the report")

    # Organisation controls.
    scps = org.get("scps")
    if scps is not None and aid in scps:
        ax.fail_or_pass("scp_guardrails", scps[aid]["missing"])
        ax.fail_or_pass("scp_region_deny", [] if scps[aid]["region_deny"] else ["no region restriction"])
    else:
        why = unavailable.get("scps", "not read (needs a scan from the management account)")
        for cid in ("scp_guardrails", "scp_region_deny"):
            ax.set(cid, "unknown", note=why)
    root = org.get("root")
    if root is None:
        ax.set("central_root_off", "unknown", note=unavailable.get("root", "not read"))
    else:
        ax.fail_or_pass("central_root_off", [] if root.get("credentials") else ["central root access off"])
        if root.get("credentials") and ax.checks.get("root_mfa", {}).get("status") == "fail":
            ax.set("root_mfa", "na", note="root credentials are managed centrally for the organisation")
    if ic and "admins" in ic:
        mine = ic["admins"].get(aid, {"people": [], "direct": [], "groups": []})
        people = sorted(set(mine["people"]) | {x for x in f.get("iam_admins") or [] if x.startswith("IAM user")})
        too_many = [f"{len(people)} people: {', '.join(people[:20])}"] if len(people) > a.admin_limit else []
        ax.fail_or_pass("admin_holders", too_many, note=f"{len(people)} with administrator access")
        ax.fail_or_pass("admin_direct_user", mine["direct"])
    else:
        why = unavailable.get("identity_center", "Identity Center not read")
        ax.set("admin_holders", "unknown", note=why)
        ax.set("admin_direct_user", "unknown", note=why)
    ta = org.get("trusted_advisor")
    if ta and aid in ta:
        ax.fail_or_pass("trusted_advisor_red", ta[aid]["red"], note="from the organisation view")
        ax.fail_or_pass("trusted_advisor_yellow", ta[aid]["yellow"], note="from the organisation view")
    trails = org.get("trails") or []
    marks_org = {m for t in trails for m in (t.get("alerts") or [])}
    if (
        ax.checks.get("security_alerts_none", {}).get("status") == "fail"
        and {"root"} <= marks_org
        and (marks_org & {"aws.iam", "iam.amazonaws.com", "putuserpolicy", "attachrolepolicy"})
    ):
        ax.set("security_alerts_none", "pass", note="alarms on the organisation trail")
    delegated = org.get("delegated") or []
    aa_admin = next((d for d in delegated if "access-analyzer.amazonaws.com" in d.get("services", [])), None)
    if aa_admin and ax.checks.get("access_analyzer_off", {}).get("status") == "fail":
        ax.set(
            "access_analyzer_off",
            "pass",
            note=f"organisation analyzer delegated to {aa_admin.get('name') or aa_admin['id']}",
        )

    # Regions and data location.
    rc = [r for r in scan.get("region_costs") or [] if r["account_id"] == aid and r.get("region") in regions]
    if not scan.get("region_costs"):
        ax.set("single_region", "unknown", note="no spend by region in the scan")
        ax.set("data_location", "unknown", note="no spend by region in the scan")
    else:
        by = defaultdict(float)
        for r in rc:
            by[r["region"]] += float(r.get("monthly") or 0)
        used = [k for k, v in by.items() if v >= 1]
        ax.fail_or_pass("single_region", [f"only {used[0]}"] if production and len(used) == 1 else [])
        if not allowed:
            ax.set("data_location", "unknown", note="no allowed locations")
        else:
            stored = defaultdict(float)
            for r in rc:
                if r["service"] in DATA_SERVICES:
                    stored[r["region"]] += float(r.get("monthly") or 0)
            outside = [
                f"{k} (US${v:,.0f}/month)"
                for k, v in sorted(stored.items(), key=lambda kv: -kv[1])
                if v >= 1 and not ({regions[k].get("country"), regions[k].get("jurisdiction")} & allowed)
            ]
            ax.fail_or_pass("data_location", outside)

    # AI use.
    billed = {
        r["service"] for r in scan.get("costs") or [] if r["account_id"] == aid and float(r.get("amount") or 0) > 0
    }
    ai = sorted(s for s in billed if any(m in s for m in AI_MARKS))
    if not ai:
        ax.set("ai_unapproved", "na", note="no AI services billed")
    else:
        ax.fail_or_pass("ai_unapproved", [] if _matches(acct.get("name", ""), _patterns(a.ai_approved)) else ai)

    # Sensitive data.
    _sensitive(ax, sensitive, trails)


def _sensitive(ax: _Account, sensitive: list[tuple[dict, str]], org_trails: list[dict]) -> None:
    f = ax.facts
    cids = ("sensitive_no_versioning", "sensitive_no_lock", "sensitive_no_replication", "sensitive_no_kms",
            "sensitive_no_data_events", "sensitive_human_write")  # fmt: skip
    if f.get("buckets") is None:
        for cid in cids:
            ax.set(cid, "unknown", note="buckets not read")
        return
    if not sensitive:
        for cid in cids:
            ax.set(cid, "na", note="no bucket tagged or named as sensitive")
        return

    def failing(key: str, bad) -> tuple[list[str], bool]:
        read = [(b, w) for b, w in sensitive if b.get(key) is not None]
        return [f"{b['name']} ({w})" for b, w in read if b[key] is bad], bool(read)

    controls = (("sensitive_no_versioning", "versioning"), ("sensitive_no_lock", "lock"),
                ("sensitive_no_replication", "replicated"), ("sensitive_no_kms", "kms"))  # fmt: skip
    for cid, key in controls:
        bad = False
        items, read = failing(key, bad)
        if read:
            ax.fail_or_pass(cid, items)
        else:
            ax.set(cid, "unknown", note=f"bucket {key} not readable")
    covers = [t.get("s3_writes") for t in (f.get("trails") or []) + org_trails]
    rules = f.get("s3_rules") or {}
    gd = f.get("guardduty_s3") or {}
    unlogged, unwatched = [], []
    for b, why in sensitive:
        cov = [_covered(b["name"], c) for c in covers]
        logged = any(cov)
        if not logged:
            unlogged.append(f"{b['name']} ({why})")
        region = b.get("region", "")
        alert = gd.get(region) or any(b["name"] in p or '"object created"' in p or "putobject" in p
                                      for p in rules.get(region, []))  # fmt: skip
        if b.get("writers") and not (logged and alert):
            unwatched.append(f"{b['name']}: {', '.join(b['writers'][:5])}")
    ax.fail_or_pass("sensitive_no_data_events", unlogged)
    if any(b.get("writers") is None for b, _ in sensitive):
        ax.set("sensitive_human_write", "unknown", note="IAM policies not readable")
    else:
        ax.fail_or_pass("sensitive_human_write", unwatched)


def _score(acct, results, severity, points, critical, production, edge, sensitive, spend) -> dict:
    weight = CRITICAL_ACCOUNT_WEIGHT if critical else 1.0
    keep = 1.0
    counts = Counter(r["status"] for r in results)
    by_sev = Counter()
    any_critical = False
    for r in results:
        if r["status"] != "fail":
            continue
        sev = severity[r["id"]]
        by_sev[sev] += 1
        any_critical |= sev == "critical"
        keep *= 1 - min(points[sev] * weight, 99) / 100
    score = 100 * (1 - keep)
    if any_critical:
        score = max(score, CRITICAL_FLOOR)
    applicable = counts["pass"] + counts["fail"] + counts["unknown"]
    owner, executive = owner_of(acct)
    findings = sorted(
        (r for r in results if r["status"] in ("fail", "unknown")),
        key=lambda r: (r["status"] != "fail", SEVERITY_ORDER[severity[r["id"]]], r["id"]),
    )
    return {
        "id": acct["id"],
        "name": acct["name"],
        "ou_path": acct.get("ou_path", ""),
        "owner": owner,
        "executive": executive,
        "monthly_spend": round(spend.get(acct["id"], 0.0), 2),
        "production": production,
        "edge": edge,
        "critical": critical,
        "sensitive_buckets": len(sensitive),
        "score": round(score, 1),
        "rating": _rating(score),
        "fails": {s: by_sev.get(s, 0) for s in SEVERITY_ORDER},
        "counts": {s: counts.get(s, 0) for s in STATES},
        "coverage": round(100 * (counts["pass"] + counts["fail"]) / applicable, 1) if applicable else 100.0,
        "findings": [{**r, "severity": severity[r["id"]]} for r in findings],
        "passed": [r["id"] for r in results if r["status"] == "pass"],
        "not_applicable": [{"id": r["id"], "note": r.get("note", "")} for r in results if r["status"] == "na"],
    }


def _summary(rows: list[dict], not_checked: list[dict]) -> dict:
    total_spend = sum(r["monthly_spend"] for r in rows)
    by_spend = sum(r["score"] * r["monthly_spend"] for r in rows) / total_spend if total_spend else None
    by_count = sum(r["score"] for r in rows) / len(rows) if rows else 0.0
    score = by_spend if by_spend is not None else by_count
    ratings = Counter(r["rating"] for r in rows)
    fails = Counter()
    for r in rows:
        fails.update(r["fails"])
    measured = sum(r["counts"]["pass"] + r["counts"]["fail"] for r in rows)
    applicable = measured + sum(r["counts"]["unknown"] for r in rows)
    return {
        "accounts": len(rows),
        "not_checked": len(not_checked),
        "score": round(score, 1),
        "score_by_count": round(by_count, 1),
        "rating": _rating(score),
        "ratings": {label: ratings.get(label, 0) for _, label in RATINGS},
        "fails": {s: fails.get(s, 0) for s in SEVERITY_ORDER},
        "accounts_with_critical": sum(1 for r in rows if r["fails"]["critical"]),
        "coverage": round(100 * measured / applicable, 1) if applicable else 100.0,
        "monthly_spend": round(total_spend, 2),
    }


def _areas(rows, rules, areas, severity) -> list[dict]:
    out = []
    for key, meta in areas.items():
        ids = [cid for cid in severity if rules[cid]["area"] == key]
        if not ids:
            continue
        fail = unknown = passed = 0
        failing_accounts = set()
        for r in rows:
            for fnd in r["findings"]:
                if fnd["id"] in ids:
                    if fnd["status"] == "fail":
                        fail += 1
                        failing_accounts.add(r["id"])
                    else:
                        unknown += 1
            passed += sum(1 for p in r["passed"] if p in ids)
        measured = fail + passed
        out.append({
            "id": key, "label": meta["label"], "concern": meta["concern"], "rules": len(ids), "fails": fail,
            "unknown": unknown, "passes": passed, "accounts_failing": len(failing_accounts),
            "pass_rate": round(100 * passed / measured, 1) if measured else None,
        })  # fmt: skip
    return sorted(out, key=lambda x: (x["pass_rate"] if x["pass_rate"] is not None else 101, x["label"]))


def _rules(rows, rules, severity) -> list[dict]:
    stats: dict[str, dict] = {cid: {"fail": 0, "unknown": 0, "pass": 0, "na": 0, "resources": 0, "accounts": []}
                              for cid in severity}  # fmt: skip
    for r in rows:
        for fnd in r["findings"]:
            s = stats[fnd["id"]]
            s[fnd["status"]] += 1
            if fnd["status"] == "fail":
                s["resources"] += fnd.get("n", 1)
                s["accounts"].append(
                    {"id": r["id"], "name": r["name"], "n": fnd.get("n", 1), "ev": fnd.get("ev", [])[:5]}
                )
        for p in r["passed"]:
            stats[p]["pass"] += 1
        for na in r["not_applicable"]:
            stats[na["id"]]["na"] += 1
    out = []
    for cid, s in stats.items():
        rule = rules[cid]
        s["accounts"].sort(key=lambda x: -x["n"])
        out.append({
            "id": cid, "title": rule["title"], "area": rule["area"], "severity": severity[cid],
            "catalog_severity": rule["severity"], "scope": rule.get("scope", "all"), "why": rule["why"],
            "fix": rule["fix"], "refs": rule.get("refs") or [], **s,
        })  # fmt: skip
    return sorted(out, key=lambda x: (x["fail"] == 0, SEVERITY_ORDER[x["severity"]], -x["fail"], x["id"]))


def _stem(name: str) -> str:
    n = name.lower().strip()
    for prefix in ("aws-", "acc-", "account-"):
        if n.startswith(prefix):
            n = n[len(prefix) :]
    for env in ("prd-", "prod-", "dev-", "tst-", "test-", "uat-", "qa-", "np-", "nonprod-", "sbx-"):
        if n.startswith(env):
            n = n[len(env) :]
    return ENV_SUFFIX.sub("", n)


def _ownership(accounts: list[dict], checked: dict, org: dict) -> dict:
    """Each account's owner, whether it checks out, and a proposed owner where it does not: the
    owner most of its sibling accounts (same name without the environment) have."""
    found = ((org.get("identity_center") or {}).get("owners")) or {}
    owners = {x["id"]: owner_of(x)[0] for x in accounts}

    def status(owner: str) -> str:
        if not owner:
            return "missing"
        if "@" in owner and owner.strip().lower() in found:
            return "verified" if found[owner.strip().lower()] else "not found"
        return "unverified"

    stems: dict[str, Counter] = defaultdict(Counter)
    ous: dict[str, Counter] = defaultdict(Counter)
    for x in accounts:
        o = owners[x["id"]]
        if status(o) in ("verified", "unverified"):
            stems[_stem(x["name"])][o] += 1
            ous[x.get("ou_path", "")][o] += 1
    rows = []
    for x in accounts:
        o = owners[x["id"]]
        st = status(o)
        proposal, basis = "", ""
        if st in ("missing", "not found"):
            cands = stems.get(_stem(x["name"]))
            in_ou = ous.get(x.get("ou_path", ""))
            if cands:
                proposal, n = cands.most_common(1)[0]
                basis = f"owner of {n} related account{'s' if n != 1 else ''} ({_stem(x['name'])})"
            elif in_ou:
                proposal, n = in_ou.most_common(1)[0]
                basis = f"owner of {n} of the accounts in {x.get('ou_path', '')}"
        rows.append({"id": x["id"], "name": x["name"], "owner": o, "status": st, "proposal": proposal,
                     "basis": basis, "checked": x["id"] in checked})  # fmt: skip
    counts = Counter(r["status"] for r in rows)
    return {
        "rows": sorted(rows, key=lambda r: (r["status"] in ("verified", "unverified"), r["name"].lower())),
        "counts": dict(counts),
        "directory": bool(found) or "identity_center" in org,
    }


def _org_summary(org: dict) -> dict:
    ic = org.get("identity_center") or {}
    return {
        "read": bool(org),
        "admin_permission_sets": ic.get("admin_sets", []),
        "delegated": org.get("delegated") or [],
        "root": org.get("root"),
        "trails": [{k: t.get(k) for k in ("name", "home", "logging")} for t in org.get("trails") or []],
        "trusted_advisor_org": "trusted_advisor" in org,
        "unavailable": org.get("unavailable") or {},
    }


# ---------------------------------------------------------------------------------- exports


OWNER_TAG = "Owner"


def ownership_export(report: dict, approved: dict[str, str], tag: str = OWNER_TAG) -> dict:
    """The approved owner changes as a CSV and as AWS CLI commands, for an administrator to apply.
    The console never writes to AWS: ``approved`` is {account id: new owner}."""
    names = {r["id"]: r for r in report.get("ownership", {}).get("rows", [])}
    rows = [(aid, names[aid]["name"], names[aid]["owner"], new.strip()) for aid, new in approved.items()
            if aid in names and new.strip()]  # fmt: skip
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["account_id", "account_name", "current_owner", "new_owner"])
    w.writerows(rows)
    safe_tag = re.sub(r"[^\w.:/=+@-]", "", tag) or OWNER_TAG
    lines = [
        "# Apply in the management account with a role allowed organizations:TagResource.",
        "# Review every line first: this changes the account's owner tag.",
    ]
    for aid, name, _old, new in rows:
        value = new.replace("'", "")
        lines.append(
            f"aws organizations tag-resource --resource-id {aid} --tags 'Key={safe_tag},Value={value}'  # {name}"
        )
    return {"csv": buf.getvalue(), "commands": "\n".join(lines) + "\n", "count": len(rows)}


def evidence(report: dict) -> dict:
    """The report as an evidence record, with a SHA-256 of its canonical JSON to show it is unchanged."""
    body = {k: v for k, v in report.items() if k != "build_ms"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "algorithm": "SHA-256 of the report JSON with sorted keys and no spaces",
        "report": body,
    }
