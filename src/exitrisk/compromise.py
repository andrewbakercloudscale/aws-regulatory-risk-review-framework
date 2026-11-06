"""The Developer Compromise Report: from the chosen accounts' reads (collectors/compromise.py) to findings.

Every finding stands on evidence: a simulated path names the principal, the call and the policy that allows
it; a detection gap names the trail settings; a change made by hand names who, with which tool, how often.
Severity starts from the rule (data/compromise.yaml) and is lowered for what would notice.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from functools import lru_cache
from importlib import resources

import yaml

from . import zscaler
from .collectors.compromise import ACTIONS, KEY_DAYS, MANAGED_RULE, _data_selector_covers, _management

SEV = ("critical", "high", "medium", "low")
LONG_SESSION_HOURS = 4
PEOPLE = ("person", "user", "role")  # a role counts as a person when a person can switch into it
WRITE = {
    "s3_write",
    "s3_erase",
    "ddb_write",
    "fn_code",
    "fn_config",
    "ecs_deploy",
    "ecr_push",
    "fn_invoke",
    "api_invoke",
}
DB = {"db_secret", "db_reset", "db_iam", "db_data_api"}
RTYPE = {"bucket": "AWS::S3::Object", "table": "AWS::DynamoDB::Table", "function": "AWS::Lambda::Function"}


@lru_cache(maxsize=1)
def catalog() -> dict:
    return yaml.safe_load(resources.files("exitrisk").joinpath("data/compromise.yaml").read_text(encoding="utf-8"))


def _lower(sev: str, steps: int) -> str:
    return SEV[min(SEV.index(sev) + max(steps, 0), len(SEV) - 1)]


def _alert_rules(raw: dict) -> list[dict]:
    """The account's alert rules, without those an AWS service made for its own use (Inspector's and Auto
    Scaling's managed rules match API calls too, but alert nobody)."""
    return [r for r in (raw.get("detect") or {}).get("rules") or [] if not MANAGED_RULE.search(r.get("name", ""))]


def _detection(raw: dict, asset: dict, action: str) -> tuple[str, str]:
    """("alert" | "logged" | "not logged" | "unknown", what says so) for one action on one asset."""
    trails = (raw.get("detect") or {}).get("trails") or []
    live = [t for t in trails if t.get("logging")]
    unread = [t for t in trails if not t.get("read")]
    kind = ACTIONS[action][2]
    calls = ACTIONS[action][1]
    if kind == "none":
        return "not logged", "not in CloudTrail: only the database's own logs or activity stream record it"
    if action == "api_invoke":
        return "not logged", "API calls are not in CloudTrail; only the API's access logs record them"
    if kind == "data":
        rtype = RTYPE.get(asset["kind"])
        arn = asset["arn"] + ("/x" if asset["kind"] == "bucket" else "")
        logged = bool(rtype) and any(_data_selector_covers(t, rtype, arn) for t in live)
    else:
        need = "read" if kind == "read" else "write"
        logged = any(_management(t)[need] for t in live)
    if not logged and unread:
        return "unknown", f"the organisation trail {unread[0].get('name')} cannot be read from this account"
    if not logged:
        what = {"data": "data events are off for it", "read": "no trail keeps read events"}.get(kind, "no trail")
        return "not logged", f"CloudTrail does not record it: {what}"
    names = {c.split(":")[1] for c in calls}
    service = calls[0].split(":")[0]
    for r in _alert_rules(raw):
        sources = {s.replace("aws.", "") for s in r["sources"]}
        if asset["kind"] == "bucket" and kind == "data" and "s3" in sources and asset["facts"].get("eventbridge"):
            if not r["types"] or any(t.startswith("Object ") for t in r["types"]):
                return "alert", f"alert rule {r['name']}"
        if "AWS API Call via CloudTrail" in r["types"] or r["people"]:
            if (not sources or service in sources or service.replace("-", "") in sources) and (
                not r["events"] or names & set(r["events"])
            ):
                return "alert", f"alert rule {r['name']}"
    return "logged", "recorded by CloudTrail; no alert rule on it in this account"


def _finding(rule: str, account: dict, sev: str | None = None, **kw) -> dict:
    r = next(x for x in catalog()["rules"] if x["id"] == rule)
    return {
        "rule": rule,
        "area": r["area"],
        "title": r["title"],
        "why": r["why"],
        "fix": r["fix"],
        "severity": sev or r["severity"],
        "account": account["name"],
        "account_id": account["id"],
        **kw,
    }


def db_sources(a: dict, known: dict) -> list[dict]:
    """Each source that can reach a database's port, judged: "proxy" (the database proxy), "known" (a workload
    of this account, the database's own group, or a source the analyst listed as known) or "unknown" (an
    address range, a prefix list, or a group with nothing known behind it). Unknown is treated as a laptop:
    it must go through the proxy."""
    out = []
    found = proxy_groups(a)
    for src in a["facts"].get("ingress") or []:
        label = src.get("cidr") or src.get("pl") or src.get("sg")
        name = src.get("name") or ""
        if src.get("sg"):
            same = not src.get("account") or src["account"] == a.get("account_id", src["account"])
            if src["sg"] in found and same and src["sg"] not in known["ids"]:
                verdict, why = "proxy", found[src["sg"]]
            elif src["sg"] in known["ids"] or any(p and p.lower() in name.lower() for p in known["proxy_names"]):
                verdict, why = (
                    (
                        "proxy"
                        if src["sg"] in known["proxy"]
                        or any(p and p.lower() in name.lower() for p in known["proxy_names"])
                        else "known"
                    ),
                    "listed as known",
                )
            elif src.get("self"):
                verdict, why = "known", "the database's own group"
            elif src.get("account") and src["account"] != a.get("account_id", src["account"]):
                verdict, why = "unknown", f"a group in account {src['account']}"
            elif src.get("attached"):
                kinds = ", ".join(f"{n} {k}" for k, n in sorted(src["attached"].items()))
                verdict, why = "known", f"used by {kinds}"
            else:
                verdict, why = "unknown", "a group nothing in this account uses"
            label = f"{src['sg']} ({name})" if name else src["sg"]
        else:
            cidrs = [src["cidr"]] if src.get("cidr") else src.get("cidrs") or []
            if label in known["ids"] or (cidrs and all(zscaler.overlaps(c, known["nets"]) for c in cidrs)):
                verdict, why = "known", "listed as known"
            else:
                laptop = [c for c in cidrs if zscaler.overlaps(c, known["laptop"])]
                verdict = "unknown"
                why = "a laptop range (Zscaler or VPN)" if laptop else "an address range: anything in it can connect"
        out.append(
            {"source": label, "verdict": verdict, "why": why, "note": src.get("note", ""), "via": src.get("via")}
        )
    return out


def proxy_groups(a: dict) -> dict[str, str]:
    """The security groups of the database proxies found in the database's account and region, each with what
    the proxy is: an RDS Proxy, or a self run proxy such as pg-proxy found by its load balancer, ECS service or
    group name. Nothing has to be set: the proxy is always in the same account."""
    out: dict[str, str] = {}
    for px in a["facts"].get("proxies") or []:
        for g in px.get("groups") or []:
            out.setdefault(g, f"{px['kind']} {px['name']}")
    return out


def _proxy_note(a: dict) -> str:
    seen = sorted({f"{px['kind']} {px['name']}" for px in a["facts"].get("proxies") or []})
    if a["facts"].get("rds_proxy"):
        return f"an RDS Proxy already fronts it ({', '.join(a['facts']['rds_proxy'])}): route access through it"
    if seen:
        return f"a proxy runs in this account ({', '.join(seen[:3])}): route access through it"
    if "proxies" in a["facts"]:
        return "no database proxy found in this account"
    return ""


def _known(answers: dict | None) -> dict:
    a = answers or {}
    items = [x.strip() for x in a.get("known") or [] if x and x.strip()]
    proxy = [x.strip() for x in a.get("proxy") or [] if x and x.strip()]
    ids = {x for x in items + proxy if x.startswith(("sg-", "pl-"))}
    laptop = zscaler.networks(list(a.get("laptop") or []) + (zscaler.ranges() if a.get("zscaler", True) else []))
    return {
        "ids": ids,
        "proxy": {x for x in proxy if x.startswith("sg-")},
        "proxy_names": [x for x in proxy if not x.startswith("sg-")],
        "nets": zscaler.networks([x for x in items if "/" in x]),
        "laptop": laptop,
    }


def _account_findings(account: dict, raw: dict, known: dict | None = None) -> tuple[list[dict], dict]:
    known = known or _known(None)
    out: list[dict] = []
    assets = {a["id"]: a for a in raw.get("assets") or []}
    principals = {p["label"]: p for p in raw.get("principals") or []}
    paths = raw.get("paths") or []
    # The roles a person can switch into act as that person.
    persons = {
        label
        for label, p in principals.items()
        if p["kind"] in ("person", "user", "cross") or (p.get("reached_by") and p["kind"] != "outside")
    }
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for x in paths:
        if x["decision"] == "blocked":
            continue
        grouped[(x["asset"], x["action"])].append(x)
    stats = Counter()
    for (asset_id, action), found in grouped.items():
        a = assets.get(asset_id)
        if not a:
            continue
        people = [x for x in found if x["principal"] in persons]
        pipes = [x for x in found if x["principal"] not in persons]
        stats["paths"] += len(found)
        if action == "fn_invoke" and not a["payment"]:
            continue
        if not found:
            continue
        if action.startswith("blind"):
            rule = "person_blind"
        elif action == "api_invoke":
            rule = "api_callable"
        elif action == "key_sign":
            rule = "person_sign"
        elif action in DB:
            rule = "person_db" if a["payment"] else "person_write"
        elif action == "secret_read":
            rule = "person_secret"
        else:
            rule = "person_payment_write" if a["payment"] else "person_write"
        base = next(x for x in catalog()["rules"] if x["id"] == rule)["severity"]
        if rule == "person_secret" and not a["payment"]:
            base = "medium"
        level, said = _detection(raw, a, action)
        steps = {"alert": 2, "logged": 1}.get(level, 0)
        if all(x["decision"] in ("network", "depends") for x in found):
            steps += 1
        reach = db_sources(a, known) if a["kind"] == "database" else []
        if reach and action in ("db_iam", "db_secret") and all(r["verdict"] != "unknown" for r in reach):
            steps += 1  # the port is open only to the proxy and known workloads
        who = sorted({x["principal"] for x in people}) + sorted({x["principal"] for x in pipes})
        via = [_via(principals.get(x["principal"])) for x in people]
        out.append(
            _finding(
                rule,
                account,
                _lower(base, steps),
                asset=a["name"],
                asset_kind=a["kind"],
                region=a["region"],
                payment=a["payment"],
                what=ACTIONS[action][0],
                action=action,
                who=who[:12],
                people=len({x["principal"] for x in people}),
                pipeline_count=len({x["principal"] for x in pipes}),
                detect=level,
                detect_why=said,
                calls=sorted({x["call"] for x in found}),
                network=all(x["decision"] in ("network", "depends") for x in found),
                evidence=[
                    f"{x['principal']}: {x['call']} {x['decision']}" + (f" ({x['why']})" if x["why"] else "")
                    for x in people + pipes
                ][:8],
                via=sorted({v for v in via if v})[:4],
                pipelines=sorted({x["principal"] for x in pipes})[:6],
            )
        )
        stats["person_paths"] += len(found)
        if level in ("not logged", "unknown"):
            stats["undetected"] += 1
    # Credentials: keys on disk, MFA, root, long sessions.
    can_write = {x["principal"] for x in paths if x["decision"] in ("allowed", "network", "depends")}
    long_sessions: list[dict] = []
    for p in principals.values():
        if p["kind"] == "user":
            old = [k for k in p.get("keys") or [] if (k.get("age") or 0) >= 0]
            if old and p["label"] in can_write:
                out.append(
                    _finding(
                        "user_keys_write",
                        account,
                        who=[p["label"]],
                        asset=p["label"],
                        asset_kind="user",
                        evidence=[
                            f"key {k.get('age')} days old, last used {k.get('last_used') or 'never'}" for k in old
                        ],
                    )
                )
            elif old:
                sev = "medium" if any((k.get("age") or 0) > KEY_DAYS for k in old) else "low"
                out.append(
                    _finding(
                        "user_keys",
                        account,
                        sev,
                        who=[p["label"]],
                        asset=p["label"],
                        asset_kind="user",
                        evidence=[f"key {k.get('age')} days old" for k in old],
                    )
                )
            if p.get("console") and not p.get("mfa"):
                out.append(
                    _finding(
                        "user_no_mfa",
                        account,
                        who=[p["label"]],
                        asset=p["label"],
                        asset_kind="user",
                        evidence=["console password, no MFA device"],
                    )
                )
        if p["kind"] == "person" and p["label"] in can_write and (p.get("hours") or 1) > LONG_SESSION_HOURS:
            long_sessions.append(p)
        if p["kind"] == "pipeline" and p.get("weak"):
            reach = sorted(
                {
                    assets[x["asset"]]["name"]
                    for x in paths
                    if x["principal"] == p["label"] and x["decision"] != "blocked" and x["asset"] in assets
                }
            )
            pay = any(
                assets[x["asset"]]["payment"]
                for x in paths
                if x["principal"] == p["label"] and x["decision"] != "blocked" and x["asset"] in assets
            )
            out.append(
                _finding(
                    "pipeline_trust_open",
                    account,
                    None if pay else "high",
                    who=[p["label"]],
                    asset=p["label"],
                    asset_kind="role",
                    evidence=[p["weak"], *([f"can change {', '.join(reach[:5])}"] if reach else [])],
                )
            )
        if p["kind"] == "outside" and p.get("weak"):
            out.append(
                _finding(
                    "outside_trust",
                    account,
                    who=[p["label"]],
                    asset=p["label"],
                    asset_kind="role",
                    evidence=[p["weak"]],
                )
            )
    if long_sessions:
        out.append(
            _finding(
                "long_session",
                account,
                who=sorted(p["label"] for p in long_sessions)[:12],
                asset=f"{len(long_sessions)} permission sets",
                asset_kind="permission set",
                evidence=[f"{p['label']}: up to {p['hours']:g} hours" for p in long_sessions][:8],
            )
        )
    out += _role_alerts(account, raw, principals, assets, paths)
    root = (raw.get("facts") or {}).get("root") or {}
    if root and (root.get("keys") or not root.get("mfa")):
        out.append(
            _finding(
                "root_exposed",
                account,
                asset="root user",
                asset_kind="user",
                evidence=[
                    x
                    for x, on in (
                        ("root has an access key", root.get("keys")),
                        ("root has no MFA", not root.get("mfa")),
                    )
                    if on
                ],
            )
        )
    # Exposure.
    for e in raw.get("exposures") or []:
        a = assets.get(e["asset"]) or {"name": e["asset"], "kind": "", "payment": False, "region": ""}
        sev = "critical" if a["payment"] and e["rule"] in ("api_open", "fn_url_open", "fn_public_policy") else None
        out.append(
            _finding(
                e["rule"],
                account,
                sev,
                asset=a["name"],
                asset_kind=a["kind"],
                region=a["region"],
                payment=a["payment"],
                evidence=[e["note"]],
            )
        )
    # Tamper evidence and pipeline controls on assets.
    by_tag_repos = any(a["facts"].get("by_tag") for a in assets.values() if a["kind"] == "service")
    for a in assets.values():
        f = a["facts"]
        if a["kind"] == "bucket" and a["payment"]:
            if f.get("versioning") is False:
                out.append(
                    _finding(
                        "payment_no_versioning",
                        account,
                        asset=a["name"],
                        asset_kind="bucket",
                        region=a["region"],
                        payment=True,
                        evidence=["versioning is off"],
                    )
                )
            elif f.get("versioning") and not f.get("object_lock") and f.get("object_lock") is not None:
                out.append(
                    _finding(
                        "payment_no_lock",
                        account,
                        asset=a["name"],
                        asset_kind="bucket",
                        region=a["region"],
                        payment=True,
                        evidence=["no Object Lock"],
                    )
                )
        if a["kind"] == "function" and a["payment"] and f.get("code_signing") is False:
            out.append(
                _finding(
                    "unsigned_code",
                    account,
                    asset=a["name"],
                    asset_kind="function",
                    region=a["region"],
                    payment=True,
                    evidence=["no code signing configuration"],
                )
            )
        if a["kind"] == "repository" and f.get("mutable") and by_tag_repos:
            out.append(
                _finding(
                    "mutable_images",
                    account,
                    "medium" if a["payment"] else "low",
                    asset=a["name"],
                    asset_kind="repository",
                    region=a["region"],
                    payment=a["payment"],
                    evidence=["tags are mutable; services in this account deploy by tag"],
                )
            )
        if a["kind"] == "database" and a["payment"] and f.get("activity_stream") is False:
            out.append(
                _finding(
                    "db_no_activity",
                    account,
                    asset=a["name"],
                    asset_kind="database",
                    region=a["region"],
                    payment=True,
                    evidence=[f"{f.get('engine')}: no activity stream"],
                )
            )
    for a in assets.values():
        if a["kind"] != "database" or "ingress" not in a["facts"]:
            continue
        reach = db_sources(a, known)
        bad = [r for r in reach if r["verdict"] == "unknown"]
        if bad:
            laptop = any("laptop" in r["why"] for r in bad)
            out.append(
                _finding(
                    "db_direct",
                    account,
                    "critical" if a["payment"] else "high",
                    asset=a["name"],
                    asset_kind="database",
                    region=a["region"],
                    payment=a["payment"],
                    what=f"port {a['facts'].get('port') or 'any'} open to {len(bad)} source(s) not known"
                    + (", including a laptop range" if laptop else ""),
                    evidence=([_proxy_note(a)] if _proxy_note(a) else [])
                    + [f"{r['source']}: {r['why']}" + (f" ({r['note']})" if r["note"] else "") for r in bad][:8],
                    proxy_note=_proxy_note(a),
                    proxy=sorted({r["source"] for r in reach if r["verdict"] == "proxy"}),
                )
            )
    out += _detection_findings(account, raw, assets)
    out += _change_findings(account, raw)
    return _merge(out), stats


HIGH_RISK = {
    "s3_write",
    "s3_erase",
    "ddb_write",
    "fn_code",
    "fn_config",
    "ecs_deploy",
    "ecr_push",
    "key_sign",
    "db_secret",
    "db_reset",
    "db_iam",
    "db_data_api",
    "blind_trail",
    "blind_gd",
    "blind_alerts",
}


def _role_alerts(account: dict, raw: dict, principals: dict, assets: dict, paths: list[dict]) -> list[dict]:
    """The roles that can make a high-risk change to a money-moving resource, and whether becoming one raises
    an alert in this account. With the laptops and pipelines assumed compromised, a session on one of these
    roles is the moment to look."""
    risky = sorted(
        {
            x["principal"]
            for x in paths
            if x["decision"] != "blocked"
            and x["action"] in HIGH_RISK
            and (assets.get(x["asset"]) or {}).get("payment", x["action"].startswith("blind"))
        }
    )
    if not risky:
        return []
    rules = _alert_rules(raw)
    arns = {principals[r]["arn"] for r in risky if r in principals}
    named = {r for rule in rules for r in rule.get("roles") or []}
    general = [
        rule["name"]
        for rule in rules
        if (
            "sts" in {s.replace("aws.", "") for s in rule["sources"]}
            or any(e.startswith("AssumeRole") for e in rule["events"])
        )
        and not rule.get("roles")
    ]
    if general:
        return []
    missing = sorted(r for r in risky if r in principals and principals[r]["arn"] not in named)
    if not missing:
        return []
    return [
        _finding(
            "role_assume_no_alert",
            account,
            who=missing[:12],
            asset=f"{len(missing)} high-risk roles",
            asset_kind="role",
            count=len(missing),
            evidence=[f"{len(arns)} roles can change money-moving resources; no alert rule here on assuming them"],
        )
    ]


def _merge(found: list[dict]) -> list[dict]:
    """One line for the same change by the same people with the same detection, over many resources: 78
    tables a permission set can write are one finding naming the tables, not 78."""
    keyed: dict[tuple, dict] = {}
    out = []
    for f in found:
        if not f.get("action") and f.get("asset_kind") in ("account", "user", "role", "permission set", None, ""):
            out.append(f)
            continue
        key = (
            f["rule"],
            f.get("action"),
            f["severity"],
            f.get("detect"),
            tuple(f.get("who") or ()),
            f.get("network"),
            f.get("proxy_note"),
        )
        if key not in keyed:
            keyed[key] = {**f, "assets": [f["asset"]], "count": 1}
            out.append(keyed[key])
            continue
        m = keyed[key]
        m["count"] += 1
        if len(m["assets"]) < 25:
            m["assets"].append(f["asset"])
        ev = m.get("evidence") or []
        m["evidence"] = ev if len(ev) >= 8 else ev + (f.get("evidence") or [])[:1]
    for m in keyed.values():
        if m["count"] > 1:
            kinds = {
                "bucket": "buckets",
                "table": "tables",
                "function": "functions",
                "database": "databases",
                "secret": "secrets",
                "service": "services",
                "repository": "repositories",
                "api": "APIs",
                "signing key": "signing keys",
            }
            m["asset"] = (
                f"{m['count']} {kinds.get(m['asset_kind'], m['asset_kind'] + 's')}: "
                + ", ".join(m["assets"][:4])
                + (" and more" if m["count"] > 4 else "")
            )
            m["region"] = ""
    return out


def _via(p: dict | None) -> str:
    if p and p["kind"] == "role" and p.get("reached_by"):
        return f"{p['label']} is reachable by {', '.join(p['reached_by'][:3])}"
    return ""


def _detection_findings(account: dict, raw: dict, assets: dict) -> list[dict]:
    out = []
    d = raw.get("detect") or {}
    trails = d.get("trails") or []
    checks = raw.get("checks") or {}
    if (checks.get("trails") or {}).get("status") != "unknown":
        live = [t for t in trails if t.get("logging")]
        if not live and not any(not t.get("read") for t in trails):
            out.append(
                _finding(
                    "trail_off",
                    account,
                    asset="CloudTrail",
                    asset_kind="account",
                    evidence=[f"{len(trails)} trail(s), none logging"],
                )
            )
        elif live and not any(_management(t)["read"] for t in live):
            out.append(
                _finding(
                    "read_events_off",
                    account,
                    asset="CloudTrail",
                    asset_kind="account",
                    evidence=[f"{t['name']}: write events only" for t in live][:3],
                )
            )
        if live:
            gaps = []
            for a in assets.values():
                rtype = RTYPE.get(a["kind"])
                if a["payment"] and a["kind"] in ("bucket", "table") and rtype:
                    arn = a["arn"] + ("/x" if a["kind"] == "bucket" else "")
                    if not any(_data_selector_covers(t, rtype, arn) for t in live):
                        gaps.append(f"{a['kind']} {a['name']}")
            if gaps:
                out.append(
                    _finding(
                        "data_events_off",
                        account,
                        asset=f"{len(gaps)} payment resources",
                        asset_kind="account",
                        evidence=gaps[:12],
                        count=len(gaps),
                    )
                )
    for t in trails:
        if t.get("logging") and t.get("read") and not t.get("validation"):
            out.append(
                _finding(
                    "trail_no_validation",
                    account,
                    asset=t.get("name") or "CloudTrail",
                    asset_kind="account",
                    evidence=["log file validation is off"],
                )
            )
    for a in assets.values():
        f = a["facts"]
        if not a["payment"]:
            continue
        if a["kind"] == "bucket" and _detection(raw, a, "s3_write")[0] != "alert":
            out.append(
                _finding(
                    "payment_file_no_alert",
                    account,
                    asset=a["name"],
                    asset_kind="bucket",
                    region=a["region"],
                    payment=True,
                    evidence=[_detection(raw, a, "s3_write")[1]],
                )
            )
        if a["kind"] == "table" and f.get("pitr") is False:
            out.append(
                _finding(
                    "table_no_pitr",
                    account,
                    asset=a["name"],
                    asset_kind="table",
                    region=a["region"],
                    payment=True,
                    evidence=["point-in-time recovery is off"],
                )
            )
        if a["kind"] == "secret" and f.get("rotation") is False:
            out.append(
                _finding(
                    "secret_no_rotation",
                    account,
                    asset=a["name"],
                    asset_kind="secret",
                    region=a["region"],
                    payment=True,
                    evidence=["rotation is off"],
                )
            )
    for a in assets.values():
        if a["kind"] == "api" and a["facts"].get("logged") is False:
            out.append(
                _finding(
                    "api_no_logs",
                    account,
                    "high" if a["payment"] else None,
                    asset=a["name"],
                    asset_kind="api",
                    region=a["region"],
                    payment=a["payment"],
                    evidence=["a stage has no access logging"],
                )
            )
    regions_with = {a["region"] for a in assets.values() if a["region"] != "global"}
    gd = d.get("guardduty") or {}
    off = sorted(r for r in regions_with if r in gd and not gd[r]["on"])
    if off:
        out.append(
            _finding(
                "guardduty_off", account, asset="GuardDuty", asset_kind="account", evidence=[f"off in {', '.join(off)}"]
            )
        )
    has_payment_bucket = any(a["kind"] == "bucket" and a["payment"] for a in assets.values())
    no_s3 = sorted(r for r, s in gd.items() if s["on"] and "S3_DATA_EVENTS" not in s["features"])
    if has_payment_bucket and no_s3:
        out.append(
            _finding(
                "guardduty_s3_off",
                account,
                asset="GuardDuty",
                asset_kind="account",
                evidence=[f"S3 protection off in {', '.join(no_s3)}"],
            )
        )
    rules = _alert_rules(raw)
    if (checks.get("detection") or {}).get("status") != "unknown" and not any(
        r["people"] or "AWS API Call via CloudTrail" in r["types"] for r in rules
    ):
        out.append(
            _finding(
                "no_change_alert",
                account,
                asset="EventBridge",
                asset_kind="account",
                evidence=[f"{len(rules)} enabled rule(s) with targets, none on API calls"],
            )
        )
    return out


def _change_findings(account: dict, raw: dict) -> list[dict]:
    out = []
    changes = raw.get("changes") or []
    laptop = [c for c in changes if c["tool"] != "Console"]
    console = [c for c in changes if c["tool"] == "Console"]
    for rule, found in (("laptop_changes", laptop), ("console_changes", console)):
        if not found:
            continue
        who = sorted({c["who"] for c in found})
        out.append(
            _finding(
                rule,
                account,
                asset=f"{sum(c['count'] for c in found)} changes",
                asset_kind="account",
                who=who[:12],
                people=len(who),
                count=sum(c["count"] for c in found),
                evidence=[
                    f"{c['who']} ({c['tool']}): {c['action']} x{c['count']}"
                    + (f", last on {c['resource']}" if c.get("resource") else "")
                    for c in found[:10]
                ],
            )
        )
    return out


PRIMARY = {
    "bucket": "s3_write",
    "table": "ddb_write",
    "function": "fn_code",
    "service": "ecs_deploy",
    "repository": "ecr_push",
    "secret": "secret_read",
    "signing key": "key_sign",
    "database": "db_reset",
    "api": "api_invoke",
}


def _immutable(a: dict) -> tuple[str, str]:
    """("immutable" | "recoverable" | "changeable", why) for a resource, from its own settings."""
    f = a["facts"]
    k = a["kind"]
    if k == "bucket":
        if f.get("object_lock") == "COMPLIANCE":
            return "immutable", "Object Lock, compliance mode"
        if f.get("object_lock"):
            return "recoverable", f"Object Lock {str(f['object_lock']).lower()}: can be bypassed with permission"
        if f.get("versioning"):
            return "recoverable", "versioning on, no Object Lock"
        return "changeable", "no versioning"
    if k == "function":
        return ("immutable", "code signing") if f.get("code_signing") else ("changeable", "no code signing")
    if k == "repository":
        return ("immutable", "tags immutable") if not f.get("mutable") else ("changeable", "tags mutable")
    if k == "table":
        return (
            ("recoverable", "point-in-time recovery") if f.get("pitr") else ("changeable", "no point-in-time recovery")
        )
    if k == "database":
        return ("recoverable", "activity stream") if f.get("activity_stream") else ("changeable", "no activity stream")
    if k == "secret":
        return ("recoverable", "rotated") if f.get("rotation") else ("changeable", "not rotated")
    return "changeable", ""


def _flows(account: dict, raw: dict, known: dict | None = None) -> list[dict]:
    """Each money-moving resource: who could change it, and whether the change is prevented, recorded or
    alerted. With laptops and pipelines assumed compromised, each must be immutable or observed."""
    paths = raw.get("paths") or []
    principals = {p["label"]: p for p in raw.get("principals") or []}
    out = []
    for a in raw.get("assets") or []:
        action = PRIMARY.get(a["kind"])
        if not a.get("payment") or not action:
            continue
        who = {
            x["principal"]
            for x in paths
            if x["asset"] == a["id"] and x["decision"] != "blocked" and x["action"] == action
        }
        pipes = {w for w in who if (principals.get(w) or {}).get("kind") in ("pipeline", "outside")}
        state, why = _immutable(a)
        level, said = _detection(raw, a, action)
        if a["kind"] == "database" and "ingress" in a["facts"]:
            reach = db_sources(a, known or _known(None))
            unknown = [r for r in reach if r["verdict"] == "unknown"]
            via = sorted({r["source"] for r in reach if r["verdict"] == "proxy"})
            why = (
                f"port open to {len(unknown)} unknown source(s)"
                if unknown
                else "only the proxy and known workloads reach it" + (f" (proxy {', '.join(via)})" if via else "")
            )
            state = "changeable" if unknown else "recoverable"
        if state == "immutable" or not who:
            verdict = "protected"
        elif level == "alert":
            verdict = "observed"
        elif level == "logged":
            verdict = "recorded only"
        else:
            verdict = "neither"
        out.append(
            {
                "account": account["name"],
                "kind": a["kind"],
                "name": a["name"],
                "region": a["region"],
                "what": ACTIONS[action][0],
                "people": len(who - pipes),
                "pipelines": len(pipes),
                "immutable": state,
                "immutable_why": why,
                "detect": level,
                "detect_why": said,
                "verdict": verdict,
            }
        )
    order = {"neither": 0, "recorded only": 1, "observed": 2, "protected": 3}
    return sorted(out, key=lambda x: (order[x["verdict"]], x["account"], x["kind"], x["name"]))


def build_compromise(scan: dict, answers: dict | None = None) -> dict:
    """The report for the accounts read, or {"available": False, "reason": ...}."""
    data = scan.get("compromise") or {}
    reads = data.get("accounts") or {}
    names = {a["id"]: a for a in scan.get("accounts") or []}
    base = {"scan_id": scan.get("id"), "scan_at": scan.get("created_at"), "label": scan.get("label", "")}
    picker = [
        {
            "id": a["id"],
            "name": a.get("name", a["id"]),
            "ou_path": a.get("ou_path", ""),
            "suggested": bool(_suggest(a)),
            "status": a.get("status"),
        }
        for a in sorted(scan.get("accounts") or [], key=lambda a: (not _suggest(a), a.get("name", "")))
        if a.get("status") in ("ACTIVE", "UNKNOWN", None)
    ]
    if not reads:
        return {
            **base,
            "available": False,
            "accounts_to_pick": picker,
            "reason": "Pick the payment and channel accounts to check, then run the checks.",
        }
    cat = catalog()
    known = _known(answers)
    findings, rows, people, changes, flows = [], [], [], [], []
    totals = Counter()
    for acct_id, raw in reads.items():
        acct = names.get(acct_id) or {"id": acct_id, "name": acct_id}
        account = {"id": acct_id, "name": acct.get("name", acct_id)}
        for a in raw.get("assets") or []:
            a.setdefault("account_id", acct_id)
        got, stats = _account_findings(account, raw, known)
        flows += _flows(account, raw, known)
        findings += got
        totals.update(stats)
        sev = Counter(f["severity"] for f in got)
        assets = raw.get("assets") or []
        rows.append(
            {
                "id": acct_id,
                "name": account["name"],
                "ou_path": acct.get("ou_path", ""),
                **{s: sev.get(s, 0) for s in SEV},
                "points": sum(cat["points"][f["severity"]] for f in got),
                "assets": len([a for a in assets if a["kind"] != "account"]),
                "payment_assets": sum(1 for a in assets if a.get("payment")),
                "principals": len(raw.get("principals") or []),
                "unknown": sorted(k for k, v in (raw.get("checks") or {}).items() if v.get("status") == "unknown"),
                "read_at": raw.get("read_at"),
            }
        )
        for p in raw.get("principals") or []:
            mine = [x for x in raw.get("paths") or [] if x["principal"] == p["label"] and x["decision"] != "blocked"]
            blocked = [x for x in raw.get("paths") or [] if x["principal"] == p["label"] and x["decision"] == "blocked"]
            people.append(
                {
                    "account": account["name"],
                    "label": p["label"],
                    "kind": p["kind"],
                    "hours": p.get("hours"),
                    "keys": len(p.get("keys") or []),
                    "weak": p.get("weak"),
                    "reached_by": p.get("reached_by") or [],
                    "can": len(mine),
                    "payment": len(
                        {x["asset"] for x in mine if x["asset"] in {a["id"] for a in assets if a.get("payment")}}
                    ),
                    "blocked": len(blocked),
                    "guardrail": sum(1 for x in blocked if "SCP" in x["why"]),
                }
            )
        changes += [{**c, "account": account["name"]} for c in raw.get("changes") or []]
    order = {s: i for i, s in enumerate(SEV)}
    findings.sort(key=lambda f: (order[f["severity"]], not f.get("payment"), f["account"], f["title"]))
    rows.sort(key=lambda r: (-r["critical"], -r["high"], -r["points"], r["name"]))
    people.sort(key=lambda p: (-p["payment"], -p["can"], p["account"], p["label"]))
    sev = Counter(f["severity"] for f in findings)
    by_area = []
    for area, info in cat["areas"].items():
        mine = [f for f in findings if f["area"] == area]
        by_area.append(
            {
                "area": area,
                "label": info["label"],
                "action": info["action"],
                **{s: sum(1 for f in mine if f["severity"] == s) for s in SEV},
            }
        )
    return {
        **base,
        "available": True,
        "accounts_to_pick": picker,
        "selected": sorted(reads),
        "summary": {
            "accounts": len(reads),
            "assets": sum(r["assets"] for r in rows),
            "payment_assets": sum(r["payment_assets"] for r in rows),
            "principals": sum(r["principals"] for r in rows),
            "paths": totals["paths"],
            "person_paths": totals["person_paths"],
            "undetected": totals["undetected"],
            "laptop_changes": sum(c["count"] for c in changes if c["tool"] != "Console"),
            **{s: sev.get(s, 0) for s in SEV},
        },
        "top": [f for f in findings if f["severity"] in ("critical", "high")][:40],
        "findings": findings,
        "areas": by_area,
        "accounts": rows,
        "people": people[:300],
        "changes": sorted(changes, key=lambda c: (c["tool"] == "Console", -c["count"]))[:200],
        "blind_spots": cat["blind_spots"],
        "flows": [f for f in flows if f["verdict"] in ("neither", "recorded only")][:500],
        "known": {
            "proxy": sorted(known["proxy"]) + known["proxy_names"],
            "known": sorted(known["ids"] - known["proxy"]),
            "laptop_ranges": len(known["laptop"]),
        },
        "flow_counts": dict(Counter(f["verdict"] for f in flows)),
        "catalog_version": cat["version"],
    }


SUGGEST = re.compile(
    r"pay|card|ledger|settle|clearing|eft|debit|swift|wallet|treasury|channel|bank|core|mobile|app|digital|"
    r"connect|atm|branch|switch|rpp|debicheck|forex|fx",
    re.I,
)


def _suggest(a: dict) -> bool:
    """A production account whose name looks like a payment or channel account: ticked to start with."""
    name = a.get("name", "")
    return bool(SUGGEST.search(name)) and bool(re.search(r"prod|prd", name, re.I))
