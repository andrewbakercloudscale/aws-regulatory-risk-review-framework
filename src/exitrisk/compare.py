"""What changed between two scans: score, spend, tiers, accounts and services.

Both scans are scored with the same account filter and questionnaire, so every difference comes
from the estate (or the catalog), not from different answers. Spend is the monthly average of each
scan's own period, so scans of different lengths still compare like for like.
"""

from __future__ import annotations

from .estimate import Questionnaire
from .filtering import AccountFilter
from .scoring import build_report

TOP_N = 10
HIGH_RATINGS = ("High", "Critical")


def _delta(before: float | None, after: float | None) -> dict:
    out = {"before": before, "after": after, "change": None, "change_pct": None}
    if before is not None and after is not None:
        out["change"] = round(after - before, 2)
        if before:
            out["change_pct"] = round(100 * (after - before) / abs(before), 1)
    return out


def _scan_info(r: dict) -> dict:
    m = r["meta"]
    return {
        "scan_id": m["scan_id"],
        "label": m.get("label") or "",
        "scanned_at": m.get("scanned_at"),
        "ou": (m.get("ou") or {}).get("path", ""),
        "period": m.get("period") or {},
        "catalog_version": m.get("catalog_version"),
    }


def compare_scans(
    before_scan: dict,
    after_scan: dict,
    account_filter: AccountFilter | None = None,
    questionnaire: Questionnaire | None = None,
) -> dict:
    a = build_report(before_scan, account_filter, questionnaire)
    b = build_report(after_scan, account_filter, questionnaire)
    sa, sb = a["summary"], b["summary"]
    headline = {
        "score": _delta(sa["score"], sb["score"]),
        "rating": {"before": sa["rating"], "after": sb["rating"]},
        "monthly_spend": _delta(sa["monthly_spend"], sb["monthly_spend"]),
        "high_risk_monthly": _delta(sa["high_risk_monthly"], sb["high_risk_monthly"]),
        "high_risk_pct": _delta(sa["high_risk_pct"], sb["high_risk_pct"]),
        "accounts": _delta(sa["accounts_with_spend"], sb["accounts_with_spend"]),
        "high_risk_accounts": _delta(sa["high_risk_accounts"], sb["high_risk_accounts"]),
        "services": _delta(sa["services"], sb["services"]),
        "cost_low": _delta(a["estimate"]["cost"]["low"], b["estimate"]["cost"]["low"]),
        "cost_high": _delta(a["estimate"]["cost"]["high"], b["estimate"]["cost"]["high"]),
        "cost_range": {"before": a["estimate"]["ranges"]["cost"], "after": b["estimate"]["ranges"]["cost"]},
    }
    tiers_a = {t["tier"]: t for t in a["tiers"]}
    tiers = [
        {
            "tier": t["tier"],
            "label": t["label"],
            **_delta(tiers_a.get(t["tier"], {}).get("monthly_spend", 0.0), t["monthly_spend"]),
        }
        for t in b["tiers"]
    ]

    acc_a = {x["id"]: x for x in a["accounts"] if x["monthly_spend"] > 0}
    acc_b = {x["id"]: x for x in b["accounts"] if x["monthly_spend"] > 0}
    # An account recreated under a new ID (or a renumbered demo) is still the same workload: pair
    # leftovers by name before calling them added and removed.
    by_name = {x["name"]: k for k, x in acc_a.items() if k not in acc_b}
    for k in [k for k in acc_b if k not in acc_a]:
        old = by_name.pop(acc_b[k]["name"], None)
        if old:
            acc_a[k] = acc_a.pop(old)

    def brief(x: dict) -> dict:
        return {"id": x["id"], "name": x["name"], "monthly_spend": x["monthly_spend"], "rating": x["rating"],
                "spend_at_risk": x["spend_at_risk"]}  # fmt: skip

    added = sorted((brief(x) for k, x in acc_b.items() if k not in acc_a), key=lambda x: -x["spend_at_risk"])
    removed = sorted((brief(x) for k, x in acc_a.items() if k not in acc_b), key=lambda x: -x["spend_at_risk"])
    movers = []
    for k in acc_a.keys() & acc_b.keys():
        x, y = acc_a[k], acc_b[k]
        movers.append(
            {
                "id": k,
                "name": y["name"],
                "rating": {"before": x["rating"], "after": y["rating"]},
                "score": _delta(x["score"], y["score"]),
                "monthly_spend": _delta(x["monthly_spend"], y["monthly_spend"]),
                "spend_at_risk": _delta(x["spend_at_risk"], y["spend_at_risk"]),
            }
        )
    movers = [
        m
        for m in movers
        if abs(m["spend_at_risk"]["change"] or 0) >= 1 or m["rating"]["before"] != m["rating"]["after"]
    ]
    movers.sort(key=lambda m: -abs(m["spend_at_risk"]["change"] or 0))
    rating_changes = [m for m in movers if m["rating"]["before"] != m["rating"]["after"]]
    became_high = [
        m for m in rating_changes if m["rating"]["after"] in HIGH_RATINGS and m["rating"]["before"] not in HIGH_RATINGS
    ]

    svc_a = {s["service"]: s for s in a["services"]}
    svc_b = {s["service"]: s for s in b["services"]}
    services = []
    for k in svc_a.keys() | svc_b.keys():
        x, y = svc_a.get(k), svc_b.get(k)
        ref = y or x
        services.append(
            {
                "service": ref["display"],
                "tier": ref["tier"],
                "tier_label": ref["tier_label"],
                "status": "new" if x is None else "gone" if y is None else "both",
                **_delta(x["monthly_spend"] if x else 0.0, y["monthly_spend"] if y else 0.0),
            }
        )
    services = [s for s in services if abs(s["change"] or 0) >= 1 or s["status"] != "both"]
    services.sort(key=lambda s: -abs(s["change"] or 0))
    new_lockin = [s for s in services if s["status"] == "new" and s["tier"] >= 4]

    out = {
        "before": _scan_info(a),
        "after": _scan_info(b),
        "same_scope": _scan_info(a)["ou"] == _scan_info(b)["ou"],
        "headline": headline,
        "tiers": tiers,
        "accounts": {
            "added": added[:TOP_N],
            "added_count": len(added),
            "removed": removed[:TOP_N],
            "removed_count": len(removed),
            "movers": movers[:TOP_N],
            "rating_changes": len(rating_changes),
            "became_high": [m["name"] for m in became_high[:TOP_N]],
        },
        "services": services[:TOP_N],
        "new_lockin_services": [s["service"] for s in new_lockin],
        "same_period": a["meta"].get("period") == b["meta"].get("period"),
        "summary": _summary(headline, added, removed, became_high, new_lockin),
    }
    if out["same_period"]:
        out["summary"].append(
            "Both scans cover the same months, so spend differs only through scope, tags or the catalog. "
            "Compare with a scan taken after another month has closed to see the trend."
        )
    return out


def _money(v: float) -> str:
    sign = "-" if v < 0 else ""
    v = abs(v)
    for div, unit in ((1e6, "m"), (1e3, "k")):
        if v >= div:
            return f"{sign}${v / div:,.1f}{unit}"
    return f"{sign}${v:,.0f}"


def _accounts(n: int) -> str:
    return f"{n} account{'' if n == 1 else 's'}"


def _summary(h: dict, added: list, removed: list, became_high: list, new_lockin: list) -> list[str]:
    """Plain sentences for the top of the comparison, most important first."""
    out = []
    sc = h["score"]
    if sc["change"] is not None:
        if abs(sc["change"]) < 1:
            out.append(f"The exit-risk score is unchanged at {sc['after']:.0f} ({h['rating']['after']}).")
        else:
            word = "rose" if sc["change"] > 0 else "fell"
            out.append(
                f"The exit-risk score {word} from {sc['before']:.0f} to {sc['after']:.0f} "
                f"({h['rating']['before']} to {h['rating']['after']})."
                if h["rating"]["before"] != h["rating"]["after"]
                else f"The exit-risk score {word} from {sc['before']:.0f} to {sc['after']:.0f}."
            )
    ms, hr = h["monthly_spend"], h["high_risk_monthly"]
    if ms["change"] is not None and abs(ms["change_pct"] or 0) < 0.5:
        out.append(f"Monthly spend is unchanged at {_money(ms['after'])}.")
    elif ms["change"] is not None:
        pct = f" ({ms['change_pct']:+.0f}%)" if ms["change_pct"] is not None else ""
        out.append(
            f"Monthly spend {_money(ms['before'])} to {_money(ms['after'])}{pct}; on High/Critical services "
            f"{_money(hr['before'])} to {_money(hr['after'])}."
        )
    if added or removed:
        parts = [f"{_accounts(len(added))} added"] if added else []
        parts += [f"{len(removed) if added else _accounts(len(removed))} removed"] if removed else []
        out.append(f"{' and '.join(parts)}.".capitalize())
    if became_high:
        names = ", ".join(m["name"] for m in became_high[:3])
        out.append(f"Now High or Critical: {names}{' and others' if len(became_high) > 3 else ''}.")
    if new_lockin:
        names = ", ".join(s["service"] for s in new_lockin[:3])
        out.append(f"New High/Critical services in use: {names}{' and others' if len(new_lockin) > 3 else ''}.")
    return out
