from exitrisk.catalog import load_catalog
from exitrisk.demo import build_demo_scan
from exitrisk.focus import MAX_ACCOUNTS, build_focus
from exitrisk.scoring import build_report


def _row(**kw):
    row = {
        "id": "111111111111",
        "name": "acct",
        "monthly_spend": 10_000.0,
        "effort_weeks": 10.0,
        "spend_at_risk": 0.0,
        "high_risk_pct": 0.0,
        "top_lockin": [],
        "effort_by_tier": {"1": 10.0},
        "deep_scanned": True,
        "owner": "Owner",
    }
    row.update(kw)
    return row


def _focus(rows, summary=None, resilience=None):
    return build_focus(summary or {"scan_depth": "dependency"}, rows, [], resilience or {}, {}, load_catalog())


def test_demo_report_has_ranked_focus_accounts_and_themes():
    f = build_report(build_demo_scan())["focus"]
    assert 0 < len(f["accounts"]) <= MAX_ACCOUNTS <= f["accounts_total"] or len(f["accounts"]) == f["accounts_total"]
    prio = [a["priority"] for a in f["accounts"]]
    assert prio == sorted(prio, reverse=True)
    for a in f["accounts"]:
        assert a["concerns"] and all(c["action"] and c["phase"] for c in a["concerns"])
    assert {t["key"] for t in f["themes"]} >= {"platforms", "data"}


def test_critical_tier_service_and_critical_flag_are_concerns_with_guidance():
    plain = _row(id="2", name="plain")
    hard = _row(
        id="1",
        name="contact",
        critical=True,
        top_lockin=[{"service": "Connect", "tier": 5, "monthly_spend": 50_000.0}],
        effort_by_tier={"5": 10.0},
        spend_at_risk=50_000.0,
        high_risk_pct=90.0,
    )
    f = _focus([plain, hard])
    assert [a["name"] for a in f["accounts"]] == ["contact"]  # nothing stands out in the plain account
    a = f["accounts"][0]
    keys = [c["key"] for c in a["concerns"]]
    assert "platform" in keys and "critical" in keys and "lockin" not in keys  # lock-in folded into platform
    assert a["wave"] == "Wave 3" and a["level"] == "high"
    assert keys.index("platform") < keys.index("critical")  # ordered by project phase: cutover last


def test_owner_and_evidence_gaps_alone_are_themes_not_accounts():
    rows = [_row(id=str(i), owner="", deep_scanned=False) for i in range(3)]
    f = _focus(
        rows, {"scan_depth": "quick", "deep_scan_pct": 0}, {"owners": {"tagged_accounts": 1, "accounts_with_spend": 3}}
    )
    assert f["accounts"] == []
    assert {t["key"] for t in f["themes"]} == {"ownership", "evidence"}


def test_data_and_integrations_raise_concerns():
    f = _focus([_row(data_tb=500.0, integrations=80, integrations_hard=40)])
    keys = {c["key"] for c in f["accounts"][0]["concerns"]}
    assert {"data", "integrations"} <= keys
