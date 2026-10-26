"""AI insights for the Multi-Region and Cloud Assurance reports, with a fake model."""

import json
import re

import pytest

from exitrisk.ai import insights
from exitrisk.ai.providers import AISettings, Reply
from exitrisk.assurance import build_assurance
from exitrisk.demo import build_demo_scan
from exitrisk.multiregion import build_multiregion


@pytest.fixture(scope="module")
def scan():
    return build_demo_scan(6)


def test_facts_are_compact_and_name_no_resources(scan):
    for kind, rep in (("multiregion", build_multiregion(scan)), ("assurance", build_assurance(scan))):
        facts, accounts = insights.FACTS[kind](rep)
        assert 0 < len(accounts) <= insights.MAX_ACCOUNTS
        text = json.dumps([facts, accounts])
        assert "arn:aws" not in text and len(text) < 60_000


def test_a_run_masks_names_and_drops_made_up_accounts(scan, monkeypatch):
    rep = build_assurance(scan)
    sent = {}

    class FakeClient:
        model = "fake"

        def __init__(self, s):
            pass

        def complete(self, system, user, max_tokens=0, effort="high"):
            sent["system"], sent["user"] = system, user
            real = re.search(r'"id":"(A\d{3})"', user).group(1)
            view = {
                "headline": "Fix internet exposure first.",
                "key_points": ["One", "Two"],
                "risks": [{"title": "Open SSH", "why": "x", "accounts": [real, "999999999999"]}],
                "actions": [{"title": "Close port 22", "detail": "y", "owner": "Security", "when": "first 30 days"}],
                "questions": ["Who owns this?"],
                "confidence": {"level": "Medium", "why": "z"},
            }
            return Reply(text=json.dumps(view), input_tokens=10, output_tokens=5, stop="end", truncated=False)

    monkeypatch.setattr(insights, "Client", FakeClient)
    monkeypatch.setattr(insights, "add_cost", lambda r, s: r)
    s = AISettings(provider="anthropic", mask_names=True)
    out = insights.Run("demo-scan", "assurance", rep, s, {}).run()
    assert "CISO" in sent["system"]
    assert rep["accounts"][0]["name"] not in sent["user"]  # names are masked before sending
    risk = out["final"]["risks"][0]
    assert len(risk["accounts"]) == 1 and risk["account_names"][0] in {a["name"] for a in rep["accounts"]}
    assert insights.load_result(out["scan_id"], "assurance")["final"]["headline"] == "Fix internet exposure first."


def test_bad_kind_or_id_is_refused():
    with pytest.raises(ValueError):
        insights.status("../x", "assurance")
    with pytest.raises(ValueError):
        insights.status("abc", "exit")


def test_one_shared_cause_is_flagged_without_naming_the_resource():
    rules = [{"id": "admin_policy", "title": "Admin policies", "fail": 3},
             {"id": "scp_guardrails", "title": "Missing guardrails", "fail": 3}]  # fmt: skip
    accounts = [{"findings": [{"id": "admin_policy", "status": "fail", "ev": ["role base-adm-role (inline)"]},
                              {"id": "scp_guardrails", "status": "fail", "ev": ["no new IAM users"]}]}
                for _ in range(3)]  # fmt: skip
    causes = insights._common_causes({"rules": rules, "accounts": accounts})
    assert causes["Admin policies"]["accounts_with_the_most_common_finding"] == 3
    assert "shared cause" in causes["Admin policies"]["note"] and "base-adm-role" not in json.dumps(causes)
    assert causes["Missing guardrails"]["findings"] == {"no new IAM users": 3}
