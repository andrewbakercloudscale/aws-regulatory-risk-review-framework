import json
import os
import re

import pytest
from fastapi.testclient import TestClient

from exitrisk.ai import providers, review
from exitrisk.ai.providers import AISettings, Reply
from exitrisk.demo import build_demo_scan, create_demo_scan
from exitrisk.scoring import build_report
from exitrisk.server import create_app

H = {"X-ExitRisk": "1"}


@pytest.fixture(autouse=True)
def _known_price(monkeypatch):
    """No network for prices in tests: every model costs $2 in and $10 out per million tokens."""
    monkeypatch.setattr(review, "price", lambda s: {"input": 2.0, "output": 10.0, "source": "test"})


@pytest.fixture
def report():
    return build_report(build_demo_scan())


def _ids(prompt: str, section: str) -> list[str]:
    body = prompt.split(section, 1)[1].split("\n\n", 1)[0]
    return [a["id"] for a in json.loads(body.strip())]


class FakeModel:
    """Answers each pass in the requested shape; the draft estate view has a deliberate error."""

    def __init__(self):
        self.prompts = []

    def __call__(self, _client, system, user, max_tokens=16000):
        self.prompts.append(user)
        if user.startswith("Assess each account"):
            ids = _ids(user, "ACCOUNTS:\n")
            body = {
                "accounts": [
                    {
                        "id": i,
                        "entrenchment": "High",
                        "effort_engineer_weeks": [5, 9],
                        "vs_model": "agree",
                        "why": f"{i} uses DynamoDB",
                        "key_risks": [],
                        "approach": "Rebuild",
                        "phase": "Wave 3",
                        "confidence": "medium",
                        "evidence_gaps": [],
                    }
                    for i in ids
                ]
            }
            return Reply(json.dumps(body), 100, 50)
        first = re.search(r'"id":"([^"]+)"', user.split("ACCOUNT ANALYSES:", 1)[1]).group(1)
        view = {
            "headline": f"Hard. {first} decides it.",
            "key_points": ["Score 62 of 100.", "Exit cost about 7 million."],
            "entrenchment": {"level": "High", "summary": "x"},
            "estimate": {
                "effort_engineer_days": [10000, 16000],
                "duration_months": [24, 36],
                "cost": [5e6, 9e6],
                "confidence": "medium",
                "compared_with_model": "",
                "drivers": [],
                "adjustments": [],
                "not_included": [],
            },
            "areas_of_focus": [
                {
                    "title": "Cards",
                    "accounts": [first],
                    "concern": "c",
                    "how_to_tackle": "h",
                    "phase": "Wave 3",
                    "priority": "high",
                }
            ],
            "programme_risks": [],
            "sequencing": [],
            "quick_wins": [],
            "questions_to_validate": [],
            "evidence_to_collect": [],
        }
        if user.startswith("Using the FACTS"):
            view["areas_of_focus"].append(
                {
                    "title": "Ghost",
                    "accounts": ["A999"],
                    "concern": "",
                    "how_to_tackle": "",
                    "phase": "Someday",
                    "priority": "medium",
                }
            )
            return Reply("Here you go:\n```json\n" + json.dumps(view) + "\n```", 100, 50)
        assert "names unknown accounts: A999" in user  # the automated checks reach the reviewer
        return Reply(json.dumps({"changes": [{"issue": "Ghost account", "fix": "Removed"}], "final": view}), 100, 50)


def test_masker_round_trip():
    m = review.Masker(True)
    a, n = m.code("111122223333", "A"), m.code("cards-prod", "acct-")
    assert (a, n) == ("A001", "acct-001")
    assert m.unmask({"x": [f"{a} and {n}", "A0011 stays"]}) == {"x": ["111122223333 and cards-prod", "A0011 stays"]}
    assert review.Masker(False).code("cards-prod", "acct-") == "cards-prod"


def test_parse_json_tolerates_fences_and_prose():
    assert review.parse_json('Sure.\n```json\n{"a": 1}\n```') == {"a": 1}
    assert review.parse_json('{"a": {"b": 2}} thanks') == {"a": {"b": 2}}
    with pytest.raises(ValueError):
        review.parse_json("no json here")


def test_context_masks_names_and_sends_no_owner_names(report):
    facts, rows = review.build_context(report, review.Masker(True))
    sent = json.dumps([facts, rows])
    for a in report["accounts"]:
        assert a["name"] not in sent and a["id"] not in sent
        if a.get("owner"):
            assert a["owner"] not in sent
    assert rows[0]["model_effort_weeks"] >= rows[-1]["model_effort_weeks"]


def test_checks_flag_bad_ranges_unknown_accounts_and_far_estimates(report):
    facts, _ = review.build_context(report, review.Masker(False))
    view = {
        "estimate": {"effort_engineer_days": [10, 5], "duration_months": [1, 2], "cost": [1, 2]},
        "areas_of_focus": [{"title": "t", "accounts": ["nope"], "phase": "Later"}],
        "entrenchment": {"level": "Huge"},
    }
    found = " ".join(review.check_estate(view, facts, {"real"}))
    for text in (
        "not a valid range",
        "away from the model",
        "unknown accounts: nope",
        "phase 'Later'",
        "entrenchment.level",
    ):
        assert text in found


def test_full_run_three_passes_restores_names_and_records_review(monkeypatch, report):
    fake = FakeModel()
    monkeypatch.setattr(providers.Client, "complete", lambda self, *a, **k: fake(self, *a, **k))
    s = AISettings(provider="anthropic", keys={"anthropic": "sk-test-123456789"}, mask_names=True)
    out = review.Run("scan-x", report, s, {"filter": "all"}).run()
    batches = -(-len(out["accounts"]) // review.BATCH_ACCOUNTS)
    assert len(fake.prompts) == batches + 2
    names = {a["name"] for a in report["accounts"]}
    assert all(a["name"] not in p for p in fake.prompts for a in report["accounts"][:5])  # masked on the wire
    focus = out["final"]["areas_of_focus"]
    assert [f["title"] for f in focus] == ["Cards"] and focus[0]["account_names"][0] in names
    assert out["changes"][0]["issue"] == "Ghost account"
    assert focus[0]["account_names"][0] in out["final"]["headline"]  # ids in sentences read as names
    assert any("A999" in c for c in out["checks_before_review"]) and not out["open_checks"]
    assert out["usage"]["calls"] == batches + 2
    assert review.load_result("scan-x")["model"] == "claude-fable-5-1"


def test_settings_api_never_returns_keys_and_stores_them_privately():
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    r = c.put(
        "/api/ai/settings", headers=H, json={"provider": "together", "model": "", "api_key": "tg-secret-abcd1234"}
    )
    assert r.status_code == 200 and "tg-secret" not in r.text
    assert r.json()["settings"]["keys"]["together"] == {"set": True, "hint": "...1234", "env": False}
    path = providers._settings_path()
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert "tg-secret" not in c.get("/api/ai/settings").text
    # Saving without a key keeps it; an empty key removes it.
    c.put("/api/ai/settings", headers=H, json={"provider": "together", "model": "x"})
    assert providers.load_settings().keys["together"] == "tg-secret-abcd1234"
    c.put("/api/ai/settings", headers=H, json={"provider": "together", "api_key": ""})
    assert "together" not in providers.load_settings().keys


def test_review_endpoint_runs_in_background(monkeypatch):
    fake = FakeModel()
    monkeypatch.setattr(providers.Client, "complete", lambda self, *a, **k: fake(self, *a, **k))
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    c.put("/api/ai/settings", headers=H, json={"provider": "openrouter", "api_key": "or-key-12345678"})
    scan = create_demo_scan()
    r = c.post("/api/ai/review", headers=H, json={"scan_id": scan["id"]})
    assert r.status_code == 200, r.text
    import time

    for _ in range(100):
        got = c.get(f"/api/ai/review/{scan['id']}").json()
        if got["run"]["status"] != "running":
            break
        time.sleep(0.05)
    assert got["run"]["status"] == "complete", got["run"]
    assert got["result"]["provider"] == "openrouter"
    assert c.delete(f"/api/ai/review/{scan['id']}?remove=true", headers=H).json()["removed"]
    assert c.get(f"/api/ai/review/{scan['id']}").json()["result"] is None


def test_scan_can_ask_for_the_ai_review_and_it_starts_when_the_scan_finishes(monkeypatch):
    import time

    from exitrisk import scanner, server

    fake = FakeModel()
    monkeypatch.setattr(providers.Client, "complete", lambda self, *a, **k: fake(self, *a, **k))
    jobs = []

    def fake_start(params):
        scan = create_demo_scan()
        job = scanner.ScanJob(id=scan["id"], params=params)  # still running: the review must wait
        scanner._jobs[job.id] = job
        jobs.append(job)
        return job

    monkeypatch.setattr(server, "start_scan", fake_start)
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    body = {"profile": None, "ai_review": {"filter": {"include": ""}}}
    r = c.post("/api/scans", headers=H, json=body)
    assert r.status_code == 400 and "needs a deep scan" in r.json()["detail"] and not jobs  # quick scan
    body |= {"inventory": True, "dependencies": True}
    providers._settings_path().unlink(missing_ok=True)
    r = c.post("/api/scans", headers=H, json=body)
    assert r.status_code == 400 and "not set up" in r.json()["detail"] and not jobs  # no scan started

    c.put("/api/ai/settings", headers=H, json={"provider": "openrouter", "api_key": "or-key-12345678"})
    r = c.post("/api/scans", headers=H, json=body)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    run = c.get(f"/api/ai/review/{sid}").json()["run"]
    assert run["status"] == "running" and run["stage"] == "Waiting for the scan"
    jobs[0].status = "complete"
    for _ in range(200):
        got = c.get(f"/api/ai/review/{sid}").json()
        if got["result"]:
            break
        time.sleep(0.05)
    assert got["result"]["final"]["key_points"][0] == "Score 62 of 100."


def test_review_asked_for_with_a_failed_scan_says_why():
    review.expect("scan-f")
    assert review.waiting("scan-f")
    review.give_up("scan-f", "the scan failed")
    assert review.status("scan-f")["status"] == "failed" and not review.waiting("scan-f")
    review.expect("scan-g")
    assert review.cancel("scan-g") and review.status("scan-g")["status"] == "cancelled"


def test_missing_key_fails_fast():
    with pytest.raises(providers.AIError, match="No API key"):
        providers.Client(AISettings(provider="together", keys={}))


def test_gateway_sends_key_and_headers_to_its_base_url(monkeypatch):
    calls = []

    def fake_http(method, url, headers, body=None, timeout=0):
        calls.append((url, headers, body))
        return {"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 3, "completion_tokens": 1}}

    monkeypatch.setattr(providers, "_http", fake_http)
    s = AISettings(
        provider="gateway",
        model="@bedrock-prod/claude-opus-5-5",
        base_url="https://api.portkey.ai/v1/",
        key_header="x-portkey-api-key",
        headers=providers.parse_headers("x-portkey-config: pc-secret-cfg\n\n"),
        keys={"gateway": "pk-secret-12345678"},
    )
    reply = providers.Client(s).complete("sys", "user")
    url, headers, body = calls[0]
    assert url == "https://api.portkey.ai/v1/chat/completions" and reply.text == "ok"
    assert headers == {"x-portkey-config": "pc-secret-cfg", "x-portkey-api-key": "pk-secret-12345678"}
    assert body["model"] == "@bedrock-prod/claude-opus-5-5" and body["reasoning_effort"] == "high"
    s.key_header = "authorization"
    assert s.gateway_headers()["Authorization"] == "Bearer pk-secret-12345678"
    pub = json.dumps(s.public())
    assert "pk-secret" not in pub and "pc-secret" not in pub and "x-portkey-config" in pub


def test_gateway_settings_are_checked():
    with pytest.raises(providers.AIError, match="Name: value"):
        providers.parse_headers("no colon here")
    with pytest.raises(providers.AIError, match="set by the console"):
        providers.parse_headers("Host: evil.example")
    with pytest.raises(providers.AIError, match="base URL"):
        providers.Client(AISettings(provider="gateway", model="m", keys={"gateway": "k"}))
    with pytest.raises(providers.AIError, match="model id"):
        providers.Client(AISettings(provider="gateway", base_url="https://gw.example/v1", keys={"gateway": "k"}))
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    r = c.put("/api/ai/settings", headers=H, json={"provider": "gateway", "base_url": "http://gw.example/v1"})
    assert r.status_code == 422  # https only
    r = c.put("/api/ai/settings", headers=H, json={"provider": "gateway", "headers": "bad header"})
    assert r.status_code == 400
    r = c.put(
        "/api/ai/settings",
        headers=H,
        json={
            "provider": "gateway",
            "model": "gw-model",
            "base_url": "https://gw.example/v1",
            "headers": "X-A: s3cret",
        },
    )
    assert r.status_code == 200 and "s3cret" not in r.text
    saved = providers.load_settings()
    assert saved.headers == {"x-a": "s3cret"} and saved.gateway_model == "gw-model"
    # Choosing another provider keeps the gateway's model, base URL and headers for later.
    c.put("/api/ai/settings", headers=H, json={"provider": "together", "model": ""})
    saved = providers.load_settings()
    assert saved.headers == {"x-a": "s3cret"} and saved.base_url == "https://gw.example/v1"
    assert AISettings(**{**saved.__dict__, "provider": "gateway", "model": ""}).model_id() == "gw-model"


def test_cut_off_reply_is_asked_again_with_more_room_then_fails_loudly(monkeypatch, report):
    sizes = []

    def cut(self, system, user, max_tokens=16000):
        sizes.append(max_tokens)
        return Reply('{"accounts": [', 10, max_tokens, truncated=True, stop="length")

    monkeypatch.setattr(providers.Client, "complete", cut)
    s = AISettings(provider="anthropic", keys={"anthropic": "sk-test-123456789"})
    run = review.Run("scan-t", report, s, {})
    with pytest.raises(providers.AIError, match="cut off at 64,000"):
        run._ask(providers.Client(s), "prompt", 16000, "estate view")
    assert sizes == [16000, 32000, 64000]
    assert any("asked again with 32,000" in n for n in run.notes)


def test_clean_run_has_no_notes_and_a_cost(monkeypatch, report):
    fake = FakeModel()
    monkeypatch.setattr(providers.Client, "complete", lambda self, *a, **k: fake(self, *a, **k))
    s = AISettings(provider="anthropic", keys={"anthropic": "sk-test-123456789"}, mask_names=False)
    out = review.Run("scan-c", report, s, {}).run()
    assert out["notes"] == [] and out["accounts_analysed"] == out["accounts_sent"]
    u = out["usage"]
    assert out["cost_usd"] == round(u["input_tokens"] / 1e6 * 2 + u["output_tokens"] / 1e6 * 10, 2)
    # Every service an account uses is sent, with the model's effort for it.
    big = max(report["accounts"], key=lambda a: len(a["services_used"]))
    assert len(big["services_used"]) > 5
    assert any(len(p.split('"services":')) > 1 for p in fake.prompts)


def test_openrouter_id_for_price_lookup():
    f = providers._openrouter_id
    assert f(AISettings(provider="bedrock", model="global.anthropic.claude-opus-5-5")) == "anthropic/claude-opus-5.5"
    assert f(AISettings(provider="anthropic", model="claude-fable-5-1")) == "anthropic/claude-fable-5.1"
    assert f(AISettings(provider="together", model="zai-org/GLM-5.3")) == "z-ai/glm-5.3"
    assert providers.cost({"input_tokens": 1_000_000, "output_tokens": 500_000}, {"input": 2, "output": 10}) == 7.0


def test_show_key_returns_the_saved_key_only_with_the_header():
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    c.put("/api/ai/settings", headers=H, json={"provider": "together", "api_key": "tg-show-me-12345678"})
    assert c.post("/api/ai/key", headers=H, json={"provider": "together"}).json()["key"] == "tg-show-me-12345678"
    assert c.post("/api/ai/key", json={"provider": "together"}).status_code == 403
