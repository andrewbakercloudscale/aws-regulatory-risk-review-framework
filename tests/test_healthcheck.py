"""Health Check: credential discovery, metric judging, cause ranking and the API."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from exitrisk import aws_session, healthcheck
from exitrisk.collectors import healthcheck as hc
from exitrisk.server import create_app

H = {"X-ExitRisk": "1"}
T0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
TS = [T0 + timedelta(minutes=5 * i) for i in range(12)]


# ------------------------------------------------------------------ credentials
def test_profile_details_lists_keys_masked_and_never_the_secret(tmp_path, monkeypatch):
    cfg, creds = tmp_path / "config", tmp_path / "credentials"
    cfg.write_text(
        "[profile portal]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
        "[sso-session corp]\nsso_start_url = https://example.awsapps.com/start\nsso_region = eu-west-1\n"
        "[profile hop]\nrole_arn = arn:aws:iam::444455556666:role/Audit\nsource_profile = customer\n"
    )
    creds.write_text(
        "[customer]\naws_access_key_id = AKIAEXAMPLE0000WXYZ\naws_secret_access_key = topsecretvalue\n"
        "[temp]\naws_access_key_id = ASIAEXAMPLE1111ABCD\naws_secret_access_key = alsosecret\n"
        "aws_session_token = tok\n"
    )
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    d = aws_session.profile_details()
    assert d["customer"]["kind"] == "access key" and d["customer"]["key"] == "AKIA…WXYZ"
    assert d["temp"]["kind"] == "session key"
    assert d["portal"]["kind"] == "sso" and d["portal"]["account"] == "111122223333"
    assert d["hop"]["kind"] == "role" and "Audit" in d["hop"]["label"]
    flat = repr(d)
    assert "topsecretvalue" not in flat and "alsosecret" not in flat and "tok" not in flat.replace("token", "")
    assert "AKIAEXAMPLE0000WXYZ" not in flat


# ------------------------------------------------------------------ metric judging
def test_runs_and_rolling_ratio():
    pts = [(t, v) for t, v in zip(TS, [0, 5, 6, 7, 0, 9, 9, 9, 9, 0, 0, 0], strict=True)]
    first, hits, _ = hc._runs(pts, lambda v: v > 4, 3)
    assert first == TS[1] and hits == 7
    worst, onset, bad, errs, reqs = hc._rolling_ratio(
        [(TS[0], 0.0), (TS[1], 10.0)], [(TS[0], 100.0), (TS[1], 20.0)], 20
    )
    assert onset == TS[1] and bad == 1 and errs == 10 and reqs == 120
    assert round(worst, 3) == round(10 / 120, 3)


def _alb_probe():
    return next(p for p in hc.PROBES if p["id"] == "alb_5xx")


def test_judge_flags_new_errors_and_marks_old_ones_chronic():
    d = {"app/web/1": [(t, 100.0) for t in TS]}
    bad = {"app/web/1": [(t, 50.0) for t in TS]}
    zero = {"app/web/1": [(t, 0.0) for t in TS]}
    new = hc.judge(_alb_probe(), {"n": bad, "d": d}, {"n": zero, "d": d}, 300)
    assert len(new) == 1 and new[0]["severity"] == "critical" and not new[0]["chronic"]
    old = hc.judge(_alb_probe(), {"n": bad, "d": d}, {"n": bad, "d": d}, 300)
    assert old[0]["chronic"]
    assert hc.judge(_alb_probe(), {"n": zero, "d": d}, {"n": zero, "d": d}, 300) == []


# ------------------------------------------------------------------ ranking
def _sig(**kw):
    base = {"account": "123456789012", "account_name": "shop", "region": "eu-west-1", "role": "symptom",
            "chronic": False, "severity": "high", "service": "app", "check": "lambda_errors",
            "evidence": "x"}  # fmt: skip
    return {**base, **kw}


def test_change_before_errors_ranks_first_with_high_likelihood():
    errors = _sig(title="Function checkout is failing", resource="checkout", started="2026-01-01T12:20:00+00:00",
                  severity="critical")  # fmt: skip
    noise = _sig(title="Queue reports is backing up", resource="reports", started="2026-01-01T09:00:00+00:00",
                 severity="medium", service="db")  # fmt: skip
    change = {"account": "123456789012", "account_name": "shop", "region": "eu-west-1",
              "time": "2026-01-01T12:10:00+00:00", "event": "UpdateFunctionConfiguration", "service": "lambda",
              "who": "deployer", "resource": "checkout", "sharp": True}  # fmt: skip
    out = healthcheck.rank([errors, noise], [change], "", "2026-01-01T06:00:00+00:00")
    assert out[0]["kind"] == "change" and out[0]["likelihood"] == "high"
    assert "Function checkout is failing" in out[0]["why"]


def test_a_change_with_nothing_after_it_is_not_a_guess():
    change = {"account": "123456789012", "account_name": "shop", "region": "eu-west-1",
              "time": "2026-01-01T12:10:00+00:00", "event": "DeleteTopic", "service": "sns",
              "who": "cleanup", "resource": "old-topic", "sharp": True}  # fmt: skip
    assert healthcheck.rank([], [change]) == []


def test_many_alike_fold_into_one_guess():
    sigs = [_sig(title=f"Lambda function f{i} is throttled", resource=f"f{i}", check="lambda_throttles",
                 role="cause", service="capacity", started="2026-01-01T12:00:00+00:00") for i in range(7)]  # fmt: skip
    out = healthcheck.rank(sigs, [])
    assert len(out) == 1 and out[0]["members"] == 7 and out[0]["title"].startswith("7 at once")


def test_symptom_words_lift_a_match_and_minor_causes_stay_below_high():
    a = _sig(title="Function whatsapp-send is failing", resource="whatsapp-send", severity="medium")
    b = _sig(title="Function billing is failing", resource="billing", severity="high")
    out = healthcheck.rank([a, b], [], "whatsapp messages not going out")
    match = next(g for g in out if g["resource"] == "whatsapp-send")
    assert "whatsapp" in match["why"] and match["likelihood"] == "medium"
    assert out[0]["resource"] == "billing"  # still most critical first
    minor = _sig(title="SendEvent is denied", resource="x", severity="low", role="cause", service="security",
                 check="denied", started="2026-01-01T12:00:00+00:00")  # fmt: skip
    hit = _sig(title="Function x is failing", resource="x", started="2026-01-01T12:05:00+00:00")
    ranked = healthcheck.rank([minor, hit], [])
    assert all(g["likelihood"] != "high" for g in ranked if g["severity"] == "low")


def test_report_sorts_by_criticality_and_explains_likelihood():
    doc = {"id": "hc-test", "window": {"start": "2026-01-01T06:00:00+00:00", "hours": 6}, "request": {},
           "raw": {"accounts": [{"account": "123456789012", "name": "shop", "regions": ["eu-west-1"], "changes": [],
                                 "gaps": [], "signals": [
               _sig(title="Old", resource="old", chronic=True, severity="critical"),
               _sig(title="Minor old", resource="minor", chronic=True, severity="low"),
               _sig(title="New", resource="new", started="2026-01-01T11:00:00+00:00")]}]}}  # fmt: skip
    r = healthcheck.build_report(doc)
    assert [g["title"] for g in r["top"]] == ["Old", "New"]  # most critical first; a minor old one stays out
    assert [g["rank"] for g in r["top"]] == [1, 2]
    assert r["top"][0]["likelihood"] == "medium" and r["top"][0]["likelihood_why"]
    assert r["summary"]["chronic"] == 2


# ------------------------------------------------------------------ API
def test_api_runs_lists_reads_and_deletes(monkeypatch):
    def fake_run(job):
        job.status = "done"
        healthcheck._save({"id": job.id, "created": "2026-01-01T12:00:00+00:00", "status": "done",
                           "request": job.req, "window": {"start": "2026-01-01T06:00:00+00:00", "hours": 6},
                           "raw": {"accounts": [], "unreachable": []}})  # fmt: skip

    monkeypatch.setattr(healthcheck, "_run", fake_run)
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    assert c.get("/health").status_code == 200
    body = {"profile": "p", "accounts": [{"id": "123456789012", "name": "shop"}], "hours": 6}
    assert c.post("/api/health-check", headers=H, json={**body, "accounts": []}).status_code == 422
    assert c.post("/api/health-check", headers=H, json={**body, "hours": 5}).status_code == 400
    run_id = c.post("/api/health-check", headers=H, json=body).json()["id"]
    for _ in range(50):
        got = c.get(f"/api/health-check/{run_id}").json()
        if got["report"]:
            break
    assert got["report"]["top"] == [] and got["report"]["accounts"] == []
    assert any(r["id"] == run_id for r in c.get("/api/health-checks").json()["runs"])
    assert c.delete(f"/api/health-check/{run_id}", headers=H).json() == {"deleted": True}
    assert c.get(f"/api/health-check/{run_id}").status_code == 404


def test_saved_keys_read_their_own_account_without_a_role(monkeypatch):
    from exitrisk import sso

    class Sts:
        def get_caller_identity(self):
            return {"Account": "222222222222"}

    class Base:
        def client(self, name, **_kw):
            return Sts()

    monkeypatch.setattr(sso, "profile_permission_set", lambda p: None)
    base = Base()
    assert aws_session.member_session(base, "keys", "222222222222", None, "t") is base
    with pytest.raises(ValueError):
        aws_session.member_session(base, "keys", "999999999999", None, "t")


def test_access_check_names_refused_reads_as_a_policy(monkeypatch):
    from exitrisk import preflight

    monkeypatch.setattr(healthcheck, "make_session", lambda p: object())
    monkeypatch.setattr(healthcheck, "caller_identity", lambda s: {"account_id": "111111111111"})
    monkeypatch.setattr(healthcheck, "_session_for", lambda *a: object())
    monkeypatch.setattr(preflight, "probe_actions", lambda s, a, p: (["logs:StartQuery"], []) if a == "2" else ([], []))
    r = healthcheck.check_access("keys", [{"id": "1", "name": "a"}, {"id": "2", "name": "b"}])
    assert not r["ready"] and r["missing"] == ["logs:StartQuery"]
    assert r["policy"]["Statement"][0]["Action"] == ["logs:StartQuery"]
    assert healthcheck.check_access("keys", [{"id": "1", "name": "a"}])["ready"]


def test_log_samples_are_redacted_and_spikes_need_a_floor():
    assert hc._redact("card 4111111111111111 for a@b.co") == "card <n> for <email>"
    assert hc._spike(600, 50, 500, 3) and not hc._spike(400, 0, 500, 3) and not hc._spike(900, 400, 500, 3)
    keep, big = hc._fit({"small": 1.0, "huge": 100.0}, 60)
    assert keep == ["small"] and big == ["huge"]


def test_new_serious_problem_without_symptoms_is_medium_and_ranks_by_criticality():
    dyn = _sig(title="Table t throttles writes", resource="t", role="cause", service="capacity", check="ddb",
               severity="high", ongoing=True, started="2026-01-01T09:00:00+00:00")  # fmt: skip
    denied = _sig(title="Call is denied", resource="k", role="cause", service="security", check="denied",
                  severity="low", ongoing=True, started="2026-01-01T12:00:00+00:00")  # fmt: skip
    tg = _sig(title="Target group tg has unhealthy targets", resource="tg", severity="critical", chronic=True,
              ongoing=True)  # fmt: skip
    out = healthcheck.rank([dyn, denied, tg], [], "", "2026-01-01T06:00:00+00:00")
    assert [g["severity"] for g in out] == ["critical", "high", "low"]
    assert out[0]["likelihood"] == "medium" and "more than a day" in out[0]["likelihood_why"]
    assert out[1]["likelihood"] == "medium" and "New pressure" in out[1]["likelihood_why"]
    assert out[2]["likelihood"] == "low"
    new_down = _sig(title="Target group web has no healthy target", resource="web", severity="critical", ongoing=True)
    assert healthcheck.rank([new_down], [])[0]["likelihood"] == "high"


def test_old_runs_drop_kafka_reads_logged_under_an_iam_action():
    doc = {"id": "hc-test", "window": {"start": "2026-01-01T06:00:00+00:00", "hours": 6}, "request": {},
           "raw": {"accounts": [{"account": "123456789012", "name": "shop", "regions": ["eu-west-1"], "gaps": [],
                                 "signals": [], "changes": [
               {"account": "123456789012", "account_name": "shop", "region": "eu-west-1",
                "time": "2026-01-01T07:00:00+00:00",
                "event": e, "service": "kafka-cluster", "who": "app", "resource": "topic/t", "sharp": True}
               for e in ("DeleteTopic", "DeleteTopics")]}]}}  # fmt: skip
    r = healthcheck.build_report(doc)
    assert r["summary"]["changes"] == 1


def test_old_target_group_titles_name_the_load_balancer_kind():
    sig = _sig(title="Target group targetgroup/web-tg/abc123 has unhealthy targets", check="nlb_unhealthy")
    assert healthcheck._legacy_title(sig)["title"] == "NLB target group web-tg has unhealthy targets"


def test_accounts_carry_owner_tags_from_the_newest_scan(monkeypatch):
    from exitrisk import store

    scans = {
        "new": {"accounts": [{"id": "111111111111", "tags": {"Owner": "Ann", "Executive": "Bo"}}]},
        "old": {"accounts": [{"id": "111111111111", "tags": {"Owner": "Old"}},
                             {"id": "222222222222", "tags": {"owner": "Cy"}}]},
    }  # fmt: skip
    monkeypatch.setattr(store, "list_scans", lambda: [{"id": "new", "accounts": 1}, {"id": "old", "accounts": 2}])
    monkeypatch.setattr(store, "load_scan", lambda i: scans[i])
    healthcheck._owner_cache["key"] = None
    got = healthcheck._with_owners([{"id": "111111111111"}, {"id": "222222222222"}, {"id": "333333333333"}])
    assert got[0]["owner"] == "Ann" and got[0]["executive"] == "Bo"
    assert got[1]["owner"] == "Cy" and "owner" not in got[2]
    healthcheck._owner_cache["key"] = None
