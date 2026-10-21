from fastapi.testclient import TestClient

from exitrisk.server import create_app

H = {"X-ExitRisk": "1"}


def client():
    return TestClient(create_app(), base_url="http://127.0.0.1")


def test_health_and_index():
    c = client()
    h = c.get("/api/health").json()
    assert h["status"] == "ok" and h["scans_running"] == [] and h["pid"] > 0
    r = c.get("/")
    assert r.status_code == 200 and "AWS Exit Risk Review" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_rejects_foreign_host_and_missing_header():
    c = client()
    assert c.get("/api/health", headers={"Host": "evil.example"}).status_code == 403
    assert c.post("/api/scans/demo").status_code == 403


def test_demo_report_roundtrip():
    c = client()
    scan_id = c.post("/api/scans/demo", headers=H).json()["id"]
    assert any(s["id"] == scan_id for s in c.get("/api/scans").json()["scans"])
    r = c.post(
        "/api/report",
        headers=H,
        json={
            "scan_id": scan_id,
            "filter": {"include": "prod"},
            "questionnaire": {
                "cicd": "standard",
                "cloud_team_size": 25,
                "ai_agents": True,
                "exclude_services": ["AWS Lambda"],
            },
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["filter"]["include"] == "prod"
    assert body["estimate"]["inputs"]["cloud_team_size"] == 25
    assert body["estimate"]["effort"]["agentic_saved_weeks"] > 0
    assert [x["service"] for x in body["summary"]["excluded_services"]] == ["AWS Lambda"]


def test_bad_inputs():
    c = client()
    scan_id = c.post("/api/scans/demo", headers=H).json()["id"]
    assert (
        c.post(
            "/api/report", headers=H, json={"scan_id": scan_id, "filter": {"include": "(", "mode": "regex"}}
        ).status_code
        == 400
    )
    assert c.post("/api/report", headers=H, json={"scan_id": "../../etc/passwd"}).status_code == 404
    assert (
        c.post("/api/report", headers=H, json={"scan_id": scan_id, "questionnaire": {"cicd": "x"}}).status_code == 422
    )
    assert c.post("/api/scans", headers=H, json={"inventory": True}).status_code == 400  # role required


def test_catalog_endpoint():
    cat = client().get("/api/catalog").json()
    assert cat["services"] and all(not s["excluded"] for s in cat["services"])


def test_static_assets_revalidate_so_upgrades_take_effect():
    c = client()
    assert c.get("/").headers["cache-control"] == "no-store"
    assert c.get("/static/app.js").headers["cache-control"] == "no-cache"


def test_multiregion_endpoint():
    c = client()
    scan_id = c.post("/api/scans/demo", headers=H).json()["id"]
    body = {"scan_id": scan_id, "multiregion": {"recovery": "instant", "residency": "same_continent"}}
    r = c.post("/api/multiregion", headers=H, json=body)
    assert r.status_code == 200
    assert r.json()["answers"]["recovery"] == "instant" and r.json()["summary"]["recommended"]
    bad = {"scan_id": scan_id, "multiregion": {"recovery": "sometime"}}
    assert c.post("/api/multiregion", headers=H, json=bad).status_code == 422


def test_compare_two_scans():
    c = client()
    a = c.post("/api/scans/demo", headers=H).json()["id"]
    b = c.post("/api/scans/demo", headers=H).json()["id"]
    r = c.post("/api/compare", headers=H, json={"before_id": a, "after_id": b})
    assert r.status_code == 200
    body = r.json()
    assert body["before"]["scan_id"] == a and body["after"]["scan_id"] == b and body["summary"]
    assert c.post("/api/compare", headers=H, json={"before_id": a, "after_id": "nope"}).status_code == 404
