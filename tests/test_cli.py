import json

import pytest

from exitrisk import cli, scanner
from exitrisk.demo import create_demo_scan


@pytest.fixture
def errors(monkeypatch):
    """What the CLI logs at error level (its handler writes to the real stderr, not pytest's capture)."""
    seen: list[str] = []
    monkeypatch.setattr(cli.log, "error", lambda msg, *a, **k: seen.append(msg % a if a else msg))
    monkeypatch.setattr(cli.log, "exception", lambda msg, *a, **k: seen.append("Traceback " + (msg % a)))
    return seen


def test_bad_answers_file_is_one_clear_error(tmp_path, errors):
    scan_id = create_demo_scan()["id"]
    bad = tmp_path / "answers.json"
    bad.write_text('{"target": ')
    assert cli.main(["report", scan_id, "--questionnaire", str(bad)]) == 2
    bad.write_text("[1, 2]")
    assert cli.main(["report", scan_id, "--questionnaire", str(bad)]) == 2
    assert cli.main(["report", scan_id, "--multiregion", str(tmp_path / "missing.json"), "--view", "multiregion"]) == 2
    assert "not valid JSON (line 1, column 12)" in errors[0]
    assert "must hold a JSON object" in errors[1]
    assert "cannot read the multi-region answers file" in errors[2]
    assert not any("Traceback" in e for e in errors)


def test_unknown_scan_id_is_one_clear_error(errors):
    assert cli.main(["report", "20990101-000000-0000"]) == 2
    assert errors and "no scan with id 20990101-000000-0000" in errors[0]


def test_report_writes_json(tmp_path):
    scan_id = create_demo_scan()["id"]
    out, answers = tmp_path / "r.json", tmp_path / "a.json"
    answers.write_text(json.dumps({"target": "gcp"}))
    assert cli.main(["report", scan_id, "--questionnaire", str(answers), "--out", str(out)]) == 0
    r = json.loads(out.read_text())
    assert r["meta"]["target_label"] == "Google Cloud"
    assert r["estimate"]["provisional"] is False


def test_scan_passes_the_exit_target(monkeypatch):
    seen = {}

    def fake_run(job):
        seen["target"] = job.params.target
        return {"id": job.id, "status": "complete", "accounts": [], "issues": []}

    monkeypatch.setattr(scanner, "run_scan", fake_run)
    assert cli.main(["scan", "--profile", "x", "--target", "onprem"]) == 0
    assert seen["target"] == "onprem"
