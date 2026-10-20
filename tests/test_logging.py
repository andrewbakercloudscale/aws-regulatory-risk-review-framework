import json
import logging

from exitrisk.logging_config import JsonFormatter, redact


def test_redacts_secrets():
    text = "aws_secret_access_key = abcdEFGH1234/xyz and AKIAABCDEFGHIJKLMNOP and SessionToken: 'tok'"  # noqa: E501 pragma:allow-secret
    out = redact(text)
    assert "abcdEFGH1234" not in out and "ABCDEFGHIJKLMNOP" not in out and "tok'" not in out


def test_json_formatter_has_run_id_and_extras():
    rec = logging.LogRecord("exitrisk.x", logging.WARNING, __file__, 1, "hello %s", ("world",), None)
    rec.run_id = "20260101-000000-abcd"
    rec.account_id = "123"
    data = json.loads(JsonFormatter().format(rec))
    assert data["msg"] == "hello world" and data["run_id"] == rec.run_id and data["account_id"] == "123"
