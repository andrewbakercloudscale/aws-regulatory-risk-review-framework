"""The Outage Risk Report: how a measure is judged, what the collector reads, and the report built on it."""

import base64
from datetime import date, datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import boto3
import pytest
from botocore.exceptions import ClientError

from exitrisk.collectors import outage as collector
from exitrisk.demo import build_demo_scan
from exitrisk.filtering import AccountFilter
from exitrisk.outage import (
    OutageAnswers,
    black_friday,
    build_outage,
    catalog,
    findings_csv,
    judge_burstable,
    judge_capacity,
    workload_rows,
)


@pytest.fixture(scope="module")
def scan():
    return build_demo_scan(6)


@pytest.fixture(scope="module")
def report(scan):
    return build_outage(scan)


def test_black_friday_is_the_day_after_the_fourth_thursday_of_november():
    assert black_friday(date(2026, 11, 1)) == date(2026, 11, 27)
    assert black_friday(date(2024, 11, 1)) == date(2024, 11, 29)
    assert black_friday(date(2026, 11, 28)) == date(2027, 11, 26)


def _sev(pct=50.0, load=False, days=None):
    row = {"pct": pct, "load": load}
    if days is not None:
        row["days"] = days
    return judge_capacity(row, OutageAnswers(), 26)[0]


def test_capacity_is_judged_on_now_on_the_peak_and_on_running_out():
    assert _sev(91.0) == "critical"
    assert _sev(60.0, load=True) == "high"  # 120% at twice the load
    assert _sev(60.0) is None  # a store does not grow with traffic
    assert _sev(40.0, load=True) == "medium"
    assert _sev(20.0, load=True) is None
    assert _sev(days=10.0) == "critical"  # full before the peak
    assert _sev(days=40.0) == "high"  # full within a month after it


@pytest.mark.parametrize(("text", "want"), [("250m", 250), ("2", 2000), ("0.5", 500), ("", None), (None, None)])
def test_parse_cpu(text, want):
    assert collector.parse_cpu(text) == want


@pytest.mark.parametrize(("text", "want"), [("512Mi", 512), ("1Gi", 1024), ("1G", 954), ("1048576", 1), (None, None)])
def test_parse_mem(text, want):
    assert collector.parse_mem(text) == want


def test_days_until_and_slope():
    s = collector.Series()
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    for h in range(96):
        s.add(start + timedelta(hours=h), 50.0 + h / 24)  # one point a day
    assert round(s.slope(), 3) == 1.0
    assert round(collector.days_until(s.last, 100.0, s.slope())) == 46
    assert collector.days_until(50.0, 100.0, 0.0) is None
    short = collector.Series()
    short.add(start, 1.0)
    assert short.slope() == 0.0


def test_pod_sizes_add_up_and_a_missing_limit_is_unknown():
    tmpl = {"spec": {"containers": [
        {"resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"memory": "128Mi"}}},
        {"resources": {"requests": {"cpu": "50m", "memory": "64Mi"}}},
    ]}}  # fmt: skip
    assert collector._pod_sizes(tmpl) == {"cpu_req": 150, "mem_req": 128, "mem_lim": None}


def _lists():
    deploy = lambda name, n: {  # noqa: E731
        "metadata": {"namespace": "pay", "name": name},
        "spec": {"replicas": n, "template": {"spec": {"containers": [
            {"resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"memory": "64Mi"}}}
        ]}}},
    }  # fmt: skip
    return {
        "/apis/apps/v1/deployments": [deploy("api", 3), deploy("worker", 1), deploy("off", 0)],
        "/apis/apps/v1/statefulsets": [],
        "/apis/policy/v1/poddisruptionbudgets": [],
        "/apis/autoscaling/v2/horizontalpodautoscalers": [{
            "metadata": {"namespace": "pay", "name": "api"},
            "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "api"}, "maxReplicas": 4},
            "status": {"currentReplicas": 4},
        }],
        "/api/v1/pods": [
            {"metadata": {"namespace": "pay", "name": "worker-7c9d6f5b8-abcde",
                          "ownerReferences": [{"kind": "ReplicaSet", "name": "worker-7c9d6f5b8"}]},
             "status": {"phase": "Running",
                        "containerStatuses": [{"lastState": {"terminated": {"reason": "OOMKilled"}}}]}},
            {"metadata": {"namespace": "pay", "name": "x"}, "status": {"phase": "Pending"}},
        ],
    }  # fmt: skip


def test_read_workloads_matches_autoscalers_and_ooms_to_their_workload():
    lists = _lists()
    got = collector.read_workloads(lambda path, cap: lists[path])
    rows = {w["name"]: w for w in got["workloads"]}
    assert set(rows) == {"api", "worker"}  # scaled to nothing is left alone
    assert rows["api"]["hpa_max"] == 4 and rows["api"]["current"] == 4
    assert rows["worker"]["oom"] == 1 and "hpa_max" not in rows["worker"]
    assert got["pending"] == 1


def test_workload_rules_find_fixed_single_low_and_killed():
    lists = _lists()
    got = collector.read_workloads(lambda path, cap: lists[path])
    rows = workload_rows({"name": "c", "region": "eu-west-1", "access": "read", **got}, OutageAnswers())
    rules = {(r["rule"], r["res"].split("/")[-1]) for r in rows}
    assert ("eks_single_replica", "worker") in rules
    assert ("eks_hpa_max", "api") in rules
    assert ("eks_low_cpu", "worker") in rules
    assert ("eks_low_memory", "worker") in rules
    assert ("eks_oom", "worker") in rules
    assert ("eks_fixed_replicas", "api") not in rules  # it has an autoscaler


def test_a_namespace_can_be_left_out_and_a_dns_autoscaler_counts():
    workloads = [
        {"ns": "kube-system", "name": "coredns", "kind": "Deployment", "replicas": 2},
        {"ns": "tools", "name": "x", "kind": "Deployment", "replicas": 2},
    ]
    a = OutageAnswers(ignore_namespaces="tools")
    assert {r["rule"] for r in workload_rows({"name": "c", "region": "r", "workloads": workloads}, a)} >= {
        "eks_coredns"
    }
    assert not [r for r in workload_rows({"name": "c", "region": "r", "workloads": workloads}, a) if "/x" in r["res"]]
    scaled = [*workloads, {"ns": "kube-system", "name": "dns-autoscaler", "kind": "Deployment", "replicas": 1}]
    assert "eks_coredns" not in {r["rule"] for r in workload_rows({"name": "c", "region": "r", "workloads": scaled}, a)}


def test_eks_token_is_a_presigned_call_that_names_the_cluster():
    sts = boto3.Session(aws_access_key_id="AKIAFAKE", aws_secret_access_key="fake", region_name="eu-west-1").client(
        "sts"
    )
    token = collector.eks_token(sts, "my-cluster", "eu-west-1")
    assert token.startswith("k8s-aws-v1.")
    raw = token.removeprefix("k8s-aws-v1.")
    url = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
    query = parse_qs(urlparse(url).query)
    assert urlparse(url).netloc == "sts.eu-west-1.amazonaws.com"
    assert query["Action"] == ["GetCallerIdentity"]
    assert "x-k8s-aws-id" in query["X-Amz-SignedHeaders"][0]
    assert query["X-Amz-Expires"] == ["60"]


class _CW:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def get_metric_data(self, **kw):
        self.calls.append(kw)
        return self.pages.pop(0) if self.pages else {"MetricDataResults": []}


class _Session:
    def __init__(self, clients):
        self.clients = clients

    def client(self, name, **_):
        return self.clients[name]


def _ctx(clients, services=None):
    return collector.OutageCtx(
        _Session(clients), "111111111111", ["eu-west-1"], {"services": services, "home": "eu-west-1"}
    )


def test_metrics_are_read_once_and_the_label_names_the_resource():
    when = datetime(2026, 10, 1, tzinfo=timezone.utc)
    cw = _CW([{"MetricDataResults": [
        {"Label": "q0~i-123", "Timestamps": [when, when + timedelta(hours=1)], "Values": [40.0, 80.0]}
    ]}])  # fmt: skip
    ctx = _ctx({"cloudwatch": cw})
    got = ctx.metrics("eu-west-1")
    first = next(iter(collector.METRICS))
    assert got[first]["i-123"].high == 80.0
    calls = len(cw.calls)
    ctx.metrics("eu-west-1")
    assert len(cw.calls) == calls
    assert all("SEARCH(" in q["Expression"] for c in cw.calls for q in c["MetricDataQueries"])
    assert all(len(c["MetricDataQueries"]) <= 500 for c in cw.calls)


class _Paged:
    """A client whose list calls return one fixed page; other calls refuse."""

    def __init__(self, **pages):
        self.pages = pages

    def can_paginate(self, _):
        return False

    def __getattr__(self, name):
        if name in self.pages:
            return lambda **_: self.pages[name]

        def refuse(**_):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, name)

        return refuse


def test_msk_disk_filling_imbalance_and_no_autoscaling_are_found():
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    disk = collector.METRICS["msk_disk"]
    assert disk[2] == "KafkaDataLogsDiskUsed"
    ctx = _ctx({})
    full, empty = collector.Series(), collector.Series()
    full.add(now, 85.0)
    empty.add(now, 40.0)
    ctx._metrics["eu-west-1"] = {k: {} for k in collector.METRICS} | {
        "msk_disk": {"kafka-1|1": full, "kafka-1|2": empty}
    }
    ctx.clients = None
    ctx.session = _Session({
        "kafka": _Paged(list_clusters_v2={"ClusterInfoList": [{
            "ClusterName": "kafka-1", "ClusterArn": "arn:x",
            "Provisioned": {"NumberOfBrokerNodes": 2, "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large", "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1000}}}},
        }]}),
        "application-autoscaling": _Paged(describe_scalable_targets={"ScalableTargets": []}),
    })  # fmt: skip
    collector.task_msk(ctx, "eu-west-1")
    rules = {r["rule"]: r for r in ctx.rows}
    assert rules["msk_disk"]["pct"] == 85.0
    assert "msk_imbalance" in rules and "msk_no_autoscale" in rules


def test_a_refused_read_is_recorded_as_not_measured_and_is_not_a_pass():
    ctx = _ctx({"kafka": _Paged()})
    collector._run(ctx, ("msk", ("msk",), collector.task_msk, None), "eu-west-1")
    assert not ctx.rows
    assert ctx.r.finish()["msk"]["status"] != "ok"


def test_a_task_that_runs_twice_counts_its_rows_once(monkeypatch):
    def twice(ctx, region):
        ctx.add("msk_disk", "a", region, pct=90.0)
        ctx.add("msk_disk", "a", region, pct=90.0)

    monkeypatch.setattr(collector, "GLOBAL_TASKS", [])
    monkeypatch.setattr(collector, "REGION_TASKS", [("twice", ("msk",), twice, None)])
    monkeypatch.setattr(collector, "_finish", lambda ctx: None)
    monkeypatch.setattr("exitrisk.collectors.inventory.enabled_regions", lambda s, r: ["eu-west-1"])
    out, _ = collector.account_checks(object(), "111111111111", ["eu-west-1"], {})
    assert len(out["rows"]) == 1


# -------------------------------------------------------------------- the report


def test_report_on_the_demo_is_available_and_adds_up(report):
    s = report["summary"]
    assert report["available"] and s["accounts"] > 0
    assert s["critical"] == sum(x["critical"] for x in report["focus"])
    assert s["high"] == sum(x["high"] for x in report["focus"])
    assert sum(a["critical"] for a in report["accounts"]) >= s["critical"]
    assert report["findings"][0]["severity"] == "critical"
    assert s["clusters_read"] < s["clusters"]  # the demo has clusters with no access entry


def test_every_rule_in_the_demo_is_in_the_catalog(scan):
    ids = {r["id"] for r in catalog()["rules"]}
    for acct in scan["outage"]["accounts"].values():
        assert {r["rule"] for r in acct.get("rows") or []} <= ids


def test_every_cause_has_a_source_and_says_what_it_cannot_show():
    for c in catalog()["causes"]:
        assert c["url"].startswith("https://") and c["source"] and c["limits"] and c["evidence"]


def test_answers_change_the_result_with_no_new_scan(scan, report):
    calm = build_outage(scan, a=OutageAnswers(peak_multiplier=1.0))
    assert calm["summary"]["breach_at_peak"] < report["summary"]["breach_at_peak"]
    wider = build_outage(scan, a=OutageAnswers(cpu_request_floor_m=4000))
    assert wider["summary"]["all_findings"] > report["summary"]["all_findings"]


def test_a_peak_date_moves_the_dates_and_the_freeze(scan):
    r = build_outage(scan, a=OutageAnswers(peak_date="2027-01-31", freeze_days=7))
    assert r["summary"]["peak_date"] == "2027-01-31" and r["summary"]["freeze_date"] == "2027-01-24"


def test_outside_production_a_finding_is_one_level_lower():
    scan = {"accounts": [{"id": "1", "name": "dev", "ou_path": "Root"}], "params": {"outage": True}}
    row = {"rule": "msk_disk", "res": "k", "region": "eu-west-1", "pct": 95.0}
    scan["outage"] = {"accounts": {"1": {"rows": [row], "clusters": [], "checks": {}, "regions": ["eu-west-1"]}}}
    assert build_outage(scan)["findings"][0]["severity"] == "high"
    prod = build_outage(scan, a=OutageAnswers(production_patterns="dev"))
    assert prod["findings"][0]["severity"] == "critical"


@pytest.mark.parametrize(
    "kind, want",
    [
        ("t3.medium", ("t3", 20)),
        ("db.t4g.large", ("t4g", 30)),
        ("cache.t3.micro", ("t3", 10)),
        ("t3.small.search", ("t3", 20)),
        ("kafka.t3.small", ("t3", 20)),
        ("t2.2xlarge", ("t2", 16.9)),
        ("m5.large", None),
        ("db.r6g.large", None),
        ("", None),
    ],
)
def test_burstable_sizes_and_their_baselines(kind, want):
    assert collector.burstable(kind) == want


@pytest.mark.parametrize(
    "row, want",
    [
        ({"cpu": 15, "baseline": 20, "unlimited": False}, "high"),  # 30% at 2x load, over 20%
        ({"cpu": 15, "baseline": 20, "unlimited": True}, "medium"),  # bills instead of slowing
        ({"cpu": 5, "baseline": 20, "unlimited": False}, "low"),  # 10% at peak, under its baseline
        ({"baseline": 20, "unlimited": None}, "medium"),  # nothing says how busy
        ({"cpu": 5, "baseline": 20, "credits": 1.0, "unlimited": False}, "high"),  # already ran out
        ({"cpu": 5, "baseline": 20, "credits": 1.0, "unlimited": True}, "low"),  # unlimited: zero is normal
    ],
)
def test_a_burstable_size_is_judged_against_its_baseline_at_peak_load(row, want):
    sev, why = judge_burstable({"type": "t3.medium", **row}, OutageAnswers(peak_multiplier=2.0))
    assert sev == want and why.startswith("t3.medium")


def test_burstable_findings_are_production_only_and_name_the_service():
    rows = [
        {"rule": "ec2_burstable", "res": "web", "region": "eu-west-1", "type": "t3.large", "baseline": 30, "cpu": 40,
         "unlimited": False},
        {"rule": "rds_burstable", "res": "db", "region": "eu-west-1", "type": "db.t3.medium", "baseline": 20,
         "unlimited": True},
    ]  # fmt: skip
    for name, want in (("prod", 2), ("dev", 0)):
        scan = {"accounts": [{"id": "1", "name": name, "ou_path": "Root"}], "params": {"outage": True}}
        scan["outage"] = {"accounts": {"1": {"rows": rows, "clusters": [], "checks": {}, "regions": ["eu-west-1"]}}}
        found = build_outage(scan)["findings"]
        assert len(found) == want
        if want:
            assert {f["rule"]: f["severity"] for f in found} == {"ec2_burstable": "high", "rds_burstable": "medium"}


def test_a_filter_narrows_the_accounts(scan, report):
    r = build_outage(scan, AccountFilter(include="prod"))
    assert 0 < r["summary"]["accounts"] < report["summary"]["accounts"]


def test_a_scan_without_the_checks_says_so(scan):
    r = build_outage({**scan, "outage": None, "params": {**scan["params"], "outage": False}})
    assert r["available"] is False and "did not run" in r["reason"]


def test_csv_has_a_row_for_each_finding_and_cannot_run_a_formula(report):
    text = findings_csv(report)
    assert len(text.strip().splitlines()) == len(report["findings"]) + 1
    bad = {**report, "findings": [{**report["findings"][0], "res": "=cmd()"}]}
    assert ",'=cmd()," in findings_csv(bad)


# -------------------------------------------------------------------- against botocore's own API models


def _answering(status: int):
    """A real boto3 session with no network: botocore validates every call, and this answers it."""
    from botocore.awsrequest import AWSResponse

    denied = b"<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>"
    xml = ("iam.", "ec2.", "rds.", "autoscaling.", "elasticloadbalancing.", "route53.", "s3.", "sts.", "monitoring.")
    xml += ("cloudfront.", "elasticache.", "redshift.")

    class Raw:
        def __init__(self, body):
            self.body = body

        def stream(self, **_):
            body, self.body = self.body, None
            if body:
                yield body

    session = boto3.Session(aws_access_key_id="AKIAFAKE", aws_secret_access_key="fake", region_name="eu-west-1")

    def reply(request, **_):
        is_xml = urlparse(request.url).netloc.startswith(xml) or ".s3." in request.url
        if status == 403:
            return AWSResponse(request.url, 403, {}, Raw(denied if is_xml else b'{"__type": "AccessDeniedException"}'))
        if not is_xml:
            return AWSResponse(request.url, 200, {}, Raw(b"{}"))
        body = parse_qs(request.body.decode() if isinstance(request.body, bytes) else str(request.body or ""))
        action = (body.get("Action") or ["R"])[0]
        return AWSResponse(
            request.url, 200, {}, Raw(f"<{action}Response><{action}Result/></{action}Response>".encode())
        )

    session.events.register("before-send", reply)
    return session


@pytest.mark.parametrize("status", [403, 200])
def test_every_call_is_valid_for_its_api(monkeypatch, caplog, status):
    """A wrong operation or parameter name would only show on a real scan: this finds it with no AWS."""
    monkeypatch.setattr("exitrisk.collectors.inventory.enabled_regions", lambda s, r: ["eu-west-1"])
    out, _ = collector.account_checks(_answering(status), "111111111111", ["eu-west-1"], {"home": "eu-west-1"})
    assert out["checks"]
    unexpected = [
        r.getMessage() + str(r.exc_info and r.exc_info[1]) for r in caplog.records if "unexpected" in r.getMessage()
    ]
    assert not unexpected
    if status == 403:
        assert not out["rows"]
