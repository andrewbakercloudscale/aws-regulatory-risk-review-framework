"""End of life software, container images, Aurora at its ACU ceiling, and reading every metric series."""

from datetime import date, datetime, timedelta, timezone

from exitrisk.collectors import outage as collector
from exitrisk.collectors import outage_lifecycle as L
from exitrisk.outage import OutageAnswers, workload_rows

TODAY = date(2026, 11, 6)


def _lc(std_end: str, ext_end: str | None = None) -> list[dict]:
    out = [{"LifecycleSupportName": "open-source-rds-standard-support", "LifecycleSupportEndDate": std_end}]
    if ext_end:
        out.append({"LifecycleSupportName": "open-source-rds-extended-support", "LifecycleSupportEndDate": ext_end})
    return out


def test_registry_is_read_as_a_container_runtime_reads_it():
    assert L.registry("nginx:1.27") == "docker.io"
    assert L.registry("library/nginx") == "docker.io"
    assert L.registry("quay.io/org/app:1") == "quay.io"
    assert L.registry("registry.example.net:5000/app:1") == "registry.example.net:5000"
    assert L.registry("localhost/app") == "localhost"
    assert L.is_ecr("123456789012.dkr.ecr.eu-west-1.amazonaws.com")
    assert L.is_ecr("public.ecr.aws")
    assert not L.is_ecr("artifacts.example.com")


def test_pull_on_every_start_follows_the_kubernetes_defaults():
    assert L.pulls_every_start("app", None)  # no tag: latest, pulled every time
    assert L.pulls_every_start("repo.example.com/app:latest", None)
    assert not L.pulls_every_start("repo.example.com/app:1.2.3", None)
    assert L.pulls_every_start("repo.example.com/app:1.2.3", "Always")
    assert not L.pulls_every_start("repo.example.com/app:latest", "IfNotPresent")
    assert not L.pulls_every_start("repo.example.com/app@sha256:abc", None)


def test_database_support_dates_judge_by_what_aws_forces_and_when():
    # in extended support, the forced upgrade within 180 days: high
    sev, why = L.judge_db_support("postgres 11.22", _lc("2024-02-29", "2027-03-31"), True, TODAY)
    assert sev == "high" and "2027-03-31" in why
    # in extended support with years left: medium
    assert L.judge_db_support("postgres 13.20", _lc("2026-02-28", "2029-02-28"), True, TODAY)[0] == "medium"
    # standard support ending soon, extended support on: medium
    assert L.judge_db_support("postgres 14.17", _lc("2027-02-28", "2030-02-28"), True, TODAY)[0] == "medium"
    # standard support ending soon with extended support refused: AWS upgrades at the standard end
    assert L.judge_db_support("postgres 14.17", _lc("2027-02-28", "2030-02-28"), False, TODAY)[0] == "high"
    # years of standard support left, or no dates published: nothing
    assert L.judge_db_support("postgres 17.6", _lc("2030-02-28", "2033-02-28"), True, TODAY) is None
    assert L.judge_db_support("aurora-postgresql 18.1", [], True, TODAY) is None


def test_major_version_is_the_longest_that_matches():
    assert L.major_of("17.9", ["16", "17"]) == "17"
    assert L.major_of("8.0.mysql_aurora.3.08.0", ["5.7", "8.0", "8.4"]) == "8.0"
    assert L.major_of("1.2", ["17"]) is None


def test_eks_versions_flag_forced_upgrades_not_cost():
    info = {"endOfStandardSupportDate": "2026-11-26", "endOfExtendedSupportDate": "2027-11-26"}
    # standard support ending within 60 days with upgrade policy STANDARD: AWS upgrades it
    assert L.judge_eks_support("1.34", info, "STANDARD", TODAY)[0] == "high"
    # the same with extended support on: a low note, nothing is forced for a year
    assert L.judge_eks_support("1.34", info, "EXTENDED", TODAY)[0] == "low"
    far = {"endOfStandardSupportDate": "2027-03-27", "endOfExtendedSupportDate": "2028-03-27"}
    assert L.judge_eks_support("1.35", far, "EXTENDED", TODAY) is None
    past = {"endOfStandardSupportDate": "2025-11-26", "endOfExtendedSupportDate": "2026-11-26"}
    assert L.judge_eks_support("1.31", past, "EXTENDED", TODAY)[0] == "high"


def test_operating_systems_match_the_names_systems_manager_reports():
    assert L.os_end("Amazon Linux", "2")[0] == "2026-06-30"
    assert L.os_end("Amazon Linux", "2023") is None
    assert L.os_end("Microsoft Windows Server 2012 R2 Datacenter", "6.3.9600")[0] == "2023-10-10"
    assert L.os_end("Microsoft Windows Server 2019 Datacenter", "10.0.17763")[0] == "2029-01-09"
    assert L.os_end("Red Hat Enterprise Linux", "7.9")[0] == "2024-06-30"
    assert L.os_end("Red Hat Enterprise Linux", "8.10") is None
    assert L.os_end("Ubuntu", "20.04")[0] == "2025-05-31"
    assert L.os_end("Ubuntu", "24.04") is None


def test_workload_images_outside_ecr_pulled_always_or_failing():
    def deploy(name, image, policy=None):
        c = {"name": "c", "image": image, **({"imagePullPolicy": policy} if policy else {})}
        template = {"metadata": {"labels": {"app": name}}, "spec": {"containers": [c]}}
        return {"metadata": {"namespace": "pay", "name": name}, "spec": {"replicas": 2, "template": template}}

    lists = {
        "/apis/apps/v1/deployments": [
            deploy("api", "artifacts.example.com/pay/api:1.4.2"),
            deploy("web", "artifacts.example.com/pay/web:latest"),
            deploy("own", "123456789012.dkr.ecr.eu-west-1.amazonaws.com/own:3", "Always"),
        ],
        "/apis/apps/v1/statefulsets": [],
        "/apis/autoscaling/v2/horizontalpodautoscalers": [],
        "/apis/policy/v1/poddisruptionbudgets": [],
        "/api/v1/pods": [
            {
                "metadata": {"namespace": "pay", "name": "api-7d9f8c6b5-x2k4p",
                             "ownerReferences": [{"kind": "ReplicaSet", "name": "api-7d9f8c6b5"}]},
                "status": {"phase": "Pending",
                           "containerStatuses": [{"state": {"waiting": {"reason": "ImagePullBackOff"}}}]},
            }
        ],
    }  # fmt: skip
    got = collector.read_workloads(lambda path, cap: lists[path])
    by = {w["name"]: w for w in got["workloads"]}
    assert by["api"]["registries"] == ["artifacts.example.com"] and not by["api"].get("pull_always")
    assert by["web"]["pull_always"] and by["api"]["pull_failed"] == 1
    assert "registries" not in by["own"]  # ECR: not a registry outside AWS, and not flagged for Always
    rows = workload_rows({"name": "c1", "region": "eu-west-1", "access": "read", **got}, OutageAnswers())
    found = {r["rule"]: r for r in rows if r["rule"].startswith("image_")}
    assert found["image_registry_outside"]["res"] == "c1 from artifacts.example.com"
    assert found["image_registry_outside"]["used"] == 2
    assert found["image_pull_always"]["used"] == 1 and "pay/web" in found["image_pull_always"]["note"]
    assert found["image_pull_failing"]["res"] == "c1/pay/api"


def test_series_counts_hours_at_the_limit():
    s = collector.Series()
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    for i, v in enumerate([10, 96, 100, 94.9, 95]):
        s.add(now + timedelta(hours=i), v)
    assert s.hot == 3 and s.n == 5


class _Fake:
    """GetMetricData as AWS answers it: at most 500 series in one call, across all its searches; the searches
    past that return nothing, with a MaxMetricsExceeded message."""

    def __init__(self, sizes: dict[str, int]):
        self.sizes, self.calls = sizes, 0

    def get_paginator(self, op):
        assert op == "list_metrics"
        fake = self

        class _P:
            def paginate(self, **kw):
                n = max(fake.sizes.values())
                yield {"Metrics": [{"Dimensions": [{"Name": "InstanceId", "Value": f"r{i}"}]} for i in range(n)]}

        return _P()

    def get_metric_data(self, MetricDataQueries, **_):
        self.calls += 1
        left, results, cut = collector.METRIC_SERIES_MAX, [], False
        for q in MetricDataQueries:
            if "MetricStat" in q:  # one series, read by name
                results.append({"Label": q["Label"], "Timestamps": [datetime(2026, 11, 1)], "Values": [1.0]})
                left -= 1
                continue
            n = self.sizes[q["Id"]]
            if n > left:
                cut = True
                continue
            left -= n
            for i in range(n):
                results.append({"Label": f"{q['Id']}~r{i}", "Timestamps": [datetime(2026, 11, 1)], "Values": [1.0]})
        return {"MetricDataResults": results, "Messages": [{"Code": "MaxMetricsExceeded"}] if cut else []}


def test_metric_batches_split_until_every_series_is_read(monkeypatch):
    monkeypatch.setattr(collector, "with_backoff", lambda fn, transient=False, **kw: fn(**kw))
    sizes = {"q0": 300, "q1": 300, "q2": 5, "q3": 6}  # the last two, database metrics, used to come back empty
    ids = {"q0": "ec2_cpu", "q1": "ebs_burst", "q2": "rds_cpu", "q3": "rds_acu"}
    ctx = collector.OutageCtx(None, "111111111111", ["eu-west-1"], {})
    out = {k: {} for k in ids.values()}
    queries = [{"Id": q} for q in sizes]
    collector._gather_split(_Fake(sizes), queries, None, None, ids, out, ctx, "eu-west-1")
    assert {k: len(v) for k, v in out.items()} == {"ec2_cpu": 300, "ebs_burst": 300, "rds_cpu": 5, "rds_acu": 6}
    assert not ctx.r.facts.get("metrics_cut")


def test_a_search_too_big_for_one_read_is_listed_and_read_by_name(monkeypatch):
    monkeypatch.setattr(collector, "with_backoff", lambda fn, transient=False, **kw: fn(**kw))
    monkeypatch.setattr(collector, "_live_ids", lambda ctx, region, dims: {f"r{i}" for i in range(850)})
    ids = {"q0": "ec2_cpu"}  # 900 series: more than one search returns; 850 of the instances exist now
    ctx = collector.OutageCtx(None, "111111111111", ["eu-west-1"], {})
    out = {"ec2_cpu": {}}
    collector._gather_split(_Fake({"q0": 900}), [{"Id": "q0"}], None, None, ids, out, ctx, "eu-west-1")
    assert len(out["ec2_cpu"]) == 850 and not ctx.r.facts.get("metrics_cut")


def test_a_search_that_cannot_be_read_whole_is_shown_as_not_measured(monkeypatch):
    monkeypatch.setattr(collector, "with_backoff", lambda fn, transient=False, **kw: fn(**kw))
    ids = {"q0": "disk_used"}  # the agent's disk metric has no fixed dimensions to list by
    ctx = collector.OutageCtx(None, "111111111111", ["eu-west-1"], {})
    collector._gather_split(_Fake({"q0": 900}), [{"Id": "q0"}], None, None, ids, {"disk_used": {}}, ctx, "eu-west-1")
    assert ctx.r.facts["metrics_cut"] is True
    fixed = ctx.r.finish()["fixed"]
    assert fixed["status"] == "unknown" and "disk_used in eu-west-1" in fixed["note"]  # the report counts it unread
    ctx.r.ok("fixed")  # the other reads passed: still shown as measured only in part
    assert "not measured" in ctx.r.finish()["fixed"]["note"]


def test_aws_default_quotas_are_read_once_per_region_and_service():
    from exitrisk.collectors import outage

    calls = []

    class SQ:
        def can_paginate(self, op):
            return False

        def list_aws_default_service_quotas(self, **kw):
            calls.append(kw["ServiceCode"])
            return {"Quotas": [{"QuotaCode": "L-1", "Value": 5.0}]}

    for _ in range(3):
        assert outage._default_quotas(SQ(), "eu-west-1", "ec2") == [{"QuotaCode": "L-1", "Value": 5.0}]
    outage._default_quotas(SQ(), "us-east-1", "ec2")
    assert calls == ["ec2", "ec2"]
