"""Outage risk checks inside one member account (the "outage" scan).

Reads what is close to a limit before a peak: Service Quotas against their usage metrics, account
limits, utilisation of capacity that cannot grow by itself, storage and how fast it fills, MSK
brokers, Amazon Connect, subnets, and the workloads inside each EKS cluster.

Nothing is judged here. Each measure is kept as a row (rule, resource, used, limit, percent) and
report/outage.py decides its severity from the answers given in the report, so changing the peak
date or the expected load needs no new scan. Rows below KEEP_PCT are not kept: even at the highest
load the report allows they would not reach a limit.

Everything is read-only and no object, log line or secret is read. Kubernetes is read with the scan
role's own identity and only if that identity has been given read access to the cluster; the scan
never adds an access entry. A cluster it cannot read is recorded as not read, never as a pass.

CloudWatch is read through SEARCH expressions, one per metric per region rather than one per
resource. It is billed at US$0.01 per 1,000 metrics returned.
"""

from __future__ import annotations

import base64
import contextvars
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import with_backoff
from ..issues import Issue, describe_exception
from ..logging_config import get_logger
from .assurance import _NOT_HERE, Ctx, _code, _collapse, _pages, _run

log = get_logger("outage")

WORKERS = 16
LOOKBACK_DAYS = 35  # long enough to hold a month-end, when a bank's load peaks
PERIOD = 3600  # hourly averages: a real peak, without one-minute spikes
RATE_DAYS, RATE_PERIOD = 14, 300  # API rate quotas are per second or minute: read finer
KEEP_PCT = 30.0  # the report's highest load multiplier is 3
MAX_ROWS = 800  # per account, worst first
MAX_ITEMS = 2000  # volumes, services, ... read per region
MAX_WORKLOADS = 1500  # per cluster
MAX_PODS = 8000  # per cluster
K8S_TIMEOUT = 8
CERT_DAYS = 120
RENEWAL_DAYS = 60  # ACM starts renewing this long before expiry: a renewal still not done by then has stalled
METRIC_BATCH = 100
METRIC_SERIES_MAX = 500  # time series one GetMetricData call returns, across its searches
LISTED_MAX = 5000  # series of one metric read by name, when one search has more than a call returns
MIB, GIB = 1024**2, 1024**3
EFS_BURST_MAX = 2.31 * 1024**4  # a file system starts with, and can bank, 2.31 TiB of credits

# Service Quotas codes read, and the billed service that makes each one worth reading (None: always).
QUOTA_SERVICES = {
    "ec2": None,
    "vpc": None,
    "ebs": None,
    "elasticloadbalancing": None,
    "autoscaling": None,
    "lambda": None,
    "iam": None,
    "s3": None,
    "kms": None,
    "cloudformation": None,
    "route53": None,
    "route53resolver": "Amazon Route 53",
    "logs": None,
    "rds": "Amazon Relational Database Service",
    "dynamodb": "Amazon DynamoDB",
    "connect": "Amazon Connect",
    "eks": "Amazon Elastic Container Service for Kubernetes",
    "kafka": "Amazon Managed Streaming for Apache Kafka",
    "elasticache": "Amazon ElastiCache",
    "kinesis": "Amazon Kinesis",
    "sqs": "Amazon Simple Queue Service",
    "sns": "Amazon Simple Notification Service",
    "apigateway": "Amazon API Gateway",
    "ecs": "Amazon Elastic Container Service",
    "fargate": "Amazon Elastic Container Service",
    "es": "Amazon OpenSearch Service",
    "elasticfilesystem": "Amazon Elastic File System",
    "secretsmanager": "AWS Secrets Manager",
    "states": "AWS Step Functions",
    "events": "Amazon EventBridge",
    "ecr": "Amazon EC2 Container Registry (ECR)",
    "cloudfront": "Amazon CloudFront",
    "wafv2": "AWS WAF",
    "cognito-idp": "Amazon Cognito",
    "ssm": "AWS Systems Manager",
    "firehose": "Amazon Kinesis Firehose",
    "glue": "AWS Glue",
    "athena": "Amazon Athena",
    "sagemaker": "Amazon SageMaker",
    "bedrock": "Amazon Bedrock",
    "ses": "Amazon Simple Email Service",
    "mq": "Amazon MQ",
    "redshift": "Amazon Redshift",
    "elasticmapreduce": "Amazon Elastic MapReduce",
    "batch": "AWS Batch",
    "appsync": "AWS AppSync",
}
ACCOUNT_QUOTAS = ("ec2", "vpc", "ebs", "iam", "route53", "autoscaling")
# Usage that rises with traffic, as opposed to a count of things someone has created.
LOAD_QUOTA = re.compile(r"vcpu|concurrent|network interface|throughput|active|running|per second", re.I)
# AWS's guidance for partitions per broker, by broker size.
MSK_PARTITIONS = {
    "t3.small": 300,
    "m5.large": 1000,
    "m5.xlarge": 1000,
    "m7g.large": 1000,
    "m7g.xlarge": 1000,
    "m5.2xlarge": 2000,
    "m7g.2xlarge": 2000,
}
MSK_PARTITIONS_LARGE = 4000
# Burstable (T-family) sizes: the CPU each vCPU sustains without spending credits, in percent, from
# AWS's instance type pages. CPUUtilization is a share of all vCPUs, so it compares directly.
_T3_BASELINE = {"nano": 5, "micro": 10, "small": 20, "medium": 20, "large": 30, "xlarge": 40, "2xlarge": 40}
BURST_BASELINE = {
    "t2": {"nano": 5, "micro": 10, "small": 20, "medium": 20, "large": 30, "xlarge": 22.5, "2xlarge": 16.9},
    "t3": _T3_BASELINE,
    "t3a": _T3_BASELINE,
    "t4g": _T3_BASELINE,
}
BURST_TYPE = re.compile(r"^(?:db\.|cache\.|kafka\.)?(t2|t3a?|t4g)\.(\w+?)(?:\.search|\.elasticsearch)?$")
CREDITS_LOW = 5  # a balance this low means the credits ran out in the window
# ENA driver counters of packets queued or dropped for passing an instance allowance. They only rise
# (until a reboot), so a rise from the window's lowest value to its latest means the allowance was passed.
ETHTOOL = {
    "net_bw_in": "ethtool_bw_in_allowance_exceeded",
    "net_bw_out": "ethtool_bw_out_allowance_exceeded",
    "net_pps": "ethtool_pps_allowance_exceeded",
    "net_conntrack": "ethtool_conntrack_allowance_exceeded",
    "net_linklocal": "ethtool_linklocal_allowance_exceeded",
}
ETHTOOL_WHAT = {
    "net_bw_in": "inbound bandwidth",
    "net_bw_out": "outbound bandwidth",
    "net_pps": "packets a second",
    "net_conntrack": "connection tracking",
}
# Amazon Connect objects counted per instance: (a phrase in the quota's name, the call, its result key, arguments).
CONNECT_COUNTS = (
    ("users per instance", "list_users", "UserSummaryList", {}),
    ("queues per instance", "list_queues", "QueueSummaryList", {}),
    ("phone numbers per instance", "list_phone_numbers", "PhoneNumberSummaryList", {}),
    ("routing profiles per instance", "list_routing_profiles", "RoutingProfileSummaryList", {}),
    ("flows per instance", "list_contact_flows", "ContactFlowSummaryList", {}),
)
SYSTEM_ACCESS = (401, 403)


# --------------------------------------------------------------------------------- one CloudWatch series
class Series:
    """A metric's maximum, minimum, latest value, total and trend, without keeping its datapoints."""

    __slots__ = ("high", "hot", "last", "low", "n", "sx", "sxx", "sxy", "sy", "total")
    HOT = 95.0  # a percentage at or above this counts as an hour at the limit

    def __init__(self) -> None:
        self.n = 0
        self.hot = 0
        self.high = float("-inf")
        self.low = float("inf")
        self.last = 0.0
        self.total = 0.0
        self.sx = self.sy = self.sxx = self.sxy = 0.0

    def add(self, when: datetime, value: float) -> None:
        day = when.timestamp() / 86400
        self.n += 1
        if value >= self.HOT:
            self.hot += 1
        self.high = max(self.high, value)
        self.low = min(self.low, value)
        self.last = value
        self.total += value
        self.sx += day
        self.sy += value
        self.sxx += day * day
        self.sxy += day * value

    def slope(self) -> float:
        """Change per day, by least squares (0 with too little data to say)."""
        if self.n < 48:
            return 0.0
        denom = self.n * self.sxx - self.sx**2
        return (self.n * self.sxy - self.sx * self.sy) / denom if denom else 0.0


def days_until(level: float, target: float, slope: float) -> float | None:
    """Days for a value now at ``level`` to reach ``target`` at ``slope`` per day (None: not heading there)."""
    if (target - level) * slope <= 0:
        return None
    return round((target - level) / slope, 1)


def _search(namespace: str, dims: tuple[str, ...], metric: str, stat: str) -> str:
    schema = ",".join([namespace, *(f'"{d}"' for d in dims)])
    return f"SEARCH('{{{schema}}} MetricName=\"{metric}\"', '{stat}', {PERIOD})"


# id: (namespace, dimensions, metric, statistic, billed service needed or None).
METRICS = {
    "ec2_cpu": ("AWS/EC2", ("InstanceId",), "CPUUtilization", "Average", None),
    "ec2_credits": ("AWS/EC2", ("InstanceId",), "CPUCreditBalance", "Minimum", None),
    "ebs_burst": ("AWS/EBS", ("VolumeId",), "BurstBalance", "Minimum", None),
    "ebs_iops": ("AWS/EBS", ("VolumeId",), "VolumeIOPSExceededCheck", "Maximum", None),
    "ebs_tput": ("AWS/EBS", ("VolumeId",), "VolumeThroughputExceededCheck", "Maximum", None),
    "ebs_rops": ("AWS/EBS", ("VolumeId",), "VolumeReadOps", "Sum", None),
    "ebs_wops": ("AWS/EBS", ("VolumeId",), "VolumeWriteOps", "Sum", None),
    "ebs_rbytes": ("AWS/EBS", ("VolumeId",), "VolumeReadBytes", "Sum", None),
    "ebs_wbytes": ("AWS/EBS", ("VolumeId",), "VolumeWriteBytes", "Sum", None),
    "ec2_ebsio": ("AWS/EC2", ("InstanceId",), "EBSIOBalance%", "Minimum", None),
    "ec2_ebsbyte": ("AWS/EC2", ("InstanceId",), "EBSByteBalance%", "Minimum", None),
    "rds_cpu": (
        "AWS/RDS",
        ("DBInstanceIdentifier",),
        "CPUUtilization",
        "Average",
        "Amazon Relational Database Service",
    ),
    "rds_free": (
        "AWS/RDS",
        ("DBInstanceIdentifier",),
        "FreeStorageSpace",
        "Minimum",
        "Amazon Relational Database Service",
    ),
    "rds_burst": (
        "AWS/RDS",
        ("DBInstanceIdentifier",),
        "BurstBalance",
        "Minimum",
        "Amazon Relational Database Service",
    ),
    "rds_ebsio": (
        "AWS/RDS",
        ("DBInstanceIdentifier",),
        "EBSIOBalance%",
        "Minimum",
        "Amazon Relational Database Service",
    ),
    "rds_ebsbyte": (
        "AWS/RDS",
        ("DBInstanceIdentifier",),
        "EBSByteBalance%",
        "Minimum",
        "Amazon Relational Database Service",
    ),
    "rds_credits": (
        "AWS/RDS",
        ("DBInstanceIdentifier",),
        "CPUCreditBalance",
        "Minimum",
        "Amazon Relational Database Service",
    ),
    "rds_riops": ("AWS/RDS", ("DBInstanceIdentifier",), "ReadIOPS", "Average", "Amazon Relational Database Service"),
    "rds_wiops": ("AWS/RDS", ("DBInstanceIdentifier",), "WriteIOPS", "Average", "Amazon Relational Database Service"),
    "rds_acu": (
        "AWS/RDS",
        ("DBInstanceIdentifier",),
        "ACUUtilization",
        "Average",
        "Amazon Relational Database Service",
    ),
    "cache_cpu": (
        "AWS/ElastiCache",
        ("CacheClusterId", "CacheNodeId"),
        "EngineCPUUtilization",
        "Average",
        "Amazon ElastiCache",
    ),
    "cache_mem": (
        "AWS/ElastiCache",
        ("CacheClusterId", "CacheNodeId"),
        "DatabaseMemoryUsagePercentage",
        "Maximum",
        "Amazon ElastiCache",
    ),
    "cache_evict": ("AWS/ElastiCache", ("CacheClusterId", "CacheNodeId"), "Evictions", "Sum", "Amazon ElastiCache"),
    "search_cpu": ("AWS/ES", ("ClientId", "DomainName"), "CPUUtilization", "Average", "Amazon OpenSearch Service"),
    "search_jvm": ("AWS/ES", ("ClientId", "DomainName"), "JVMMemoryPressure", "Maximum", "Amazon OpenSearch Service"),
    "search_free": ("AWS/ES", ("ClientId", "DomainName"), "FreeStorageSpace", "Minimum", "Amazon OpenSearch Service"),
    "search_red": ("AWS/ES", ("ClientId", "DomainName"), "ClusterStatus.red", "Maximum", "Amazon OpenSearch Service"),
    "redshift_cpu": ("AWS/Redshift", ("ClusterIdentifier",), "CPUUtilization", "Average", "Amazon Redshift"),
    "redshift_disk": ("AWS/Redshift", ("ClusterIdentifier",), "PercentageDiskSpaceUsed", "Maximum", "Amazon Redshift"),
    "efs_credits": ("AWS/EFS", ("FileSystemId",), "BurstCreditBalance", "Minimum", "Amazon Elastic File System"),
    "efs_io": ("AWS/EFS", ("FileSystemId",), "PercentIOLimit", "Maximum", "Amazon Elastic File System"),
    "fsx_used": ("AWS/FSx", ("FileSystemId",), "StorageCapacityUtilization", "Maximum", "Amazon FSx"),
    "ddb_rcu": ("AWS/DynamoDB", ("TableName",), "ConsumedReadCapacityUnits", "Sum", "Amazon DynamoDB"),
    "ddb_wcu": ("AWS/DynamoDB", ("TableName",), "ConsumedWriteCapacityUnits", "Sum", "Amazon DynamoDB"),
    "ddb_prcu": ("AWS/DynamoDB", ("TableName",), "ProvisionedReadCapacityUnits", "Average", "Amazon DynamoDB"),
    "ddb_pwcu": ("AWS/DynamoDB", ("TableName",), "ProvisionedWriteCapacityUnits", "Average", "Amazon DynamoDB"),
    "ddb_rthrottle": ("AWS/DynamoDB", ("TableName",), "ReadThrottleEvents", "Sum", "Amazon DynamoDB"),
    "ddb_wthrottle": ("AWS/DynamoDB", ("TableName",), "WriteThrottleEvents", "Sum", "Amazon DynamoDB"),
    "lambda_throttle": ("AWS/Lambda", ("FunctionName",), "Throttles", "Sum", "AWS Lambda"),
    "lambda_conc": ("AWS/Lambda", (), "ConcurrentExecutions", "Maximum", "AWS Lambda"),
    "kin_write": ("AWS/Kinesis", ("StreamName",), "WriteProvisionedThroughputExceeded", "Sum", "Amazon Kinesis"),
    "kin_read": ("AWS/Kinesis", ("StreamName",), "ReadProvisionedThroughputExceeded", "Sum", "Amazon Kinesis"),
    "nat_ports": ("AWS/NATGateway", ("NatGatewayId",), "ErrorPortAllocation", "Sum", None),
    "alb_rejected": ("AWS/ApplicationELB", ("LoadBalancer",), "RejectedConnectionCount", "Sum", None),
    "nlb_ports": ("AWS/NetworkELB", ("LoadBalancer",), "PortAllocationErrorCount", "Sum", None),
    "dx_in": ("AWS/DX", ("ConnectionId",), "ConnectionBpsIngress", "Maximum", "AWS Direct Connect"),
    "dx_out": ("AWS/DX", ("ConnectionId",), "ConnectionBpsEgress", "Maximum", "AWS Direct Connect"),
    "ecs_cpu": (
        "AWS/ECS",
        ("ClusterName", "ServiceName"),
        "CPUUtilization",
        "Average",
        "Amazon Elastic Container Service",
    ),
    "ecs_mem": (
        "AWS/ECS",
        ("ClusterName", "ServiceName"),
        "MemoryUtilization",
        "Average",
        "Amazon Elastic Container Service",
    ),
    "msk_disk": (
        "AWS/Kafka",
        ("Cluster Name", "Broker ID"),
        "KafkaDataLogsDiskUsed",
        "Maximum",
        "Amazon Managed Streaming for Apache Kafka",
    ),
    "msk_user": (
        "AWS/Kafka",
        ("Cluster Name", "Broker ID"),
        "CpuUser",
        "Average",
        "Amazon Managed Streaming for Apache Kafka",
    ),
    "msk_sys": (
        "AWS/Kafka",
        ("Cluster Name", "Broker ID"),
        "CpuSystem",
        "Average",
        "Amazon Managed Streaming for Apache Kafka",
    ),
    "msk_parts": (
        "AWS/Kafka",
        ("Cluster Name", "Broker ID"),
        "PartitionCount",
        "Maximum",
        "Amazon Managed Streaming for Apache Kafka",
    ),
    "connect_pct": (
        "AWS/Connect",
        ("InstanceId", "MetricGroup"),
        "ConcurrentCallsPercentage",
        "Maximum",
        "Amazon Connect",
    ),
    "connect_throttled": ("AWS/Connect", ("InstanceId", "MetricGroup"), "ThrottledCalls", "Sum", "Amazon Connect"),
    "connect_breach": (
        "AWS/Connect",
        ("InstanceId", "MetricGroup"),
        "CallsBreachingConcurrencyQuota",
        "Sum",
        "Amazon Connect",
    ),
    "s3_5xx": ("AWS/S3", ("BucketName", "FilterId"), "5xxErrors", "Sum", None),
    "s3_get": ("AWS/S3", ("BucketName", "FilterId"), "GetRequests", "Sum", None),
    "s3_put": ("AWS/S3", ("BucketName", "FilterId"), "PutRequests", "Sum", None),
    "ci_mem": (
        "ContainerInsights",
        ("ClusterName", "Namespace", "PodName"),
        "pod_memory_utilization_over_pod_limit",
        "Average",
        "Amazon Elastic Container Service for Kubernetes",
    ),
    "ci_cpu": (
        "ContainerInsights",
        ("ClusterName", "Namespace", "PodName"),
        "pod_cpu_utilization_over_pod_limit",
        "Average",
        "Amazon Elastic Container Service for Kubernetes",
    ),
}


class OutageCtx(Ctx):
    """An account's reads: the rows found, and each region's CloudWatch metrics read once."""

    what = "outage"

    def __init__(self, session, account_id: str, regions: list[str], info: dict):
        super().__init__(session, account_id, regions, info)
        self.rows: list[dict] = []
        self.clusters: list[dict] = []
        self.compared = 0
        self.subnets: dict[str, list[dict]] = {}
        self.eks_subnets: dict[str, dict[str, str]] = {}
        self.quota_values: dict[str, dict[str, float]] = {}
        self.profiles: list[dict] = []  # what each resource is set to, for the per-service reviews
        self.alarm_wants: list[tuple[str, str, str, str]] = []
        self.lambda_subnets: list[tuple[str, str, str, list[str]]] = []
        self.alarms: dict[str, set[tuple[str, str, str]]] = {}
        self._metric_locks = {r: threading.Lock() for r in regions}
        self._metrics: dict[str, dict | Exception] = {}

    def add(
        self,
        rule: str,
        res: str,
        region: str,
        pct: float | None = None,
        used=None,
        limit=None,
        unit: str = "",
        load: bool = False,
        days: float | None = None,
        note: str = "",
        **extra,
    ) -> None:
        """One measure. A capacity measure under KEEP_PCT is counted as compared and not kept."""
        with self._lock:
            self.compared += 1
            if pct is not None and pct < KEEP_PCT and days is None:
                return
            row = {"rule": rule, "res": res, "region": region, **extra}
            if pct is not None:
                row["pct"] = round(pct, 1)
            for k, v in (("used", used), ("limit", limit), ("unit", unit), ("days", days), ("note", note)):
                if v not in (None, ""):
                    row[k] = round(v, 2) if isinstance(v, float) else v
            if load:
                row["load"] = True
            self.rows.append(row)

    def metrics(self, region: str) -> dict[str, dict[str, Series]]:
        """{metric id: {resource: Series}} for the region, read once by whichever task asks first."""
        with self._metric_locks[region]:
            if region not in self._metrics:
                try:
                    self._metrics[region] = _read_metrics(self, region)
                except (ClientError, BotoCoreError, TimeoutError) as exc:
                    self._metrics[region] = exc
            got = self._metrics[region]
        if isinstance(got, Exception):
            raise got
        return got


def _read_metrics(ctx: OutageCtx, region: str) -> dict[str, dict[str, Series]]:
    wanted = {k: v for k, v in METRICS.items() if v[4] is None or ctx.billed(v[4])}
    queries = []
    ids = {}
    for i, (key, (ns, dims, metric, stat, _)) in enumerate(wanted.items()):
        qid = f"q{i}"
        ids[qid] = key
        label = "|".join(f"${{PROP('Dim.{d}')}}" for d in dims) or "all"
        queries.append(
            {"Id": qid, "Expression": _search(ns, dims, metric, stat), "Label": f"{qid}~{label}", "ReturnData": True}
        )
    if ctx.billed("Amazon CloudWatch", "AmazonCloudWatch"):
        qid = "qdisk"
        ids[qid] = "disk_used"
        queries.append(
            {
                "Id": qid,
                "Expression": f"SEARCH('Namespace=\"CWAgent\" MetricName=\"disk_used_percent\"', 'Maximum', {PERIOD})",
                "Label": f"{qid}~${{PROP('Dim.InstanceId')}}|${{PROP('Dim.path')}}",
                "ReturnData": True,
            }
        )
        # The ENA allowance counters, where the CloudWatch agent publishes them (ethtool plugin).
        for key, metric in ETHTOOL.items():
            qid = f"q{key}"
            ids[qid] = key
            queries.append(
                {
                    "Id": qid,
                    "Expression": f"SEARCH('Namespace=\"CWAgent\" MetricName=\"{metric}\"', 'Maximum', {PERIOD})",
                    "Label": f"{qid}~${{PROP('Dim.InstanceId')}}|${{PROP('Dim.interface')}}",
                    "ReturnData": True,
                }
            )
    # Every metric has an entry, read or not: a task shared by two services may have only one billed.
    out: dict[str, dict[str, Series]] = {key: {} for key in (*METRICS, *ETHTOOL, *ids.values())}
    cw = ctx.client("cloudwatch", region)
    end = ctx.now
    start = end - timedelta(days=LOOKBACK_DAYS)
    for at in range(0, len(queries), METRIC_BATCH):
        _gather_split(cw, queries[at : at + METRIC_BATCH], start, end, ids, out, ctx, region)
    return out


def _gather_split(cw, queries: list[dict], start, end, ids: dict, out: dict, ctx: OutageCtx, region: str) -> None:
    """Read the queries, splitting the batch in two while it passes the limit. GetMetricData returns at
    most METRIC_SERIES_MAX time series in one call, across all its searches, and the searches past it
    return nothing: in a busy account the database and cache metrics read last came back empty."""
    got: dict[str, dict[str, Series]] = {}
    if not _gather(cw, queries, start, end, ids, got, ctx, region) or len(queries) == 1:
        if len(queries) == 1 and "_cut" in got and ids.get(queries[0]["Id"]) in METRICS:
            # One search with more series than a call returns: list them, then read them by name.
            listed: dict[str, dict[str, Series]] = {}
            try:
                if not _gather_listed(
                    cw, queries[0]["Id"], ids[queries[0]["Id"]], start, end, ids, listed, ctx, region
                ):
                    got = listed  # every series read
            except ClientError as exc:  # no cloudwatch:ListMetrics: keep the first series, shown as cut
                log.info("outage %s %s: listing metrics failed: %s", ctx.account_id, region, _code(exc))
        if len(queries) == 1 and "_cut" in got:
            ctx.r.fact("metrics_cut", True)
            # Loud, not a quiet note: the check shows as not fully measured, and Complete the scan reads it again.
            ctx.r.unknown("fixed", f"{ids.get(queries[0]['Id'])} in {region} has more series than one read returns")
            log.info(
                "outage %s %s: metric %s has more series than one read returns",
                ctx.account_id,
                region,
                ids.get(queries[0]["Id"]),
            )
        for key, series in got.items():
            if key != "_cut":
                out[key].update(series)
        return
    half = len(queries) // 2
    _gather_split(cw, queries[:half], start, end, ids, out, ctx, region)
    _gather_split(cw, queries[half:], start, end, ids, out, ctx, region)


_LIVE = {
    "VolumeId": ("describe_volumes", "Volumes", "VolumeId", {}),
    "InstanceId": ("describe_instances", "Reservations", None,
                   {"Filters": [{"Name": "instance-state-name", "Values": ["pending", "running", "stopping"]}]}),
}  # fmt: skip


def _live_ids(ctx: OutageCtx, region: str, dims: tuple[str, ...]) -> set[str] | None:
    """The EC2 instances or EBS volumes that exist now, read once per region; None for other metrics."""
    if len(dims) != 1 or dims[0] not in _LIVE:
        return None
    cache = ctx.__dict__.setdefault("_live", {})
    if (region, dims[0]) not in cache:
        op, key, field, kwargs = _LIVE[dims[0]]
        found = _pages(ctx.client("ec2", region), op, key, **kwargs)
        if field is None:  # reservations hold the instances
            cache[(region, dims[0])] = {i["InstanceId"] for r in found for i in r.get("Instances") or []}
        else:
            cache[(region, dims[0])] = {v[field] for v in found}
    return cache[(region, dims[0])]


def _gather_listed(cw, qid: str, key: str, start, end, ids: dict, out: dict, ctx: OutageCtx, region: str) -> bool:
    """Read every series of one metric by name, METRIC_SERIES_MAX at a time. True if some still could not be read."""
    ns, dims, metric, stat, _ = METRICS[key]
    found = []
    # Only what reported in the last three hours: a busy cluster leaves tens of thousands of volumes behind it.
    for page in cw.get_paginator("list_metrics").paginate(
        Namespace=ns, MetricName=metric, Dimensions=[{"Name": d} for d in dims], RecentlyActive="PT3H"
    ):
        for m in page.get("Metrics") or []:
            got = {d["Name"]: d["Value"] for d in m.get("Dimensions") or []}
            if set(got) == set(dims):  # the same dimensions as the search, no more
                found.append(got)
    live = _live_ids(ctx, region, dims)
    if live is not None:  # read only what exists now: a volume deleted last week is no outage risk
        found = [got for got in found if got[dims[0]] in live]
    cut = len(found) > LISTED_MAX
    found = found[:LISTED_MAX]
    for at in range(0, len(found), METRIC_SERIES_MAX):
        queries = []
        for i, got in enumerate(found[at : at + METRIC_SERIES_MAX]):
            stat_q = {"Metric": {"Namespace": ns, "MetricName": metric,
                                 "Dimensions": [{"Name": d, "Value": got[d]} for d in dims]},
                      "Period": PERIOD, "Stat": stat}  # fmt: skip
            label = "|".join(got[d] for d in dims)
            queries.append({"Id": f"l{i}", "MetricStat": stat_q, "Label": f"{qid}~{label}", "ReturnData": True})
        cut = _gather(cw, queries, start, end, ids, out, ctx, region) or cut
    return cut


def _gather(cw, queries: list[dict], start, end, ids: dict, out: dict, ctx: OutageCtx, region: str) -> bool:
    """Read one batch into ``out``; True when it passed the series limit, so some searches were cut."""
    token = None
    cut = False
    while True:
        kwargs = {"MetricDataQueries": queries, "StartTime": start, "EndTime": end, "ScanBy": "TimestampAscending"}
        if token:
            kwargs["NextToken"] = token
        resp = with_backoff(cw.get_metric_data, transient=True, **kwargs)
        for r in resp.get("MetricDataResults") or []:
            qid, _, res = str(r.get("Label") or "").partition("~")
            key = ids.get(qid)
            if key is None:
                continue
            if r.get("StatusCode") in ("InternalError", "Forbidden"):
                ctx.r.fact("metrics_cut", True)
                ctx.r.unknown("fixed", f"{key} in {region} answered {r['StatusCode']}")
                log.warning("outage %s %s: metric %s answered %s", ctx.account_id, region, key, r["StatusCode"])
            series = out.setdefault(key, {}).setdefault(res, Series())
            for when, value in zip(r.get("Timestamps") or [], r.get("Values") or [], strict=False):
                series.add(when, value)
        if any(m.get("Code") == "MaxMetricsExceeded" for m in resp.get("Messages") or []):
            cut = True
        token = resp.get("NextToken")
        if not token:
            if cut:
                out["_cut"] = {}
            return cut


def _short(arn_or_id: str) -> str:
    return arn_or_id.rsplit("/", 1)[-1].rsplit(":", 1)[-1]


# ------------------------------------------------------------------------------------------ limits
# AWS's default quotas are the same in every account of a region, so they are read once per region and
# service for the life of the process, not again in each of hundreds of accounts. Only the values applied
# in the account are read per account. EC2 alone lists about 1,750 quotas, 100 to a page.
_DEFAULTS: dict[tuple[str, str], list[dict]] = {}
_DEFAULTS_LOCK = threading.Lock()
_DEFAULTS_KEYS: dict[tuple[str, str], threading.Lock] = {}
QUOTA_WORKERS = 4  # services read at once in a region; Service Quotas throttles beyond a few calls a second


def clear_quota_defaults() -> None:
    with _DEFAULTS_LOCK:
        _DEFAULTS.clear()
        _DEFAULTS_KEYS.clear()


QUOTA_PAGE = 100  # the largest page Service Quotas returns; its default of 20 needs five times the calls


def _quota_pages(sq, op: str, code: str) -> list[dict]:
    """Every quota ``op`` lists for ``code``, 100 to a page. A throttled page is retried on its own:
    retrying the whole read restarted EC2's 17 pages (83 at the default size) from the first."""
    out: list[dict] = []
    kwargs = {"ServiceCode": code, "MaxResults": QUOTA_PAGE}
    while True:
        page = with_backoff(getattr(sq, op), transient=True, **kwargs)
        out.extend(page.get("Quotas") or [])
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _default_quotas(sq, region: str, code: str) -> list[dict]:
    key = (region, code)
    with _DEFAULTS_LOCK:
        if key in _DEFAULTS:
            return _DEFAULTS[key]
        one = _DEFAULTS_KEYS.setdefault(key, threading.Lock())
    with one:  # one account reads it; the others in this region wait for that read
        with _DEFAULTS_LOCK:
            if key in _DEFAULTS:
                return _DEFAULTS[key]
        found = _quota_pages(sq, "list_aws_default_service_quotas", code)
        if found:  # an empty answer is not kept: the next account asks again
            with _DEFAULTS_LOCK:
                _DEFAULTS[key] = found
        return found


def _service_quotas(sq, region: str, code: str) -> dict[str, dict] | None:
    try:
        quotas = {q["QuotaCode"]: dict(q) for q in _default_quotas(sq, region, code)}
        for q in _quota_pages(sq, "list_service_quotas", code):
            # An applied quota has the value; the default list has the usage metric, and either may lack it.
            quotas[q["QuotaCode"]] = {**quotas.get(q["QuotaCode"], {}), **{k: v for k, v in q.items() if v}}
    except ClientError as exc:
        if _code(exc) in ("NoSuchResourceException", *_NOT_HERE):
            return None
        raise
    return quotas


def task_quotas(ctx: OutageCtx, region: str) -> None:
    """Every quota that publishes a usage metric, against the value that applies in this account."""
    sq = ctx.client("service-quotas", region)
    found: list[tuple[str, dict]] = []
    codes = [code for code, needs in QUOTA_SERVICES.items() if not needs or ctx.billed(needs)]
    base = contextvars.copy_context()  # each thread runs in its own copy, so log lines keep the scan's run id
    with ThreadPoolExecutor(max_workers=QUOTA_WORKERS) as pool:
        futures = [pool.submit(base.copy().run, _service_quotas, sq, region, code) for code in codes]
        read = [f.result() for f in futures]
    for code, quotas in zip(codes, read, strict=True):
        if quotas is None:
            continue
        for q in quotas.values():
            with ctx._lock:
                if q.get("Value"):
                    ctx.quota_values.setdefault(q["QuotaCode"], {})[region] = q["Value"]
            metric = q.get("UsageMetric") or {}
            if metric.get("MetricName") and q.get("Value", 0) > 0:
                if q.get("GlobalQuota") and region != ctx.home:
                    continue
                found.append((code, q))
    _quota_usage(ctx, region, found)


def _quota_usage(ctx: OutageCtx, region: str, found: list[tuple[str, dict]]) -> None:
    cw = ctx.client("cloudwatch", region)
    for at in range(0, len(found), METRIC_BATCH):
        batch = found[at : at + METRIC_BATCH]
        queries = []
        for i, (_, q) in enumerate(batch):
            m = q["UsageMetric"]
            rate = _is_rate(q)
            stat = m.get("MetricStatisticRecommendation") or ("Sum" if rate else "Maximum")
            queries.append(
                {
                    "Id": f"u{i}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": m["MetricNamespace"],
                            "MetricName": m["MetricName"],
                            "Dimensions": [
                                {"Name": k, "Value": v} for k, v in (m.get("MetricDimensions") or {}).items()
                            ],
                        },
                        "Period": _rate_period(q) if rate else PERIOD,
                        "Stat": stat,
                    },
                }
            )
        end = ctx.now
        kwargs = {"MetricDataQueries": queries, "StartTime": end - timedelta(days=RATE_DAYS), "EndTime": end}
        highs: dict[str, float] = {}
        while True:
            resp = with_backoff(cw.get_metric_data, transient=True, **kwargs)
            for r in resp.get("MetricDataResults") or []:
                if r.get("Values"):
                    highs[r["Id"]] = max(highs.get(r["Id"], 0.0), *r["Values"])
            if not resp.get("NextToken"):
                break
            kwargs["NextToken"] = resp["NextToken"]
        for i, (code, q) in enumerate(batch):
            high = highs.get(f"u{i}")
            if high is None:
                continue
            _quota_row(ctx, region, code, q, high)


_PERIOD_SECONDS = {"MICROSECOND": 1e-6, "MILLISECOND": 1e-3, "SECOND": 1, "MINUTE": 60, "HOUR": 3600, "DAY": 86400}


def _quota_seconds(q: dict) -> float:
    per = q.get("Period") or {}
    return per.get("PeriodValue", 1) * _PERIOD_SECONDS.get(per.get("PeriodUnit"), 1)


def _rate_period(q: dict) -> int:
    """Seconds summed per datapoint: RATE_PERIOD for a quota per second or minute, the quota's own period
    for a longer one (up to a day). Scaling five busy minutes up to a day read a daily email quota 8 times over."""
    seconds = _quota_seconds(q)
    return RATE_PERIOD if seconds <= RATE_PERIOD else int(min(seconds, 86400) // 60 * 60)


def _is_rate(q: dict) -> bool:
    """A count of calls in a period. A count of resources has a Period too (an hour for RDS's), but it is a level:
    reading it as a rate reported 7 subnets as 84."""
    return bool(q.get("Period")) and (q.get("UsageMetric") or {}).get("MetricName") != "ResourceCount"


def _quota_row(ctx: OutageCtx, region: str, code: str, q: dict, high: float) -> None:
    per = (q.get("Period") or {}) if _is_rate(q) else {}
    if per:  # a rate: the sum over the period read, as a figure for the quota's own period
        high = high / _rate_period(q) * _quota_seconds(q)
    limit = q["Value"]
    rule = {"s3": "limit_s3", "connect": "limit_connect"}.get(code) or (
        "limit_account" if code in ACCOUNT_QUOTAS else "limit_product"
    )
    ctx.add(
        rule,
        f"{code}: {q.get('QuotaName', q['QuotaCode'])}",
        "global" if q.get("GlobalQuota") else region,
        pct=100.0 * high / limit,
        used=float(high),
        limit=float(limit),
        load=bool(per) or bool(LOAD_QUOTA.search(q.get("QuotaName", ""))),
        qcode=q["QuotaCode"],
        **({} if q.get("Adjustable", True) else {"hard": True}),
    )


def task_account_limits(ctx: OutageCtx) -> None:
    """Limits that come with their own usage in the API, whatever Service Quotas publishes."""
    s = ctx.client("iam").get_account_summary().get("SummaryMap") or {}
    for used, limit, what in (
        ("Roles", "RolesQuota", "IAM roles"),
        ("Policies", "PoliciesQuota", "IAM customer managed policies"),
        ("Users", "UsersQuota", "IAM users"),
        ("Groups", "GroupsQuota", "IAM groups"),
        ("InstanceProfiles", "InstanceProfilesQuota", "IAM instance profiles"),
        ("ServerCertificates", "ServerCertificatesQuota", "IAM server certificates"),
    ):
        if s.get(limit):
            ctx.add(
                "limit_account",
                what,
                "global",
                pct=100.0 * s.get(used, 0) / s[limit],
                used=s.get(used, 0),
                limit=s[limit],
            )
    r53 = ctx.client("route53")
    got = with_backoff(r53.get_account_limit, Type="MAX_HOSTED_ZONES_BY_OWNER")
    if got.get("Limit", {}).get("Value"):
        ctx.add(
            "limit_account",
            "Route 53 hosted zones",
            "global",
            pct=100.0 * got["Count"] / got["Limit"]["Value"],
            used=got["Count"],
            limit=got["Limit"]["Value"],
        )
    ctx.r.ok("limits")


def task_s3_limits(ctx: OutageCtx) -> None:
    buckets = ctx.client("s3").list_buckets().get("Buckets") or []
    sq = ctx.client("service-quotas", ctx.home)
    limit = None
    for q in _default_quotas(sq, ctx.home, "s3") + _quota_pages(sq, "list_service_quotas", "s3"):
        name = q.get("QuotaName", "").lower()
        if q.get("Value") and "bucket" in name and ("general purpose" in name or name == "buckets"):
            limit = q["Value"]
    if limit:
        ctx.add(
            "limit_s3",
            "General purpose buckets in the account",
            "global",
            pct=100.0 * len(buckets) / limit,
            used=len(buckets),
            limit=limit,
        )
    ctx.r.ok("s3_limits")


def task_s3_requests(ctx: OutageCtx, region: str) -> None:
    """Only for buckets with request metrics turned on. Rates are for the whole bucket against the rate
    S3 supports per prefix, so a bucket whose keys are well spread has more room than this shows."""
    m = ctx.metrics(region)
    for res, s in m["s3_5xx"].items():
        if s.total > 0:
            ctx.add("s3_5xx", res.split("|")[0], region, used=round(s.total), unit="errors")
    for key, limit, what in (("s3_get", 5500, "GET"), ("s3_put", 3500, "PUT")):
        for res, s in m[key].items():
            rate = s.high / PERIOD
            ctx.add(
                "limit_s3",
                f"{res.split('|')[0]} {what} rate",
                region,
                pct=100.0 * rate / limit,
                used=round(rate, 1),
                limit=limit,
                unit="requests a second, per prefix",
                load=True,
            )
    ctx.r.fact("s3_request_metrics", len(m["s3_get"]) + len(m["s3_put"]), region)
    ctx.r.ok("s3_limits")


def task_region_limits(ctx: OutageCtx, region: str) -> None:
    """RDS and load balancer account limits; Lambda concurrency and code storage."""
    if ctx.billed("Amazon Relational Database Service"):
        for q in ctx.client("rds", region).describe_account_attributes().get("AccountQuotas") or []:
            if q.get("Max"):
                ctx.add(
                    "limit_product",
                    f"rds: {q['AccountQuotaName']}",
                    region,
                    pct=100.0 * q["Used"] / q["Max"],
                    used=q["Used"],
                    limit=q["Max"],
                )
    elb = ctx.client("elbv2", region)
    limits = {x["Name"]: float(x["Max"]) for x in _pages(elb, "describe_account_limits", "Limits")}
    lbs = _pages(elb, "describe_load_balancers", "LoadBalancers")
    groups = _pages(elb, "describe_target_groups", "TargetGroups")
    for name, used in (
        ("application-load-balancers", sum(lb.get("Type") == "application" for lb in lbs)),
        ("network-load-balancers", sum(lb.get("Type") == "network" for lb in lbs)),
        ("target-groups", len(groups)),
    ):
        if limits.get(name):
            ctx.add(
                "limit_product",
                f"elasticloadbalancing: {name}",
                region,
                pct=100.0 * used / limits[name],
                used=used,
                limit=limits[name],
            )
    if ctx.billed("AWS Lambda"):
        settings = ctx.client("lambda", region).get_account_settings()
        lim, use = settings.get("AccountLimit") or {}, settings.get("AccountUsage") or {}
        if lim.get("TotalCodeSize"):
            ctx.add(
                "limit_product",
                "lambda: code storage",
                region,
                pct=100.0 * use.get("TotalCodeSize", 0) / lim["TotalCodeSize"],
                used=round(use.get("TotalCodeSize", 0) / GIB, 1),
                limit=round(lim["TotalCodeSize"] / GIB, 1),
                unit="GiB",
            )
        m = ctx.metrics(region)
        s = m["lambda_conc"].get("all")
        if s and s.n and lim.get("ConcurrentExecutions"):
            ctx.add(
                "limit_account",
                "Lambda concurrent executions",
                region,
                pct=100.0 * s.high / lim["ConcurrentExecutions"],
                used=round(s.high),
                limit=lim["ConcurrentExecutions"],
                load=True,
            )
        for res, x in m["lambda_throttle"].items():
            if x.total > 0:
                ctx.add("lambda_throttles", res, region, used=round(x.total), unit="throttles")
    ctx.r.ok("limits")


def task_connect(ctx: OutageCtx, region: str) -> None:
    conn = ctx.client("connect", region)
    instances = _pages(conn, "list_instances", "InstanceSummaryList")
    if not instances:
        ctx.r.ok("connect")
        return
    quotas = {}
    sq = ctx.client("service-quotas", region)
    for q in _default_quotas(sq, region, "connect") + _quota_pages(sq, "list_service_quotas", "connect"):
        if q.get("Value"):
            quotas[q.get("QuotaName", "").lower()] = q["Value"]
    m = ctx.metrics(region)
    for inst in instances:
        iid, name = inst["Id"], inst.get("InstanceAlias") or inst["Id"]
        for res, s in m["connect_pct"].items():
            if res.startswith(iid) and s.n:
                ctx.add("limit_connect", f"{name}: concurrent calls", region, pct=s.high, load=True)
        rejected = sum(
            s.total
            for key in ("connect_throttled", "connect_breach")
            for res, s in m[key].items()
            if res.startswith(iid)
        )
        if rejected > 0:
            ctx.add("connect_throttled", name, region, used=round(rejected), unit="calls")
        for phrase, op, key, args in CONNECT_COUNTS:
            limit = next((v for q, v in quotas.items() if phrase in q), None)
            if not limit:
                continue
            used = len(_pages(conn, op, key, cap=int(limit) + 1, InstanceId=inst["Id"], **args))
            ctx.add(
                "limit_connect",
                f"{name}: {phrase.replace(' per instance', '')}",
                region,
                pct=100.0 * used / limit,
                used=used,
                limit=limit,
            )
    ctx.r.ok("connect")


# -------------------------------------------------------------------------------- compute and storage
def _util(ctx: OutageCtx, rule: str, series: dict[str, Series], region: str, note: str = "") -> None:
    for res, s in series.items():
        if s.n:
            ctx.add(rule, res, region, pct=min(s.high, 100.0), load=True, note=note)


def _filling(ctx: OutageCtx, rule: str, res: str, region: str, pct: float, slope_pct: float, **kw) -> None:
    """A storage row: how full now, and the days to full at the rate of the lookback window."""
    days = days_until(pct, 100.0, slope_pct)
    if days is not None and days > 365:
        days = None
    ctx.add(rule, res, region, pct=pct, days=days, **kw)


# Families on the Xen hypervisor: hardware from before the Nitro system (2017). Checked against
# ec2:DescribeInstanceTypes (Hypervisor "xen") in November 2026; g2 to hs1 are Xen families no longer
# offered, kept for the servers still running them. AWS's own CurrentGeneration flag is not used:
# it now marks m5, r5, m6i and even r7g sizes as not current, which would flag nearly everything.
XEN_FAMILIES = frozenset({"c1", "c3", "c4", "d2", "h1", "i2", "i3", "m1", "m2", "m3", "m4", "r3", "r4", "t1", "t2",
                          "x1", "x1e", "g2", "g3", "p2", "p3", "cc2", "cr1", "hs1"})  # fmt: skip
SUCCESSOR = {"t": "t3 or t4g", "m": "m7i or m7g", "c": "c7i or c7g", "r": "r7i or r7g", "i": "i4i or i7ie",
             "d": "d3", "h": "d3en", "x": "x2idn or x2iedn", "g": "g5 or g6", "p": "p4d or p5",
             "cc": "c7i", "cr": "r7i", "hs": "d3en"}  # fmt: skip
TYPE_PREFIXES = ("db.", "cache.", "kafka.", "mq.")


def old_generation(kind: str) -> tuple[str, str] | None:
    """(family, a current family to move to) of an instance size on Xen hardware, for any service that
    names its sizes after EC2 (db.r4.large, cache.m4.xlarge, r4.large.search, mq.t2.micro); else None."""
    size = kind or ""
    for prefix in TYPE_PREFIXES:
        size = size.removeprefix(prefix)
    family = size.split(".")[0]
    if family not in XEN_FAMILIES:
        return None
    letters = re.match(r"[a-z]+", family)[0]
    return family, SUCCESSOR.get(letters, "a current generation")


def add_old_generation(ctx: OutageCtx, rule: str, res: str, region: str, kind: str, note: str = "") -> None:
    """A resource on pre-Nitro hardware, if it is."""
    old = old_generation(kind)
    if old:
        said = f"{kind}: {old[0]} runs on Xen, pre-Nitro hardware; move to {old[1]}"
        ctx.add(rule, res, region, note=f"{said}; {note}" if note else said)


def _scheduled_events(ctx: OutageCtx, ec2, region: str, label) -> None:
    """Reboots, retirements and stops AWS has scheduled on running servers."""
    for page in ec2.get_paginator("describe_instance_status").paginate():
        for st in page.get("InstanceStatuses") or []:
            for e in st.get("Events") or []:
                text = e.get("Description") or ""
                when = e.get("NotBefore")
                if not when or text.startswith(("[Completed]", "[Canceled]")):
                    continue
                ctx.add(
                    "ec2_event",
                    label(st["InstanceId"]),
                    region,
                    ends=when.date().isoformat(),
                    note=f"{e.get('Code')}: {text}"[:200],
                )


def burstable(kind: str) -> tuple[str, float | None] | None:
    """(family, baseline CPU % per vCPU or None) of a T-family size; None for a fixed-performance one."""
    hit = BURST_TYPE.match(kind or "")
    return (hit[1], BURST_BASELINE[hit[1]].get(hit[2])) if hit else None


def add_burstable(
    ctx: OutageCtx,
    rule: str,
    res: str,
    region: str,
    kind: str,
    cpu: float | None = None,
    credits: Series | None = None,
    unlimited: bool | None = None,
) -> None:
    """A burstable size, with what the report needs to judge it against the expected peak load:
    the busiest hour's CPU, the baseline it can hold, the lowest credit balance and the credit mode."""
    found = burstable(kind)
    if not found:
        return
    extra = {"type": kind, "baseline": found[1], "unlimited": unlimited}
    if cpu is not None:
        extra["cpu"] = round(min(cpu, 100.0), 1)
    if credits and credits.n:
        extra["credits"] = round(credits.low, 1)
    ctx.add(rule, res, region, **extra)


def _credit_modes(ec2, ids: list[str]) -> dict[str, bool]:
    """{instance: True when unlimited} for T-family instances; empty when the read is refused."""
    modes = {}
    try:
        for at in range(0, len(ids), 1000):
            got = ec2.describe_instance_credit_specifications(InstanceIds=ids[at : at + 1000])
            for c in got.get("InstanceCreditSpecifications") or []:
                modes[c["InstanceId"]] = c.get("CpuCredits") == "unlimited"
    except ClientError as exc:
        log.info("credit specifications not read: %s", _code(exc))
    return modes


def _net_allowances(ctx: OutageCtx, m: dict, instances: dict, label, region: str) -> None:
    """Instances whose network interfaces passed an allowance in the window, by the agent's counters."""
    passed: dict[str, dict[str, float]] = {}
    for key in ETHTOOL:
        for res, s in m.get(key, {}).items():
            iid = res.split("|")[0]
            if iid in instances and s.n >= 2 and s.last > s.low:  # rose since its lowest: a reboot resets it
                got = passed.setdefault(iid, {})
                got[key] = got.get(key, 0.0) + s.last - s.low
    for iid, got in passed.items():
        kind = instances[iid]["type"]
        if "net_linklocal" in got:
            ctx.add(
                "ec2_dns_allowance",
                label(iid),
                region,
                used=round(got["net_linklocal"]),
                unit="packets over the 1024 a second to DNS, metadata and time",
                note=kind,
            )
        over = {k: v for k, v in got.items() if k in ETHTOOL_WHAT}
        if over:
            ctx.add(
                "ec2_net_allowance",
                label(iid),
                region,
                used=round(sum(over.values())),
                unit="packets queued or dropped",
                note=f"{kind}: " + ", ".join(ETHTOOL_WHAT[k] for k in over),
            )


def task_ec2(ctx: OutageCtx, region: str) -> None:
    ec2 = ctx.client("ec2", region)
    instances = {}
    for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    ):
        for res in page.get("Reservations") or []:
            for i in res.get("Instances") or []:
                tags = {t["Key"]: t["Value"] for t in i.get("Tags") or []}
                instances[i["InstanceId"]] = {
                    "type": i.get("InstanceType", ""),
                    "name": tags.get("Name", ""),
                    "scaled": "aws:autoscaling:groupName" in tags or "eks:cluster-name" in tags,
                }
    m = ctx.metrics(region)
    label = lambda iid: f"{instances[iid]['name']} ({iid})" if instances[iid]["name"] else iid  # noqa: E731
    for iid, s in m["ec2_cpu"].items():
        if iid in instances and not instances[iid]["scaled"] and s.n:
            ctx.add("ec2_cpu", label(iid), region, pct=min(s.high, 100.0), load=True, note=instances[iid]["type"])
    out_of_credits = set()
    for iid, s in m["ec2_credits"].items():
        if iid in instances and s.n and s.low < CREDITS_LOW:
            out_of_credits.add(iid)
            ctx.add(
                "ec2_credits",
                label(iid),
                region,
                used=round(s.low, 1),
                unit="credits at the lowest",
                note=instances[iid]["type"],
            )
    _net_allowances(ctx, m, instances, label, region)
    by_type: dict[str, list[str]] = {}
    for iid, i in instances.items():
        if old_generation(i["type"]):
            by_type.setdefault(i["type"], []).append(label(iid))
    for kind, names in by_type.items():
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        add_old_generation(ctx, "ec2_old_gen", f"{len(names)} x {kind}", region, kind, note=shown)
    try:
        _scheduled_events(ctx, ec2, region, lambda iid: label(iid) if iid in instances else iid)
    except ClientError:  # a role from before this check: the rest of the server checks stand
        pass
    bursting = [iid for iid, i in instances.items() if burstable(i["type"]) and iid not in out_of_credits]
    modes = _credit_modes(ec2, bursting) if bursting else {}
    for iid in bursting:
        cpu = m["ec2_cpu"].get(iid)
        add_burstable(
            ctx,
            "ec2_burstable",
            label(iid),
            region,
            instances[iid]["type"],
            cpu=cpu.high if cpu and cpu.n else None,
            credits=m["ec2_credits"].get(iid),
            unlimited=modes.get(iid),
        )
    for key, unit in (("ebs_iops", "IOPS"), ("ebs_tput", "throughput")):
        for vol, s in m[key].items():
            if s.n and s.high > 0:
                ctx.add("ebs_exceeded", vol, region, used=1, unit=f"over its provisioned {unit}")
    for vol, s in m["ebs_burst"].items():
        if s.n:
            ctx.add("ebs_burst", vol, region, pct=100.0 - s.low, note=f"lowest burst balance {s.low:.0f}%")
    for key, what in (("ec2_ebsio", "EBS IO"), ("ec2_ebsbyte", "EBS byte")):
        for iid, s in m[key].items():
            if iid in instances and s.n:
                ctx.add(
                    "ec2_ebs_burst",
                    label(iid),
                    region,
                    pct=100.0 - s.low,
                    note=f"{instances[iid]['type']}; lowest {what} balance {s.low:.0f}%",
                )
    for res, s in m.get("disk_used", {}).items():
        iid, _, path = res.partition("|")
        if s.n and iid in instances:
            _filling(ctx, "disk_full", f"{label(iid)} {path}", region, min(s.last, 100.0), s.slope())
    _ebs_mismatch(ctx, ec2, instances, region)
    ctx.r.ok("storage")
    ctx.r.ok("fixed")


def _io_peak(parts, limit, exceeded: Series | None) -> float:
    """A second's worth of the busiest read hour plus the busiest write hour. They need not be the same
    hour, so past the limit with no exceeded check the larger one alone is the honest figure."""
    highs = [s.high for s in parts if s and s.n]
    total = sum(highs)
    hit = exceeded is not None and exceeded.n and exceeded.high > 0
    if limit and total / PERIOD > limit and not hit:
        total = max(highs, default=0.0)
    return total / PERIOD


def _volume_headroom(ctx: OutageCtx, volumes: list[dict], region: str) -> None:
    """IOPS and throughput used against what each gp3, io1 or io2 volume is provisioned for (gp2 is
    judged by its burst balance). The busiest read hour is added to the busiest write hour, so it errs high."""
    m = ctx.metrics(region)
    for v in volumes:
        vid, kind = v.get("VolumeId", ""), v.get("VolumeType", "")
        if kind not in ("gp3", "io1", "io2"):
            continue
        rops, wops = m["ebs_rops"].get(vid), m["ebs_wops"].get(vid)
        ops = _io_peak((rops, wops), v.get("Iops"), m["ebs_iops"].get(vid))
        if v.get("Iops") and (rops or wops):
            ctx.add(
                "ebs_iops_use",
                vid,
                region,
                pct=100.0 * ops / v["Iops"],
                used=round(ops),
                limit=v["Iops"],
                unit="IOPS",
                load=True,
                note=f"{kind}, {v.get('Size')} GiB",
            )
        rb, wb = m["ebs_rbytes"].get(vid), m["ebs_wbytes"].get(vid)
        mib = 1024**2
        mbps = _io_peak((rb, wb), (v.get("Throughput") or 0) * mib, m["ebs_tput"].get(vid)) / 1024**2
        if kind == "gp3" and v.get("Throughput") and (rb or wb):
            ctx.add(
                "ebs_iops_use",
                f"{vid} throughput",
                region,
                pct=100.0 * mbps / v["Throughput"],
                used=round(mbps),
                limit=v["Throughput"],
                unit="MiB/s",
                load=True,
                note=f"{kind}, {v.get('Size')} GiB",
            )


def _ebs_mismatch(ctx: OutageCtx, ec2, instances: dict, region: str) -> None:
    """The volumes on one instance, added up, against what the instance type can drive."""
    volumes = _pages(
        ec2, "describe_volumes", "Volumes", cap=MAX_ITEMS, Filters=[{"Name": "status", "Values": ["in-use"]}]
    )
    _volume_headroom(ctx, volumes, region)
    per: dict[str, dict] = {}
    for v in volumes:
        for a in v.get("Attachments") or []:
            if a.get("InstanceId") in instances:
                row = per.setdefault(a["InstanceId"], {"iops": 0, "mbps": 0, "n": 0})
                row["iops"] += v.get("Iops") or 0
                row["mbps"] += v.get("Throughput") or 0
                row["n"] += 1
    types = sorted({instances[i]["type"] for i in per})
    caps = {}
    for at in range(0, len(types), 100):
        for t in _pages(ec2, "describe_instance_types", "InstanceTypes", InstanceTypes=types[at : at + 100]):
            caps[t["InstanceType"]] = (t.get("EbsInfo") or {}).get("EbsOptimizedInfo") or {}
    for iid, row in per.items():
        cap = caps.get(instances[iid]["type"]) or {}
        over = []
        if cap.get("MaximumIops") and row["iops"] > cap["MaximumIops"]:
            over.append(f"{row['iops']:,} IOPS against {cap['MaximumIops']:,}")
        if cap.get("MaximumThroughputInMBps") and row["mbps"] > cap["MaximumThroughputInMBps"]:
            over.append(f"{row['mbps']:,} MB/s against {cap['MaximumThroughputInMBps']:,.0f}")
        if over:
            name = instances[iid]["name"]
            ctx.add(
                "ebs_instance_mismatch",
                f"{name} ({iid})" if name else iid,
                region,
                note=f"{instances[iid]['type']}, {row['n']} volume(s): {'; '.join(over)}",
            )


# Aurora Serverless v2. ACUUtilization and CPUUtilization are percentages of the maximum ACUs in force at
# the time, so a maximum raised last week would leave the old peaks looking full. Each hour is turned back
# into ACUs (capacity / utilisation gives the maximum then) and judged against today's maximum.
SERVERLESS_STATS = (
    ("ua", "ACUUtilization", "Average"),
    ("ca", "ServerlessDatabaseCapacity", "Average"),
    ("cm", "ServerlessDatabaseCapacity", "Maximum"),
    ("pa", "CPUUtilization", "Average"),
    ("pm", "CPUUtilization", "Maximum"),
)
SERVERLESS_MAX_ACU = 256  # the most Aurora Serverless v2 allows, on current engine versions
CEILING_HOURS = 24  # hours at the maximum in the lookback window before it is worth a look
SATURATED_HOURS = 7  # hours also at full CPU there: it ran out, not just reached its ceiling


def _serverless_hours(ctx: OutageCtx, region: str, names: list[str]) -> dict[str, dict[str, dict]]:
    """{instance: {stat id: {hour: value}}}, hourly over the lookback window."""
    cw = ctx.client("cloudwatch", region)
    out: dict[str, dict[str, dict]] = {}
    per = 500 // len(SERVERLESS_STATS)
    for at in range(0, len(names), per):
        queries, ids = [], {}
        for i, name in enumerate(names[at : at + per]):
            for sid, metric, stat in SERVERLESS_STATS:
                qid = f"{sid}{i}"
                ids[qid] = (name, sid)
                metric_q = {"Namespace": "AWS/RDS", "MetricName": metric,
                            "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": name}]}  # fmt: skip
                queries.append({"Id": qid, "MetricStat": {"Metric": metric_q, "Period": PERIOD, "Stat": stat}})
        kwargs = {
            "MetricDataQueries": queries,
            "StartTime": ctx.now - timedelta(days=LOOKBACK_DAYS),
            "EndTime": ctx.now,
            "ScanBy": "TimestampAscending",
        }
        while True:
            resp = with_backoff(cw.get_metric_data, transient=True, **kwargs)
            for r in resp.get("MetricDataResults") or []:
                name, sid = ids.get(r.get("Id"), (None, None))
                if name:
                    got = out.setdefault(name, {}).setdefault(sid, {})
                    got.update(zip(r.get("Timestamps") or [], r.get("Values") or [], strict=False))
            if not resp.get("NextToken"):
                break
            kwargs["NextToken"] = resp["NextToken"]
    return out


def serverless_usage(hours: dict[str, dict], top: float) -> dict | None:
    """Peak use of one Serverless v2 instance against today's maximum ACUs ``top``, or None with no data."""
    ua, ca, cm, pa, pm = (hours.get(k) or {} for k in ("ua", "ca", "cm", "pa", "pm"))
    if not ca or not top:
        return None
    cpu_acus = cpu_max_acus = 0.0
    then: dict = {}  # hour: the maximum ACUs in force then
    for when, util in ua.items():
        cap = ca.get(when)
        if util and util > 0 and cap is not None:
            then[when] = cap / (util / 100)
    for when, ceiling in then.items():
        cpu_acus = max(cpu_acus, (pa.get(when) or 0) * ceiling / 100)
        cpu_max_acus = max(cpu_max_acus, (pm.get(when) or 0) * ceiling / 100)
    at_top = [w for w, v in cm.items() if v >= 0.95 * top]
    full = sum(1 for w in at_top if w in then and (pm.get(w) or 0) * then[w] / 100 >= 0.95 * top)
    # A different maximum in force before: the last hour it was not today's.
    before = [(w, v) for w, v in sorted(then.items()) if abs(v - top) > max(1.0, 0.1 * top)]
    changed = None
    if before:
        # The value in force most of that time: the hour of a change mixes the old and new maximum.
        was = Counter(round(v * 2) / 2 for _, v in before).most_common(1)[0][0]
        changed = {"until": before[-1][0].date().isoformat(), "was": was}
    return {
        "acus": round(max(ca.values()), 1),
        "acu_pct": round(min(100.0, max(ca.values()) / top * 100), 1),
        "cpu_acus": round(cpu_acus, 1),
        "cpu_pct": round(min(100.0, cpu_acus / top * 100), 1) if then else None,
        "ceiling_hours": len(at_top),
        "full_hours": full,
        "hours": len(ca),
        "changed": changed,
        "cpu_max_acus": round(cpu_max_acus, 1),
    }


def _serverless_v2(ctx: OutageCtx, region: str, rds, dbs: list[dict]) -> None:
    if not dbs:
        return
    scaling = {
        c["DBClusterIdentifier"]: c.get("ServerlessV2ScalingConfiguration") or {}
        for c in _pages(rds, "describe_db_clusters", "DBClusters")
    }
    hours = _serverless_hours(ctx, region, [d["DBInstanceIdentifier"] for d in dbs])
    for d in dbs:
        name = d["DBInstanceIdentifier"]
        conf = scaling.get(d.get("DBClusterIdentifier") or "") or {}
        top, low = float(conf.get("MaxCapacity") or 0), float(conf.get("MinCapacity") or 0)
        use = serverless_usage(hours.get(name) or {}, top)
        if not use:
            continue
        extra = {"acu_min": low, "acu_max": top, "acu_used": use["acu_pct"], "acus": use["acus"],
                 "cpu_acus": use["cpu_acus"], "changed": use["changed"]}  # fmt: skip
        if use["cpu_pct"] is not None:
            ctx.add("aurora_acu", name, region, pct=use["cpu_pct"], load=True, **extra)
        if use["ceiling_hours"] >= CEILING_HOURS:
            at, of, full = f"{use['ceiling_hours']:,}", f"{use['hours']:,}", use["full_hours"]
            note = f"at today's maximum of {top:g} ACUs in {at} of {of} hours (hourly maximum)"
            if full >= SATURATED_HOURS:
                note += f"; CPU at the limit in {full:,} of them, so it ran out of capacity, not just reached it"
            sev = "high" if use["full_hours"] >= SATURATED_HOURS else "medium"
            ctx.add("aurora_acu_ceiling", name, region, sev=sev, note=note, **extra)


def task_rds(ctx: OutageCtx, region: str) -> None:
    rds = ctx.client("rds", region)
    dbs = _pages(rds, "describe_db_instances", "DBInstances", cap=MAX_ITEMS)
    m = ctx.metrics(region)
    by_id = {d["DBInstanceIdentifier"]: d for d in dbs}
    _serverless_v2(ctx, region, rds, [d for d in dbs if d.get("DBInstanceClass") == "db.serverless"])
    for d in dbs:
        name = d["DBInstanceIdentifier"]
        cls = d.get("DBInstanceClass", "")
        engine = d.get("Engine", "")
        shared = d.get("DBClusterIdentifier") and engine.startswith(("aurora", "docdb", "neptune"))
        if cls == "db.serverless":
            continue  # judged by _serverless_v2 below, against today's maximum ACUs
        else:
            s = m["rds_cpu"].get(name)
            if s and s.n:
                ctx.add("rds_cpu", name, region, pct=min(s.high, 100.0), load=True, note=f"{cls}, {engine}")
            # RDS runs T3 and T4g classes in unlimited mode, T2 in standard: it cannot be changed.
            add_burstable(
                ctx,
                "rds_burstable",
                name,
                region,
                cls,
                cpu=s.high if s and s.n else None,
                credits=m["rds_credits"].get(name),
                unlimited=not cls.startswith("db.t2."),
            )
        for key, what in (("rds_burst", "gp2 burst"), ("rds_ebsio", "EBS IO"), ("rds_ebsbyte", "EBS byte")):
            s = m[key].get(name)
            if s and s.n:
                ctx.add("rds_burst", name, region, pct=100.0 - s.low, note=f"lowest {what} balance {s.low:.0f}%")
        reads, writes = m["rds_riops"].get(name), m["rds_wiops"].get(name)
        if d.get("Iops") and not shared and (reads or writes):
            iops = sum(s.high for s in (reads, writes) if s and s.n)
            ctx.add(
                "rds_iops",
                name,
                region,
                pct=100.0 * iops / d["Iops"],
                used=round(iops),
                limit=d["Iops"],
                unit="IOPS",
                load=True,
                note=f"{cls}, {d.get('StorageType', '')}; busiest read and write hours added",
            )
        if shared:  # the cluster volume grows by itself
            continue
        _rds_storage(ctx, d, m["rds_free"].get(name), region)
        source = _short(d.get("ReadReplicaSourceDBInstanceIdentifier") or "")
        if source in by_id:
            src = by_id[source]
            diff = []
            if src.get("DBInstanceClass") != cls:
                diff.append(f"class {cls}, source {src.get('DBInstanceClass')}")
            if (d.get("AllocatedStorage") or 0) < (src.get("AllocatedStorage") or 0):
                diff.append(f"{d.get('AllocatedStorage')} GiB, source {src.get('AllocatedStorage')} GiB")
            if diff:
                ctx.add("rds_replica_mismatch", name, region, note="; ".join(diff))
        elif not source and not d.get("MultiAZ"):
            ctx.add("rds_single_az", name, region, note=f"{cls}, {engine}")
    ctx.r.ok("storage")
    ctx.r.ok("fixed")


def _rds_storage(ctx: OutageCtx, d: dict, free: Series | None, region: str) -> None:
    allocated = (d.get("AllocatedStorage") or 0) * GIB
    if not free or not free.n or not allocated:
        return
    ceiling = max((d.get("MaxAllocatedStorage") or 0) * GIB, allocated)
    used = allocated - free.last
    pct = 100.0 * used / ceiling
    _filling(
        ctx,
        "rds_storage",
        d["DBInstanceIdentifier"],
        region,
        pct,
        -free.slope() * 100.0 / ceiling,
        used=round(used / GIB, 1),
        limit=round(ceiling / GIB),
        unit="GiB",
        note="storage autoscaling on" if ceiling > allocated else "no storage autoscaling",
    )


def task_asg(ctx: OutageCtx, region: str) -> None:
    for g in _pages(
        ctx.client("autoscaling", region), "describe_auto_scaling_groups", "AutoScalingGroups", cap=MAX_ITEMS
    ):
        name, low, high, want = (
            g["AutoScalingGroupName"],
            g.get("MinSize", 0),
            g.get("MaxSize", 0),
            g.get("DesiredCapacity", 0),
        )
        if want and len(g.get("AvailabilityZones") or []) == 1:
            ctx.add("asg_one_az", name, region, note=f"{want} instance(s) in {g['AvailabilityZones'][0]}")
        if high and low == high and high > 0:
            ctx.add("asg_fixed", name, region, note=f"{high} instance(s), minimum equals maximum")
        elif high:
            ctx.add("asg_near_max", name, region, pct=100.0 * want / high, used=want, limit=high, load=True)
    ctx.r.ok("fixed")


def _scalable(ctx: OutageCtx, region: str, namespace: str) -> dict[str, list[dict]]:
    """{resource id: its Application Auto Scaling targets}."""
    client = ctx.client("application-autoscaling", region)
    out: dict[str, list[dict]] = {}
    for t in _pages(client, "describe_scalable_targets", "ScalableTargets", ServiceNamespace=namespace):
        out.setdefault(t["ResourceId"], []).append(t)
    return out


def task_ecs(ctx: OutageCtx, region: str) -> None:
    ecs = ctx.client("ecs", region)
    targets = _scalable(ctx, region, "ecs")
    m = ctx.metrics(region)
    seen = 0
    for arn in _pages(ecs, "list_clusters", "clusterArns"):
        cluster = _short(arn)
        names = _pages(ecs, "list_services", "serviceArns", cap=MAX_ITEMS, cluster=arn)
        for at in range(0, len(names), 10):
            if seen >= MAX_ITEMS:
                break
            for svc in ecs.describe_services(cluster=arn, services=names[at : at + 10]).get("services") or []:
                seen += 1
                _ecs_service(ctx, region, cluster, svc, targets, m)
    ctx.r.ok("fixed")


def _ecs_service(ctx: OutageCtx, region: str, cluster: str, svc: dict, targets: dict, m: dict) -> None:
    name = svc["serviceName"]
    want = svc.get("desiredCount", 0)
    if not want:
        return
    res = f"{cluster}/{name}"
    running = svc.get("runningCount", want)
    if running < want:
        ctx.add("ecs_below_desired", res, region, used=running, limit=want, unit="tasks running")
    target = (targets.get(f"service/{cluster}/{name}") or [None])[0]
    if target:
        if target.get("MaxCapacity"):
            ctx.add(
                "ecs_near_max",
                res,
                region,
                pct=100.0 * want / target["MaxCapacity"],
                used=want,
                limit=target["MaxCapacity"],
                load=True,
            )
    else:
        if want == 1:
            ctx.add("ecs_single_task", res, region)
        for key, what in (("ecs_cpu", "CPU"), ("ecs_mem", "memory")):
            s = m[key].get(f"{cluster}|{name}")
            if s and s.n:
                ctx.add(
                    "ecs_util",
                    f"{res} {what}",
                    region,
                    pct=min(s.high, 100.0),
                    load=True,
                    note=f"{want} task(s), fixed",
                )
    breaker = (svc.get("deploymentConfiguration") or {}).get("deploymentCircuitBreaker") or {}
    if svc.get("launchType") != "EXTERNAL" and not (breaker.get("enable") and breaker.get("rollback")):
        ctx.add("ecs_no_circuit_breaker", res, region)


def _worst(series: dict[str, Series], top: bool = True) -> dict[str, tuple[float, Series]]:
    """{first part of the label: (highest or lowest value, its series)}: a cluster's worst node."""
    out: dict[str, tuple[float, Series]] = {}
    for res, s in series.items():
        if not s.n:
            continue
        name = res.split("|")[0]
        value = s.high if top else s.low
        if name not in out or (value > out[name][0] if top else value < out[name][0]):
            out[name] = (value, s)
    return out


def task_elasticache(ctx: OutageCtx, region: str) -> None:
    m = ctx.metrics(region)
    for key, rule in (("cache_cpu", "cache_cpu"), ("cache_mem", "cache_memory")):
        for name, (value, _) in _worst(m[key]).items():
            ctx.add(rule, name, region, pct=min(value, 100.0), load=True)
    for name in {res.split("|")[0] for res, s in m["cache_evict"].items() if s.total > 0}:
        total = sum(s.total for res, s in m["cache_evict"].items() if res.split("|")[0] == name)
        ctx.add("cache_evictions", name, region, used=round(total), unit="evictions")
    ctx.r.ok("fixed")


def task_opensearch(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("opensearch", region)
    names = [d["DomainName"] for d in client.list_domain_names().get("DomainNames") or []]
    sizes = {}
    for at in range(0, len(names), 5):
        for d in client.describe_domains(DomainNames=names[at : at + 5]).get("DomainStatusList") or []:
            sizes[d["DomainName"]] = (d.get("EBSOptions") or {}).get("VolumeSize") or 0
    m = ctx.metrics(region)
    for res, s in m["search_cpu"].items():
        if s.n:
            ctx.add("search_cpu", res.split("|")[-1], region, pct=min(s.high, 100.0), load=True)
    for res, s in m["search_jvm"].items():
        if s.n:
            ctx.add("search_jvm", res.split("|")[-1], region, pct=min(s.high, 100.0), load=True)
    for res, s in m["search_red"].items():
        if s.n and s.high > 0:
            ctx.add("search_red", res.split("|")[-1], region, used=1, unit="seen red")
    for res, s in m["search_free"].items():
        name = res.split("|")[-1]
        size = sizes.get(name)
        if s.n and size:  # FreeStorageSpace is MB; its minimum is the emptiest node's, the volume is per node
            total = size * 1024.0
            _filling(
                ctx,
                "search_storage",
                name,
                region,
                100.0 * (total - s.last) / total,
                -s.slope() * 100.0 / total,
                used=round((total - s.last) / 1024, 1),
                limit=size,
                unit="GiB per node",
            )
    ctx.r.ok("fixed")
    ctx.r.ok("storage")


def task_redshift(ctx: OutageCtx, region: str) -> None:
    m = ctx.metrics(region)
    _util(ctx, "redshift_cpu", m["redshift_cpu"], region)
    for res, s in m["redshift_disk"].items():
        if s.n:
            _filling(ctx, "redshift_disk", res, region, min(s.last, 100.0), s.slope())
    ctx.r.ok("fixed")


def task_efs_fsx(ctx: OutageCtx, region: str) -> None:
    m = ctx.metrics(region)
    for res, s in m["efs_credits"].items():
        if s.n:
            ctx.add(
                "efs_burst",
                res,
                region,
                pct=100.0 - 100.0 * s.low / EFS_BURST_MAX,
                note=f"lowest credit balance {s.low / 1024**3:,.0f} GiB",
            )
    _util(ctx, "efs_io", m["efs_io"], region)
    for res, s in m["fsx_used"].items():
        if s.n:
            _filling(ctx, "fsx_storage", res, region, min(s.last, 100.0), s.slope())
    ctx.r.ok("storage")


def task_dynamodb(ctx: OutageCtx, region: str) -> None:
    targets = _scalable(ctx, region, "dynamodb")
    m = ctx.metrics(region)
    for used_key, prov_key, dim, what in (
        ("ddb_rcu", "ddb_prcu", "ReadCapacityUnits", "read"),
        ("ddb_wcu", "ddb_pwcu", "WriteCapacityUnits", "write"),
    ):
        for table, prov in m[prov_key].items():
            used = m[used_key].get(table)
            if not prov.n or not used or not used.n:
                continue
            target = next(
                (t for t in targets.get(f"table/{table}") or [] if t["ScalableDimension"].endswith(dim)), None
            )
            ceiling = float(target["MaxCapacity"]) if target else prov.last
            rate = used.high / PERIOD
            if ceiling > 0:
                ctx.add(
                    "ddb_provisioned",
                    f"{table} {what}",
                    region,
                    pct=100.0 * rate / ceiling,
                    used=round(rate, 1),
                    limit=round(ceiling),
                    unit="units",
                    load=True,
                    note="autoscaling maximum" if target else "no autoscaling",
                )
    for key in ("ddb_rthrottle", "ddb_wthrottle"):
        for table, s in m[key].items():
            if s.total > 0:
                ctx.add(
                    "ddb_throttles",
                    table,
                    region,
                    used=round(s.total),
                    unit=f"{'read' if key == 'ddb_rthrottle' else 'write'} throttles",
                )
    ctx.r.ok("fixed")


def task_kinesis(ctx: OutageCtx, region: str) -> None:
    m = ctx.metrics(region)
    for key, what in (("kin_write", "write"), ("kin_read", "read")):
        for res, s in m[key].items():
            if s.total > 0:
                ctx.add("kinesis_throttles", res, region, note=f"{what} throughput exceeded")
    ctx.r.ok("fixed")


def task_msk(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("kafka", region)
    clusters = _pages(client, "list_clusters_v2", "ClusterInfoList")
    targets = _scalable(ctx, region, "kafka")
    m = ctx.metrics(region)
    for c in clusters:
        prov = c.get("Provisioned")
        if not prov:  # serverless: AWS manages the capacity
            continue
        name = c["ClusterName"]
        node = prov.get("BrokerNodeGroupInfo") or {}
        size = (node.get("InstanceType") or "").removeprefix("kafka.")
        disk = {res.split("|")[-1]: s for res, s in m["msk_disk"].items() if res.split("|")[0] == name and s.n}
        volume = ((node.get("StorageInfo") or {}).get("EbsStorageInfo") or {}).get("VolumeSize")
        if disk:
            worst = max(disk.values(), key=lambda s: s.last)
            _filling(
                ctx,
                "msk_disk",
                name,
                region,
                min(worst.last, 100.0),
                worst.slope(),
                note=f"{size}, {prov.get('NumberOfBrokerNodes')} brokers, {volume} GiB each" if volume else size,
            )
            spread = max(s.last for s in disk.values()) - min(s.last for s in disk.values())
            if spread >= 20:
                ctx.add(
                    "msk_imbalance", name, region, note=f"{spread:.0f} points between the fullest and emptiest broker"
                )
        if volume and not targets.get(c.get("ClusterArn", "")):
            ctx.add("msk_no_autoscale", name, region, note=f"{volume} GiB per broker")
        cpu = 0.0
        for res, user in m["msk_user"].items():
            if res.split("|")[0] == name and user.n:
                other = m["msk_sys"].get(res)
                cpu = max(cpu, user.high + (other.high if other and other.n else 0.0))
        if cpu:
            ctx.add(
                "msk_cpu", name, region, pct=min(cpu, 100.0), load=True, note=f"{size}; AWS advises staying under 60%"
            )
        add_burstable(ctx, "msk_burstable", name, region, size, cpu=cpu or None)
        guide = MSK_PARTITIONS.get(size, MSK_PARTITIONS_LARGE if re.search(r"\d+xlarge", size) else None)
        parts = max((s.high for res, s in m["msk_parts"].items() if res.split("|")[0] == name and s.n), default=None)
        if guide and parts is not None:
            ctx.add(
                "msk_partitions",
                name,
                region,
                pct=100.0 * parts / guide,
                used=round(parts),
                limit=guide,
                unit="per broker",
                days=_partitions_days(m, name, guide),
            )
        outage_services.msk_profile(ctx, client, c, region, m)
    ctx.r.ok("msk")


def _partitions_days(m: dict, name: str, guide: int) -> float | None:
    """Days until the busiest broker reaches the guidance at the rate of the lookback window."""
    series = [s for res, s in m["msk_parts"].items() if res.split("|")[0] == name and s.n]
    worst = max(series, key=lambda s: s.high, default=None)
    if not worst:
        return None
    days = days_until(worst.last, guide, worst.slope())
    return days if days is not None and days <= 365 else None


def task_network(ctx: OutageCtx, region: str) -> None:
    subnets = _pages(ctx.client("ec2", region), "describe_subnets", "Subnets", cap=MAX_ITEMS)
    with ctx._lock:
        ctx.subnets[region] = subnets
    m = ctx.metrics(region)
    for key, rule in (
        ("nat_ports", "nat_port_errors"),
        ("alb_rejected", "lb_rejected"),
        ("nlb_ports", "nlb_port_errors"),
    ):
        for res, s in m[key].items():
            if s.total > 0:
                ctx.add(rule, res, region, used=round(s.total), unit="in the lookback window")
    ctx.r.ok("network")


_BANDWIDTH = re.compile(r"([\d.]+)\s*(M|G)bps", re.I)


def task_dx(ctx: OutageCtx, region: str) -> None:
    dx = ctx.client("directconnect", region)
    conns = dx.describe_connections().get("connections") or []
    m = ctx.metrics(region)
    live = [c for c in conns if c.get("connectionState") == "available"]
    for c in live:
        state = m["dx_state"].get(c["connectionId"])
        if state and state.n and state.low < 1:
            ctx.add("dx_down", c.get("connectionName") or c["connectionId"], region, note=c.get("location", ""))
    places = {c.get("location") for c in live}
    if len(live) == 1 or (live and len(places) == 1):
        ctx.add(
            "dx_no_redundancy",
            f"Direct Connect in {region}",
            region,
            note=f"{len(live)} connection(s), all at {next(iter(places))}",
        )
    for v in dx.describe_virtual_interfaces().get("virtualInterfaces") or []:
        if v.get("virtualInterfaceState") in ("deleting", "deleted", "rejected", "confirming", "pending", "verifying"):
            continue
        down = [p for p in v.get("bgpPeers") or [] if p.get("bgpStatus") == "down"]
        if v.get("virtualInterfaceState") == "down" or down:
            ctx.add(
                "dx_vif_down",
                v.get("virtualInterfaceName") or v.get("virtualInterfaceId", ""),
                region,
                note=f"{v.get('virtualInterfaceType', '')} interface {v.get('virtualInterfaceState')}, "
                f"{len(down)} of {len(v.get('bgpPeers') or [])} BGP sessions down",
            )
    for c in conns:
        got = _BANDWIDTH.match(c.get("bandwidth") or "")
        if not got or c.get("connectionState") != "available":
            continue
        bps = float(got[1]) * (1e9 if got[2].upper() == "G" else 1e6)
        cid = c["connectionId"]
        high = max((s.high for key in ("dx_in", "dx_out") if (s := m[key].get(cid)) and s.n), default=None)
        if high is not None:
            ctx.add(
                "dx_bandwidth",
                f"{c.get('connectionName') or cid} ({c.get('bandwidth')})",
                region,
                pct=100.0 * high / bps,
                used=round(high / 1e6),
                limit=round(bps / 1e6),
                unit="Mbps",
                load=True,
            )
    ctx.r.ok("network")


def task_certificates(ctx: OutageCtx, region: str) -> None:
    """ACM certificates in use that expire by the peak, renewals that have stalled, and private CAs."""
    acm = ctx.client("acm", region)
    limit = ctx.now + timedelta(days=CERT_DAYS)
    for c in _pages(acm, "list_certificates", "CertificateSummaryList", CertificateStatuses=["ISSUED"]):
        ends = c.get("NotAfter")
        if not ends or not c.get("InUse") or ends > limit:
            continue
        auto = c.get("Type") == "AMAZON_ISSUED" and c.get("RenewalEligibility") == "ELIGIBLE"
        name = c.get("DomainName") or _short(c["CertificateArn"])
        if auto and ends <= ctx.now + timedelta(days=RENEWAL_DAYS):
            got = with_backoff(acm.describe_certificate, CertificateArn=c["CertificateArn"]).get("Certificate") or {}
            renewal = got.get("RenewalSummary") or {}
            status = renewal.get("RenewalStatus") or ""
            if status in ("PENDING_VALIDATION", "FAILED"):
                ctx.add(
                    "cert_renewal_failing",
                    name,
                    region,
                    ends=ends.date().isoformat(),
                    note=f"renewal {status.replace('_', ' ').lower()}"
                    + (f": {renewal['RenewalStatusReason']}" if renewal.get("RenewalStatusReason") else "")
                    + f"; expires {ends.date().isoformat()}",
                    now=True,
                )
                continue
        ctx.add(
            "cert_expiry",
            c.get("DomainName") or _short(c["CertificateArn"]),
            region,
            ends=ends.date().isoformat(),
            note="AWS renews this one by itself" if auto else "does not renew by itself",
            auto=auto,
        )
    pca = ctx.client("acm-pca", region)
    for ca in _pages(pca, "list_certificate_authorities", "CertificateAuthorities", cap=MAX_ITEMS):
        ends = ca.get("NotAfter")
        if ca.get("Status") != "ACTIVE" or not ends or ends > limit:
            continue
        ctx.add(
            "cert_expiry",
            f"private CA {_short(ca['Arn'])}",
            region,
            ends=ends.date().isoformat(),
            note="a private certificate authority: every certificate it issued stops being trusted with it",
            auto=False,
        )
    ctx.r.ok("certificates")


# ----------------------------------------------------------------------------------------- EKS and Kubernetes
_CPU = re.compile(r"^([\d.]+)(m?)$")
_MEM = re.compile(r"^([\d.]+(?:e\d+)?)(Ki|Mi|Gi|Ti|k|M|G|T)?$")
_MEM_UNIT = {
    "Ki": 1 / 1024,
    "Mi": 1,
    "Gi": 1024,
    "Ti": 1024**2,
    "k": 1000 / MIB,
    "M": 1e6 / MIB,
    "G": 1e9 / MIB,
    "T": 1e12 / MIB,
    None: 1 / MIB,
}


def parse_cpu(text) -> int | None:
    """Kubernetes CPU quantity as millicores."""
    got = _CPU.match(str(text or ""))
    if not got:
        return None
    return round(float(got[1]) * (1 if got[2] else 1000))


def parse_mem(text) -> int | None:
    """Kubernetes memory quantity as MiB."""
    got = _MEM.match(str(text or ""))
    if not got:
        return None
    return round(float(got[1]) * _MEM_UNIT[got[2]])


def eks_token(sts, cluster: str, region: str) -> str:
    """The bearer token `aws eks get-token` makes: a presigned sts:GetCallerIdentity naming the cluster."""
    url = sts._request_signer.generate_presigned_url(
        {
            "method": "GET",
            "url": f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
            "body": {},
            "headers": {"x-k8s-aws-id": cluster},
            "context": {},
        },
        region_name=region,
        expires_in=60,
        operation_name="",
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class K8sRefused(Exception):
    """The API answered 401 or 403: this identity has no read access to the cluster."""


class K8sUnreachable(Exception):
    """No answer: usually a private endpoint and a scan run from outside its network."""


def _k8s_list(endpoint: str, ca_b64: str, token: str, path: str, cap: int | None = None) -> list[dict]:
    """Every item of a Kubernetes list call, a page at a time."""
    context = ssl.create_default_context(cadata=base64.b64decode(ca_b64).decode())
    items: list[dict] = []
    cont = ""
    while True:
        url = f"{endpoint}{path}?limit=500" + (f"&continue={cont}" if cont else "")
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=K8S_TIMEOUT, context=context) as resp:  # noqa: S310
                body = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code in SYSTEM_ACCESS:
                raise K8sRefused(str(exc.code)) from exc
            raise K8sUnreachable(f"HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            raise K8sUnreachable(str(getattr(exc, "reason", exc))[:120]) from exc
        items.extend(body.get("items") or [])
        cont = (body.get("metadata") or {}).get("continue") or ""
        if not cont or (cap and len(items) >= cap):
            return items


def _pod_sizes(template: dict) -> dict:
    """The pod's requests and limits, added over its containers. A limit any container lacks is None."""
    containers = ((template.get("spec") or {}).get("containers")) or []
    out: dict = {"cpu_req": 0, "mem_req": 0, "mem_lim": 0}
    for c in containers:
        res = c.get("resources") or {}
        req, lim = res.get("requests") or {}, res.get("limits") or {}
        cpu = parse_cpu(req.get("cpu") or lim.get("cpu"))  # with no request, Kubernetes uses the limit
        mem_req = parse_mem(req.get("memory") or lim.get("memory"))
        mem_lim = parse_mem(lim.get("memory"))
        out["cpu_req"] = None if cpu is None or out["cpu_req"] is None else out["cpu_req"] + cpu
        out["mem_req"] = None if mem_req is None or out["mem_req"] is None else out["mem_req"] + mem_req
        out["mem_lim"] = None if mem_lim is None or out["mem_lim"] is None else out["mem_lim"] + mem_lim
    return out


def _selects(budget: dict, namespace: str, labels: dict) -> bool:
    """Does this pod disruption budget cover pods with these labels?"""
    if (budget.get("metadata") or {}).get("namespace") != namespace:
        return False
    want = ((budget.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}
    return bool(want) and all(labels.get(k) == v for k, v in want.items())


_POD_HASH = re.compile(r"-[a-z0-9]{5,10}$")


def read_workloads(list_items) -> dict:
    """Deployments and StatefulSets with their autoscalers and pod troubles. ``list_items(path, cap)``
    reads one Kubernetes list; kept apart so it can be tested with no cluster."""
    deployments = list_items("/apis/apps/v1/deployments", None)
    stateful = list_items("/apis/apps/v1/statefulsets", None)
    hpas = list_items("/apis/autoscaling/v2/horizontalpodautoscalers", None)
    pods = list_items("/api/v1/pods", MAX_PODS)
    budgets = list_items("/apis/policy/v1/poddisruptionbudgets", None)
    scalers = {}
    for h in hpas:
        ref = (h.get("spec") or {}).get("scaleTargetRef") or {}
        ns = (h.get("metadata") or {}).get("namespace")
        scalers[(ns, ref.get("kind"), ref.get("name"))] = h
    oom: dict[tuple, int] = {}
    pull_failed: dict[tuple, int] = {}
    pending = 0
    for p in pods:
        status = p.get("status") or {}
        meta = p.get("metadata") or {}
        if status.get("phase") == "Pending":
            pending += 1
        owner_ref = (meta.get("ownerReferences") or [{}])[0]
        owner = owner_ref.get("name") or meta.get("name") or ""
        key = (meta.get("namespace"), _POD_HASH.sub("", owner) if owner_ref.get("kind") == "ReplicaSet" else owner)
        for c in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
            last = (c.get("lastState") or {}).get("terminated") or {}
            if last.get("reason") == "OOMKilled":
                oom[key] = oom.get(key, 0) + 1
            if ((c.get("state") or {}).get("waiting") or {}).get("reason") in outage_lifecycle.PULL_FAILED:
                pull_failed[key] = pull_failed.get(key, 0) + 1
    rows = []
    for kind, found in (("Deployment", deployments), ("StatefulSet", stateful)):
        for w in found:
            meta, spec = w.get("metadata") or {}, w.get("spec") or {}
            ns, name = meta.get("namespace"), meta.get("name")
            replicas = spec.get("replicas", 1)
            if not replicas:
                continue  # scaled to nothing on purpose
            template = spec.get("template") or {}
            row = {"ns": ns, "name": name, "kind": kind, "replicas": replicas, **_pod_sizes(template)}
            labels = (template.get("metadata") or {}).get("labels") or {}
            row["pdb"] = any(_selects(b, ns, labels) for b in budgets)
            row["ready"] = all(c.get("readinessProbe") for c in (template.get("spec") or {}).get("containers") or [])
            h = scalers.get((ns, kind, name))
            if h:
                row["hpa_max"] = (h.get("spec") or {}).get("maxReplicas")
                row["current"] = (h.get("status") or {}).get("currentReplicas") or replicas
            if oom.get((ns, name)):
                row["oom"] = oom[(ns, name)]
            if pull_failed.get((ns, name)):
                row["pull_failed"] = pull_failed[(ns, name)]
            pod_spec = template.get("spec") or {}
            images = (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or [])
            outside = [(outage_lifecycle.registry(c.get("image") or ""), c) for c in images]
            outside = [(h, c) for h, c in outside if not outage_lifecycle.is_ecr(h)]
            if outside:
                row["registries"] = sorted({h for h, _ in outside})
                if any(
                    outage_lifecycle.pulls_every_start(c.get("image") or "", c.get("imagePullPolicy"))
                    for _, c in outside
                ):
                    row["pull_always"] = True
            rows.append(row)
    return {
        "workloads": rows[:MAX_WORKLOADS],
        "workload_count": len(rows),
        "pods": len(pods),
        "pending": pending,
        "pods_cut": len(pods) >= MAX_PODS,
    }


def task_eks(ctx: OutageCtx, region: str) -> None:
    eks = ctx.client("eks", region)
    names = _pages(eks, "list_clusters", "clusters")
    if not names:
        ctx.r.ok("eks")
        return
    m = ctx.metrics(region)
    sts = ctx.client("sts", region)
    subnets: dict[str, str] = {}
    for name in names:
        c = eks.describe_cluster(name=name)["cluster"]
        for sid in (c.get("resourcesVpcConfig") or {}).get("subnetIds") or []:
            subnets[sid] = name
        row = {"name": name, "region": region, "version": c.get("version", "")}
        groups = []
        for g in _pages(eks, "list_nodegroups", "nodegroups", clusterName=name):
            sc = eks.describe_nodegroup(clusterName=name, nodegroupName=g)["nodegroup"].get("scalingConfig") or {}
            groups.append(g)
            if sc.get("maxSize"):
                ctx.add(
                    "eks_nodegroup_max",
                    f"{name}/{g}",
                    region,
                    pct=100.0 * sc.get("desiredSize", 0) / sc["maxSize"],
                    used=sc.get("desiredSize", 0),
                    limit=sc["maxSize"],
                    load=True,
                    min=sc.get("minSize"),
                )
        row["nodegroups"] = len(groups)
        try:
            token = eks_token(sts, name, region)

            def read(path: str, cap: int, c: dict = c, token: str = token) -> list[dict]:
                return _k8s_list(c["endpoint"], c["certificateAuthority"]["data"], token, path, cap)

            row.update(read_workloads(read), access="read")
        except K8sRefused as exc:
            row.update(access="refused", detail=f"HTTP {exc}: this identity has no access entry on the cluster")
        except K8sUnreachable as exc:
            row.update(access="unreachable", detail=f"could not reach the endpoint from this network: {exc}")
        except (KeyError, ValueError, ssl.SSLError) as exc:
            row.update(access="unreachable", detail=f"could not read: {type(exc).__name__}")
        for key, rule in (("ci_mem", "eks_memory_pressure"), ("ci_cpu", "eks_cpu_pressure")):
            for res, s in m[key].items():
                parts = res.split("|")
                if parts[0] == name and s.n and len(parts) == 3:
                    row["insights"] = True
                    ctx.add(rule, f"{name}/{parts[1]}/{parts[2]}", region, pct=min(s.high, 100.0), load=True)
        outage_services.profile(
            ctx,
            "eks",
            name,
            region,
            {
                "Kubernetes": c.get("version"),
                "Platform": c.get("platformVersion"),
                "Node groups": len(groups),
                "Workloads read": row.get("workload_count") if row.get("access") == "read" else "not read",
                "Pods": row.get("pods"),
                "Endpoint": "public" if (c.get("resourcesVpcConfig") or {}).get("endpointPublicAccess") else "private",
            },
        )
        with ctx._lock:
            ctx.clusters.append(row)
    with ctx._lock:
        ctx.eks_subnets[region] = subnets
    ctx.r.ok("eks")


# ------------------------------------------------------------------------------------------------ running
AREAS = ("limits", "s3_limits", "connect", "fixed", "storage", "msk", "eks", "network", "certificates")
EKS_BILLED = "Amazon Elastic Container Service for Kubernetes"  # what Cost Explorer calls EKS
GLOBAL_TASKS = [
    ("account limits", ("limits",), task_account_limits, None),
    ("s3 limits", ("s3_limits",), task_s3_limits, None),
]
REGION_TASKS = [
    ("service quotas", ("limits",), task_quotas, None),
    ("region limits", ("limits",), task_region_limits, None),
    ("s3 requests", ("s3_limits",), task_s3_requests, None),
    ("connect", ("connect",), task_connect, ("Amazon Connect",)),
    ("ec2", ("fixed", "storage"), task_ec2, None),
    ("rds", ("fixed", "storage"), task_rds, ("Amazon Relational Database Service",)),
    ("autoscaling", ("fixed",), task_asg, None),
    ("ecs", ("fixed",), task_ecs, ("Amazon Elastic Container Service",)),
    ("elasticache", ("fixed",), task_elasticache, ("Amazon ElastiCache",)),
    ("opensearch", ("fixed", "storage"), task_opensearch, ("Amazon OpenSearch Service",)),
    ("redshift", ("fixed",), task_redshift, ("Amazon Redshift",)),
    ("efs and fsx", ("storage",), task_efs_fsx, ("Amazon Elastic File System", "Amazon FSx")),
    ("dynamodb", ("fixed",), task_dynamodb, ("Amazon DynamoDB",)),
    ("kinesis", ("fixed",), task_kinesis, ("Amazon Kinesis",)),
    ("msk", ("msk",), task_msk, ("Amazon Managed Streaming for Apache Kafka",)),
    ("eks", ("eks",), task_eks, ("Amazon Elastic Kubernetes Service", EKS_BILLED)),
    ("network", ("network",), task_network, None),
    ("direct connect", ("network",), task_dx, ("AWS Direct Connect",)),
    ("certificates", ("certificates",), task_certificates, None),
]


def _finish(ctx: OutageCtx) -> None:
    """Subnets, once it is known which of them EKS uses; quota values kept only for quotas near a limit."""
    outage_services.finish_alarms(ctx)
    outage_services.finish_lambda_zones(ctx)
    for region, subnets in ctx.subnets.items():
        used_by = ctx.eks_subnets.get(region) or {}
        for s in subnets:
            bits = int((s.get("CidrBlock") or "0/32").rsplit("/", 1)[-1])
            total = 2 ** (32 - bits) - 5  # AWS reserves five addresses in each subnet
            if total <= 16:  # /27 and smaller are carved out for one job, such as a TGW attachment
                continue
            left = s.get("AvailableIpAddressCount", 0)
            tags = {t["Key"]: t["Value"] for t in s.get("Tags") or []}
            label = f"{tags['Name']} ({s['SubnetId']})" if tags.get("Name") else s["SubnetId"]
            cluster = used_by.get(s["SubnetId"])
            ctx.add(
                "eks_subnet_ips" if cluster else "subnet_ips",
                label,
                region,
                pct=100.0 * (total - left) / total,
                used=total - left,
                limit=total,
                load=bool(cluster),
                note=f"EKS cluster {cluster}" if cluster else "",
            )


def _keep_profiles(profiles: list[dict]) -> list[dict]:
    """The busiest of each service in the account: a task that ran twice counts once."""
    unique = {(p["svc"], p["res"], p["region"]): p for p in profiles}
    by_service: dict[str, list[dict]] = {}
    for p in unique.values():
        by_service.setdefault(p["svc"], []).append(p)
    keep = outage_services.MAX_PROFILES
    return [
        p
        for rows in by_service.values()
        for p in sorted(rows, key=lambda p: -max((s.get("peak") or 0 for s in p["stats"]), default=0))[:keep]
    ]


def account_checks(
    session: boto3.Session, account_id: str, regions: list[str] | None, info: dict | None = None
) -> tuple[dict, list[Issue]]:
    """Return ({rows, clusters, checks, regions, read_at, seconds, compared}, issues) for one account."""
    from ..aws_session import ClientCache
    from .inventory import enabled_regions

    started = time.monotonic()
    session = ClientCache(session)
    try:
        region_list = enabled_regions(session, regions)
    except (ClientError, BotoCoreError) as exc:
        code, msg, hint = describe_exception(exc)
        return {}, [
            Issue("error", "outage", f"could not list regions: {msg}", hint, account_id=account_id, error_code=code)
        ]
    if regions:
        region_list = [r for r in regions if r in region_list]
    ctx = OutageCtx(session, account_id, region_list, info or {})
    jobs = [(t, None) for t in GLOBAL_TASKS] + [(t, r) for r in region_list for t in REGION_TASKS]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(contextvars.copy_context().run, _run, ctx, t, r) for t, r in jobs]
        for fut in futures:
            fut.result()
    _finish(ctx)
    # A task that failed on a timeout runs again from the start: a row read twice counts once.
    unique = {(r["rule"], r["res"], r["region"]): r for r in ctx.rows}
    rows = sorted(unique.values(), key=lambda r: -(r.get("pct") or 0))
    kept = {r["qcode"] for r in rows if r.get("qcode")}
    out = {
        "rows": rows[:MAX_ROWS],
        "rows_cut": max(len(rows) - MAX_ROWS, 0),
        "clusters": list({(c["name"], c["region"]): c for c in ctx.clusters}.values()),
        "profiles": _keep_profiles(ctx.profiles),
        "profile_counts": dict(Counter(p for p, _, _ in {(p["svc"], p["res"], p["region"]) for p in ctx.profiles})),
        "quota_values": {k: v for k, v in ctx.quota_values.items() if k in kept and len(v) > 1},
        "checks": ctx.r.finish(),
        "facts": ctx.r.facts,
        "compared": ctx.compared,
        "regions": region_list,
        "read_at": ctx.now.isoformat(timespec="seconds"),
        "seconds": round(time.monotonic() - started, 1),
    }
    return out, _collapse(ctx.issues)


# The per-service reviews add their metrics and tasks to the ones above. Last, as they use this module.
from . import outage_lifecycle, outage_services  # noqa: E402, F401
