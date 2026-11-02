"""Per-service reviews for the Outage Risk Report: what each service is set to, its peak against its
average, its limits and its resilience settings, resource by resource.

The rows in collectors/outage.py say what is wrong. The profiles here say what is there, so that a
service's review can show its live configuration as well as its findings. Everything is read-only.
What a review cannot see from these calls (topics inside a cluster, Terraform drift, prices of other
options) is listed for each service in data/outage_services.yaml and shown as not checked.

Imported at the end of collectors/outage.py, and adds its metrics and tasks to that module's.
"""

from __future__ import annotations

import ast
import operator
import re
from datetime import timedelta

from botocore.exceptions import ClientError

from ..aws_session import with_backoff
from ..logging_config import get_logger
from .assurance import _code, _pages
from .outage import (
    GIB,
    GLOBAL_TASKS,
    LOOKBACK_DAYS,
    MAX_ITEMS,
    METRICS,
    PERIOD,
    REGION_TASKS,
    OutageCtx,
    Series,
    _filling,
    _search,
)

log = get_logger("outage")

MAX_PROFILES = 60  # per service per account, busiest first; the counts cover every resource
MAX_ALARMS = 5000
# AWS's documented figures, used where no API gives them.
CACHE_MAX_CLIENTS = 65000  # maxclients on Redis OSS and Valkey, not modifiable
SEARCH_SHARDS_PER_NODE = 1000
KINESIS_MB_PER_SHARD = 1.0  # write, per second
GLOBAL_METRIC_REGION = "us-east-1"  # CloudFront publishes here, whichever regions are scanned

RDS = "Amazon Relational Database Service"
MQ = "Amazon MQ"
APIGW = "Amazon API Gateway"
SQS = "Amazon Simple Queue Service"
SNS = "Amazon Simple Notification Service"
SFN = "AWS Step Functions"
EVENTS = "Amazon EventBridge"
COGNITO = "Amazon Cognito"
KAFKA = "Amazon Managed Streaming for Apache Kafka"
CACHE = "Amazon ElastiCache"
SEARCH = "Amazon OpenSearch Service"
KINESIS = "Amazon Kinesis"
LAMBDA = "AWS Lambda"
DDB = "Amazon DynamoDB"
LB = "Amazon Elastic Load Balancing"
CLOUDFRONT = "Amazon CloudFront"

METRICS.update(
    {
        "msk_in": ("AWS/Kafka", ("Cluster Name", "Broker ID"), "BytesInPerSec", "Maximum", KAFKA),
        "msk_out": ("AWS/Kafka", ("Cluster Name", "Broker ID"), "BytesOutPerSec", "Maximum", KAFKA),
        "msk_urp": ("AWS/Kafka", ("Cluster Name", "Broker ID"), "UnderReplicatedPartitions", "Maximum", KAFKA),
        "msk_offline": ("AWS/Kafka", ("Cluster Name",), "OfflinePartitionsCount", "Maximum", KAFKA),
        "rds_conn": ("AWS/RDS", ("DBInstanceIdentifier",), "DatabaseConnections", "Maximum", RDS),
        "rds_mem": ("AWS/RDS", ("DBInstanceIdentifier",), "FreeableMemory", "Minimum", RDS),
        "rds_lag": ("AWS/RDS", ("DBInstanceIdentifier",), "ReplicaLag", "Maximum", RDS),
        "cache_conn": ("AWS/ElastiCache", ("CacheClusterId", "CacheNodeId"), "CurrConnections", "Maximum", CACHE),
        "cache_hit": ("AWS/ElastiCache", ("CacheClusterId", "CacheNodeId"), "CacheHitRate", "Minimum", CACHE),
        "search_blocked": ("AWS/ES", ("ClientId", "DomainName"), "ClusterIndexWritesBlocked", "Maximum", SEARCH),
        "search_shards": ("AWS/ES", ("ClientId", "DomainName"), "Shards.active", "Maximum", SEARCH),
        "search_nodes": ("AWS/ES", ("ClientId", "DomainName"), "Nodes", "Minimum", SEARCH),
        "search_rejected": ("AWS/ES", ("ClientId", "DomainName"), "ThreadpoolWriteRejected", "Sum", SEARCH),
        "kin_in": ("AWS/Kinesis", ("StreamName",), "IncomingBytes", "Sum", KINESIS),
        "kin_age": ("AWS/Kinesis", ("StreamName",), "GetRecords.IteratorAgeMilliseconds", "Maximum", KINESIS),
        "lambda_dur": ("AWS/Lambda", ("FunctionName",), "Duration", "Maximum", LAMBDA),
        "lambda_inv": ("AWS/Lambda", ("FunctionName",), "Invocations", "Sum", LAMBDA),
        "lambda_err": ("AWS/Lambda", ("FunctionName",), "Errors", "Sum", LAMBDA),
        "apigw_count": ("AWS/ApiGateway", ("ApiName",), "Count", "Sum", APIGW),
        "apigw_5xx": ("AWS/ApiGateway", ("ApiName",), "5XXError", "Sum", APIGW),
        "apigw2_count": ("AWS/ApiGateway", ("ApiId",), "Count", "Sum", APIGW),
        "apigw2_5xx": ("AWS/ApiGateway", ("ApiId",), "5xx", "Sum", APIGW),
        "sqs_age": ("AWS/SQS", ("QueueName",), "ApproximateAgeOfOldestMessage", "Maximum", SQS),
        "sqs_depth": ("AWS/SQS", ("QueueName",), "ApproximateNumberOfMessagesVisible", "Maximum", SQS),
        "sns_failed": ("AWS/SNS", ("TopicName",), "NumberOfNotificationsFailed", "Sum", SNS),
        "sns_pub": ("AWS/SNS", ("TopicName",), "NumberOfMessagesPublished", "Sum", SNS),
        "alb_5xx": ("AWS/ApplicationELB", ("LoadBalancer",), "HTTPCode_ELB_5XX_Count", "Sum", None),
        "alb_req": ("AWS/ApplicationELB", ("LoadBalancer",), "RequestCount", "Sum", None),
        "nat_drop": ("AWS/NATGateway", ("NatGatewayId",), "PacketsDropCount", "Sum", None),
        "nat_conn": ("AWS/NATGateway", ("NatGatewayId",), "ActiveConnectionCount", "Maximum", None),
        "tgw_hole": ("AWS/TransitGateway", ("TransitGateway",), "PacketDropCountBlackhole", "Sum", None),
        "tgw_route": ("AWS/TransitGateway", ("TransitGateway",), "PacketDropCountNoRoute", "Sum", None),
        "mq_cpu": ("AWS/AmazonMQ", ("Broker",), "CpuUtilization", "Average", MQ),
        "mq_heap": ("AWS/AmazonMQ", ("Broker",), "HeapUsage", "Maximum", MQ),
        "mq_store": ("AWS/AmazonMQ", ("Broker",), "StorePercentUsage", "Maximum", MQ),
        "sfn_throttled": ("AWS/States", ("StateMachineArn",), "ExecutionThrottled", "Sum", SFN),
        "sfn_failed": ("AWS/States", ("StateMachineArn",), "ExecutionsFailed", "Sum", SFN),
        "ev_throttled": ("AWS/Events", ("RuleName",), "ThrottledRules", "Sum", EVENTS),
        "ev_failed": ("AWS/Events", ("RuleName",), "FailedInvocations", "Sum", EVENTS),
        "cog_throttle": ("AWS/Cognito", ("UserPool", "UserPoolClient"), "SignInThrottles", "Sum", COGNITO),
        "bed_throttle": ("AWS/Bedrock", ("ModelId",), "InvocationThrottles", "Sum", "Amazon Bedrock"),
        "bed_calls": ("AWS/Bedrock", ("ModelId",), "Invocations", "Sum", "Amazon Bedrock"),
    }
)

# What should wake someone before each service fails: (service, namespace, metric).
ALARM_METRICS = {
    "msk": ("AWS/Kafka", "KafkaDataLogsDiskUsed"),
    "rds": ("AWS/RDS", "FreeStorageSpace"),
    "elasticache": ("AWS/ElastiCache", "DatabaseMemoryUsagePercentage"),
    "opensearch": ("AWS/ES", "FreeStorageSpace"),
    "redshift": ("AWS/Redshift", "PercentageDiskSpaceUsed"),
    "mq": ("AWS/AmazonMQ", "StorePercentUsage"),
    "sqs": ("AWS/SQS", "ApproximateAgeOfOldestMessage"),
}


def stat(series: Series | None, label: str, unit: str = "", scale: float = 1.0, limit=None, per: float = 1.0):
    """A metric's peak and average for a review; None with no data. ``per`` turns a sum per hour into a rate."""
    if not series or not series.n:
        return None
    row = {
        "k": label,
        "peak": round(series.high * scale / per, 2),
        "avg": round(series.total / series.n * scale / per, 2),
        "unit": unit,
    }
    if limit:
        row["limit"] = limit
    trend = series.slope() * scale / per
    if trend:
        row["per_day"] = round(trend, 3)
    return row


def profile(ctx: OutageCtx, svc: str, res: str, region: str, facts: dict, stats=(), alarm: str | None = None) -> None:
    """One resource's configuration and metrics. ``alarm``: the dimension value its alarm would name."""
    clean = {k: v for k, v in facts.items() if v not in (None, "")}
    row = {"svc": svc, "res": res, "region": region, "facts": clean, "stats": [s for s in stats if s]}
    with ctx._lock:
        ctx.profiles.append(row)
        if alarm is not None and svc in ALARM_METRICS:
            ctx.alarm_wants.append((svc, res, region, alarm))


def _per_node(series: dict[str, Series], name: str, part: int = 0) -> list[Series]:
    return [s for res, s in series.items() if res.split("|")[part] == name and s.n]


def _busiest(series: dict[str, Series], name: str, part: int = 0) -> Series | None:
    return max(_per_node(series, name, part), key=lambda s: s.high, default=None)


# -------------------------------------------------------------------------------------------- alarms
def task_alarms(ctx: OutageCtx, region: str) -> None:
    """Which metrics have a CloudWatch alarm. Another monitoring tool may watch them too: the report says so."""
    seen: set[tuple[str, str, str]] = set()
    cw = ctx.client("cloudwatch", region)
    for a in _pages(cw, "describe_alarms", "MetricAlarms", cap=MAX_ALARMS):
        metrics = [(a.get("Namespace"), a.get("MetricName"), a.get("Dimensions") or [])]
        for q in a.get("Metrics") or []:
            m = (q.get("MetricStat") or {}).get("Metric") or {}
            metrics.append((m.get("Namespace"), m.get("MetricName"), m.get("Dimensions") or []))
        for ns, name, dims in metrics:
            for d in dims:
                seen.add((ns or "", name or "", d.get("Value") or ""))
            if not dims:
                seen.add((ns or "", name or "", ""))
    with ctx._lock:
        ctx.alarms[region] = seen
    ctx.r.ok("alarms")


def finish_alarms(ctx: OutageCtx) -> None:
    """A resource whose region's alarms were read, and none watches the metric that fails first."""
    for svc, res, region, value in ctx.alarm_wants:
        seen = ctx.alarms.get(region)
        if seen is None:
            continue
        ns, metric = ALARM_METRICS[svc]
        if (ns, metric, value) not in seen:
            ctx.add("no_alarm", f"{svc}: {res}", region, note=f"no CloudWatch alarm on {metric}")


# -------------------------------------------------------------------------------------- broker settings
_PROPERTY = re.compile(r"^\s*([\w.]+)\s*=\s*(.+?)\s*$", re.M)


def msk_settings(client, software: dict) -> dict[str, str] | None:
    """The cluster's server.properties, None where it runs on the MSK defaults."""
    arn, revision = software.get("ConfigurationArn"), software.get("ConfigurationRevision")
    if not arn or not revision:
        return None
    raw = client.describe_configuration_revision(Arn=arn, Revision=revision).get("ServerProperties") or b""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    return dict(_PROPERTY.findall(text))


def msk_profile(ctx: OutageCtx, client, c: dict, region: str, m: dict) -> None:
    """The review's half of a cluster: settings, traffic, durability. Called from task_msk."""
    prov, name = c["Provisioned"], c["ClusterName"]
    node = prov.get("BrokerNodeGroupInfo") or {}
    software = prov.get("CurrentBrokerSoftwareInfo") or {}
    auth = prov.get("ClientAuthentication") or {}
    methods = [
        k
        for k, on in (
            ("IAM", ((auth.get("Sasl") or {}).get("Iam") or {}).get("Enabled")),
            ("SCRAM", ((auth.get("Sasl") or {}).get("Scram") or {}).get("Enabled")),
            ("TLS", (auth.get("Tls") or {}).get("Enabled")),
            ("none", (auth.get("Unauthenticated") or {}).get("Enabled")),
        )
        if on
    ]
    storage = (node.get("StorageInfo") or {}).get("EbsStorageInfo") or {}
    props = msk_settings(client, software)
    facts = {
        "Broker": (node.get("InstanceType") or "").removeprefix("kafka."),
        "Brokers": prov.get("NumberOfBrokerNodes"),
        "Zones": len(node.get("ClientSubnets") or []) or None,
        "Kafka": software.get("KafkaVersion"),
        "Storage per broker": f"{storage['VolumeSize']:,} GiB" if storage.get("VolumeSize") else None,
        "Provisioned storage throughput": (
            "on" if (storage.get("ProvisionedThroughput") or {}).get("Enabled") else "off"
        )
        if storage
        else None,
        "Storage mode": prov.get("StorageMode"),
        "Monitoring": prov.get("EnhancedMonitoring"),
        "Client auth": ", ".join(methods),
        "Configuration": "MSK defaults" if props is None else f"revision {software.get('ConfigurationRevision')}",
    }
    if props is not None:
        for key, label in (
            ("default.replication.factor", "Default replication factor"),
            ("min.insync.replicas", "Min in-sync replicas"),
            ("unclean.leader.election.enable", "Unclean leader election"),
            ("log.retention.hours", "Default retention, hours"),
            ("auto.create.topics.enable", "Auto create topics"),
        ):
            facts[label] = props.get(key)
        if str(props.get("unclean.leader.election.enable")).lower() == "true":
            ctx.add(
                "msk_unclean_leader", name, region, note="unclean.leader.election.enable=true: a failover can lose data"
            )
        low = []
        if (
            props.get("default.replication.factor", "3").isdigit()
            and int(props.get("default.replication.factor", "3")) < 3
        ):
            low.append(f"default.replication.factor={props['default.replication.factor']}")
        if props.get("min.insync.replicas", "2").isdigit() and int(props.get("min.insync.replicas", "2")) < 2:
            low.append(f"min.insync.replicas={props['min.insync.replicas']}")
        if low:
            ctx.add(
                "msk_low_replication",
                name,
                region,
                note="; ".join(low) + " (the cluster default; a topic can override it)",
            )
    urp = sum(s.high > 0 for s in _per_node(m["msk_urp"], name))
    if urp:
        ctx.add("msk_under_replicated", name, region, used=urp, unit="broker(s) with under-replicated partitions")
    off = m["msk_offline"].get(name)
    if off and off.n and off.high > 0:
        ctx.add("msk_offline", name, region, used=round(off.high), unit="partitions offline at the worst")
    mb = 1 / 1024**2
    stats = [
        stat(_busiest(m["msk_disk"], name), "Fullest broker disk", "%", limit=100),
        stat(_busiest(m["msk_parts"], name), "Partitions on the busiest broker", "per broker"),
        stat(_busiest(m["msk_in"], name), "Bytes in, busiest broker", "MB/s", mb),
        stat(_busiest(m["msk_out"], name), "Bytes out, busiest broker", "MB/s", mb),
        stat(_busiest(m["msk_user"], name), "CPU user, busiest broker", "%"),
    ]
    profile(ctx, "msk", name, region, facts, stats, alarm=name)


# ------------------------------------------------------------------------------------------------- RDS
_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}
_FUNCS = {"LEAST": min, "GREATEST": max}


def _eval(node):
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _FUNCS:
        return _FUNCS[node.func.id](*[_eval(a) for a in node.args])
    raise ValueError("not a plain formula")


def max_connections(value: str | None, memory_bytes: float | None) -> float | None:
    """A parameter group's max_connections: a number, or a formula such as LEAST({DBInstanceClassMemory/9531392},5000).
    None for anything else, such as a formula with log(): the report then says it was not compared.
    DBInstanceClassMemory is a little below the instance's memory, so a formula's answer is slightly high."""
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        return float(text)
    if "DBInstanceClassMemory" in text and not memory_bytes:
        return None
    body = text.replace("{", "(").replace("}", ")").replace("DBInstanceClassMemory", str(float(memory_bytes or 0)))
    try:
        return float(_eval(ast.parse(body, mode="eval")))
    except (SyntaxError, ValueError, TypeError, ZeroDivisionError, RecursionError):
        return None


def task_rds_review(ctx: OutageCtx, region: str) -> None:
    rds = ctx.client("rds", region)
    dbs = _pages(rds, "describe_db_instances", "DBInstances", cap=MAX_ITEMS)
    if not dbs:
        ctx.r.ok("rds")
        return
    m = ctx.metrics(region)
    memory = _instance_memory(ctx, region, {d.get("DBInstanceClass", "") for d in dbs})
    limits: dict[str, str | None] = {}
    members: dict[str, int] = {}
    for d in dbs:
        if d.get("DBClusterIdentifier"):
            members[d["DBClusterIdentifier"]] = members.get(d["DBClusterIdentifier"], 0) + 1
    for d in dbs:
        name = d["DBInstanceIdentifier"]
        cls = d.get("DBInstanceClass", "")
        conn = m["rds_conn"].get(name)
        limit = None
        groups = d.get("DBParameterGroups") or []
        if groups and conn and conn.n:
            group = groups[0].get("DBParameterGroupName", "")
            if group not in limits:
                limits[group] = _rds_parameter(rds, group, "max_connections")
            limit = max_connections(limits[group], memory.get(cls))
            if limit:
                ctx.add(
                    "rds_connections",
                    name,
                    region,
                    pct=100.0 * conn.high / limit,
                    used=round(conn.high),
                    limit=round(limit),
                    load=True,
                    note=f"{cls}; from parameter group {group}",
                )
        low = m["rds_mem"].get(name)
        if low and low.n and memory.get(cls):
            ctx.add(
                "rds_memory",
                name,
                region,
                pct=100.0 - 100.0 * low.low / memory[cls],
                note=f"{cls}; lowest freeable memory {low.low / GIB:,.1f} GiB of {memory[cls] / GIB:,.0f}",
            )
        lag = m["rds_lag"].get(name)
        if lag and lag.n and lag.high >= 60:
            ctx.add("rds_replica_lag", name, region, used=round(lag.high), unit="seconds behind at the worst")
        cluster = d.get("DBClusterIdentifier")
        if cluster and members.get(cluster) == 1 and d.get("Engine", "").startswith(("aurora", "docdb", "neptune")):
            ctx.add("aurora_no_reader", name, region, note=f"cluster {cluster} has one instance")
        facts = {
            "Engine": f"{d.get('Engine', '')} {d.get('EngineVersion', '')}".strip(),
            "Class": cls,
            "Multi-AZ": ("cluster" if cluster else "yes" if d.get("MultiAZ") else "no"),
            "Storage": None if cluster else f"{d.get('AllocatedStorage')} GiB {d.get('StorageType', '')}".strip(),
            "Autoscaling ceiling": f"{d['MaxAllocatedStorage']} GiB" if d.get("MaxAllocatedStorage") else None,
            "Provisioned IOPS": d.get("Iops"),
            "Backups, days": d.get("BackupRetentionPeriod"),
            "Replica of": (d.get("ReadReplicaSourceDBInstanceIdentifier") or "").rsplit(":", 1)[-1],
            "Cluster": cluster,
        }
        stats = [
            stat(m["rds_cpu"].get(name), "CPU", "%", limit=100),
            stat(conn, "Connections", "", limit=round(limit) if limit else None),
            stat(low, "Lowest freeable memory", "GiB", 1 / GIB) if low else None,
            stat(m["rds_free"].get(name), "Free storage", "GiB", 1 / GIB),
            stat(lag, "Replica lag", "s"),
        ]
        profile(ctx, "rds", name, region, facts, stats, alarm=name)
    _rds_maintenance(ctx, rds, region)
    ctx.r.ok("rds")


def _rds_parameter(rds, group: str, name: str) -> str | None:
    for p in _pages(rds, "describe_db_parameters", "Parameters", DBParameterGroupName=group):
        if p.get("ParameterName") == name:
            return p.get("ParameterValue")
    return None


def _rds_maintenance(ctx: OutageCtx, rds, region: str) -> None:
    pending = _pages(rds, "describe_pending_maintenance_actions", "PendingMaintenanceActions")
    for item in pending:
        name = item.get("ResourceIdentifier", "").rsplit(":", 1)[-1]
        for a in item.get("PendingMaintenanceActionDetails") or []:
            when = a.get("CurrentApplyDate") or a.get("ForcedApplyDate") or a.get("AutoAppliedAfterDate")
            if when:
                ctx.add(
                    "rds_maintenance",
                    name,
                    region,
                    ends=when.date().isoformat(),
                    note=f"{a.get('Action')}: {a.get('Description') or ''}"[:200],
                )


def _instance_memory(ctx: OutageCtx, region: str, classes: set[str]) -> dict[str, float]:
    """Bytes of memory of RDS classes, from the matching EC2 type (db.r6g.large has r6g.large's memory)."""
    names = {c: c.removeprefix("db.") for c in classes if c.startswith("db.") and c != "db.serverless"}
    out: dict[str, float] = {}
    if not names:
        return out
    ec2 = ctx.client("ec2", region)
    wanted = sorted(set(names.values()))
    sizes: dict[str, float] = {}
    for at in range(0, len(wanted), 100):
        try:
            for t in _pages(ec2, "describe_instance_types", "InstanceTypes", InstanceTypes=wanted[at : at + 100]):
                sizes[t["InstanceType"]] = (t.get("MemoryInfo") or {}).get("SizeInMiB", 0) * 1024.0**2
        except ClientError as exc:
            if _code(exc) != "InvalidInstanceType":  # an RDS-only class has no EC2 twin: its memory stays unknown
                raise
    for c, n in names.items():
        if sizes.get(n):
            out[c] = sizes[n]
    return out


# ------------------------------------------------------------------------------------------ ElastiCache
def task_cache_review(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("elasticache", region)
    m = ctx.metrics(region)
    for g in _pages(client, "describe_replication_groups", "ReplicationGroups", cap=MAX_ITEMS):
        name = g["ReplicationGroupId"]
        members = g.get("MemberClusters") or []
        failover, multi = g.get("AutomaticFailover"), g.get("MultiAZ")
        if failover != "enabled":
            ctx.add("cache_no_failover", name, region, note=f"automatic failover {failover or 'off'}")
        elif multi != "enabled":
            ctx.add("cache_no_multi_az", name, region)
        high = None
        for member in members:
            conn = _busiest(m["cache_conn"], member)
            if conn and (high is None or conn.high > high.high):
                high = conn
        if high:
            ctx.add(
                "cache_connections",
                name,
                region,
                pct=100.0 * high.high / CACHE_MAX_CLIENTS,
                used=round(high.high),
                limit=CACHE_MAX_CLIENTS,
                load=True,
            )
        first = members[0] if members else name
        groups = g.get("NodeGroups") or []
        stats = [
            stat(_busiest(m["cache_cpu"], first), "Engine CPU", "%", limit=100),
            stat(_busiest(m["cache_mem"], first), "Memory used", "%", limit=100),
            stat(high, "Connections", "", limit=CACHE_MAX_CLIENTS),
            stat(_busiest(m["cache_hit"], first), "Lowest hit rate", ""),
        ]
        facts = {
            "Node": g.get("CacheNodeType"),
            "Engine": g.get("Engine"),
            "Shards": len(groups) or None,
            "Nodes": len(members) or None,
            "Cluster mode": g.get("ClusterMode") or ("enabled" if g.get("ClusterEnabled") else "disabled"),
            "Automatic failover": failover,
            "Multi-AZ": multi,
            "Data tiering": g.get("DataTiering"),
        }
        profile(ctx, "elasticache", name, region, facts, stats, alarm=first)
    ctx.r.ok("elasticache")


# ------------------------------------------------------------------------------------------------ Lambda
def task_lambda_review(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("lambda", region)
    m = ctx.metrics(region)
    functions = _pages(client, "list_functions", "Functions", cap=MAX_ITEMS)
    for f in functions:
        name = f["FunctionName"]
        timeout = f.get("Timeout") or 0
        dur = m["lambda_dur"].get(name)
        if dur and dur.n and timeout:
            ctx.add(
                "lambda_timeout",
                name,
                region,
                pct=100.0 * dur.high / (timeout * 1000.0),
                used=round(dur.high / 1000.0, 1),
                limit=timeout,
                unit="seconds",
                load=True,
                note=f"{f.get('MemorySize')} MB",
            )
        inv = m["lambda_inv"].get(name)
        if not inv or not inv.n:
            continue
        stats = [
            stat(inv, "Invocations", "a second", per=PERIOD),
            stat(dur, "Longest run", "s", 1 / 1000, limit=timeout),
            stat(m["lambda_err"].get(name), "Errors", "an hour"),
            stat(m["lambda_throttle"].get(name), "Throttles", "an hour"),
        ]
        facts = {
            "Memory": f"{f.get('MemorySize')} MB",
            "Timeout": f"{timeout} s",
            "Runtime": f.get("Runtime"),
            "Architecture": ", ".join(f.get("Architectures") or []),
        }
        profile(ctx, "lambda", name, region, facts, stats)
    ctx.r.fact("lambda_functions", len(functions), region)
    ctx.r.ok("lambda")


# ---------------------------------------------------------------------------------------------- DynamoDB
def task_dynamodb_review(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("dynamodb", region)
    limits = client.describe_limits()
    per_read, per_write = limits.get("TableMaxReadCapacityUnits"), limits.get("TableMaxWriteCapacityUnits")
    m = ctx.metrics(region)
    tables = _pages(client, "list_tables", "TableNames", cap=MAX_ITEMS)
    busy = {t for key in ("ddb_rcu", "ddb_wcu") for t, s in m[key].items() if s.n}
    for name in tables:
        if name not in busy:  # idle: no metric, nothing to say, and a call saved per table
            continue
        t = client.describe_table(TableName=name).get("Table") or {}
        mode = (t.get("BillingModeSummary") or {}).get("BillingMode") or "PROVISIONED"
        on_demand = t.get("OnDemandThroughput") or {}
        for key, what, ceiling, table_max in (
            ("ddb_rcu", "read", per_read, on_demand.get("MaxReadRequestUnits")),
            ("ddb_wcu", "write", per_write, on_demand.get("MaxWriteRequestUnits")),
        ):
            s = m[key].get(name)
            limit = table_max if table_max and table_max > 0 else ceiling
            if s and s.n and limit and mode == "PAY_PER_REQUEST":
                ctx.add(
                    "ddb_table_limit",
                    f"{name} {what}",
                    region,
                    pct=100.0 * (s.high / PERIOD) / limit,
                    used=round(s.high / PERIOD, 1),
                    limit=limit,
                    unit="units a second",
                    load=True,
                )
        replicas = [r.get("RegionName") for r in t.get("Replicas") or []]
        facts = {
            "Mode": "on demand" if mode == "PAY_PER_REQUEST" else "provisioned",
            "Indexes": len(t.get("GlobalSecondaryIndexes") or []) or None,
            "Size": f"{(t.get('TableSizeBytes') or 0) / GIB:,.1f} GiB",
            "Global table": ", ".join(r for r in replicas if r) or None,
            "Table class": (t.get("TableClassSummary") or {}).get("TableClass"),
        }
        stats = [
            stat(m["ddb_rcu"].get(name), "Reads", "units a second", per=PERIOD),
            stat(m["ddb_wcu"].get(name), "Writes", "units a second", per=PERIOD),
            stat(m["ddb_rthrottle"].get(name), "Read throttles", "an hour"),
            stat(m["ddb_wthrottle"].get(name), "Write throttles", "an hour"),
        ]
        profile(ctx, "dynamodb", name, region, facts, stats)
    ctx.r.ok("dynamodb")


# --------------------------------------------------------------------------------------------- OpenSearch
def task_search_review(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("opensearch", region)
    names = [d["DomainName"] for d in client.list_domain_names().get("DomainNames") or []]
    m = ctx.metrics(region)
    for at in range(0, len(names), 5):
        for d in client.describe_domains(DomainNames=names[at : at + 5]).get("DomainStatusList") or []:
            name = d["DomainName"]
            c = d.get("ClusterConfig") or {}
            count = c.get("InstanceCount") or 0
            if not c.get("ZoneAwarenessEnabled"):
                ctx.add("search_no_zone", name, region, note=f"{count} data node(s), one zone")
            if not c.get("DedicatedMasterEnabled") and count > 2:
                ctx.add("search_no_master", name, region, note=f"{count} data nodes, no dedicated master")
            blocked = _busiest(m["search_blocked"], name, -1)
            if blocked and blocked.high > 0:
                ctx.add("search_write_blocked", name, region, used=1, unit="writes were blocked")
            rejected = _busiest(m["search_rejected"], name, -1)
            if rejected and rejected.total > 0:
                ctx.add("search_rejected", name, region, used=round(rejected.total), unit="writes rejected")
            shards = _busiest(m["search_shards"], name, -1)
            limit = SEARCH_SHARDS_PER_NODE * count
            if shards and limit:
                ctx.add(
                    "search_shards", name, region, pct=100.0 * shards.high / limit, used=round(shards.high), limit=limit
                )
            ebs = d.get("EBSOptions") or {}
            facts = {
                "Engine": d.get("EngineVersion"),
                "Data nodes": f"{count} x {c.get('InstanceType')}",
                "Dedicated masters": f"{c.get('DedicatedMasterCount')} x {c.get('DedicatedMasterType')}"
                if c.get("DedicatedMasterEnabled")
                else "none",
                "Zones": (c.get("ZoneAwarenessConfig") or {}).get("AvailabilityZoneCount") or 1,
                "Storage per node": f"{ebs.get('VolumeSize')} GiB {ebs.get('VolumeType', '')}".strip()
                if ebs.get("EBSEnabled")
                else "instance",
            }
            stats = [
                stat(_busiest(m["search_cpu"], name, -1), "CPU", "%", limit=100),
                stat(_busiest(m["search_jvm"], name, -1), "JVM memory pressure", "%", limit=100),
                stat(shards, "Active shards", "", limit=limit or None),
            ]
            profile(ctx, "opensearch", name, region, facts, stats, alarm=name)
    ctx.r.ok("opensearch")


# ------------------------------------------------------------------------------------------------ streams
def task_kinesis_review(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("kinesis", region)
    m = ctx.metrics(region)
    for s in _pages(client, "list_streams", "StreamSummaries", cap=MAX_ITEMS):
        name = s["StreamName"]
        d = client.describe_stream_summary(StreamName=name).get("StreamDescriptionSummary") or {}
        mode = (d.get("StreamModeDetails") or {}).get("StreamMode") or "PROVISIONED"
        shards = d.get("OpenShardCount") or 0
        hours = d.get("RetentionPeriodHours") or 24
        incoming, age = m["kin_in"].get(name), m["kin_age"].get(name)
        if incoming and incoming.n and shards and mode == "PROVISIONED":
            rate = incoming.high / PERIOD / 1024**2
            ctx.add(
                "kinesis_shards",
                name,
                region,
                pct=100.0 * rate / (shards * KINESIS_MB_PER_SHARD),
                used=round(rate, 2),
                limit=shards * KINESIS_MB_PER_SHARD,
                unit="MB/s written",
                load=True,
                note=f"{shards} shards",
            )
        if age and age.n:
            ctx.add(
                "kinesis_iterator",
                name,
                region,
                pct=100.0 * age.high / (hours * 3600000.0),
                note=f"oldest record {age.high / 60000:,.0f} minutes behind; records expire after {hours} hours",
            )
        facts = {
            "Mode": mode.lower().replace("_", " "),
            "Open shards": shards or None,
            "Retention": f"{hours} hours",
            "Consumers": d.get("ConsumerCount"),
        }
        stats = [stat(incoming, "Written", "MB/s", 1 / 1024**2, per=PERIOD), stat(age, "Reader behind", "s", 1 / 1000)]
        profile(ctx, "kinesis", name, region, facts, stats)
    ctx.r.ok("kinesis")


def task_sqs_review(ctx: OutageCtx, region: str) -> None:
    """Only queues that have a backlog are asked for their settings: an account can have thousands of queues."""
    m = ctx.metrics(region)
    if not m["sqs_age"]:
        ctx.r.ok("sqs")
        return
    client = ctx.client("sqs", region)
    urls = {u.rsplit("/", 1)[-1]: u for u in _pages(client, "list_queues", "QueueUrls", cap=MAX_ITEMS)}
    backed_up = sorted(m["sqs_age"].items(), key=lambda kv: -kv[1].high)
    for name, age in backed_up[:MAX_PROFILES]:
        if not age.n or age.high < 60 or name not in urls:
            continue
        attrs = (
            client.get_queue_attributes(
                QueueUrl=urls[name], AttributeNames=["MessageRetentionPeriod", "VisibilityTimeout", "RedrivePolicy"]
            ).get("Attributes")
            or {}
        )
        keep = int(attrs.get("MessageRetentionPeriod") or 345600)
        ctx.add(
            "sqs_backlog",
            name,
            region,
            pct=100.0 * age.high / keep,
            note=f"oldest message {age.high / 60:,.0f} minutes old; deleted after {keep / 3600:,.0f} hours",
        )
        if not attrs.get("RedrivePolicy") and not re.search(r"dlq|dead", name, re.I):
            ctx.add("sqs_no_dlq", name, region)
        facts = {
            "Retention": f"{keep / 3600:,.0f} hours",
            "Dead-letter queue": "yes" if attrs.get("RedrivePolicy") else "no",
            "Visibility timeout": f"{attrs.get('VisibilityTimeout')} s",
            "FIFO": "yes" if name.endswith(".fifo") else "no",
        }
        stats = [stat(age, "Oldest message", "s", limit=keep), stat(m["sqs_depth"].get(name), "Messages waiting", "")]
        profile(ctx, "sqs", name, region, facts, stats, alarm=name)
    ctx.r.fact("sqs_queues", len(urls), region)
    ctx.r.ok("sqs")


def task_sns_review(ctx: OutageCtx, region: str) -> None:
    m = ctx.metrics(region)
    for name, s in m["sns_failed"].items():
        if s.total > 0:
            ctx.add("sns_failed", name, region, used=round(s.total), unit="notifications failed")
            profile(
                ctx,
                "sns",
                name,
                region,
                {},
                [stat(m["sns_pub"].get(name), "Published", "an hour"), stat(s, "Failed", "an hour")],
            )
    ctx.r.ok("sns")


def task_mq_review(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("mq", region)
    m = ctx.metrics(region)
    for b in _pages(client, "list_brokers", "BrokerSummaries", cap=MAX_ITEMS):
        name = b.get("BrokerName") or b.get("BrokerId")
        mode = b.get("DeploymentMode")
        if mode == "SINGLE_INSTANCE":
            ctx.add("mq_single", name, region, note=f"{b.get('HostInstanceType')}, {b.get('EngineType')}")
        keys = {key: _busiest(m[key], name) for key in ("mq_cpu", "mq_heap", "mq_store")}
        if keys["mq_cpu"]:
            ctx.add("mq_cpu", name, region, pct=min(keys["mq_cpu"].high, 100.0), load=True)
        if keys["mq_heap"]:
            ctx.add("mq_heap", name, region, pct=min(keys["mq_heap"].high, 100.0), load=True)
        if keys["mq_store"]:
            _filling(ctx, "mq_storage", name, region, min(keys["mq_store"].last, 100.0), keys["mq_store"].slope())
        stats = [
            stat(keys["mq_cpu"], "CPU", "%", limit=100),
            stat(keys["mq_heap"], "Heap", "%", limit=100),
            stat(keys["mq_store"], "Store", "%", limit=100),
        ]
        profile(
            ctx,
            "mq",
            name,
            region,
            {"Engine": b.get("EngineType"), "Mode": mode, "Instance": b.get("HostInstanceType")},
            stats,
            alarm=name,
        )
    ctx.r.ok("mq")


# ------------------------------------------------------------------------------------------- API Gateway
def task_apigw_review(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("apigateway", region)
    throttle = client.get_account().get("throttleSettings") or {}
    rate = throttle.get("rateLimit")
    m = ctx.metrics(region)
    # The account's rate is shared by every API in the region; the hourly average understates a burst.
    total = sum(s.high for s in m["apigw_count"].values() if s.n) + sum(
        s.high for s in m["apigw2_count"].values() if s.n
    )
    if rate and total:
        peak = total / PERIOD
        ctx.add(
            "apigw_rate",
            "Requests a second, all APIs in the region",
            region,
            pct=100.0 * peak / rate,
            used=round(peak, 1),
            limit=rate,
            unit="a second",
            load=True,
            note=f"burst limit {throttle.get('burstLimit')}",
        )
    apis = _pages(client, "get_rest_apis", "items", cap=MAX_ITEMS)
    http_apis = _pages(ctx.client("apigatewayv2", region), "get_apis", "Items", cap=MAX_ITEMS)
    names = {a.get("name"): "REST" for a in apis} | {a.get("ApiId"): f"HTTP ({a.get('Name')})" for a in http_apis}
    for count_key, err_key in (("apigw_count", "apigw_5xx"), ("apigw2_count", "apigw2_5xx")):
        for api, count in m[count_key].items():
            if not count.n:
                continue
            err = m[err_key].get(api)
            if err and err.total > 0:
                ctx.add("apigw_5xx", api, region, used=round(err.total), unit="server errors")
            stats = [stat(count, "Requests", "a second", per=PERIOD), stat(err, "Server errors", "an hour")]
            profile(
                ctx,
                "apigateway",
                api,
                region,
                {
                    "Type": names.get(api, "not listed"),
                    "Account rate limit": rate,
                    "Account burst limit": throttle.get("burstLimit"),
                },
                stats,
            )
    ctx.r.ok("apigateway")


# ---------------------------------------------------------------------------------- load balancers, network
def task_lb_review(ctx: OutageCtx, region: str) -> None:
    lbs = _pages(ctx.client("elbv2", region), "describe_load_balancers", "LoadBalancers", cap=MAX_ITEMS)
    m = ctx.metrics(region)
    for lb in lbs:
        name = lb.get("LoadBalancerName", "")
        zones = lb.get("AvailabilityZones") or []
        if len(zones) < 2:
            ctx.add("lb_one_az", name, region, note=f"{lb.get('Type')}, {len(zones)} zone")
        key = lb.get("LoadBalancerArn", "").split(":loadbalancer/", 1)[-1]
        err, req = m["alb_5xx"].get(key), m["alb_req"].get(key)
        if err and err.total > 0:
            ctx.add("lb_5xx", name, region, used=round(err.total), unit="errors from the load balancer itself")
        stats = [stat(req, "Requests", "a second", per=PERIOD), stat(err, "Own 5xx errors", "an hour")]
        profile(
            ctx, "elb", name, region, {"Type": lb.get("Type"), "Scheme": lb.get("Scheme"), "Zones": len(zones)}, stats
        )
    ctx.r.ok("elb")


def task_vpc_review(ctx: OutageCtx, region: str) -> None:
    ec2 = ctx.client("ec2", region)
    m = ctx.metrics(region)
    gateways = _pages(
        ec2, "describe_nat_gateways", "NatGateways", cap=MAX_ITEMS, Filter=[{"Name": "state", "Values": ["available"]}]
    )
    subnets = {s["SubnetId"]: s for s in _pages(ec2, "describe_subnets", "Subnets", cap=MAX_ITEMS)}
    per_vpc: dict[str, set[str]] = {}
    for g in gateways:
        zone = (subnets.get(g.get("SubnetId")) or {}).get("AvailabilityZone") or "?"
        per_vpc.setdefault(g.get("VpcId", ""), set()).add(zone)
        name = g["NatGatewayId"]
        drop = m["nat_drop"].get(name)
        if drop and drop.total > 0:
            ctx.add("nat_drops", name, region, used=round(drop.total), unit="packets dropped")
        stats = [stat(m["nat_conn"].get(name), "Connections", ""), stat(drop, "Packets dropped", "an hour")]
        profile(ctx, "vpc", name, region, {"Zone": zone, "Vpc": g.get("VpcId")}, stats)
    zones_in: dict[str, set[str]] = {}
    for s in subnets.values():
        zones_in.setdefault(s.get("VpcId", ""), set()).add(s.get("AvailabilityZone", ""))
    for vpc, zones in per_vpc.items():
        if len(zones) == 1 and len(zones_in.get(vpc, ())) > 1:
            ctx.add(
                "nat_one_az",
                vpc,
                region,
                note=f"NAT only in {next(iter(zones))}; subnets in {len(zones_in[vpc])} zones",
            )
    for t in _pages(ec2, "describe_transit_gateways", "TransitGateways", cap=MAX_ITEMS):
        tid = t["TransitGatewayId"]
        drops = sum(s.total for key in ("tgw_hole", "tgw_route") if (s := m[key].get(tid)) and s.n)
        if drops > 0:
            ctx.add("tgw_drops", tid, region, used=round(drops), unit="packets dropped: blackhole or no route")
        profile(
            ctx,
            "transit_gateway",
            tid,
            region,
            {"State": t.get("State")},
            [
                stat(m["tgw_hole"].get(tid), "Blackhole drops", "an hour"),
                stat(m["tgw_route"].get(tid), "No-route drops", "an hour"),
            ],
        )
    for v in ec2.describe_vpn_connections().get("VpnConnections") or []:
        if v.get("State") != "available":
            continue
        tunnels = v.get("VgwTelemetry") or []
        up = sum(t.get("Status") == "UP" for t in tunnels)
        if tunnels and up < len(tunnels):
            ctx.add("vpn_tunnel_down", v["VpnConnectionId"], region, note=f"{up} of {len(tunnels)} tunnels up")
        profile(
            ctx,
            "vpn",
            v["VpnConnectionId"],
            region,
            {
                "Tunnels up": f"{up} of {len(tunnels)}",
                "Routing": "static" if (v.get("Options") or {}).get("StaticRoutesOnly") else "BGP",
            },
        )
    ctx.r.ok("vpc")


def task_small_services(ctx: OutageCtx, region: str) -> None:
    """Services with only an event worth reading: throttling and failures of Step Functions, EventBridge,
    Cognito and Bedrock."""
    m = ctx.metrics(region)
    for key, rule, unit, svc in (
        ("sfn_throttled", "sfn_throttled", "executions throttled", "stepfunctions"),
        ("ev_throttled", "events_throttled", "rule runs throttled", "eventbridge"),
        ("ev_failed", "events_failed", "invocations failed", "eventbridge"),
        ("cog_throttle", "cognito_throttled", "sign-ins throttled", "cognito"),
        ("bed_throttle", "bedrock_throttled", "calls throttled", "bedrock"),
    ):
        for res, s in m[key].items():
            if s.total > 0:
                name = res.rsplit(":", 1)[-1].split("|")[0]
                ctx.add(rule, name, region, used=round(s.total), unit=unit)
                profile(ctx, svc, name, region, {}, [stat(s, unit.capitalize(), "an hour")])
    ctx.r.ok("small_services")


def task_redshift_review(ctx: OutageCtx, region: str) -> None:
    m = ctx.metrics(region)
    for c in _pages(ctx.client("redshift", region), "describe_clusters", "Clusters", cap=MAX_ITEMS):
        name = c["ClusterIdentifier"]
        if c.get("NumberOfNodes") == 1:
            ctx.add("redshift_single_node", name, region, note=str(c.get("NodeType")))
        stats = [
            stat(m["redshift_cpu"].get(name), "CPU", "%", limit=100),
            stat(m["redshift_disk"].get(name), "Disk used", "%", limit=100),
        ]
        facts = {
            "Nodes": f"{c.get('NumberOfNodes')} x {c.get('NodeType')}",
            "Multi-AZ": c.get("MultiAZ"),
            "Enhanced VPC routing": c.get("EnhancedVpcRouting"),
        }
        profile(ctx, "redshift", name, region, facts, stats, alarm=name)
    ctx.r.ok("redshift")


FSX_CONFIG = {
    "WINDOWS": "WindowsConfiguration",
    "LUSTRE": "LustreConfiguration",
    "ONTAP": "OntapConfiguration",
    "OPENZFS": "OpenZFSConfiguration",
}


def task_files_review(ctx: OutageCtx, region: str) -> None:
    m = ctx.metrics(region)
    if ctx.billed("Amazon FSx"):
        for f in _pages(ctx.client("fsx", region), "describe_file_systems", "FileSystems", cap=MAX_ITEMS):
            fid = f["FileSystemId"]
            kind = f.get("FileSystemType", "")
            cfg = f.get(FSX_CONFIG.get(kind, "")) or {}
            deployment = cfg.get("DeploymentType") or ""
            if deployment.startswith("SINGLE_AZ"):
                ctx.add("fsx_single_az", fid, region, note=f"{kind}, {deployment}")
            profile(
                ctx,
                "fsx",
                fid,
                region,
                {"Type": kind, "Deployment": deployment, "Capacity": f"{f.get('StorageCapacity')} GiB"},
                [stat(m["fsx_used"].get(fid), "Storage used", "%", limit=100)],
            )
    if ctx.billed("Amazon Elastic File System"):
        for f in _pages(ctx.client("efs", region), "describe_file_systems", "FileSystems", cap=MAX_ITEMS):
            fid = f["FileSystemId"]
            size = (f.get("SizeInBytes") or {}).get("Value") or 0
            profile(
                ctx,
                "efs",
                fid,
                region,
                {
                    "Performance": f.get("PerformanceMode"),
                    "Throughput": f.get("ThroughputMode"),
                    "Size": f"{size / GIB:,.1f} GiB",
                    "One zone": f.get("AvailabilityZoneName"),
                },
                [
                    stat(m["efs_io"].get(fid), "I/O limit used", "%", limit=100),
                    stat(m["efs_credits"].get(fid), "Burst credits", "GiB", 1 / GIB),
                ],
            )
    ctx.r.ok("files")


def task_cloudfront(ctx: OutageCtx) -> None:
    """Global. CloudFront's metrics are in us-east-1, whichever regions the scan covers."""
    items = (ctx.client("cloudfront").list_distributions().get("DistributionList") or {}).get("Items") or []
    if not items:
        ctx.r.ok("cloudfront")
        return
    cw = ctx.client("cloudwatch", GLOBAL_METRIC_REGION)
    expr = [("c5", "5xxErrorRate", "Average"), ("cr", "Requests", "Sum")]
    queries = [
        {
            "Id": qid,
            "Expression": _search("AWS/CloudFront", ("DistributionId", "Region"), metric, st),
            "Label": f"{qid}~${{PROP('Dim.DistributionId')}}",
            "ReturnData": True,
        }
        for qid, metric, st in expr
    ]

    got: dict[str, dict[str, Series]] = {"c5": {}, "cr": {}}
    kwargs = {
        "MetricDataQueries": queries,
        "StartTime": ctx.now - timedelta(days=LOOKBACK_DAYS),
        "EndTime": ctx.now,
        "ScanBy": "TimestampAscending",
    }
    while True:
        resp = with_backoff(cw.get_metric_data, transient=True, **kwargs)
        for r in resp.get("MetricDataResults") or []:
            qid, _, res = str(r.get("Label") or "").partition("~")
            if qid in got:
                s = got[qid].setdefault(res, Series())
                for when, value in zip(r.get("Timestamps") or [], r.get("Values") or [], strict=False):
                    s.add(when, value)
        if not resp.get("NextToken"):
            break
        kwargs["NextToken"] = resp["NextToken"]
    for d in items:
        did = d["Id"]
        rate = got["c5"].get(did)
        if rate and rate.n and rate.high >= 1:
            ctx.add(
                "cf_errors",
                did,
                "global",
                pct=None,
                used=round(rate.high, 1),
                unit="% of requests were 5xx, at the worst hour",
                note=(d.get("Aliases") or {}).get("Items", [""])[0] if (d.get("Aliases") or {}).get("Items") else "",
            )
        groups = (d.get("OriginGroups") or {}).get("Quantity") or 0
        origins = (d.get("Origins") or {}).get("Quantity") or 0
        if not groups and d.get("Enabled"):
            ctx.add("cf_no_failover", did, "global", note=f"{origins} origin(s), no origin group to fail over to")
        profile(
            ctx,
            "cloudfront",
            did,
            "global",
            {
                "Origins": origins,
                "Origin groups": groups,
                "Price class": d.get("PriceClass"),
                "WAF": "yes" if d.get("WebACLId") else "no",
            },
            [stat(got["cr"].get(did), "Requests", "a second", per=PERIOD), stat(rate, "5xx rate", "%")],
        )
    ctx.r.ok("cloudfront")


def task_s3_profile(ctx: OutageCtx, region: str) -> None:
    """Only buckets with request metrics turned on have anything to show here."""
    m = ctx.metrics(region)
    names = {res.split("|")[0] for res in m["s3_get"]} | {res.split("|")[0] for res in m["s3_put"]}
    for name in sorted(names)[:MAX_PROFILES]:
        get = _busiest(m["s3_get"], name)
        put = _busiest(m["s3_put"], name)
        profile(
            ctx,
            "s3",
            name,
            region,
            {"Request metrics": "on"},
            [
                stat(get, "GET", "a second", per=PERIOD, limit=5500),
                stat(put, "PUT", "a second", per=PERIOD, limit=3500),
                stat(_busiest(m["s3_5xx"], name), "5xx", "an hour"),
            ],
        )
    ctx.r.ok("s3_review")


REGION_TASKS.extend(
    [
        ("alarms", ("alarms",), task_alarms, None),
        (
            "rds review",
            ("rds",),
            task_rds_review,
            (RDS, "Amazon DocumentDB (with MongoDB compatibility)", "Amazon Neptune"),
        ),
        ("elasticache review", ("elasticache",), task_cache_review, (CACHE,)),
        ("lambda review", ("lambda",), task_lambda_review, (LAMBDA,)),
        ("dynamodb review", ("dynamodb",), task_dynamodb_review, (DDB,)),
        ("opensearch review", ("opensearch",), task_search_review, (SEARCH,)),
        ("kinesis review", ("kinesis",), task_kinesis_review, (KINESIS,)),
        ("sqs review", ("sqs",), task_sqs_review, (SQS,)),
        ("sns review", ("sns",), task_sns_review, (SNS,)),
        ("mq review", ("mq",), task_mq_review, (MQ,)),
        ("api gateway review", ("apigateway",), task_apigw_review, (APIGW,)),
        ("load balancer review", ("elb",), task_lb_review, None),
        ("vpc review", ("vpc",), task_vpc_review, None),
        ("redshift review", ("redshift",), task_redshift_review, ("Amazon Redshift",)),
        ("file systems review", ("files",), task_files_review, ("Amazon FSx", "Amazon Elastic File System")),
        ("s3 review", ("s3_review",), task_s3_profile, None),
        (
            "step functions, eventbridge, cognito",
            ("small_services",),
            task_small_services,
            (SFN, EVENTS, "CloudWatch Events", COGNITO, "Amazon Bedrock"),
        ),
    ]
)
GLOBAL_TASKS.append(("cloudfront", ("cloudfront",), task_cloudfront, (CLOUDFRONT,)))
