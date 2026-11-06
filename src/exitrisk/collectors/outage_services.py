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
    CERT_DAYS,
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
    add_burstable,
    add_old_generation,
    task_certificates,
)

log = get_logger("outage")

MAX_PROFILES = 60  # per service per account, busiest first; the counts cover every resource
MAX_ALARMS = 5000
# AWS's documented figures, used where no API gives them.
CACHE_MAX_CLIENTS = 65000  # maxclients on Redis OSS and Valkey, not modifiable
SEARCH_SHARDS_PER_NODE = 1000
KINESIS_MB_PER_SHARD = 1.0  # write, per second
LAMBDA_CONCURRENCY_READS = 200  # busiest functions whose reserved concurrency is read, per region
LAMBDA_BEHIND_MS = 300_000  # a stream consumer or async queue this far behind is not keeping up
LAMBDA_ERROR_SHARE = 0.05
# Runtimes AWS has deprecated: past the block-update date a function on one cannot be changed, so a fix
# cannot be deployed during an incident. From AWS's Lambda runtimes page.
LAMBDA_DEPRECATED = {
    "python2.7", "python3.6", "python3.7", "python3.8", "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "java8", "go1.x", "dotnetcore1.0", "dotnetcore2.0",
    "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0", "dotnet6", "ruby2.5", "ruby2.7", "provided",
    "python3.9", "nodejs18.x", "ruby3.2",
}  # fmt: skip
VPN_TUNNEL_BPS = {"standard": 1.25e9, "large": 5e9}  # per tunnel, by the connection's TunnelBandwidth
TGW_ATTACHMENTS = 5000  # attachments per transit gateway, the default quota
TGW_ATTACHMENT_BPS = 100e9  # per VPC attachment in each zone: the total is compared, so it errs early
RESOLVER_QPS_PER_IP = 10000  # queries a second each endpoint address answers
VPCE_DIMS = ("Endpoint Type", "Service Name", "VPC Endpoint Id", "VPC Id")
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
        "rds_xid": ("AWS/RDS", ("DBInstanceIdentifier",), "MaximumUsedTransactionIDs", "Maximum", RDS),
        "rds_slot": ("AWS/RDS", ("DBInstanceIdentifier",), "OldestReplicationSlotLag", "Maximum", RDS),
        "cache_conn": ("AWS/ElastiCache", ("CacheClusterId", "CacheNodeId"), "CurrConnections", "Maximum", CACHE),
        "cache_hit": ("AWS/ElastiCache", ("CacheClusterId", "CacheNodeId"), "CacheHitRate", "Minimum", CACHE),
        "cache_host_cpu": ("AWS/ElastiCache", ("CacheClusterId", "CacheNodeId"), "CPUUtilization", "Average", CACHE),
        "cache_credits": ("AWS/ElastiCache", ("CacheClusterId", "CacheNodeId"), "CPUCreditBalance", "Minimum", CACHE),
        "search_blocked": ("AWS/ES", ("ClientId", "DomainName"), "ClusterIndexWritesBlocked", "Maximum", SEARCH),
        "search_shards": ("AWS/ES", ("ClientId", "DomainName"), "Shards.active", "Maximum", SEARCH),
        "search_nodes": ("AWS/ES", ("ClientId", "DomainName"), "Nodes", "Minimum", SEARCH),
        "search_rejected": ("AWS/ES", ("ClientId", "DomainName"), "ThreadpoolWriteRejected", "Sum", SEARCH),
        "search_iops_throttle": ("AWS/ES", ("ClientId", "DomainName"), "IopsThrottle", "Maximum", SEARCH),
        "search_tput_throttle": ("AWS/ES", ("ClientId", "DomainName"), "ThroughputThrottle", "Maximum", SEARCH),
        "kin_in": ("AWS/Kinesis", ("StreamName",), "IncomingBytes", "Sum", KINESIS),
        "kin_age": ("AWS/Kinesis", ("StreamName",), "GetRecords.IteratorAgeMilliseconds", "Maximum", KINESIS),
        "lambda_dur": ("AWS/Lambda", ("FunctionName",), "Duration", "Maximum", LAMBDA),
        "lambda_inv": ("AWS/Lambda", ("FunctionName",), "Invocations", "Sum", LAMBDA),
        "lambda_err": ("AWS/Lambda", ("FunctionName",), "Errors", "Sum", LAMBDA),
        "lambda_fconc": ("AWS/Lambda", ("FunctionName",), "ConcurrentExecutions", "Maximum", LAMBDA),
        "lambda_unres": ("AWS/Lambda", (), "UnreservedConcurrentExecutions", "Maximum", LAMBDA),
        "lambda_pc_util": (
            "AWS/Lambda",
            ("FunctionName", "Resource"),
            "ProvisionedConcurrencyUtilization",
            "Maximum",
            LAMBDA,
        ),
        "lambda_spill": (
            "AWS/Lambda",
            ("FunctionName", "Resource"),
            "ProvisionedConcurrencySpilloverInvocations",
            "Sum",
            LAMBDA,
        ),
        "lambda_iter": ("AWS/Lambda", ("FunctionName",), "IteratorAge", "Maximum", LAMBDA),
        "lambda_async_drop": ("AWS/Lambda", ("FunctionName",), "AsyncEventsDropped", "Sum", LAMBDA),
        "lambda_async_age": ("AWS/Lambda", ("FunctionName",), "AsyncEventAge", "Maximum", LAMBDA),
        "apigw_count": ("AWS/ApiGateway", ("ApiName",), "Count", "Sum", APIGW),
        "apigw_5xx": ("AWS/ApiGateway", ("ApiName",), "5XXError", "Sum", APIGW),
        "apigw2_count": ("AWS/ApiGateway", ("ApiId",), "Count", "Sum", APIGW),
        "apigw2_5xx": ("AWS/ApiGateway", ("ApiId",), "5xx", "Sum", APIGW),
        "sqs_age": ("AWS/SQS", ("QueueName",), "ApproximateAgeOfOldestMessage", "Maximum", SQS),
        "sqs_depth": ("AWS/SQS", ("QueueName",), "ApproximateNumberOfMessagesVisible", "Maximum", SQS),
        "sqs_sent": ("AWS/SQS", ("QueueName",), "NumberOfMessagesSent", "Sum", SQS),
        "sqs_recv": ("AWS/SQS", ("QueueName",), "NumberOfMessagesReceived", "Sum", SQS),
        "sns_failed": ("AWS/SNS", ("TopicName",), "NumberOfNotificationsFailed", "Sum", SNS),
        "sns_pub": ("AWS/SNS", ("TopicName",), "NumberOfMessagesPublished", "Sum", SNS),
        "alb_5xx": ("AWS/ApplicationELB", ("LoadBalancer",), "HTTPCode_ELB_5XX_Count", "Sum", None),
        "alb_req": ("AWS/ApplicationELB", ("LoadBalancer",), "RequestCount", "Sum", None),
        "nat_drop": ("AWS/NATGateway", ("NatGatewayId",), "PacketsDropCount", "Sum", None),
        "nat_conn": ("AWS/NATGateway", ("NatGatewayId",), "ActiveConnectionCount", "Maximum", None),
        "tgw_hole": ("AWS/TransitGateway", ("TransitGateway",), "PacketDropCountBlackhole", "Sum", None),
        "tgw_route": ("AWS/TransitGateway", ("TransitGateway",), "PacketDropCountNoRoute", "Sum", None),
        "tgw_att_in": ("AWS/TransitGateway", ("TransitGateway", "TransitGatewayAttachment"), "BytesIn", "Sum", None),
        "tgw_att_out": ("AWS/TransitGateway", ("TransitGateway", "TransitGatewayAttachment"), "BytesOut", "Sum", None),
        "vpn_in": ("AWS/VPN", ("VpnId", "TunnelIpAddress"), "TunnelDataIn", "Sum", None),
        "vpn_out": ("AWS/VPN", ("VpnId", "TunnelIpAddress"), "TunnelDataOut", "Sum", None),
        "resolver_in": ("AWS/Route53Resolver", ("EndpointId",), "InboundQueryVolume", "Sum", None),
        "resolver_out": ("AWS/Route53Resolver", ("EndpointId",), "OutboundQueryVolume", "Sum", None),
        "vpce_drop": ("AWS/PrivateLinkEndpoints", VPCE_DIMS, "PacketsDropped", "Sum", None),
        "alb_healthy": ("AWS/ApplicationELB", ("TargetGroup", "LoadBalancer"), "HealthyHostCount", "Minimum", None),
        "alb_healthy_max": ("AWS/ApplicationELB", ("TargetGroup", "LoadBalancer"), "HealthyHostCount", "Maximum", None),
        "nlb_healthy": ("AWS/NetworkELB", ("TargetGroup", "LoadBalancer"), "HealthyHostCount", "Minimum", None),
        "nlb_healthy_max": ("AWS/NetworkELB", ("TargetGroup", "LoadBalancer"), "HealthyHostCount", "Maximum", None),
        "dx_state": ("AWS/DX", ("ConnectionId",), "ConnectionState", "Minimum", "AWS Direct Connect"),
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


def finish_lambda_zones(ctx: OutageCtx) -> None:
    """A function attached to a VPC through subnets in one zone only, where its VPC spans more than one:
    the loss of that zone stops it. Judged once the subnets of the region are read."""
    for name, region, vpc, ids in ctx.lambda_subnets:
        subnets = ctx.subnets.get(region)
        if not subnets:
            continue
        zone_of = {s["SubnetId"]: s.get("AvailabilityZone") for s in subnets}
        if any(i not in zone_of for i in ids):
            continue  # a subnet the scan did not see: say nothing rather than guess
        mine = {zone_of[i] for i in ids}
        vpc_zones = {s.get("AvailabilityZone") for s in subnets if s.get("VpcId") == vpc}
        if len(mine) == 1 and len(vpc_zones) > 1:
            ctx.add("lambda_one_az", name, region, note=f"{len(ids)} subnet(s), all in {next(iter(mine))}")


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
    nodes = _per_node(m["msk_urp"], name)
    urp = sum(s.high > 0 for s in nodes)
    if urp:
        now = sum(s.n and s.last > 0 for s in nodes)
        ctx.add(
            "msk_under_replicated",
            name,
            region,
            used=urp,
            unit="broker(s) with under-replicated partitions",
            now=now,
            note=f"{now} still under-replicated in the last hour" if now else "none in the last hour",
        )
    off = m["msk_offline"].get(name)
    if off and off.n and off.high > 0:
        now = round(off.last) if off.last > 0 else 0  # offline in the last hour; 0 means it recovered
        ctx.add(
            "msk_offline", name, region, used=round(off.high), unit="partitions offline at the worst", now=now,
            note=f"{now} still offline in the last hour" if now else "none offline in the last hour",
        )  # fmt: skip
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
    groups_read: dict[str, dict[str, tuple[str | None, str]]] = {}
    try:
        cluster_groups, acu_range = _cluster_parameter_groups(rds, dbs)
    except ClientError:  # a role from before this check: the instance groups still say most of it
        cluster_groups, acu_range = {}, {}
    members: dict[str, int] = {}
    zones: dict[str, set[str]] = {}
    for d in dbs:
        if d.get("DBClusterIdentifier"):
            members[d["DBClusterIdentifier"]] = members.get(d["DBClusterIdentifier"], 0) + 1
            zones.setdefault(d["DBClusterIdentifier"], set()).add(d.get("AvailabilityZone") or "")
    for cluster, n in members.items():
        where = zones[cluster] - {""}
        if n > 1 and len(where) == 1 and len(zones[cluster]) == 1:
            ctx.add("aurora_one_az", cluster, region, note=f"all {n} instances in {next(iter(where))}")
    for d in dbs:
        name = d["DBInstanceIdentifier"]
        cls = d.get("DBInstanceClass", "")
        conn = m["rds_conn"].get(name)
        limit = None
        groups = d.get("DBParameterGroups") or []
        group = groups[0].get("DBParameterGroupName", "") if groups else ""
        params = _group_parameters(rds, group, groups_read) if group else {}
        if group and conn and conn.n:
            limit = max_connections(params.get("max_connections", (None, ""))[0], memory.get(cls))
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
        add_old_generation(ctx, "rds_old_gen", name, region, cls, note=d.get("Engine", ""))
        if cluster and members.get(cluster) == 1 and d.get("Engine", "").startswith(("aurora", "docdb", "neptune")):
            ctx.add("aurora_no_reader", name, region, note=f"cluster {cluster} has one instance")
        cluster_params = cluster_groups.get(cluster or "", {})
        vacuum = _postgres(ctx, d, name, region, params, cluster_params, m)
        ctx.add(
            "rds_busy_window",
            name,
            region,
            maintenance=d.get("PreferredMaintenanceWindow") or "",
            backup="" if cluster else d.get("PreferredBackupWindow") or "",
            multi_az=bool(cluster or d.get("MultiAZ")),
        )
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
            "Maintenance window, UTC": d.get("PreferredMaintenanceWindow"),
            "Backup window, UTC": None if cluster else d.get("PreferredBackupWindow"),
            "Autovacuum": vacuum,
            "ACUs, minimum to maximum": (
                f"{acu_range[cluster][0]:g} to {acu_range[cluster][1]:g}" if cluster in acu_range else None
            ),
        }
        stats = [
            stat(m["rds_cpu"].get(name), "CPU", "%", limit=100),
            stat(m["rds_acu"].get(name), "Capacity used, of maximum ACUs", "%", limit=100)
            if cls == "db.serverless"
            else None,
            stat(conn, "Connections", "", limit=round(limit) if limit else None),
            stat(low, "Lowest freeable memory", "GiB", 1 / GIB) if low else None,
            stat(m["rds_free"].get(name), "Free storage", "GiB", 1 / GIB),
            stat(lag, "Replica lag", "s"),
            stat(m["rds_xid"].get(name), "Oldest transaction ID age", "million", 1e-6, limit=XID_WRAP / 1e6),
        ]
        aurora = bool(cluster) and d.get("Engine", "").startswith(("aurora", "docdb", "neptune"))
        profile(ctx, "rds", name, region, facts, stats, alarm=None if aurora else name)
    _rds_maintenance(ctx, rds, region)
    ctx.r.ok("rds")


PG_PARAMETERS = ("max_connections", "autovacuum", "track_counts")
XID_WRAP = 2**31  # PostgreSQL stops taking writes a few million transactions short of this
XID_ALARM = 1e9  # AWS's advice: alarm when the oldest transaction ID age passes a billion
SLOT_FLOOR = GIB  # write-ahead log a replication slot holds back, below which it is not worth a line


def _group_parameters(rds, group: str, seen: dict) -> dict[str, tuple[str | None, str]]:
    """{name: (value, source)} of the parameters this review reads, from one DB parameter group, read once."""
    if group not in seen:
        seen[group] = {
            p["ParameterName"]: (p.get("ParameterValue"), p.get("Source") or "")
            for p in _pages(rds, "describe_db_parameters", "Parameters", DBParameterGroupName=group)
            if p.get("ParameterName") in PG_PARAMETERS
        }
    return seen[group]


def _cluster_parameter_groups(rds, dbs: list[dict]) -> tuple[dict, dict[str, tuple[float, float]]]:
    """({cluster: its cluster parameter group's parameters} for the Aurora PostgreSQL clusters, and
    {cluster: (minimum, maximum) ACUs} for the Serverless v2 ones)."""
    wanted = {d["DBClusterIdentifier"] for d in dbs if d.get("DBClusterIdentifier") and _is_postgres(d)}
    serverless = {d["DBClusterIdentifier"] for d in dbs if d.get("DBInstanceClass") == "db.serverless"}
    out: dict[str, dict] = {}
    acu: dict[str, tuple[float, float]] = {}
    if not wanted and not serverless:
        return out, acu
    seen: dict[str, dict] = {}
    for c in _pages(rds, "describe_db_clusters", "DBClusters"):
        name, group = c.get("DBClusterIdentifier"), c.get("DBClusterParameterGroup")
        scaling = c.get("ServerlessV2ScalingConfiguration") or {}
        if name in serverless and scaling.get("MaxCapacity"):
            acu[name] = (float(scaling.get("MinCapacity") or 0), float(scaling["MaxCapacity"]))
        if name not in wanted or not group:
            continue
        if group not in seen:
            seen[group] = {
                p["ParameterName"]: (p.get("ParameterValue"), p.get("Source") or "")
                for p in _pages(rds, "describe_db_cluster_parameters", "Parameters", DBClusterParameterGroupName=group)
                if p.get("ParameterName") in PG_PARAMETERS
            }
        out[name] = seen[group]
    return out, acu


def _is_postgres(d: dict) -> bool:
    return d.get("Engine", "") in ("postgres", "aurora-postgresql")


def _off(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("0", "off", "false")


def pg_setting(name: str, instance: dict, cluster: dict) -> str | None:
    """A parameter's value as the database runs it: the instance's group where it was set there, else
    the cluster's (Aurora), else the instance group's own default. None: the engine default."""
    mine, source = instance.get(name, (None, ""))
    if source == "user" or not cluster:
        return mine
    theirs = cluster.get(name, (None, ""))[0]
    return theirs if theirs is not None else mine


def _postgres(ctx: OutageCtx, d: dict, name: str, region: str, params: dict, cluster: dict, m) -> str | None:
    """The PostgreSQL checks: autovacuum off, transaction ID wraparound, and a replication slot holding
    back write-ahead log. Each fires on a setting read or a figure measured, never on a guess.
    Returns the autovacuum state for the review."""
    if not _is_postgres(d):
        return None
    vacuum = pg_setting("autovacuum", params, cluster)
    counts = pg_setting("track_counts", params, cluster)
    state = "on"
    if _off(vacuum) or _off(counts):
        why = "autovacuum is off" if _off(vacuum) else "track_counts is off, so autovacuum cannot run"
        ctx.add("pg_autovacuum_off", name, region, note=f"{why} in the parameter group")
        state = "off" if _off(vacuum) else "stopped by track_counts=off"
    xid = m["rds_xid"].get(name)
    if xid and xid.n:
        ctx.add(
            "pg_xid_age",
            name,
            region,
            pct=100.0 * xid.high / XID_ALARM,
            used=round(xid.high / 1e6),
            limit=round(XID_ALARM / 1e6),
            unit="million transactions",
            note=(
                f"oldest transaction ID age {xid.high / 1e6:,.0f} million; "
                f"writes stop near {XID_WRAP / 1e6:,.0f} million"
            ),
        )
    slot = m["rds_slot"].get(name)
    allocated = (d.get("AllocatedStorage") or 0) * GIB
    if slot and slot.n and not d.get("DBClusterIdentifier"):
        if slot.high >= max(SLOT_FLOOR, 0.1 * allocated):
            share = f", {100.0 * slot.high / allocated:.0f}% of its {allocated / GIB:,.0f} GiB" if allocated else ""
            ctx.add(
                "pg_slot_lag",
                name,
                region,
                used=round(slot.high / GIB, 1),
                unit="GiB of write-ahead log held by a replication slot at the worst",
                note=f"oldest replication slot held {slot.high / GIB:,.1f} GiB{share}",
            )
    return state


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
        cpus = [s for member in members for s in _per_node(m["cache_host_cpu"], member)]
        credits = [s for member in members for s in _per_node(m["cache_credits"], member)]
        # ElastiCache runs T-family nodes in standard mode: out of credits, a node is held to its baseline.
        add_old_generation(ctx, "cache_old_gen", name, region, g.get("CacheNodeType") or "")
        add_burstable(
            ctx,
            "cache_burstable",
            name,
            region,
            g.get("CacheNodeType") or "",
            cpu=max((s.high for s in cpus), default=None),
            credits=min(credits, key=lambda s: s.low, default=None),
            unlimited=False,
        )
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
        vpc = f.get("VpcConfig") or {}
        if vpc.get("SubnetIds"):
            with ctx._lock:
                ctx.lambda_subnets.append((name, region, vpc.get("VpcId") or "", list(vpc["SubnetIds"])))
        if f.get("Runtime") in LAMBDA_DEPRECATED:
            ctx.add("lambda_runtime", name, region, note=f"{f['Runtime']}: AWS no longer supports it")
        inv = m["lambda_inv"].get(name)
        if not inv or not inv.n:
            continue
        _lambda_events(ctx, m, name, inv, region)
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
    _lambda_concurrency(ctx, client, m, functions, region)
    ctx.r.fact("lambda_functions", len(functions), region)
    ctx.r.ok("lambda")


def _lambda_events(ctx: OutageCtx, m: dict, name: str, inv: Series, region: str) -> None:
    """What already went wrong for one function: errors, a stream falling behind, async events lost or late,
    provisioned concurrency spilling over or full."""
    err = m["lambda_err"].get(name)
    if err and err.n and inv.total and err.total >= 100 and err.total / inv.total >= LAMBDA_ERROR_SHARE:
        ctx.add(
            "lambda_errors",
            name,
            region,
            used=round(100 * err.total / inv.total, 1),
            unit="% of invocations failed",
            note=f"{err.total:,.0f} errors",
        )
    behind = m["lambda_iter"].get(name)
    if behind and behind.n and behind.high >= LAMBDA_BEHIND_MS:
        ctx.add("lambda_iterator_age", name, region, used=round(behind.high / 60000, 1), unit="minutes behind")
    dropped = m["lambda_async_drop"].get(name)
    if dropped and dropped.n and dropped.total > 0:
        ctx.add("lambda_async_dropped", name, region, used=round(dropped.total), unit="events dropped")
    late = m["lambda_async_age"].get(name)
    if late and late.n and late.high >= LAMBDA_BEHIND_MS:
        ctx.add("lambda_async_backlog", name, region, used=round(late.high / 60000, 1), unit="minutes old")
    for res, spill in m["lambda_spill"].items():
        if res.split("|")[0] == name and spill.n and spill.total > 0:
            ctx.add("lambda_pc_spill", name, region, used=round(spill.total), unit="invocations past provisioned")
            break
    util = _busiest(m["lambda_pc_util"], name)
    if util:
        ctx.add("lambda_pc_util", name, region, pct=min(100.0 * util.high, 100.0), load=True)


def _lambda_concurrency(ctx: OutageCtx, client, m: dict, functions: list[dict], region: str) -> None:
    """The busiest functions against their reserved concurrency, which is also their ceiling; and the
    pool every other function shares against what is left of the account's limit."""
    busy = sorted(
        (f["FunctionName"] for f in functions if (s := m["lambda_fconc"].get(f["FunctionName"])) and s.n),
        key=lambda n: -m["lambda_fconc"][n].high,
    )[:LAMBDA_CONCURRENCY_READS]
    for name in busy:
        try:
            reserved = client.get_function_concurrency(FunctionName=name).get("ReservedConcurrentExecutions")
        except ClientError as exc:
            log.info("concurrency of %s not read: %s", name, _code(exc))
            break
        peak = m["lambda_fconc"][name].high
        if reserved:  # 0 means the function is switched off on purpose
            ctx.add(
                "lambda_reserved",
                name,
                region,
                pct=100.0 * peak / reserved,
                used=round(peak),
                limit=reserved,
                load=True,
            )
    try:
        limit = (client.get_account_settings().get("AccountLimit") or {}).get("UnreservedConcurrentExecutions")
    except ClientError:
        return
    pool = m["lambda_unres"].get("all")
    if limit and pool and pool.n:
        ctx.add(
            "lambda_unreserved",
            "Lambda unreserved concurrency",
            region,
            pct=100.0 * pool.high / limit,
            used=round(pool.high),
            limit=limit,
            load=True,
        )


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
            throttled = [w for key, w in (("search_iops_throttle", "IOPS"), ("search_tput_throttle", "throughput"))
                         if (s := _busiest(m[key], name, -1)) and s.high > 0]  # fmt: skip
            if throttled:
                ctx.add("search_io_throttled", name, region, note=f"EBS {' and '.join(throttled)} throttled")
            shards = _busiest(m["search_shards"], name, -1)
            limit = SEARCH_SHARDS_PER_NODE * count
            if shards and limit:
                ctx.add(
                    "search_shards", name, region, pct=100.0 * shards.high / limit, used=round(shards.high), limit=limit
                )
            busiest = _busiest(m["search_cpu"], name, -1)
            kind = c.get("InstanceType") or ""
            add_burstable(ctx, "search_burstable", name, region, kind, cpu=busiest.high if busiest else None)
            add_old_generation(
                ctx, "search_old_gen", name, region, kind.removesuffix(".search").removesuffix(".elasticsearch")
            )
            if c.get("DedicatedMasterEnabled"):
                add_burstable(ctx, "search_burstable", f"{name} masters", region, c.get("DedicatedMasterType") or "")
                masters = (c.get("DedicatedMasterType") or "").removesuffix(".search").removesuffix(".elasticsearch")
                add_old_generation(ctx, "search_old_gen", f"{name} masters", region, masters)
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
        sent, recv = m["sqs_sent"].get(name), m["sqs_recv"].get(name)
        traffic = {"age_now_pct": round(100.0 * age.last / keep, 1)}
        if recv is not None or sent is not None:  # a queue no one reads shows 0 received, not missing data
            traffic |= {"sent": round(sent.total if sent else 0), "received": round(recv.total if recv else 0)}
        ctx.add(
            "sqs_backlog",
            name,
            region,
            pct=100.0 * age.high / keep,
            note=f"oldest message {age.high / 60:,.0f} minutes old; deleted after {keep / 3600:,.0f} hours",
            **traffic,
        )
        if not attrs.get("RedrivePolicy") and not re.search(r"dlq|dead", name, re.I):
            ctx.add("sqs_no_dlq", name, region)
        facts = {
            "Retention": f"{keep / 3600:,.0f} hours",
            "Dead-letter queue": "yes" if attrs.get("RedrivePolicy") else "no",
            "Visibility timeout": f"{attrs.get('VisibilityTimeout')} s",
            "FIFO": "yes" if name.endswith(".fifo") else "no",
        }
        stats = [
            stat(age, "Oldest message", "s", limit=keep),
            stat(m["sqs_depth"].get(name), "Messages waiting", ""),
            stat(sent, "Messages sent", ""),
            stat(recv, "Messages received", ""),
        ]
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
        add_old_generation(ctx, "mq_old_gen", name, region, b.get("HostInstanceType") or "")
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
        kind = "nlb" if lb.get("Type") == "network" else "alb"
        for res, low in m[f"{kind}_healthy"].items():
            group, _, owner = res.partition("|")
            high = m[f"{kind}_healthy_max"].get(res)
            if owner != key or not low.n or not high or not high.n or high.high <= 0:
                continue  # an empty target group serves nothing, so it is not an outage
            target = f"{name}: {group.split('/')[1] if group.count('/') >= 2 else group}"
            if low.low <= 0:
                now = low.last <= 0
                note = f"up to {high.high:.0f} healthy at other times" + (
                    "; none healthy in the last hour" if now else ""
                )
                ctx.add("lb_no_healthy", target, region, note=note, now=now)
            elif high.high <= 1:
                ctx.add("lb_single_target", target, region, note="one healthy target at most")
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
    _endpoints(ctx, ec2, subnets, zones_in, m, region)
    _tgw_attachments(ctx, m, region)
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
        size = ((v.get("Options") or {}).get("TunnelBandwidth") or "standard").lower()
        _vpn_bandwidth(ctx, m, v["VpnConnectionId"], VPN_TUNNEL_BPS.get(size, VPN_TUNNEL_BPS["standard"]), region)
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


def _bps(series: Series | None) -> float | None:
    """Bits a second in the busiest hour of a byte count summed per hour."""
    return series.high * 8 / PERIOD if series and series.n else None


def _vpn_bandwidth(ctx: OutageCtx, m: dict, vpn: str, limit: float, region: str) -> None:
    """Each tunnel against its own limit: one flow stays on one tunnel, so tunnels do not add up."""
    for res in {r for key in ("vpn_in", "vpn_out") for r in m[key] if r.split("|")[0] == vpn}:
        high = max((b for key in ("vpn_in", "vpn_out") if (b := _bps(m[key].get(res))) is not None), default=None)
        if high is None:
            continue
        ctx.add(
            "vpn_bandwidth",
            f"{vpn} tunnel {res.split('|')[-1]}",
            region,
            pct=100.0 * high / limit,
            used=round(high / 1e6),
            limit=round(limit / 1e6),
            unit="Mbps",
            load=True,
        )


def _tgw_attachments(ctx: OutageCtx, m: dict, region: str) -> None:
    for res in {r for key in ("tgw_att_in", "tgw_att_out") for r in m[key]}:
        high = max(
            (b for key in ("tgw_att_in", "tgw_att_out") if (b := _bps(m[key].get(res))) is not None), default=None
        )
        if high is None:
            continue
        ctx.add(
            "tgw_bandwidth",
            res.split("|")[-1],
            region,
            pct=100.0 * high / TGW_ATTACHMENT_BPS,
            used=round(high / 1e9, 2),
            limit=round(TGW_ATTACHMENT_BPS / 1e9),
            unit="Gbps",
            load=True,
        )


def _endpoints(ctx: OutageCtx, ec2, subnets: dict, zones_in: dict, m: dict, region: str) -> None:
    """Interface endpoints (PrivateLink) in one zone, and packets they dropped."""
    for e in _pages(ec2, "describe_vpc_endpoints", "VpcEndpoints", cap=MAX_ITEMS):
        if e.get("VpcEndpointType") != "Interface" or e.get("State", "").lower() != "available":
            continue
        name = f"{e['VpcEndpointId']} ({e.get('ServiceName', '').rsplit('.', 1)[-1]})"
        zones = {(subnets.get(s) or {}).get("AvailabilityZone") for s in e.get("SubnetIds") or []} - {None}
        if len(zones) == 1 and len(zones_in.get(e.get("VpcId", ""), ())) > 1:
            ctx.add("vpce_one_az", name, region, note=f"only in {next(iter(zones))}")
        drop = next((s for res, s in m["vpce_drop"].items() if e["VpcEndpointId"] in res.split("|") and s.n), None)
        if drop and drop.total > 0:
            ctx.add("vpce_drops", name, region, used=round(drop.total), unit="packets dropped")


# ------------------------------------------------------------------------------------------- Resolver
def task_resolver_review(ctx: OutageCtx, region: str) -> None:
    """Route 53 Resolver endpoints: the DNS path between AWS and the data centre."""
    client = ctx.client("route53resolver", region)
    endpoints = _pages(client, "list_resolver_endpoints", "ResolverEndpoints", cap=MAX_ITEMS)
    if not endpoints:
        ctx.r.ok("resolver")
        return
    zone_of = {
        s["SubnetId"]: s.get("AvailabilityZone")
        for s in _pages(ctx.client("ec2", region), "describe_subnets", "Subnets", cap=MAX_ITEMS)
    }
    m = ctx.metrics(region)
    for e in endpoints:
        if e.get("Status") not in ("OPERATIONAL", "ACTION_NEEDED", "AUTO_RECOVERING"):
            continue
        eid, way = e["Id"], (e.get("Direction") or "").lower()
        label = e.get("Name") or eid
        label = label if way in label.lower() else f"{label} ({way})"
        ips = _pages(client, "list_resolver_endpoint_ip_addresses", "IpAddresses", ResolverEndpointId=eid)
        zones = {zone_of.get(ip.get("SubnetId")) for ip in ips} - {None}
        if len(zones) == 1:
            ctx.add("resolver_one_az", label, region, note=f"{len(ips)} addresses, all in {next(iter(zones))}")
        count = e.get("IpAddressCount") or len(ips)
        series = m["resolver_in" if e.get("Direction") == "INBOUND" else "resolver_out"].get(eid)
        if series and series.n and count:
            qps, limit = series.high / PERIOD, RESOLVER_QPS_PER_IP * count
            ctx.add(
                "resolver_load",
                label,
                region,
                pct=100.0 * qps / limit,
                used=round(qps),
                limit=limit,
                unit="queries a second",
                load=True,
            )
        profile(
            ctx,
            "route53",
            label,
            region,
            {
                "Direction": e.get("Direction"),
                "Addresses": count,
                "Zones": len(zones) or None,
                "VPC": e.get("HostVPCId"),
            },
            [stat(series, "Queries", "a second", per=PERIOD, limit=RESOLVER_QPS_PER_IP * count if count else None)],
        )
    ctx.r.ok("resolver")


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


# ------------------------------------------------------------------------------- shared network and DNS
MAX_ZONES = 100  # hosted zones read per account
MAX_RECORDS = 5000  # records read per hosted zone
MAX_HEALTH_CHECKS = 200


def _depends(ctx: OutageCtx, region: str, owner: str | None, what: str, detail: str) -> None:
    """Something this account uses that another account owns: ``what`` is the kind (Transit gateway, Shared
    subnets, DNS forwarding rules), ``detail`` which one."""
    if not owner or owner == ctx.account_id:
        return
    with ctx._lock:
        got = ctx.r.facts.setdefault("depends_on", {}).setdefault(region, [])
        if not any(d["owner"] == owner and d["detail"] == detail for d in got):
            got.append({"owner": owner, "what": what, "detail": detail})


def task_shared_network(ctx: OutageCtx, region: str) -> None:
    """Transit gateway attachments by zone, blackhole routes and attachment counts in a gateway this account
    owns, forwarding rules with one target, and what this account uses that another account owns."""
    ec2 = ctx.client("ec2", region)
    subnets = {s["SubnetId"]: s for s in _pages(ec2, "describe_subnets", "Subnets", cap=MAX_ITEMS)}
    zones_in: dict[str, set[str]] = {}
    for s in subnets.values():
        zones_in.setdefault(s.get("VpcId", ""), set()).add(s.get("AvailabilityZone", ""))
        if s.get("OwnerId") and s["OwnerId"] != ctx.account_id:
            _depends(ctx, region, s["OwnerId"], "Shared subnets", s.get("VpcId", ""))
    for a in _pages(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments", cap=MAX_ITEMS):
        if a.get("State") == "available" and a.get("ResourceOwnerId") == ctx.account_id:
            _depends(ctx, region, a.get("TransitGatewayOwnerId"), "Transit gateway", a.get("TransitGatewayId", ""))
    for a in _pages(ec2, "describe_transit_gateway_vpc_attachments", "TransitGatewayVpcAttachments", cap=MAX_ITEMS):
        if a.get("State") != "available" or a.get("VpcOwnerId", ctx.account_id) != ctx.account_id:
            continue
        mine = {(subnets.get(x) or {}).get("AvailabilityZone") for x in a.get("SubnetIds") or []} - {None}
        vpc_zones = zones_in.get(a.get("VpcId", ""), set()) - {""}
        if not mine or len(vpc_zones) < 2:
            continue
        name = f"{a['TransitGatewayAttachmentId']} ({a.get('VpcId')})"
        missing = sorted(vpc_zones - mine)
        if len(mine) == 1:
            ctx.add("tgw_one_az", name, region, note=f"attached in {next(iter(mine))} only; the VPC has "
                    f"subnets in {len(vpc_zones)} zones")  # fmt: skip
        elif missing:
            ctx.add("tgw_zone_gap", name, region, note=f"no attachment subnet in {', '.join(missing)}")
    for t in _pages(ec2, "describe_transit_gateways", "TransitGateways", cap=MAX_ITEMS):
        if t.get("OwnerId") != ctx.account_id or t.get("State") != "available":
            continue
        tid = t["TransitGatewayId"]
        count = len(_pages(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments", cap=MAX_ITEMS,
                           Filters=[{"Name": "transit-gateway-id", "Values": [tid]}]))  # fmt: skip
        ctx.add("limit_product", f"ec2: Attachments per transit gateway ({tid})", region,
                pct=100.0 * count / TGW_ATTACHMENTS, used=count, limit=TGW_ATTACHMENTS)  # fmt: skip
        tables = _pages(ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables", cap=MAX_ITEMS,
                        Filters=[{"Name": "transit-gateway-id", "Values": [tid]}])  # fmt: skip
        for rt in tables:
            got = with_backoff(
                ec2.search_transit_gateway_routes,
                TransitGatewayRouteTableId=rt["TransitGatewayRouteTableId"],
                Filters=[{"Name": "state", "Values": ["blackhole"]}],
                MaxResults=1000,
            )
            holes = [r.get("DestinationCidrBlock") or r.get("PrefixListId") for r in got.get("Routes") or []]
            if holes:
                ctx.add(
                    "tgw_blackhole_route",
                    f"{tid} route table {rt['TransitGatewayRouteTableId']}",
                    region,
                    used=len(holes),
                    unit="blackhole routes",
                    note=", ".join(h for h in holes[:5] if h)
                    + (f" and {len(holes) - 5} more" if len(holes) > 5 else ""),
                )
    _forwarding_rules(ctx, region)
    ctx.r.ok("shared")


def _forwarding_rules(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("route53resolver", region)
    used = {a.get("ResolverRuleId") for a in _pages(client, "list_resolver_rule_associations",
                                                    "ResolverRuleAssociations", cap=MAX_ITEMS)}  # fmt: skip
    for r in _pages(client, "list_resolver_rules", "ResolverRules", cap=MAX_ITEMS):
        if r.get("RuleType") != "FORWARD" or r.get("Id") not in used or r.get("Status") != "COMPLETE":
            continue
        domain = (r.get("DomainName") or "").rstrip(".") or "."
        _depends(ctx, region, r.get("OwnerId"), "DNS forwarding rules", domain)
        targets = r.get("TargetIps") or []
        if len(targets) == 1:
            t = targets[0]
            ctx.add("resolver_rule_one_target", f"{domain} ({r.get('Name') or r['Id']})", region,
                    note=f"forwards to {t.get('Ip') or t.get('Ipv6')} only")  # fmt: skip


def task_dns_and_domains(ctx: OutageCtx) -> None:
    """Failover records with nothing to fail them over, health checks failing now on records in use, domains
    about to expire, IAM server certificates, and ACM certificates in us-east-1 (CloudFront's) when the scan's
    regions leave it out."""
    r53 = ctx.client("route53")
    zones = _pages(r53, "list_hosted_zones", "HostedZones", cap=MAX_ZONES)
    checked: set[str] = set()
    for z in zones:
        zone = z["Name"].rstrip(".")
        for rec in _pages(
            r53, "list_resource_record_sets", "ResourceRecordSets", cap=MAX_RECORDS, HostedZoneId=z["Id"]
        ):
            if rec.get("HealthCheckId"):
                checked.add(rec["HealthCheckId"])
            alias = rec.get("AliasTarget") or {}
            if (
                rec.get("Failover") == "PRIMARY"
                and not rec.get("HealthCheckId")
                and not alias.get("EvaluateTargetHealth")
            ):
                private = " (private)" if (z.get("Config") or {}).get("PrivateZone") else ""
                name = f"{rec['Name'].rstrip('.')} {rec.get('Type')}"
                ctx.add("r53_failover_no_check", name, "global", note=f"zone {zone}{private}")
    for hc in _pages(r53, "list_health_checks", "HealthChecks", cap=MAX_HEALTH_CHECKS):
        cfg = hc.get("HealthCheckConfig") or {}
        if hc["Id"] not in checked or cfg.get("Disabled") or cfg.get("Inverted"):
            continue
        if cfg.get("Type") not in ("HTTP", "HTTPS", "HTTP_STR_MATCH", "HTTPS_STR_MATCH", "TCP"):
            continue
        seen = with_backoff(r53.get_health_check_status, HealthCheckId=hc["Id"]).get("HealthCheckObservations") or []
        bad = sum(1 for o in seen if not ((o.get("StatusReport") or {}).get("Status") or "").startswith("Success"))
        if seen and bad * 2 > len(seen):
            where = cfg.get("FullyQualifiedDomainName") or cfg.get("IPAddress") or hc["Id"]
            ctx.add("r53_health_failing", f"{where}:{cfg.get('Port', '')} ({hc['Id']})", "global",
                    note=f"{bad} of {len(seen)} checkers report a failure", now=True)  # fmt: skip
    limit = ctx.now + timedelta(days=CERT_DAYS)
    for c in _pages(ctx.client("iam"), "list_server_certificates", "ServerCertificateMetadataList", cap=MAX_ITEMS):
        ends = c.get("Expiration")
        if ends and ends <= limit:
            ctx.add("iam_cert_expiry", c.get("ServerCertificateName", ""), "global", ends=ends.date().isoformat(),
                    note="an IAM server certificate: it does not renew by itself")  # fmt: skip
    if "us-east-1" not in ctx.regions:
        task_certificates(ctx, "us-east-1")
    ctx.r.ok("dns")


def task_domains(ctx: OutageCtx) -> None:
    """Domains registered in this account with Route 53 that expire by the peak."""
    client = ctx.client("route53domains", "us-east-1")
    limit = ctx.now + timedelta(days=CERT_DAYS)
    for d in _pages(client, "list_domains", "Domains", cap=MAX_ITEMS):
        ends = d.get("Expiry")
        if ends and ends <= limit:
            auto = bool(d.get("AutoRenew"))
            ctx.add("domain_expiry", d.get("DomainName", ""), "global", ends=ends.date().isoformat(), auto=auto,
                    note="renews by itself, if the payment goes through" if auto else "auto-renew is off")  # fmt: skip
    ctx.r.ok("domains")


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
        ("route 53 resolver review", ("resolver",), task_resolver_review, None),
        ("redshift review", ("redshift",), task_redshift_review, ("Amazon Redshift",)),
        ("file systems review", ("files",), task_files_review, ("Amazon FSx", "Amazon Elastic File System")),
        ("s3 review", ("s3_review",), task_s3_profile, None),
        ("shared network", ("shared",), task_shared_network, None),
        (
            "step functions, eventbridge, cognito",
            ("small_services",),
            task_small_services,
            (SFN, EVENTS, "CloudWatch Events", COGNITO, "Amazon Bedrock"),
        ),
    ]
)
GLOBAL_TASKS.append(("cloudfront", ("cloudfront",), task_cloudfront, (CLOUDFRONT,)))
GLOBAL_TASKS.append(("dns and certificates", ("dns",), task_dns_and_domains, None))
GLOBAL_TASKS.append(("domains", ("domains",), task_domains, None))
