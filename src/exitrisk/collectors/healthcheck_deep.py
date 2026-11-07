"""Health Check, deeper: more metrics per service, and checks that read each service's own state.

``healthcheck`` holds the engine (probes, judge, Ctx, the runner). This module adds:

- ``PROBES``: further CloudWatch probes per service (load balancer latency and refusals, API latency,
  Lambda async and stream problems, SQS backlog, DynamoDB index throttles and replication, RDS lag,
  memory, latency, IOPS and throughput limits, transaction ID age (vacuum), replication slots, RDS Proxy,
  ElastiCache evictions and network limits, OpenSearch, EBS IOPS and throughput limits, EFS, FSx, MSK,
  transit gateway drops, Resolver endpoints, WAF, Network Firewall, canaries, Container Insights);
- checks that read state: RDS connections against max_connections, provisioned IOPS and throughput,
  free storage share, autovacuum, Performance Insights (load against vCPUs, top waits and SQL), database
  logs; EBS volume status, EFS and FSx state, disk and memory from the CloudWatch agent; blackhole routes,
  VPC endpoints; MSK, DynamoDB, ElastiCache state; Lambda timeouts, account concurrency, event source
  mappings; SQS queues nobody reads; EKS add-ons and Kubernetes pods and nodes; X-Ray service graph; the
  accounts that own the shared network this account uses; flow logs kept only in S3 (Athena, opt in).
Every check is read only except the Athena one, which is off unless asked for.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import math
import operator
import re
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import BotoCoreError, ClientError

from . import healthcheck as hc
from .healthcheck import SUSTAIN, Ctx, _metric_data, _pages, _runs, _t

GiB = 1024**3
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def P(pid: str, ns: str, dims: list[str], metric: str, kind: str, **kw) -> dict:
    """One probe; see ``healthcheck.PROBES`` for the kinds. Defaults: Maximum, symptom, medium."""
    return {"id": pid, "ns": ns, "dims": dims, "metric": metric, "kind": kind, "stat": "Maximum",
            "sev": "medium", "role": "symptom", "x": 3, **kw}  # fmt: skip


ALB, NLB, API = "AWS/ApplicationELB", "AWS/NetworkELB", "AWS/ApiGateway"
RDS_I = ["DBInstanceIdentifier"]
MSK_C, MSK_B = ["Cluster Name"], ["Cluster Name", "Broker ID"]

PROBES: list[dict] = [
    # ---- load balancers
    P("alb_latency", ALB, ["LoadBalancer"], "TargetResponseTime", "spike", stat="p99", at=1.0, x=3, sev="high",
      area="Load balancer", svc="elb", unit="sec", title="Responses behind load balancer {r} slowed sharply",
      next="Find the slow target or dependency: compare target response times per target group and the "
           "database and downstream calls behind it."),
    P("alb_rejected", ALB, ["LoadBalancer"], "RejectedConnectionCount", "count", stat="Sum", at=10, sev="high",
      area="Load balancer", svc="elb", title="Load balancer {r} turns connections away",
      next="The load balancer reached its connection limit: AWS scales it, but a sudden surge needs pre-warming "
           "or spreading over more load balancers."),
    P("alb_target_conn", ALB, ["LoadBalancer"], "TargetConnectionErrorCount", "count", stat="Sum", at=20,
      sev="high", area="Load balancer", svc="elb", title="Load balancer {r} cannot connect to its targets",
      next="Check the targets' security groups allow the load balancer, the port is right and the process "
           "listens."),
    P("alb_elb4xx", ALB, ["LoadBalancer"], "HTTPCode_ELB_4XX_Count", "spike", stat="Sum", at=300, x=4,
      area="Load balancer", svc="elb", title="Load balancer {r} refuses far more requests than usual (4xx)",
      next="Often a WAF rule, a listener rule or an expired client certificate: check recent listener and WAF "
           "changes."),
    P("alb_t4xx", ALB, ["LoadBalancer"], "HTTPCode_Target_4XX_Count", "spike", stat="Sum", at=300, x=4,
      area="Load balancer", svc="app", title="Targets behind {r} reject far more requests than usual (4xx)",
      next="A jump in 401 or 403 means sign in or authorisation is failing: check identity provider, tokens, "
           "keys and secrets rotated recently."),
    P("alb_tls", ALB, ["LoadBalancer"], "ClientTLSNegotiationErrorCount", "spike", stat="Sum", at=100, x=4,
      area="Load balancer", svc="elb", title="TLS handshakes fail on load balancer {r}",
      next="Check a recent certificate or security policy change on the listener."),
    P("nlb_target_reset", NLB, ["LoadBalancer"], "TCP_Target_Reset_Count", "spike", stat="Sum", at=1000, x=5,
      area="Load balancer", svc="elb", title="Targets behind network load balancer {r} reset connections",
      next="The targets close connections: a crashing process, a full connection table or a restart."),
    P("nlb_port_alloc", NLB, ["LoadBalancer"], "PortAllocationErrorCount", "count", stat="Sum", at=1, sev="high",
      area="Load balancer", svc="elb", title="Network load balancer {r} has run out of ports to its targets",
      next="Too many connections to one target address: add targets or spread the traffic."),
    P("nlb_sg_blocked", NLB, ["LoadBalancer"], "SecurityGroupBlockedFlowCount_Outbound_TCP", "spike", stat="Sum",
      at=100, x=5, sev="high", area="Load balancer", svc="elb",
      title="Network load balancer {r}'s security group blocks traffic to its targets",
      next="Allow the target port in the load balancer's outbound security group rules."),
    P("nlb_fail_open", NLB, ["LoadBalancer"], "UnhealthyRoutingFlowCount", "count", stat="Sum", at=1, sev="high",
      area="Load balancer", svc="elb", title="Network load balancer {r} sends traffic to unhealthy targets",
      next="Every target in a zone failed its health check, so the load balancer fails open: fix the targets."),
    # ---- API Gateway
    P("apigw_latency", API, ["ApiName"], "Latency", "spike", stat="p99", at=3000, x=3, sev="high", area="API",
      svc="app", unit="ms", title="API {r} slowed sharply",
      next="Compare with IntegrationLatency: if that rose too, the backend is slow; if not, look at "
           "authorisers and mapping."),
    P("apigw_4xx", API, ["ApiName"], "4XXError", "spike", stat="Sum", at=200, x=4, area="API", svc="app",
      title="API {r} rejects far more requests than usual (4xx)",
      next="401 or 403: an authoriser, key or token problem. 429: throttling; check usage plans and limits."),
    P("apigw2_latency", API, ["ApiId"], "Latency", "spike", stat="p99", at=3000, x=3, sev="high", area="API",
      svc="app", unit="ms", title="HTTP API {r} slowed sharply", next="Find the slow integration behind the API."),
    # ---- Lambda
    P("lambda_async_dropped", "AWS/Lambda", ["FunctionName"], "AsyncEventsDropped", "count", stat="Sum", at=10,
      sev="high", area="Lambda", svc="app", title="Lambda function {r} drops events",
      next="Events were dropped after retries or age: add an on-failure destination and fix the errors."),
    P("lambda_async_age", "AWS/Lambda", ["FunctionName"], "AsyncEventAge", "spike", at=600000, x=3,
      area="Lambda", svc="app", unit="ms", title="Lambda function {r} falls behind its queued events",
      next="Errors or too little concurrency: check the function's errors and reserved concurrency."),
    P("lambda_dlq", "AWS/Lambda", ["FunctionName"], "DeadLetterErrors", "count", stat="Sum", at=1, sev="high",
      area="Lambda", svc="app", title="Lambda function {r} cannot write to its dead-letter queue",
      next="Failed events are being lost: check the queue exists and the role may send to it."),
    P("lambda_dest", "AWS/Lambda", ["FunctionName"], "DestinationDeliveryFailures", "count", stat="Sum", at=1,
      area="Lambda", svc="app", title="Lambda function {r} cannot deliver to its destination",
      next="Check the destination exists and the role may send to it."),
    P("lambda_iterator", "AWS/Lambda", ["FunctionName"], "IteratorAge", "spike", at=60000, x=3, sev="high",
      area="Lambda", svc="app", unit="ms", title="Lambda function {r} falls behind its stream",
      next="The function cannot keep up with its stream: errors, throttles or too little parallelism."),
    P("lambda_recursive", "AWS/Lambda", ["FunctionName"], "RecursiveInvocationsDropped", "count", stat="Sum",
      at=1, area="Lambda", svc="app", title="Lambda function {r} is stuck in a loop and AWS stopped it",
      next="The function triggers itself (through a queue, topic or bucket): break the loop."),
    # ---- queues and streams
    P("sqs_backlog", "AWS/SQS", ["QueueName"], "ApproximateNumberOfMessagesVisible", "spike", at=1000, x=4,
      area="Queue", svc="app", title="Queue {r} is piling up", name=r"^(?!.*(?i:dlq|dead)).*$",
      next="Consumers are slower than producers or have stopped: check the consumer's errors and scaling."),
    P("sqs_inflight", "AWS/SQS", ["QueueName"], "ApproximateNumberOfMessagesNotVisible", "high", at=100000,
      sev="high", area="Queue", svc="app", title="Queue {r} is near the 120,000 messages in flight limit",
      next="Consumers receive but do not delete messages: check they finish and delete, and the visibility "
           "timeout."),
    P("kinesis_read", "AWS/Kinesis", ["StreamName"], "ReadProvisionedThroughputExceeded", "count", stat="Sum",
      at=50, area="Kinesis", svc="app", title="Readers of Kinesis stream {r} are throttled",
      next="Too many readers per shard: use enhanced fan-out or add shards."),
    # ---- DynamoDB
    P("ddb_gsi_read", "AWS/DynamoDB", ["TableName", "GlobalSecondaryIndexName"], "ReadThrottleEvents", "count",
      stat="Sum", at=20, sev="high", area="DynamoDB", svc="db", title="DynamoDB index {r} throttles reads",
      next="Raise the index's capacity, or on demand, its maximum."),
    P("ddb_gsi_write", "AWS/DynamoDB", ["TableName", "GlobalSecondaryIndexName"], "WriteThrottleEvents", "count",
      stat="Sum", at=20, sev="high", area="DynamoDB", svc="db",
      title="DynamoDB index {r} throttles writes (and so the table's writes)",
      next="An index short of write capacity throttles the table's writes: raise the index's capacity."),
    P("ddb_latency", "AWS/DynamoDB", ["TableName", "Operation"], "SuccessfulRequestLatency", "spike",
      stat="Average", at=50, x=4, area="DynamoDB", svc="db", unit="ms", title="DynamoDB {r} slowed sharply",
      next="Look for hot keys, large items or scans; check AWS Health for DynamoDB."),
    P("ddb_replication", "AWS/DynamoDB", ["TableName", "ReceivingRegion"], "ReplicationLatency", "high",
      stat="Average", at=60000, sev="high", area="DynamoDB", svc="db", unit="ms",
      title="Global table {r} replicates late", next="Check throttling in the receiving region and AWS Health."),
    P("ddb_wcu", "AWS/DynamoDB", ["TableName"], "ConsumedWriteCapacityUnits", "share", stat="Sum",
      den="ProvisionedWriteCapacityUnits", den_stat="Average", per_s=True, at=0.9, role="cause", area="DynamoDB",
      svc="db", title="DynamoDB table {r} uses all its provisioned write capacity",
      next="Raise the write capacity or its autoscaling maximum, or switch to on demand."),
    P("ddb_rcu", "AWS/DynamoDB", ["TableName"], "ConsumedReadCapacityUnits", "share", stat="Sum",
      den="ProvisionedReadCapacityUnits", den_stat="Average", per_s=True, at=0.9, role="cause", area="DynamoDB",
      svc="db", title="DynamoDB table {r} uses all its provisioned read capacity",
      next="Raise the read capacity or its autoscaling maximum, or switch to on demand."),
    # ---- RDS and Aurora
    P("rds_replica_lag", "AWS/RDS", RDS_I, "ReplicaLag", "high", at=300, sev="high", area="Database", svc="db",
      unit="s", title="Read replica {r} is behind its primary",
      next="Reads from it are stale: check the replica's CPU and I/O, and long transactions on the primary."),
    P("aurora_lag", "AWS/RDS", RDS_I, "AuroraReplicaLag", "high", at=5000, sev="high", area="Database", svc="db",
      unit="ms", title="Aurora reader {r} is behind the writer",
      next="Readers lag when the writer's write rate spikes or the reader is overloaded."),
    P("aurora_global_lag", "AWS/RDS", ["DBClusterIdentifier", "SecondaryRegion"], "AuroraGlobalDBReplicationLag",
      "high", at=60000, sev="high", area="Database", svc="db", unit="ms",
      title="Aurora global database {r} replicates late",
      next="A failover now would lose this much data: check the write rate and the secondary's load."),
    P("rds_memory", "AWS/RDS", RDS_I, "FreeableMemory", "low", stat="Minimum", at=256 * 1024**2, sev="high",
      role="cause", area="Database", svc="db", unit="bytes", title="Database {r} is out of memory",
      next="Too many connections or a memory-hungry query: reduce connections (a proxy) or a larger class."),
    # Aurora keeps gigabytes in swap with hundreds free in memory: only a sharp rise is news.
    P("rds_swap", "AWS/RDS", RDS_I, "SwapUsage", "spike", at=2 * GiB, x=3, sev="medium", role="cause",
      area="Database", svc="db", unit="bytes", title="Database {r} started swapping to disk",
      next="Memory is short: see the memory finding, and the connections and queries using it."),
    P("rds_read_latency", "AWS/RDS", RDS_I, "ReadLatency", "spike", stat="Average", at=0.05, x=4, role="cause",
      area="Database", svc="db", unit="sec", title="Disk reads on database {r} slowed sharply",
      next="I/O at its limit (see IOPS findings) or a query reading far more than before (a missing index)."),
    P("rds_write_latency", "AWS/RDS", RDS_I, "WriteLatency", "spike", stat="Average", at=0.05, x=4, role="cause",
      area="Database", svc="db", unit="sec", title="Disk writes on database {r} slowed sharply",
      next="I/O at its limit (see IOPS findings) or a burst of writes."),
    P("rds_queue", "AWS/RDS", RDS_I, "DiskQueueDepth", "spike", at=32, x=4, role="cause", area="Database",
      svc="db", title="I/O requests queue on database {r}",
      next="Storage cannot keep up: provisioned IOPS or the instance class's EBS limit is reached."),
    P("rds_ebs_iops", "AWS/RDS", RDS_I, "InstanceEBSIOPSExceededCheck", "high", at=1, sustain=2, sev="high",
      role="cause", area="Database", svc="db", title="Database {r} hits its instance class's IOPS limit",
      next="The instance class caps storage I/O below what the disk could do: a larger class, or fewer reads "
           "(indexes, caching)."),
    P("rds_ebs_tput", "AWS/RDS", RDS_I, "InstanceEBSThroughputExceededCheck", "high", at=1, sustain=2, sev="high",
      role="cause", area="Database", svc="db", title="Database {r} hits its instance class's throughput limit",
      next="The instance class caps storage throughput: a larger class or less data read per query."),
    P("rds_io_balance", "AWS/RDS", RDS_I, "EBSIOBalance%", "low", stat="Minimum", at=10, sev="high",
      role="cause", area="Database", svc="db", unit="%", title="Database {r} has used up its burst I/O",
      next="Small instance classes burst storage I/O for a time only: a larger class."),
    P("rds_byte_balance", "AWS/RDS", RDS_I, "EBSByteBalance%", "low", stat="Minimum", at=10, sev="high",
      role="cause", area="Database", svc="db", unit="%", title="Database {r} has used up its burst throughput",
      next="Small instance classes burst storage throughput for a time only: a larger class."),
    P("rds_burst", "AWS/RDS", RDS_I, "BurstBalance", "low", stat="Minimum", at=10, sev="high", role="cause",
      area="Database", svc="db", unit="%", title="Database {r}'s gp2 storage has used its burst credits",
      next="gp2 falls to 3 IOPS a GB when credits run out: move to gp3 with the IOPS needed."),
    P("rds_xid", "AWS/RDS", RDS_I, "MaximumUsedTransactionIDs", "high", at=1e9, sevs=[(1.5e9, "critical")],
      sev="high", role="cause", area="Database", svc="db",
      title="Vacuum is not keeping up on database {r}: transaction IDs are running out",
      next="At about 2.1 billion PostgreSQL stops accepting writes. Find what blocks vacuum (long transactions, "
           "abandoned replication slots, prepared transactions) and run VACUUM FREEZE on the oldest tables."),
    P("rds_slot_lag", "AWS/RDS", RDS_I, "OldestReplicationSlotLag", "high", at=10 * GiB,
      sevs=[(50 * GiB, "high")], role="cause", area="Database", svc="db", unit="bytes",
      title="A replication slot on database {r} holds back the log",
      next="A slot nobody reads keeps WAL on disk and stops vacuum cleaning: drop it or fix its reader (DMS, "
           "Debezium)."),
    P("rds_txlogs", "AWS/RDS", RDS_I, "TransactionLogsDiskUsage", "high", at=20 * GiB, role="cause",
      area="Database", svc="db", unit="bytes", title="Transaction logs fill database {r}'s disk",
      next="Usually a replication slot or archiving that is stuck: see the replication slot finding."),
    P("rds_deadlocks", "AWS/RDS", RDS_I, "Deadlocks", "spike", stat="Average", at=0.1, x=4, area="Database",
      svc="db", title="Deadlocks jumped on database {r}",
      next="A new release changed the order transactions lock rows: read the database log for the statements."),
    # Some databases always queue more sessions than CPUs (and Serverless counts few vCPUs): judge the rise.
    P("rds_load", "AWS/RDS", RDS_I, "DBLoadRelativeToNumVCPUs", "spike", stat="Average", at=2, x=2, sev="medium",
      sevs=[(4, "high")],
      role="cause", area="Database", svc="db", title="Database {r} is overloaded: more sessions than CPUs",
      next="See the Performance Insights finding for the waits and SQL; a missing index or a new query is "
           "typical."),
    # A ratio that is always low is that workload's normal: flag a drop of 15 points below the usual.
    P("rds_cache_hit", "AWS/RDS", RDS_I, "BufferCacheHitRatio", "low", stat="Average", at=80, drop=15, role="cause",
      area="Database", svc="db", unit="%", title="Database {r} reads from disk instead of memory",
      next="A query now scans far more data (a missing or dropped index) or the working set outgrew memory."),
    P("rds_commit", "AWS/RDS", RDS_I, "CommitLatency", "spike", stat="Average", at=50, x=4, area="Database",
      svc="db", unit="ms", title="Commits slowed sharply on database {r}",
      next="Storage or replication is slow: check write latency and replica lag."),
    P("rds_iam_fail", "AWS/RDS", RDS_I, "IamDbAuthConnectionFailure", "count", stat="Sum", at=20, sev="high",
      area="Database", svc="db", title="IAM sign in to database {r} fails",
      next="Expired tokens, a missing rds-db:connect permission or throttling of token checks."),
    # RDS Proxy
    P("proxy_setup", "AWS/RDS", ["ProxyName"], "DatabaseConnectionsSetupFailed", "count", stat="Sum", at=10,
      sev="high", area="Database", svc="db", role="cause",
      title="RDS Proxy {r} cannot open connections to its database",
      next="The database refuses the proxy: max_connections reached, the secret is wrong, or the database is "
           "down."),
    P("proxy_auth", "AWS/RDS", ["ProxyName"], "ClientConnectionsSetupFailedAuth", "count", stat="Sum", at=20,
      area="Database", svc="db", title="Clients fail to sign in to RDS Proxy {r}",
      next="A rotated secret not yet in the proxy, or clients with old credentials."),
    P("proxy_borrow", "AWS/RDS", ["ProxyName"], "DatabaseConnectionsBorrowLatency", "spike", stat="Average",
      at=100000, x=5, sev="high", area="Database", svc="db", unit="us",
      title="Clients of RDS Proxy {r} wait for a database connection",
      next="The pool is full: raise MaxConnectionsPercent, or find what holds connections (pinning, long "
           "transactions)."),
    # ---- ElastiCache
    P("cache_evictions", "AWS/ElastiCache", ["CacheClusterId"], "Evictions", "spike", stat="Sum", at=1000, x=5,
      role="cause", area="Cache", svc="db", title="Cache {r} evicts keys: it is full",
      next="Data falls out of the cache and the database takes the load: scale the cache up or out."),
    P("cache_swap", "AWS/ElastiCache", ["CacheClusterId"], "SwapUsage", "high", at=300 * 1024**2, role="cause",
      area="Cache", svc="db", unit="bytes", title="Cache {r} is swapping", next="Memory is short: scale up."),
    P("cache_repl", "AWS/ElastiCache", ["CacheClusterId"], "ReplicationLag", "high", at=30, area="Cache",
      svc="db", unit="s", title="Cache replica {r} is behind", next="Reads from it are stale; check write load."),
    P("cache_conns", "AWS/ElastiCache", ["CacheClusterId"], "CurrConnections", "spike", at=1000, x=4,
      area="Cache", svc="db", title="Connections to cache {r} jumped",
      next="Clients reconnect in a loop or leak connections: check client timeouts and pools."),
    P("cache_bw", "AWS/ElastiCache", ["CacheClusterId"], "NetworkBandwidthOutAllowanceExceeded", "count",
      stat="Sum", at=100, role="cause", area="Cache", svc="db",
      title="Cache {r} drops packets: it is past its network allowance",
      next="The node type's network limit is reached: a larger node type or more shards."),
    P("cache_conntrack", "AWS/ElastiCache", ["CacheClusterId"], "NetworkConntrackAllowanceExceeded", "count",
      stat="Sum", at=1, sev="high", role="cause", area="Cache", svc="db",
      title="Cache {r} drops new connections: too many tracked connections",
      next="Clients open too many connections: use connection pools."),
    P("cache_sl_throttle", "AWS/ElastiCache", ["clusterId"], "ThrottledCmds", "count", stat="Sum", at=100,
      sev="high", role="cause", area="Cache", svc="db", title="Serverless cache {r} throttles commands",
      next="Raise the cache's maximum ECPUs a second, or its minimum to scale ahead of the load."),
    # ---- OpenSearch
    P("os_jvm", "AWS/ES", ["DomainName", "ClientId"], "JVMMemoryPressure", "high", at=92, sev="high",
      role="cause", area="OpenSearch", svc="db", unit="%", title="OpenSearch domain {r} is out of heap memory",
      next="Requests are rejected and nodes may crash: scale up, or reduce shard count and large aggregations."),
    P("os_storage", "AWS/ES", ["DomainName", "ClientId"], "FreeStorageSpace", "low", stat="Minimum", at=5120,
      sev="high", role="cause", area="OpenSearch", svc="db", title="OpenSearch domain {r} is running out of disk",
      next="At the flood stage, indices become read only: add storage or delete old indices."),
    P("os_write_rej", "AWS/ES", ["DomainName", "ClientId"], "ThreadpoolWriteRejected", "count", stat="Sum",
      at=100, sev="high", area="OpenSearch", svc="db", title="OpenSearch domain {r} rejects writes",
      next="The write queue is full: scale out, or slow the bulk writers."),
    P("os_5xx", "AWS/ES", ["DomainName", "ClientId"], "5xx", "count", stat="Sum", at=50, area="OpenSearch",
      svc="db", title="OpenSearch domain {r} returns 5xx errors", next="Read the domain's error logs."),
    # ---- EC2 and EBS
    P("ec2_ebs_iops", "AWS/EC2", ["InstanceId"], "InstanceEBSIOPSExceededCheck", "high", at=1, sustain=4, boot=1800,
      sev="medium", role="cause", area="EC2", svc="capacity", title="Instance {r} hits its EBS IOPS limit",
      next="The instance type caps storage I/O: a larger type or EBS-optimised type."),
    P("ec2_ebs_tput", "AWS/EC2", ["InstanceId"], "InstanceEBSThroughputExceededCheck", "high", at=1, sustain=4,
      boot=1800, sev="medium", role="cause", area="EC2", svc="capacity",
      title="Instance {r} hits its EBS throughput limit",
      next="The instance type caps storage throughput: a larger type."),
    P("ec2_attached_ebs", "AWS/EC2", ["InstanceId"], "StatusCheckFailed_AttachedEBS", "high", at=1, sustain=2,
      sev="high", role="cause", area="EC2", svc="capacity", title="Instance {r} cannot reach an attached volume",
      next="An EBS volume is impaired: stop and start the instance, or restore the volume from a snapshot."),
    P("ebs_iops", "AWS/EBS", ["InstanceId", "VolumeId"], "VolumeIOPSExceededCheck", "high", at=1, sustain=4, boot=1800,
      sev="medium", role="cause", area="EBS", svc="capacity",
      title="Volume {r} asks for more IOPS than it is provisioned for",
      next="I/O queues and slows: raise the volume's IOPS (gp3 or io2) or reduce reads."),
    P("ebs_tput", "AWS/EBS", ["InstanceId", "VolumeId"], "VolumeThroughputExceededCheck", "high", at=1,
      sustain=4, boot=1800, sev="medium", role="cause", area="EBS", svc="capacity",
      title="Volume {r} asks for more throughput than it is provisioned for",
      next="Raise the volume's throughput (gp3) or reduce the data read."),
    P("ebs_queue", "AWS/EBS", ["VolumeId"], "VolumeQueueLength", "spike", stat="Average", at=32, x=4,
      role="cause", area="EBS", svc="capacity", title="I/O requests queue on volume {r}",
      next="The volume cannot keep up: see its IOPS and throughput limits."),
    # ---- EFS and FSx
    P("efs_burst", "AWS/EFS", ["FileSystemId"], "BurstCreditBalance", "low", stat="Minimum", at=GiB,
      sev="high", role="cause", area="EFS", svc="capacity", unit="bytes",
      title="File system {r} has used its burst credits",
      next="Throughput has fallen to the baseline for its size: switch to elastic throughput."),
    P("efs_io_limit", "AWS/EFS", ["FileSystemId"], "PercentIOLimit", "high", at=95, sev="high", role="cause",
      area="EFS", svc="capacity", unit="%", title="File system {r} is at its I/O limit",
      next="General Purpose mode caps operations a second: spread the load, or a Max I/O or elastic file system."),
    P("efs_tput", "AWS/EFS", ["FileSystemId"], "MeteredIOBytes", "share", stat="Sum", den="PermittedThroughput",
      den_stat="Average", per_s=True, at=0.95, sev="high", role="cause", area="EFS", svc="capacity",
      title="File system {r} uses all its permitted throughput",
      next="Switch to elastic throughput or provision more."),
    P("fsx_used", "AWS/FSx", ["FileSystemId"], "StorageCapacityUtilization", "high", at=90,
      sevs=[(97, "critical")], sev="high", role="cause", area="FSx", svc="capacity", unit="%",
      title="File system {r} is nearly full", next="Increase the storage capacity now."),
    P("fsx_cpu", "AWS/FSx", ["FileSystemId"], "CPUUtilization", "high", at=95, role="cause", area="FSx",
      svc="capacity", unit="%", title="File server {r} is out of CPU", next="Raise the throughput capacity."),
    # ---- MSK (Kafka)
    P("msk_offline", "AWS/Kafka", MSK_C, "OfflinePartitionsCount", "high", at=1, sustain=2, sev="critical",
      area="Kafka", svc="db", role="symptom", title="Kafka cluster {r} has offline partitions",
      next="Producers and consumers of those partitions fail: find the brokers that are down (AWS Health, "
           "broker logs)."),
    P("msk_controller", "AWS/Kafka", MSK_C, "ActiveControllerCount", "low", stat="Sum", at=0, sustain=2,
      sev="critical", area="Kafka", svc="db", role="cause", title="Kafka cluster {r} has no active controller",
      next="The cluster cannot change leaders: open a case with AWS."),
    P("msk_minisr", "AWS/Kafka", MSK_B, "UnderMinIsrPartitionCount", "high", at=1, sustain=2, sev="critical",
      area="Kafka", svc="db", role="symptom", title="Kafka {r} has partitions below their minimum in-sync replicas",
      next="Producers using acks=all fail on those partitions: a broker is down or far behind."),
    P("msk_urp", "AWS/Kafka", MSK_B, "UnderReplicatedPartitions", "high", at=1, sev="high", area="Kafka",
      svc="db", role="symptom", title="Kafka {r} has under-replicated partitions",
      next="A broker is slow or restarting (patching, disk or CPU): one more failure loses availability."),
    P("msk_disk", "AWS/Kafka", MSK_B, "KafkaDataLogsDiskUsed", "high", at=85, sevs=[(95, "critical")],
      sev="high", area="Kafka", svc="db", role="cause", unit="%", title="Kafka {r}'s disk is nearly full",
      next="A full broker stops: raise the broker storage (or turn on storage autoscaling), or shorten "
           "retention."),
    P("msk_cpu", "AWS/Kafka", MSK_B, "CpuIdle", "low", stat="Minimum", at=20, sev="high", area="Kafka", svc="db",
      role="cause", unit="%", title="Kafka {r} is out of CPU",
      next="Above 60% busy a broker cannot take its partner's load in a failure: a larger broker type."),
    P("msk_heap", "AWS/Kafka", MSK_B, "HeapMemoryAfterGC", "high", at=90, sev="high", area="Kafka", svc="db",
      role="cause", unit="%", title="Kafka {r} is out of heap memory",
      next="Too many partitions or connections for the broker type: a larger type."),
    P("msk_fd", "AWS/Kafka", MSK_B, "KafkaFileDescriptorsUsagePercent", "high", at=90, sev="high", area="Kafka",
      svc="db", role="cause", unit="%", title="Kafka {r} is running out of file descriptors",
      next="Too many partitions or connections per broker."),
    P("msk_produce", "AWS/Kafka", MSK_B, "ProduceTotalTimeMsMean", "spike", stat="Average", at=100, x=4,
      area="Kafka", svc="db", unit="ms", title="Writes to Kafka {r} slowed sharply",
      next="A slow broker, its disk, or replication: see the other Kafka findings."),
    P("msk_lag", "AWS/Kafka", ["Cluster Name", "Consumer Group", "Topic"], "EstimatedMaxTimeLag", "spike",
      at=900, x=4, area="Kafka", svc="app", unit="s", title="Kafka consumer {r} is falling behind",
      next="The consumer is slow, failing or stopped: check its errors, restarts and rebalances."),
    # ---- network
    P("tgw_blackhole", "AWS/TransitGateway", ["TransitGateway", "TransitGatewayAttachment"],
      "PacketDropCountBlackhole", "count", stat="Sum", at=100, sev="high", role="cause", area="Network",
      svc="network", title="Transit gateway {r} drops traffic to a blackhole route",
      next="A route points at an attachment that is gone: fix the transit gateway route table."),
    P("tgw_noroute", "AWS/TransitGateway", ["TransitGateway", "TransitGatewayAttachment"],
      "PacketDropCountNoRoute", "spike", stat="Sum", at=1000, x=5, sev="high", role="cause", area="Network",
      svc="network", title="Transit gateway {r} drops traffic it has no route for",
      next="A route was removed or never added: compare the route tables with recent changes."),
    P("resolver_eni", "AWS/Route53Resolver", ["EndpointId"], "EndpointUnhealthyENICount", "high", at=1,
      sustain=3, sev="medium", role="cause", area="DNS", svc="network",
      title="Resolver endpoint {r} has unhealthy addresses",
      next="DNS forwarding through it fails in part: check the endpoint's subnets and security group."),
    P("resolver_capacity", "AWS/Route53Resolver", ["EndpointId"], "ResolverEndpointCapacityStatus", "high", at=2,
      sustain=2, sev="high", role="cause", area="DNS", svc="network",
      title="Resolver endpoint {r} is at its query capacity",
      next="Add addresses (network interfaces) to the endpoint."),
    P("nfw_dropped", "AWS/NetworkFirewall", ["AvailabilityZone", "Engine", "FirewallName"], "DroppedPackets",
      "spike", stat="Sum", at=1000, x=5, sev="high", role="cause", area="Network", svc="network",
      title="Network Firewall {r} drops far more traffic than usual",
      next="A rule change blocks real traffic: compare the dropped flows with recent rule group changes."),
    P("waf_blocked", "AWS/WAFV2", ["WebACL", "Rule", "Region"], "BlockedRequests", "spike", stat="Sum", at=500,
      x=5, role="cause", area="WAF", svc="security", title="WAF rule {r} blocks far more requests than usual",
      next="An attack, or a rule now blocking real users: sample the blocked requests in the WAF console."),
    P("waf_blocked_cf", "AWS/WAFV2", ["WebACL", "Rule"], "BlockedRequests", "spike", stat="Sum", at=500, x=5,
      role="cause", area="WAF", svc="security", title="WAF rule {r} blocks far more requests than usual",
      next="An attack, or a rule now blocking real users: sample the blocked requests in the WAF console.",
      **{"global": True}),
    P("dx_errors", "AWS/DX", ["ConnectionId"], "ConnectionErrorCount", "count", stat="Sum", at=10, role="cause",
      area="Network", svc="network", title="Direct Connect {r} reports errors on the line",
      next="Ask the provider to test the cross connect and optics."),
    P("cf_4xx", "AWS/CloudFront", ["DistributionId", "Region"], "4xxErrorRate", "high", stat="Average", at=20,
      area="CDN", svc="app", unit="%", title="CloudFront distribution {r} returns many 4xx errors",
      next="Often a WAF block, a signed URL or an origin access change.", **{"global": True}),
    # ---- user journeys and containers
    P("canary", "CloudWatchSynthetics", ["CanaryName"], "SuccessPercent", "low", stat="Minimum", at=50,
      sustain=2, sev="high", area="Canary", svc="app", unit="%", title="Canary {r} fails",
      next="The user journey the canary tests is broken: read its last run's screenshots and log."),
    P("ci_failed_nodes", "ContainerInsights", ["ClusterName"], "cluster_failed_node_count", "high", at=1,
      sustain=2, sev="high", role="cause", area="EKS", svc="capacity", title="EKS cluster {r} has failed nodes",
      next="Read the nodes' conditions: memory or disk pressure, or a kubelet that stopped."),
    P("ci_crashloop", "ContainerInsights", ["ClusterName", "Namespace", "PodName"],
      "pod_container_status_waiting_reason_crash_loop_back_off", "high", at=1, sustain=2, sev="high", area="EKS",
      svc="app", title="Pods of {r} keep crashing", next="Read the pod's previous log (kubectl logs --previous)."),
    P("ci_pending", "ContainerInsights", ["ClusterName", "Namespace", "PodName"], "pod_status_pending", "high",
      at=1, area="EKS", svc="capacity", title="Pods of {r} cannot start (pending)",
      next="No node fits them: check node capacity, Karpenter or the autoscaler, and the subnets' addresses."),
]  # fmt: skip


# ------------------------------------------------------------------------------------------ helpers
def _series(ctx: Ctx, region: str, ns: str, dims: list[str], metric: str, stat: str, start=None, end=None):
    """{label: points} for one metric over every resource (one SEARCH)."""
    probe = {"ns": ns, "dims": dims}
    q = [{"Id": "s", "Expression": hc._search(probe, metric, stat, ctx.period), "Label": hc._label(dims),
          "ReturnData": True}]  # fmt: skip
    got = _metric_data(ctx.client("cloudwatch", region), q, start or ctx.start, end or ctx.end)
    return got.get("s") or {}


def _class_info(ctx: Ctx, region: str, classes: set[str]) -> dict[str, tuple[float, int]]:
    """{db.r6g.large: (memory bytes, vCPUs)} from the EC2 instance type of the same name."""
    out: dict[str, tuple[float, int]] = {}
    ec2 = ctx.client("ec2", region)
    for c in classes:
        if not c.startswith("db.") or c == "db.serverless":
            continue
        with contextlib.suppress(ClientError):
            t = ec2.describe_instance_types(InstanceTypes=[c[3:]])["InstanceTypes"][0]
            out[c] = (t["MemoryInfo"]["SizeInMiB"] * 1024**2, t["VCpuInfo"]["DefaultVCpus"])
    return out


_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}
_FUNCS = {"least": min, "greatest": max, "log": math.log2, "sum": lambda *a: sum(a)}


def param_value(text: str | None, memory: float | None) -> float | None:
    """An RDS parameter value as a number, formulas included: LEAST({DBInstanceClassMemory/9531392},5000).
    RDS's log is base 2. None when it cannot be worked out."""
    if text is None:
        return None
    text = str(text).strip()
    with contextlib.suppress(ValueError):
        return float(text)
    if memory is None:
        return None
    expr = text.replace("{", "(").replace("}", ")")

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        if isinstance(node, ast.Name) and node.id == "DBInstanceClassMemory":
            return float(memory)
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id.lower() in _FUNCS:
            return _FUNCS[node.func.id.lower()](*(ev(a) for a in node.args))
        raise ValueError("unsupported")

    try:
        return ev(ast.parse(expr, mode="eval"))
    except (ValueError, SyntaxError, ZeroDivisionError, TypeError):
        return None


_param_cache: dict[tuple, dict] = {}


def _params(ctx: Ctx, region: str, group: str, cluster: bool = False) -> dict[str, str]:
    """{name: value} of the parameters that matter here, for one DB (or cluster) parameter group."""
    key = (ctx.account, region, group, cluster)
    if key in _param_cache:
        return _param_cache[key]
    want = {"max_connections", "autovacuum", "track_counts", "rds.logical_replication"}
    rds = ctx.client("rds", region)
    op, k = ("describe_db_cluster_parameters", "DBClusterParameterGroupName") if cluster else (
        "describe_db_parameters", "DBParameterGroupName")  # fmt: skip
    out = {}
    for page in rds.get_paginator(op).paginate(**{k: group}):
        for p in page.get("Parameters") or []:
            if p.get("ParameterName") in want and p.get("ParameterValue") is not None:
                out[p["ParameterName"]] = p["ParameterValue"]
    _param_cache[key] = out
    return out


def _level_runs(pts: list, limit: float, at: float) -> tuple:
    """(first run start, periods past, peak share) of value / limit against ``at``."""
    lv = [(ts, v / limit) for ts, v in pts]
    first, hits, _ = _runs(lv, lambda v: v >= at, SUSTAIN)
    return first, hits, max((v for _, v in lv), default=0.0)


def _sum_series(*series: dict) -> dict[str, list]:
    """Add several {label: points} together per label and time (read + write IOPS)."""
    out: dict[str, dict] = {}
    for s in series:
        for label, pts in s.items():
            d = out.setdefault(label, {})
            for ts, v in pts:
                d[ts] = d.get(ts, 0.0) + v
    return {k: sorted(v.items()) for k, v in out.items()}


# ------------------------------------------------------------------------------------------ RDS
WAIT_HINTS = [
    (r"^(IO:DataFileRead|io/table/sql/handler|io/file/innodb/innodb_data_file|IO:BufFileRead)",
     "reading from disk: a missing index or a large scan"),
    (r"^(Lock:|LWLock:lock_manager|synch/.*/innodb/row_lock|Lock:tuple|Lock:transactionid)",
     "row or table locks: transactions waiting on each other"),
    (r"^(CPU|cpu)", "CPU: heavy queries or too many sessions"),
    (r"^(IO:XactSync|io/aurora_redo_log_flush|io/redo_log_flush|IO:WALWrite|LWLock:WALWrite)",
     "commits waiting on the log: many small transactions or slow storage"),
    (r"^(Client:ClientRead|Client:ClientWrite)", "waiting on the application: slow clients or idle transactions"),
    (r"^(LWLock:BufferMapping|LWLock:buffer_content|LWLock:BufferContent)",
     "contention for memory pages: hot tables or too small a cache"),
    (r"^(IPC:|Timeout:)", "background work: vacuum, checkpoints or replication"),
]  # fmt: skip


def _wait_hint(name: str) -> str:
    for pat, hint in WAIT_HINTS:
        if re.search(pat, name or ""):
            return hint
    return ""


def check_rds_deep(ctx: Ctx, region: str) -> None:
    """Per database: connections against max_connections, IOPS and throughput against what is provisioned,
    free storage as a share of the disk, autovacuum turned off, and Performance Insights load and waits."""
    rds = ctx.client("rds", region)
    dbs = [d for d in _pages(rds, "describe_db_instances", "DBInstances") if d.get("DBInstanceStatus") == "available"]
    if not dbs:
        return
    info = _class_info(ctx, region, {d["DBInstanceClass"] for d in dbs})
    clusters = {}
    with contextlib.suppress(ClientError):
        clusters = {c["DBClusterIdentifier"]: c for c in _pages(rds, "describe_db_clusters", "DBClusters")}
    conns = _series(ctx, region, "AWS/RDS", RDS_I, "DatabaseConnections", "Maximum")
    bconns = _series(ctx, region, "AWS/RDS", RDS_I, "DatabaseConnections", "Maximum", ctx.base_start, ctx.base_end)
    plain = [d for d in dbs if not d["Engine"].startswith("aurora")]
    iops = tput = free = {}
    if plain:
        iops = _sum_series(*(_series(ctx, region, "AWS/RDS", RDS_I, m, "Average") for m in ("ReadIOPS", "WriteIOPS")))
        tput = _sum_series(*(_series(ctx, region, "AWS/RDS", RDS_I, m, "Average")
                             for m in ("ReadThroughput", "WriteThroughput")))  # fmt: skip
        free = _series(ctx, region, "AWS/RDS", RDS_I, "FreeStorageSpace", "Minimum")
    no_vacuum = []
    for d in dbs:
        name = d["DBInstanceIdentifier"]
        mem, vcpu = info.get(d["DBInstanceClass"], (None, None))
        groups = d.get("DBParameterGroups") or []
        params = {}
        with contextlib.suppress(ClientError):
            if groups:
                params = dict(_params(ctx, region, groups[0]["DBParameterGroupName"]))
            cl = clusters.get(d.get("DBClusterIdentifier") or "")
            if cl and cl.get("DBClusterParameterGroup"):
                for k, v in _params(ctx, region, cl["DBClusterParameterGroup"], cluster=True).items():
                    params.setdefault(k, v)
        # connections against the most the database accepts
        limit = param_value(params.get("max_connections"), mem)
        pts = conns.get(name) or []
        if limit and limit > 0 and pts:
            first, hits, peak = _level_runs(pts, limit, 0.9)
            if first:
                bfirst, *_ = _level_runs(bconns.get(name) or [], limit, 0.9)
                top = max(v for _, v in pts)
                ctx.add(region, area="Database", service="db", role="cause",
                        title=f"Database {name} is at its connection limit",
                        resource=name, severity="critical" if peak >= 0.98 else "high", started=_t(first),
                        ongoing=hc._still(pts, lambda v, lim=limit: v >= 0.9 * lim), chronic=bfirst is not None,
                        evidence=f"up to {top:,.0f} connections of max_connections {limit:,.0f} ({peak:.0%}); "
                                 f"{hits * ctx.period // 60} min at 90% or more"
                                 + ("; same a day earlier" if bfirst else ""),
                        next="New connections are refused at the limit: find who opened them (a connection leak, "
                             "a retry storm, more pods), put RDS Proxy or a pool in front, or raise the class.",
                        source="CloudWatch AWS/RDS DatabaseConnections", check="rds_connections",
                        keywords=["connection", "connections", "database"])  # fmt: skip
        # provisioned IOPS and throughput (RDS, not Aurora, whose storage has no such limit)
        if not d["Engine"].startswith("aurora"):
            for kind, series, cap, unit in (
                ("IOPS", iops.get(name), d.get("Iops"), 1),
                ("throughput", tput.get(name), d.get("StorageThroughput"), 1024**2),
            ):
                if not series or not cap:
                    continue
                first, hits, peak = _level_runs(series, cap * unit, 0.95)
                if first:
                    ctx.add(region, area="Database", service="db", role="cause",
                            title=f"Database {name} uses all its provisioned {kind}",
                            resource=name, severity="high", started=_t(first),
                            ongoing=hc._still(series, lambda v, c=cap * unit: v >= 0.95 * c),
                            evidence=f"peak {peak:.0%} of {cap:,} {'IOPS' if kind == 'IOPS' else 'MiB/s'} "
                                     f"({d.get('StorageType')}); {hits * ctx.period // 60} min at 95% or more",
                            next=f"Storage {kind} is the bottleneck: raise it (gp3 or io2), or read less: a missing "
                                 "index makes queries read far more pages.",
                            source="CloudWatch AWS/RDS", check="rds_provisioned")  # fmt: skip
            fpts = free.get(name) or []
            alloc = (d.get("AllocatedStorage") or 0) * GiB
            if fpts and alloc:
                left = fpts[-1][1]
                share = left / alloc
                auto = (d.get("MaxAllocatedStorage") or 0) > d.get("AllocatedStorage", 0) * 1.1
                if share < 0.10 and left > 2 * GiB:  # under 2 GiB is the storage probe's finding
                    ctx.add(region, area="Database", service="db", role="cause",
                            title=f"Database {name} has {share:.0%} of its disk free",
                            resource=name, severity="critical" if share < 0.05 and not auto else
                            "high" if not auto else "medium", started=None, ongoing=True,
                            evidence=f"{left / GiB:,.1f} GiB free of {d['AllocatedStorage']:,} GiB"
                                     + (f"; storage autoscaling up to {d['MaxAllocatedStorage']:,} GiB"
                                        if auto else "; storage autoscaling is off"),
                            next="A full database stops writing: add storage, or turn on storage autoscaling. "
                                 "Large growth may be logs held by a replication slot.",
                            source="CloudWatch AWS/RDS FreeStorageSpace", check="rds_free_share")  # fmt: skip
                mx = d.get("MaxAllocatedStorage") or 0
                if mx and d.get("AllocatedStorage", 0) >= 0.9 * mx and share < 0.2:
                    ctx.add(region, area="Database", service="db", role="cause",
                            title=f"Storage autoscaling of database {name} is at its maximum",
                            resource=name, severity="medium", started=None, ongoing=True,
                            evidence=f"{d['AllocatedStorage']:,} GiB allocated of a {mx:,} GiB maximum; "
                                     f"{share:.0%} free",
                            next="Raise the maximum storage before the disk fills.",
                            source="RDS", check="rds_autoscale_max")  # fmt: skip
        if "postgres" in d["Engine"] and str(params.get("autovacuum", "1")).lower() in ("0", "off", "false"):
            no_vacuum.append(name)
        if d.get("PerformanceInsightsEnabled") and d.get("DbiResourceId") and vcpu:
            with contextlib.suppress(ClientError, BotoCoreError):
                _pi(ctx, region, d, vcpu)
    for name in no_vacuum:
        ctx.add(region, area="Database", service="db", role="cause",
                title=f"Autovacuum is turned off on database {name}", resource=name, severity="high",
                started=None, ongoing=True, chronic=True,
                evidence="parameter autovacuum = off",
                next="Without autovacuum, dead rows bloat tables and indexes (queries slow down) and transaction "
                     "IDs run out (the database stops writing). Turn it back on.",
                source="RDS parameters", check="rds_autovacuum", keywords=["vacuum", "bloat"])  # fmt: skip


PI_PERIOD = 300


def _pi(ctx: Ctx, region: str, d: dict, vcpu: int) -> None:
    """Performance Insights: average active sessions against vCPUs, and what they wait on and run."""
    pi = ctx.client("pi", region)
    ident = d["DbiResourceId"]

    def load(start, end):
        r = pi.get_resource_metrics(ServiceType="RDS", Identifier=ident, StartTime=start, EndTime=end,
                                    PeriodInSeconds=PI_PERIOD, MetricQueries=[{"Metric": "db.load.avg"}])  # fmt: skip
        pts = (r.get("MetricList") or [{}])[0].get("DataPoints") or []
        return [(p["Timestamp"], p["Value"]) for p in pts if p.get("Value") is not None]

    now = load(ctx.start, ctx.end)
    first, hits, _ = _runs(now, lambda v: v >= max(2.0, 1.5 * vcpu), 2)
    if not first:
        return
    peak = max(v for _, v in now)
    base = load(ctx.base_start, ctx.base_end)
    bpeak = max((v for _, v in base), default=0.0)

    def top(group: str, n: int):
        r = pi.describe_dimension_keys(ServiceType="RDS", Identifier=ident, StartTime=ctx.start, EndTime=ctx.end,
                                       Metric="db.load.avg", GroupBy={"Group": group, "Limit": n})  # fmt: skip
        keys = r.get("Keys") or []
        total = sum(k.get("Total") or 0 for k in keys) or 1
        return [(k.get("Dimensions") or {}, (k.get("Total") or 0) / total) for k in keys]

    waits = top("db.wait_event", 4)
    sqls = top("db.sql_tokenized", 3)
    wtxt = "; ".join(
        f"{w.get('db.wait_event.name')} {s:.0%}" + (f" ({h})" if (h := _wait_hint(w.get("db.wait_event.name"))) else "")
        for w, s in waits[:3]
    )
    stxt = " | ".join(f"{s:.0%}: {hc._redact(w.get('db.sql_tokenized.statement') or '')[:110]}" for w, s in sqls[:2])
    name = d["DBInstanceIdentifier"]
    ctx.add(region, area="Database", service="db", role="cause",
            title=f"Database {name} is overloaded (Performance Insights)",
            resource=name, severity="high" if peak >= 2 * vcpu else "medium", started=_t(first),
            ongoing=hc._still(now, lambda v: v >= 1.5 * vcpu), chronic=bpeak >= 0.7 * peak,
            evidence=f"up to {peak:.1f} active sessions on {vcpu} vCPUs ({hits * PI_PERIOD // 60} min over); "
                     f"a day earlier up to {bpeak:.1f}. Waiting on: {wtxt or 'unknown'}. Top SQL: {stxt or 'unknown'}",
            next="Start with the top SQL: run EXPLAIN on it. Reading from disk points to a missing index or a new "
                 "plan; locks to a long transaction; CPU to a heavy query or too many sessions.",
            source="Performance Insights", check="rds_pi", keywords=["database", "slow", "query", "index"])  # fmt: skip


DB_LOG_RE = (
    r"/(?i)(FATAL|PANIC|too many connections|remaining connection slots|deadlock detected|out of memory|"
    r"could not extend|No space left|wraparound|canceling autovacuum|terminating connection|"
    r"Aborted connection|Lock wait timeout|Too many connections|InnoDB: .*error)/"
)


def check_db_logs(ctx: Ctx, region: str) -> None:
    """Database engine logs exported to CloudWatch Logs: fatal errors, connection refusals, deadlocks and
    vacuum warnings, now against the same hours a day earlier."""
    sizes = {g: gb for g, gb in hc._ingest_gb(ctx, region, ctx.start, ctx.end).items()
             if g.startswith("/aws/rds/") and not g.endswith(("/audit", "/slowquery", "/general"))}  # fmt: skip
    keep, _big = hc._fit(sizes, hc.SCAN_CAP_GB / 2)
    if not keep:
        return
    gb = sum(sizes[g] for g in keep)
    q = (f"filter @message like {DB_LOG_RE} | fields substr(@message, 0, 140) as msg "
         f"| stats count(*) as n, min(@timestamp) as first by @log, msg | sort n desc | limit 200")  # fmt: skip
    now_rows = hc._insights(ctx, region, keep, q, ctx.start, ctx.end, gb)
    base_rows = hc._insights(ctx, region, keep, f"filter @message like {DB_LOG_RE} | stats count(*) as n by @log",
                             ctx.base_start, ctx.base_end, gb)  # fmt: skip

    def grp(r):
        return hc._group_name((r.get("@log") or "").split(":", 1)[-1])

    base = {grp(r): float(r.get("n") or 0) for r in base_rows}
    by: dict[str, list] = {}
    for r in now_rows:
        by.setdefault(grp(r), []).append(r)
    for g, rows in by.items():
        n = sum(float(r.get("n") or 0) for r in rows)
        if g in ctx.no_history or not hc._spike(n, base.get(g, 0.0), 20, 4):
            continue
        parts = g.split("/")
        db = parts[4] if len(parts) > 4 else g
        rows.sort(key=lambda r: -float(r.get("n") or 0))
        msgs = " | ".join(f"{hc._redact(re.sub(r'^[0-9: TUC-]+', '', r.get('msg') or ''))} ×{int(float(r['n']))}"
                          for r in rows[:3])  # fmt: skip
        firsts = sorted(r.get("first") for r in rows if r.get("first"))
        started = None
        if firsts:
            with contextlib.suppress(ValueError):
                started = datetime.fromisoformat(firsts[0].replace(" ", "T")).replace(tzinfo=timezone.utc)
        ctx.add(region, area="Database", service="db", role="cause",
                title=f"Database {db} logs errors far more than usual", resource=db,
                severity="high" if re.search(r"(?i)(PANIC|too many|remaining connection|No space|wraparound|"
                                             r"out of memory)", msgs) else "medium",
                started=_t(started), ongoing=True,
                evidence=f"{int(n):,} error lines in the window against {int(base.get(g, 0)):,} the day before; "
                         f"most common: {msgs}"[:600],
                next="The messages name the problem: connection slots, deadlocks between statements, disk or "
                     "memory, or vacuum being cancelled.",
                source="Database log (CloudWatch Logs)", check="db_logs", keywords=["database", "db"])  # fmt: skip


# ------------------------------------------------------------------------------------------ storage
def check_storage(ctx: Ctx, region: str) -> None:
    """EBS volume status, EFS and FSx state and fill, and disk and memory from the CloudWatch agent."""
    ec2 = ctx.client("ec2", region)
    bad = []
    for v in _pages(ec2, "describe_volume_status", "VolumeStatuses", 2000):
        st = (v.get("VolumeStatus") or {}).get("Status")
        if st in ("impaired", "warning"):
            bad.append(v)
    for v in bad[:20]:
        events = v.get("Events") or []
        ev = "; ".join(f"{e.get('EventType')}: {(e.get('Description') or '')[:100]}" for e in events[:2])
        ctx.add(region, area="EBS", service="capacity", role="cause",
                title=f"Volume {v['VolumeId']} is {v['VolumeStatus']['Status']}", resource=v["VolumeId"],
                severity="high" if v["VolumeStatus"]["Status"] == "impaired" else "medium",
                started=_t(min((e["NotBefore"] for e in events if e.get("NotBefore")), default=None)),
                ongoing=True, evidence=(ev or "status checks failing") + f"; {v.get('AvailabilityZone')}",
                next="I/O to the volume is disabled or degraded: enable I/O and check the file system, or restore "
                     "from a snapshot.",
                source="EBS", check="ebs_status")  # fmt: skip
    with contextlib.suppress(ClientError, BotoCoreError):
        efs = ctx.client("efs", region)
        for fs in _pages(efs, "describe_file_systems", "FileSystems", 200):
            name = fs.get("Name") or fs["FileSystemId"]
            if fs.get("LifeCycleState") not in ("available", "creating", "updating"):
                ctx.add(region, area="EFS", service="capacity", role="cause",
                        title=f"File system {name} is {fs.get('LifeCycleState')}", resource=fs["FileSystemId"],
                        severity="critical" if fs.get("LifeCycleState") == "error" else "high", started=None,
                        ongoing=True, evidence=f"life cycle state {fs.get('LifeCycleState')}",
                        next="Read the file system's events; open a case with AWS for an error state.",
                        source="EFS", check="efs_state")  # fmt: skip
                continue
            for mt in efs.describe_mount_targets(FileSystemId=fs["FileSystemId"]).get("MountTargets") or []:
                if mt.get("LifeCycleState") not in ("available", "creating"):
                    ctx.add(region, area="EFS", service="capacity", role="cause",
                            title=f"Mount target of file system {name} in {mt.get('AvailabilityZoneName')} is "
                                  f"{mt.get('LifeCycleState')}",
                            resource=fs["FileSystemId"], severity="high", started=None, ongoing=True,
                            evidence=f"mount target {mt.get('MountTargetId')} in subnet {mt.get('SubnetId')}",
                            next="Instances in that zone cannot mount the file system: recreate the mount target.",
                            source="EFS", check="efs_mount")  # fmt: skip
    with contextlib.suppress(ClientError, BotoCoreError):
        fsx = ctx.client("fsx", region)
        systems = _pages(fsx, "describe_file_systems", "FileSystems", 200)
        free = _series(ctx, region, "AWS/FSx", ["FileSystemId"], "FreeStorageCapacity", "Minimum") if systems else {}
        for fs in systems:
            fid = fs["FileSystemId"]
            name = next((t["Value"] for t in fs.get("Tags") or [] if t["Key"] == "Name"), fid)
            life = fs.get("Lifecycle")
            if life in ("FAILED", "MISCONFIGURED", "MISCONFIGURED_UNAVAILABLE"):
                ctx.add(region, area="FSx", service="capacity", role="cause",
                        title=f"File system {name} is {life.lower().replace('_', ' ')}", resource=fid,
                        severity="critical" if life != "MISCONFIGURED" else "high", started=None, ongoing=True,
                        evidence=((fs.get("FailureDetails") or {}).get("Message") or life)[:300],
                        next="Misconfigured usually means the Active Directory or its DNS cannot be reached: "
                             "check the directory, DNS and security groups.",
                        source="FSx", check="fsx_state")  # fmt: skip
            pts = free.get(fid) or []
            cap = (fs.get("StorageCapacity") or 0) * GiB
            if pts and cap and fs.get("FileSystemType") in ("WINDOWS", "LUSTRE"):
                share = pts[-1][1] / cap
                if share < 0.10:
                    ctx.add(region, area="FSx", service="capacity", role="cause",
                            title=f"File system {name} has {share:.0%} free", resource=fid,
                            severity="critical" if share < 0.03 else "high", started=None, ongoing=True,
                            evidence=f"{pts[-1][1] / GiB:,.1f} GiB free of {fs['StorageCapacity']:,} GiB",
                            next="Increase the storage capacity now.", source="CloudWatch AWS/FSx",
                            check="fsx_free")  # fmt: skip
    _agent(ctx, region)


AGENT_CAP = 400


def _agent(ctx: Ctx, region: str) -> None:
    """Disk and memory use from the CloudWatch agent, when it runs: its dimensions vary, so each metric is
    listed and read as it is."""
    cw = ctx.client("cloudwatch", region)
    for metric, at, crit, what in (("disk_used_percent", 90, 97, "disk"), ("mem_used_percent", 95, 99, "memory"),
                                   ("LogicalDisk % Free Space", None, None, "disk")):  # fmt: skip
        ms = []
        for page in cw.get_paginator("list_metrics").paginate(Namespace="CWAgent", MetricName=metric,
                                                              RecentlyActive="PT3H"):  # fmt: skip
            ms += page.get("Metrics") or []
            if len(ms) >= AGENT_CAP:
                break
        if not ms:
            continue
        stat = "Minimum" if at is None else "Maximum"
        q = [{"Id": f"m{i}", "MetricStat": {"Metric": m, "Period": ctx.period, "Stat": stat}, "ReturnData": True}
             for i, m in enumerate(ms[:AGENT_CAP])]  # fmt: skip
        got = _metric_data(cw, q, ctx.start, ctx.end)
        for i, m in enumerate(ms[:AGENT_CAP]):
            pts = next(iter((got.get(f"m{i}") or {}).values()), [])
            if not pts:
                continue
            dims = {d["Name"]: d["Value"] for d in m.get("Dimensions") or []}
            if at is None:  # Windows: free space, so low is bad
                pts = [(ts, 100 - v) for ts, v in pts]
                at, crit = 90, 97
            first, hits, _ = _runs(pts, lambda v, a=at: v >= a, SUSTAIN)
            if not first:
                continue
            peak = max(v for _, v in pts)
            where = dims.get("path") or dims.get("instance") or dims.get("device") or ""
            res = dims.get("InstanceId") or dims.get("host") or "an instance"
            ctx.add(region, area="EC2", service="capacity", role="cause",
                    title=f"{what.capitalize()} {where + ' ' if where else ''}on {res} is {peak:.0f}% used",
                    resource=res, severity="critical" if peak >= crit else "high", started=_t(first),
                    ongoing=hc._still(pts, lambda v, a=at: v >= a),
                    evidence=f"peak {peak:.0f}%, {hits * ctx.period // 60} min at {at}% or more (CloudWatch agent)",
                    next="A full disk stops writes and logs; full memory brings the out-of-memory killer. Free "
                         "space or grow the volume; find the process using memory.",
                    source="CloudWatch agent", check=f"agent_{what}")  # fmt: skip


# ------------------------------------------------------------------------------------------ network
def check_routes(ctx: Ctx, region: str) -> None:
    """Routes to targets that no longer exist (blackhole), in VPC and transit gateway route tables, and
    VPC endpoints that failed."""
    ec2 = ctx.client("ec2", region)
    for rt in _pages(ec2, "describe_route_tables", "RouteTables", 2000):
        holes = [r for r in rt.get("Routes") or [] if r.get("State") == "blackhole"]
        if not holes:
            continue
        subnets = [a for a in rt.get("Associations") or [] if a.get("SubnetId") or a.get("Main")]
        name = next((t["Value"] for t in rt.get("Tags") or [] if t["Key"] == "Name"), rt["RouteTableId"])
        dests = ", ".join(
            f"{r.get('DestinationCidrBlock') or r.get('DestinationPrefixListId') or r.get('DestinationIpv6CidrBlock')}"
            f" to {next((r[k] for k in ('NatGatewayId', 'TransitGatewayId', 'VpcPeeringConnectionId', 'NetworkInterfaceId', 'InstanceId', 'GatewayId', 'VpcEndpointId') if r.get(k)), 'a deleted target')}"  # noqa: E501
            for r in holes[:4]
        )
        ctx.add(region, area="Network", service="network", role="cause",
                title=f"Route table {name} sends traffic to a target that no longer exists",
                resource=f"{rt['RouteTableId']} {rt.get('VpcId', '')}",
                severity="medium" if subnets else "low", started=None, ongoing=True, chronic=True,
                evidence=f"blackhole routes: {dests}; used by {len(subnets)} subnet association(s). How long it has "
                         "been so is unknown: a deletion in the window shows under Changes",
                next="Traffic to those addresses is dropped. If it should flow, point the route at the new NAT "
                     "gateway, transit gateway or peering; if not, delete the route.",
                source="EC2 route tables", check="route_blackhole",
                keywords=["route", "network", "unreachable", "timeout"])  # fmt: skip
    for tgw in _pages(ec2, "describe_transit_gateways", "TransitGateways"):
        if tgw.get("OwnerId") != ctx.account or tgw.get("State") != "available":
            continue
        for rtb in _pages(ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables",
                          Filters=[{"Name": "transit-gateway-id", "Values": [tgw["TransitGatewayId"]]}]):  # fmt: skip
            routes = ec2.search_transit_gateway_routes(
                TransitGatewayRouteTableId=rtb["TransitGatewayRouteTableId"],
                Filters=[{"Name": "state", "Values": ["blackhole"]}], MaxResults=100,
            ).get("Routes") or []  # fmt: skip
            routes = [r for r in routes if r.get("Type") == "static"]
            if routes:
                ctx.add(region, area="Network", service="network", role="cause",
                        title=f"Transit gateway route table {rtb['TransitGatewayRouteTableId']} has blackhole routes",
                        resource=f"{tgw['TransitGatewayId']} {rtb['TransitGatewayRouteTableId']}",
                        severity="low", started=None, ongoing=True, chronic=True,
                        evidence="dropped: " + ", ".join(r.get("DestinationCidrBlock") or "" for r in routes[:6])
                        + ". Static blackhole routes are often deliberate (to block a range)",
                        next="Traffic to those ranges is dropped by the transit gateway: fix or remove the routes.",
                        source="Transit gateway", check="tgw_blackhole_route")  # fmt: skip
    for ep in _pages(ec2, "describe_vpc_endpoints", "VpcEndpoints", 1000):
        st = (ep.get("State") or "").lower()
        if st in ("failed", "rejected", "expired", "partial"):
            made = ep.get("CreationTimestamp")
            # Failed since it was made, days ago: it never carried traffic, so it cannot be today's fault.
            old = made is not None and made < ctx.start - timedelta(days=2)
            err = ep.get("LastError") or {}
            dup = err.get("Code") == "ConflictingDomainExists"
            ctx.add(region, area="Network", service="network", role="cause",
                    title=f"VPC endpoint for {ep.get('ServiceName', '').split('.')[-1]} is {st}",
                    resource=f"{ep['VpcEndpointId']} {ep.get('VpcId', '')}",
                    severity="low" if old or dup else "medium" if st == "partial" else "high", started=_t(made),
                    ongoing=True, chronic=old,
                    evidence=f"{ep['VpcEndpointId']} to {ep.get('ServiceName')}: {st}"
                             + (f" since it was created on {made:%Y-%m-%d}" if old else "")
                             + (f"; {err.get('Code')}: {err.get('Message', '')[:160]}" if err else "")
                             + ("; another endpoint or zone already answers this name, so calls still work"
                                if dup else ""),
                    next="Calls to that service from the VPC fail or go another way: recreate the endpoint, or "
                         "ask the service owner to accept it.",
                    source="VPC endpoints", check="vpce_state")  # fmt: skip


def check_shared(ctx: Ctx, region: str) -> None:
    """The accounts that own network pieces this account uses (transit gateway, shared subnets, Resolver
    rules, private DNS zones), so the health check can read them too; and Resolver rules that failed."""
    ec2 = ctx.client("ec2", region)

    def note(owner: str | None, why: str) -> None:
        if owner and owner != ctx.account:
            ctx.related.setdefault(owner, set()).add(f"{why} ({region})")

    for a in _pages(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments"):
        if a.get("ResourceOwnerId") == ctx.account:
            note(a.get("TransitGatewayOwnerId"), "owns the transit gateway")
    vpcs = _pages(ec2, "describe_vpcs", "Vpcs")
    for v in vpcs:
        note(v.get("OwnerId"), "owns a shared VPC")
    r53r = ctx.client("route53resolver", region)
    with contextlib.suppress(ClientError):
        rules = {r["Id"]: r for r in _pages(r53r, "list_resolver_rules", "ResolverRules")}
        for r in rules.values():
            if r.get("ShareStatus") == "SHARED_WITH_ME":
                note(r.get("OwnerId"), "owns the DNS forwarding rules")
            if r.get("Status") == "FAILED":
                ctx.add(region, area="DNS", service="network", role="cause",
                        title=f"DNS forwarding rule for {r.get('DomainName')} failed", resource=r["Id"],
                        severity="high", started=None, ongoing=True,
                        evidence=(r.get("StatusMessage") or "status FAILED")[:300],
                        next="Lookups of that domain fail: fix the rule's target addresses or endpoint.",
                        source="Route 53 Resolver", check="resolver_rule")  # fmt: skip
        for a in _pages(r53r, "list_resolver_rule_associations", "ResolverRuleAssociations"):
            if a.get("Status") == "FAILED":
                r = rules.get(a.get("ResolverRuleId")) or {}
                ctx.add(region, area="DNS", service="network", role="cause",
                        title=f"DNS forwarding rule for {r.get('DomainName', a.get('ResolverRuleId'))} is not "
                              f"applied to {a.get('VPCId')}",
                        resource=f"{a.get('VPCId')} {a.get('ResolverRuleId')}", severity="high", started=None,
                        ongoing=True, evidence=(a.get("StatusMessage") or "association FAILED")[:300],
                        next="Lookups of that domain from the VPC fail: associate the rule again.",
                        source="Route 53 Resolver", check="resolver_assoc")  # fmt: skip
    r53 = ctx.client("route53", "us-east-1")
    for v in vpcs[:20]:
        with contextlib.suppress(ClientError):
            for z in r53.list_hosted_zones_by_vpc(VPCId=v["VpcId"], VPCRegion=region).get("HostedZoneSummaries") or []:
                note((z.get("Owner") or {}).get("OwningAccount"), "owns a private DNS zone")


# ------------------------------------------------------------------------------------------ services
def check_msk(ctx: Ctx, region: str) -> None:
    k = ctx.client("kafka", region)
    for c in _pages(k, "list_clusters_v2", "ClusterInfoList", 100):
        _msk_operations(ctx, region, k, c)
        st = c.get("State")
        if st in ("ACTIVE", "CREATING", "UPDATING"):
            continue
        sev = {"FAILED": "critical", "HEALING": "high", "REBOOTING_BROKER": "medium", "MAINTENANCE": "medium"}
        ctx.add(region, area="Kafka", service="aws" if st == "MAINTENANCE" else "db", role="cause",
                title=f"Kafka cluster {c['ClusterName']} is {st.lower().replace('_', ' ')}",
                resource=c["ClusterName"], severity=sev.get(st, "medium"), started=None, ongoing=True,
                evidence=((c.get("StateInfo") or {}).get("Message") or f"state {st}")[:300],
                next="During patching or healing brokers restart one at a time: clients see leader changes and "
                     "retries. Clients must have retries and at least 3 brokers in their bootstrap list.",
                source="MSK", check="msk_state", keywords=["kafka"])  # fmt: skip


MSK_AWS_OPS = {"SECURITY_PATCHING", "HEAL_CLUSTER", "CERTIFICATE_RENEWAL", "REBOOT_NODE", "MAINTENANCE"}


def _msk_operations(ctx: Ctx, region: str, k, c: dict) -> None:
    """Cluster operations in the window (patching, a broker type or version change, a reboot): brokers restart
    one by one, so partitions go under replicated and leaders move. They explain those signals."""
    ops, kw = [], {"ClusterArn": c["ClusterArn"], "MaxResults": 50}
    for _ in range(10):  # not in time order: read them all (a few hundred at most)
        r = k.list_cluster_operations_v2(**kw)
        ops += r.get("ClusterOperationInfoList") or []
        if not r.get("NextToken"):
            break
        kw["NextToken"] = r["NextToken"]
    for o in ops:
        t0, t1 = o.get("StartTime"), o.get("EndTime")
        if not t0 or t0 > ctx.end or (t1 and t1 < ctx.start - timedelta(hours=1)):
            continue
        kind = (o.get("OperationType") or "").replace("_", " ").lower()
        state = (o.get("OperationState") or "").replace("_", " ").lower()
        by_aws = o.get("OperationType") in MSK_AWS_OPS
        failed = "fail" in state
        ctx.add(region, area="Kafka", service="aws" if by_aws else "db", role="cause",
                title=f"Kafka cluster {c['ClusterName']}: {kind} {'failed' if failed else 'in the window'}",
                resource=c["ClusterName"], severity="high" if failed else "medium", started=_t(t0),
                until=_t(t1) if t1 else None, ongoing=t1 is None, chronic=False,
                evidence=f"{kind} by {'AWS' if by_aws else 'your team'} from {_t(t0)} to {_t(t1) if t1 else 'now'}, "
                         f"{state}. Brokers restart one at a time: partitions go under replicated and leaders move.",
                next="Expected during the operation. Partitions offline or below min in sync replicas mean clients "
                     "use too few replicas (replication factor 3, min.insync.replicas 2) or a broker did not return.",
                source="MSK", check="msk_operation", keywords=["kafka"])  # fmt: skip


def check_dynamodb(ctx: Ctx, region: str) -> None:
    ddb = ctx.client("dynamodb", region)
    for name in _pages(ddb, "list_tables", "TableNames", 300):
        try:
            t = ddb.describe_table(TableName=name)["Table"]
        except ClientError:
            continue
        st = t.get("TableStatus")
        issues = []
        if st in ("INACCESSIBLE_ENCRYPTION_CREDENTIALS", "ARCHIVING", "ARCHIVED"):
            issues.append(("critical", f"table is {st.lower().replace('_', ' ')}"))
        for g in t.get("GlobalSecondaryIndexes") or []:
            if g.get("IndexStatus") not in ("ACTIVE", "UPDATING"):
                issues.append(
                    (
                        "medium",
                        f"index {g['IndexName']} is {g.get('IndexStatus', '').lower()}"
                        + (" (still being built: queries on it fail)" if g.get("Backfilling") else ""),
                    )
                )
        for r in t.get("Replicas") or []:
            if r.get("ReplicaStatus") not in ("ACTIVE", "UPDATING", "CREATING"):
                issues.append(
                    (
                        "high",
                        f"replica in {r.get('RegionName')} is "
                        f"{(r.get('ReplicaStatus') or '').lower().replace('_', ' ')}",
                    )
                )
        if not issues:
            continue
        sev = max((s for s, _ in issues), key=SEV_RANK.__getitem__)
        ctx.add(region, area="DynamoDB", service="db", role="cause", title=f"DynamoDB table {name}: {issues[0][1]}",
                resource=name, severity=sev, started=None, ongoing=True,
                evidence="; ".join(w for _, w in issues),
                next="An inaccessible key: restore access to the KMS key. A replica that is not active: check "
                     "the region and the key there.",
                source="DynamoDB", check="ddb_state")  # fmt: skip


def check_elasticache_deep(ctx: Ctx, region: str) -> None:
    ec = ctx.client("elasticache", region)
    ok = {"available", "modifying", "snapshotting", "creating", "deleting"}
    for g in _pages(ec, "describe_replication_groups", "ReplicationGroups", 300):
        bad = [n for n in g.get("NodeGroups") or [] if n.get("Status") not in ok]
        if g.get("Status") not in ok or bad:
            ctx.add(region, area="Cache", service="db", role="cause",
                    title=f"Cache {g['ReplicationGroupId']} is {g.get('Status')}", resource=g["ReplicationGroupId"],
                    severity="high", started=None, ongoing=True,
                    evidence=f"status {g.get('Status')}" + (f"; shards {', '.join(n.get('NodeGroupId', '') + ' ' + n.get('Status', '') for n in bad[:4])}" if bad else ""),  # noqa: E501
                    next="Read the cache's events; clients must reconnect after a failover.",
                    source="ElastiCache", check="cache_state")  # fmt: skip
    with contextlib.suppress(ClientError, BotoCoreError):
        for s in _pages(ec, "describe_serverless_caches", "ServerlessCaches", 100):
            if s.get("Status") not in ("available", "creating", "modifying", "deleting"):
                ctx.add(region, area="Cache", service="db", role="cause",
                        title=f"Serverless cache {s['ServerlessCacheName']} is {s.get('Status')}",
                        resource=s["ServerlessCacheName"], severity="high", started=None, ongoing=True,
                        evidence=f"status {s.get('Status')}", next="Read the cache's events.",
                        source="ElastiCache", check="cache_state")  # fmt: skip


def check_lambda_deep(ctx: Ctx, region: str) -> None:
    """Functions running into their timeout, the account's concurrency near its limit, and event source
    mappings that cannot read their queue or stream."""
    lam = ctx.client("lambda", region)
    fns = {f["FunctionName"]: f for f in _pages(lam, "list_functions", "Functions", 2000)}
    if not fns:
        return
    dur = _series(ctx, region, "AWS/Lambda", ["FunctionName"], "Duration", "Maximum")
    bdur = _series(ctx, region, "AWS/Lambda", ["FunctionName"], "Duration", "Maximum", ctx.base_start, ctx.base_end)
    for name, pts in dur.items():
        f = fns.get(name)
        if not f or not pts:
            continue
        limit = f.get("Timeout", 3) * 1000 * 0.98
        hits = [ts for ts, v in pts if v >= limit]
        if len(hits) < 3:
            continue
        bhits = sum(1 for _, v in bdur.get(name) or [] if v >= limit)
        ctx.add(region, area="Lambda", service="app", role="cause",
                title=f"Lambda function {name} runs into its {f.get('Timeout')} s timeout", resource=name,
                severity="high", started=_t(hits[0]), ongoing=pts[-1][1] >= limit, chronic=bhits >= len(hits) / 2,
                evidence=f"{len(hits)} periods reached the timeout; a day earlier {bhits}",
                next="Something it calls is slow or unreachable (a database, an API, a VPC route): find which, "
                     "and set client timeouts shorter than the function's.",
                source="CloudWatch AWS/Lambda Duration", check="lambda_timeout",
                keywords=["timeout", "slow"])  # fmt: skip
    with contextlib.suppress(ClientError):
        limit = lam.get_account_settings()["AccountLimit"]["ConcurrentExecutions"]
        q = [{"Id": "c", "MetricStat": {"Metric": {"Namespace": "AWS/Lambda", "MetricName": "ConcurrentExecutions"},
                                        "Period": ctx.period, "Stat": "Maximum"}, "ReturnData": True}]  # fmt: skip
        pts = next(iter((_metric_data(ctx.client("cloudwatch", region), q, ctx.start, ctx.end).get("c") or {})
                        .values()), [])  # fmt: skip
        if pts and limit:
            first, hits, peak = _level_runs(pts, limit, 0.9)
            if first:
                ctx.add(region, area="Lambda", service="capacity", role="cause",
                        title="Lambda concurrency is near the account's limit", resource=f"Lambda {region}",
                        severity="critical" if peak >= 0.98 else "high", started=_t(first),
                        ongoing=hc._still(pts, lambda v: v >= 0.9 * limit),
                        evidence=f"up to {peak:.0%} of {limit:,} concurrent executions",
                        next="Every function in the region throttles at the limit: ask AWS to raise it, and cap "
                             "noisy functions with reserved concurrency.",
                        source="CloudWatch AWS/Lambda ConcurrentExecutions", check="lambda_account_conc")  # fmt: skip
    for m in _pages(lam, "list_event_source_mappings", "EventSourceMappings", 1000):
        res = (m.get("LastProcessingResult") or "").strip()
        fn = (m.get("FunctionArn") or "").split(":")[-1]
        src = (
            m.get("EventSourceArn")
            or ",".join(
                (m.get("SelfManagedEventSource") or {}).get("Endpoints", {}).get("KAFKA_BOOTSTRAP_SERVERS", [])[:1]
            )
            or "its source"
        )
        src_name = src.split(":")[-1].split("/")[-1] if src.startswith("arn:") else src
        problem = res.upper().startswith("PROBLEM")
        stopped = m.get("State") == "Disabled" and "USER" not in (m.get("StateTransitionReason") or "").upper()
        if problem or stopped:
            since = m.get("LastModified")
            old = since is not None and since < ctx.start - timedelta(days=2)  # stopped long ago: known, chronic
            ctx.add(region, area="Lambda", service="app", role="cause",
                    title=f"Lambda function {fn} cannot read from {src_name}", resource=f"{fn} {src_name}",
                    severity="low" if old else "high", started=_t(since), ongoing=True, chronic=old,
                    evidence=f"state {m.get('State')}; {res or m.get('StateTransitionReason') or ''}"[:300],
                    next="Messages wait in the source: fix what the result names (permissions, the network to "
                         "Kafka, a deleted queue or a key), then the mapping resumes.",
                    source="Lambda event source mapping", check="lambda_esm")  # fmt: skip


def check_sqs(ctx: Ctx, region: str) -> None:
    """Queues that normally have a reader but where messages now arrive and nobody receives them."""
    sent = _series(ctx, region, "AWS/SQS", ["QueueName"], "NumberOfMessagesSent", "Sum")
    if not sent:
        return
    recv = _series(ctx, region, "AWS/SQS", ["QueueName"], "NumberOfMessagesReceived", "Sum")
    vis = _series(ctx, region, "AWS/SQS", ["QueueName"], "ApproximateNumberOfMessagesVisible", "Maximum")
    brecv = _series(ctx, region, "AWS/SQS", ["QueueName"], "NumberOfMessagesReceived", "Sum", ctx.base_start,
                    ctx.base_end)  # fmt: skip
    for q, spts in sent.items():
        if re.search(r"(?i)(dlq|dead)", q) or sum(v for _, v in brecv.get(q) or []) == 0:
            continue
        r = dict(recv.get(q) or [])
        v = vis.get(q) or []
        run, start = 0, None
        for ts, n in spts:
            if n > 0 and r.get(ts, 0) == 0:
                run += 1
                start = start or ts
            else:
                run, start = 0, None
        if run >= max(SUSTAIN, 15 * 60 // ctx.period) and len(v) >= 2 and v[-1][1] > v[0][1]:
            ctx.add(region, area="Queue", service="app",
                    title=f"Nothing is reading queue {q}", resource=q, severity="high", started=_t(start),
                    ongoing=True,
                    evidence=f"messages arrive but none were received for {run * ctx.period // 60} min; "
                             f"{v[-1][1]:,.0f} waiting; it was read a day earlier",
                    next="The consumer stopped: crashed, scaled to zero, lost permission, or its event source "
                         "mapping is disabled.",
                    source="CloudWatch AWS/SQS", check="sqs_no_reader")  # fmt: skip


# ------------------------------------------------------------------------------------------ EKS inside
POD_BAD = {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError",
           "CreateContainerError", "InvalidImageName", "RunContainerError"}  # fmt: skip
POD_CAP = 5000


def _owner(pod: dict) -> str:
    meta = pod.get("metadata") or {}
    refs = meta.get("ownerReferences") or []
    name = refs[0]["name"] if refs else meta.get("name", "")
    if refs and refs[0].get("kind") == "ReplicaSet":
        name = re.sub(r"-[a-z0-9]{6,10}$", "", name)
    return f"{meta.get('namespace')}/{name}"


def pod_findings(pods: list[dict], nodes: list[dict], start: datetime) -> list[dict]:
    """What is wrong inside a cluster, from its pods and nodes: crashing or unpullable containers, pods no
    node can take, out-of-memory kills, nodes not ready or under pressure. Grouped by workload."""
    groups: dict[tuple, dict] = {}

    def add(kind: str, owner: str, pod: str, when: str | None, detail: str) -> None:
        g = groups.setdefault((kind, owner), {"pods": set(), "first": None, "detail": detail})
        g["pods"].add(pod)
        if when and (g["first"] is None or when < g["first"]):
            g["first"] = when

    s = start.isoformat().replace("+00:00", "Z")
    for p in pods:
        meta, st = p.get("metadata") or {}, p.get("status") or {}
        owner, pname = _owner(p), meta.get("name", "")
        for c in (st.get("containerStatuses") or []) + (st.get("initContainerStatuses") or []):
            w = (c.get("state") or {}).get("waiting") or {}
            if w.get("reason") in POD_BAD:
                last = (c.get("lastState") or {}).get("terminated") or {}
                add(
                    w["reason"],
                    owner,
                    pname,
                    last.get("finishedAt") or meta.get("creationTimestamp"),
                    (w.get("message") or last.get("reason") or "")[:160],
                )
            t = (c.get("lastState") or {}).get("terminated") or {}
            if t.get("reason") == "OOMKilled" and (t.get("finishedAt") or "") >= s:
                add("OOMKilled", owner, pname, t.get("finishedAt"), f"container {c.get('name')}")
        if st.get("phase") == "Pending":
            cond = next((c for c in st.get("conditions") or [] if c.get("type") == "PodScheduled"), {})
            if cond.get("reason") == "Unschedulable":
                add("Unschedulable", owner, pname, cond.get("lastTransitionTime"), (cond.get("message") or "")[:200])
    for n in nodes:
        name = (n.get("metadata") or {}).get("name", "")
        for c in (n.get("status") or {}).get("conditions") or []:
            if c.get("type") == "Ready" and c.get("status") != "True":
                add("NotReady", "nodes", name, c.get("lastTransitionTime"), (c.get("message") or "")[:160])
            elif c.get("type") in ("MemoryPressure", "DiskPressure", "PIDPressure") and c.get("status") == "True":
                add(c["type"], "nodes", name, c.get("lastTransitionTime"), (c.get("message") or "")[:160])
    out = []
    text = {
        "CrashLoopBackOff": ("keep crashing", "high", "app", "Read the previous log: kubectl logs --previous."),
        "ImagePullBackOff": ("cannot pull their image", "high", "deploy",
                             "Check the image tag exists and the nodes may pull from the registry."),
        "ErrImagePull": ("cannot pull their image", "high", "deploy",
                         "Check the image tag exists and the nodes may pull from the registry."),
        "CreateContainerConfigError": ("cannot start: a missing secret or config map", "high", "deploy",
                                       "Create the secret or config map the pod names."),
        "CreateContainerError": ("cannot start their container", "high", "deploy", "Describe the pod for the reason."),
        "InvalidImageName": ("have an invalid image name", "high", "deploy", "Fix the image reference."),
        "RunContainerError": ("cannot run their container", "high", "app", "Describe the pod for the reason."),
        "OOMKilled": ("were killed for running out of memory", "medium", "app",
                      "Raise the memory limit or find the leak."),
        "Unschedulable": ("cannot be placed on any node", "high", "capacity",
                          "No node fits: check Karpenter or the autoscaler, instance limits and subnet addresses."),
        "NotReady": ("are not ready", "high", "capacity", "Check the nodes' kubelet, network and AWS events."),
        "MemoryPressure": ("are short of memory", "medium", "capacity", "Pods are evicted: add nodes or memory."),
        "DiskPressure": ("are short of disk", "medium", "capacity", "Pods are evicted: grow the node volumes."),
        "PIDPressure": ("are short of process ids", "medium", "capacity", "A process forks without end."),
    }  # fmt: skip
    for (kind, owner), g in groups.items():
        what, sev, svc, nxt = text.get(kind, (kind, "medium", "app", ""))
        n = len(g["pods"])
        if kind == "OOMKilled" and n < 2:
            continue
        subject = f"{n} node{'s' if n > 1 else ''}" if owner == "nodes" else f"{n} pod{'s' if n > 1 else ''} of {owner}"
        out.append(
            {
                "kind": kind,
                "title": f"{subject} {what}",
                "resource": owner,
                "severity": sev,
                "service": svc,
                "started": g["first"],
                "detail": g["detail"],
                "names": sorted(g["pods"])[:5],
                "next": nxt,
            }
        )
    return out


def check_eks_deep(ctx: Ctx, region: str) -> None:
    """EKS add-ons that are degraded, and inside each cluster (when this identity may read it) the pods and
    nodes that are failing."""
    from .outage import K8sRefused, K8sUnreachable, _k8s_list, eks_token

    eks = ctx.client("eks", region)
    refused, unreachable = [], []
    for name in _pages(eks, "list_clusters", "clusters", 50):
        for a in _pages(eks, "list_addons", "addons", 50, clusterName=name):
            with contextlib.suppress(ClientError):
                ad = eks.describe_addon(clusterName=name, addonName=a)["addon"]
                issues = (ad.get("health") or {}).get("issues") or []
                if ad.get("status") in ("DEGRADED", "CREATE_FAILED", "UPDATE_FAILED") or issues:
                    ctx.add(region, area="EKS", service="platform", role="cause",
                            title=f"EKS add-on {a} on {name} is {(ad.get('status') or 'unhealthy').lower()}",
                            resource=f"{name}/{a}", severity="high" if a in ("vpc-cni", "coredns", "kube-proxy")
                            else "medium", started=_t(ad.get("modifiedAt")), ongoing=True,
                            evidence="; ".join(f"{i.get('code')}: {(i.get('message') or '')[:120]}"
                                               for i in issues[:3]) or f"status {ad.get('status')}",
                            next="vpc-cni, coredns and kube-proxy failing breaks pod networking and DNS: fix what "
                                 "AWS names (often the add-on's role).",
                            source="EKS add-ons", check="eks_addon")  # fmt: skip
        try:
            c = eks.describe_cluster(name=name)["cluster"]
            token = eks_token(ctx.client("sts", region), name, region)

            def read(path, c=c, token=token):
                return _k8s_list(c["endpoint"], c["certificateAuthority"]["data"], token, path, POD_CAP)

            pods, nodes = read("/api/v1/pods"), read("/api/v1/nodes")
        except K8sRefused:
            refused.append(name)
            continue
        except (K8sUnreachable, KeyError, ValueError, ssl.SSLError):
            unreachable.append(name)
            continue
        for f in pod_findings(pods, nodes, ctx.start):
            ctx.add(region, area="EKS", service=f["service"], role="cause" if f["service"] != "app" else "symptom",
                    title=f"{name}: {f['title']}", resource=f"{name}/{f['resource']}", severity=f["severity"],
                    started=f["started"], ongoing=True,
                    evidence=(f"{f['kind']}: {f['detail']}; e.g. {', '.join(f['names'][:3])}")[:400],
                    next=f["next"], source="Kubernetes API", check=f"k8s_{f['kind'].lower()}",
                    keywords=["kubernetes", "pod", "eks"])  # fmt: skip
    if refused:
        ctx.ready(region, f"No read access inside EKS cluster{'s' if len(refused) > 1 else ''} "
                          f"{', '.join(refused[:4])}{' and more' if len(refused) > 4 else ''}",
                  "Crashing pods, pods that cannot be placed and nodes that are not ready cannot be seen.",
                  "Add an EKS access entry for this role with the AmazonEKSViewPolicy access policy.",
                  permission="eks:CreateAccessEntry, eks:AssociateAccessPolicy")  # fmt: skip
    if unreachable:
        ctx.ready(region, f"EKS cluster{'s' if len(unreachable) > 1 else ''} {', '.join(unreachable[:4])} "
                          "cannot be reached from here",
                  "The cluster endpoint is private, so pods and nodes cannot be read from this network.",
                  "Run the health check from inside the network (VPN), or turn on Container Insights.")  # fmt: skip


# ------------------------------------------------------------------------------------------ traces
def check_traces(ctx: Ctx, region: str) -> None:
    """X-Ray (and Application Signals) service graph: services and calls between them that fail or slowed,
    which points at the downstream service at fault."""
    xr = ctx.client("xray", region)
    span = min(ctx.end - ctx.start, timedelta(hours=6))

    def graph(end):
        out, kw = [], {"StartTime": end - span, "EndTime": end}
        while True:
            r = xr.get_service_graph(**kw)
            out += r.get("Services") or []
            if not r.get("NextToken"):
                return out
            kw["NextToken"] = r["NextToken"]

    now = graph(ctx.end)
    if not now:
        return
    base = graph(ctx.end - (ctx.start - ctx.base_start))

    def stats(services):
        names = {s.get("ReferenceId"): s.get("Name") for s in services}
        out = {}
        for s in services:
            st = s.get("SummaryStatistics") or {}
            out[s.get("Name")] = st
            for e in s.get("Edges") or []:
                out[f"{s.get('Name')} → {names.get(e.get('ReferenceId'), '?')}"] = e.get("SummaryStatistics") or {}
        return out

    def rate(st):
        n = st.get("TotalCount") or 0
        f = (st.get("FaultStatistics") or {}).get("TotalCount") or 0
        return n, (f / n if n else 0.0), ((st.get("TotalResponseTime") or 0) / n if n else 0.0)

    b = stats(base)
    for key, st in stats(now).items():
        n, fr, lat = rate(st)
        bn, bfr, blat = rate(b.get(key) or {})
        if n >= 100 and fr >= 0.05 and fr >= 3 * bfr:
            ctx.add(region, area="Traces", service="app", title=f"{key} fails {fr:.0%} of calls", resource=key,
                    severity="high" if fr >= 0.2 else "medium", started=None, ongoing=True,
                    evidence=f"{fr:.0%} faults in {n:,} traced calls; a day earlier {bfr:.0%}",
                    next="The service at the end of the arrow is the one failing: open its traces.",
                    source="X-Ray service graph", check="xray_faults")  # fmt: skip
        elif n >= 100 and bn >= 100 and lat >= 1.0 and lat >= 3 * blat:
            ctx.add(region, area="Traces", service="app", title=f"{key} slowed from {blat:.2f} s to {lat:.2f} s",
                    resource=key, severity="medium", started=None, ongoing=True,
                    evidence=f"average {lat:.2f} s over {n:,} traced calls; a day earlier {blat:.2f} s",
                    next="The service at the end of the arrow is slow: open its traces for the slow segment.",
                    source="X-Ray service graph", check="xray_latency")  # fmt: skip


# ------------------------------------------------------------------------------------------ Athena
ATHENA_DB = "exitrisk_healthcheck"
ATHENA_WAIT = 120
NUMERIC = {"version": "int", "srcport": "int", "dstport": "int", "protocol": "int", "packets": "bigint",
           "bytes": "bigint", "start": "bigint", "end": "bigint", "tcp-flags": "int"}  # fmt: skip


def flow_table_sql(table: str, location: str, fields: list[str], parquet: bool, hive: bool) -> str:
    """CREATE EXTERNAL TABLE for one S3 flow log destination, with the day projected (no partitions to add)."""
    cols = ", ".join(f"`{f.replace('-', '_')}` {NUMERIC.get(f, 'string')}" for f in fields)
    fmt = "'year='yyyy'/month='MM'/day='dd" if hive else "yyyy/MM/dd"
    store = ("STORED AS PARQUET" if parquet else
             "ROW FORMAT DELIMITED FIELDS TERMINATED BY ' ' STORED AS TEXTFILE")  # fmt: skip
    props = {"projection.enabled": "true", "projection.day.type": "date", "projection.day.format": fmt,
             "projection.day.range": "2020/01/01,NOW" if not hive else "year=2020/month=01/day=01,NOW",
             "projection.day.interval": "1", "projection.day.interval.unit": "DAYS",
             "storage.location.template": location.rstrip("/") + "/${day}"}  # fmt: skip
    if not parquet:
        props["skip.header.line.count"] = "1"
    tp = ", ".join(f"'{k}'='{v}'" for k, v in props.items())
    return (f"CREATE EXTERNAL TABLE IF NOT EXISTS {ATHENA_DB}.{table} ({cols}) PARTITIONED BY (day string) "
            f"{store} LOCATION '{location}' TBLPROPERTIES ({tp})")  # fmt: skip


def flow_location(dest: str, account: str, region: str, hive: bool) -> tuple[str, str]:
    """(bucket, the table location) of a flow log's S3 destination arn:aws:s3:::bucket[/prefix]."""
    path = dest.split(":::", 1)[-1].rstrip("/")
    bucket, _, prefix = path.partition("/")
    base = f"s3://{bucket}/" + (f"{prefix}/" if prefix else "") + "AWSLogs/"
    if hive:
        return bucket, base + f"aws-account-id={account}/aws-service=vpcflowlogs/aws-region={region}/"
    return bucket, base + f"{account}/vpcflowlogs/{region}/"


def _days(start: datetime, end: datetime, hive: bool) -> list[str]:
    out, d = [], start.date()
    while d <= end.date():
        out.append(d.strftime("year=%Y/month=%m/day=%d" if hive else "%Y/%m/%d"))
        d += timedelta(days=1)
    return out


def check_flow_athena(ctx: Ctx, region: str, flows: list[dict]) -> None:
    """Rejected traffic in flow logs kept only in S3, through Athena: a table over the log location (created
    once, in database exitrisk_healthcheck), then two queries. Runs only when the person opts in."""
    ath = ctx.client("athena", region)
    wg = ath.get_work_group(WorkGroup="primary")["WorkGroup"]["Configuration"]
    out = (wg.get("ResultConfiguration") or {}).get("OutputLocation")
    managed = (wg.get("ManagedQueryResultsConfiguration") or {}).get("Enabled")
    if not out and not managed:
        ctx.ready(region, "Athena has no place to write query results",
                  "Flow logs kept only in S3 cannot be read.",
                  "Set a query result location for Athena's primary workgroup (Athena > Workgroups > primary).",
                  permission="athena:UpdateWorkGroup")  # fmt: skip
        return
    s3 = ctx.client("s3", region)

    def run(sql: str) -> list[list[str]]:
        qid = ath.start_query_execution(QueryString=sql, WorkGroup="primary")["QueryExecutionId"]
        waited = 0.0
        while waited < ATHENA_WAIT:
            st = ath.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
            if st["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
                if st["State"] != "SUCCEEDED":
                    raise RuntimeError(f"Athena query {st['State'].lower()}: {st.get('StateChangeReason', '')[:200]}")
                rows = ath.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"][1:]
                return [[c.get("VarCharValue") for c in r["Data"]] for r in rows]
            time.sleep(2)
            waited += 2
        with contextlib.suppress(ClientError):
            ath.stop_query_execution(QueryExecutionId=qid)
        raise TimeoutError(f"Athena query ran over {ATHENA_WAIT} s")

    run(f"CREATE DATABASE IF NOT EXISTS {ATHENA_DB}")
    for f in flows:
        opts = f.get("DestinationOptions") or {}
        hive, parquet = bool(opts.get("HiveCompatiblePartitions")), opts.get("FileFormat") == "parquet"
        bucket, loc = flow_location(f["LogDestination"], ctx.account, region, hive)
        fields = re.findall(r"\$\{([a-z0-9-]+)\}", f.get("LogFormat") or hc.DEFAULT_FLOW_FORMAT)
        if not {"action", "start", "dstaddr", "dstport"} <= set(fields):
            continue
        days = sorted(set(_days(ctx.base_start, ctx.base_end, hive) + _days(ctx.start, ctx.end, hive)))
        size = 0
        for d in days:
            prefix = loc.split(f"s3://{bucket}/", 1)[1] + d + "/"
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
                size += sum(o.get("Size", 0) for o in page.get("Contents") or [])
        if size / 1e9 > hc.SCAN_CAP_GB:
            ctx.ready(region, f"Flow logs of {f['ResourceId']} in S3 are too large to search in this window",
                      f"{size / 1e9:,.0f} GB for the window and the day before.",
                      "Choose a shorter window, or query them by hand in Athena.")  # fmt: skip
            continue
        table = "flow_" + hashlib.sha256(loc.encode()).hexdigest()[:12]
        run(flow_table_sql(table, loc, fields, parquet, hive))
        with ctx._lock:
            ctx.scanned_gb += size / 1e9
        dl = ", ".join(f"'{d}'" for d in days)
        s0, s1 = int(ctx.start.timestamp()), int(ctx.end.timestamp())
        b0, b1 = int(ctx.base_start.timestamp()), int(ctx.base_end.timestamp())
        # Only numbers, dates and a table name made here go into the SQL.
        where = f"FROM {ATHENA_DB}.{table} WHERE day IN ({dl}) AND action = 'REJECT'"
        tot = run(f'SELECT count_if("start" BETWEEN {s0} AND {s1}), count_if("start" BETWEEN {b0} AND {b1}) {where}')
        now, before = (float(tot[0][0] or 0), float(tot[0][1] or 0)) if tot else (0.0, 0.0)
        if not hc._spike(now, before, 500, 3):
            continue
        top = run(
            f'SELECT dstaddr, dstport, count(*) n {where} AND "start" BETWEEN {s0} AND {s1} '
            "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 3"
        )
        ctx.add(region, area="Network", service="network", title=f"Rejected traffic jumped in {f['ResourceId']}",
                resource=f["ResourceId"], severity="high" if now >= 10 * (before + 50) else "medium", started=None,
                ongoing=True,
                evidence=f"{int(now):,} rejected flows in the window against {int(before):,} the day before; most "
                         "refused: " + ", ".join(f"{a}:{p} ×{n}" for a, p, n in top),
                next="A security group, network ACL or firewall change usually explains a jump in refusals: compare "
                     "the refused ports with recent changes.",
                source="VPC flow logs (S3, Athena)", check="flow_rejects")  # fmt: skip


REPLICA_DAYS = 14  # a replica idle this long is not waiting for a busy day
IDLE_CONNS = 1  # at most this many connections all fortnight: a monitor at most, no reader
WRITER_HOT = 60.0  # writer CPU, daily average %, at which idle readers are a missed relief


def replica_findings(dbs: list[dict], conns: dict, cpu: dict, region: str, since: datetime) -> list[dict]:
    """Read replicas nobody reads. A plain RDS replica in the same region with no connections for two weeks;
    Aurora readers beyond the one kept as failover target with none; and a hot Aurora writer whose readers
    all sit idle, so reads that could move there do not. Cross region replicas are disaster recovery copies
    and are left alone, as are databases younger than the fortnight read."""
    out = []

    def idle(name: str) -> bool | None:
        pts = conns.get(name) or []
        return None if len(pts) < REPLICA_DAYS - 3 else max(v for _, v in pts) <= IDLE_CONNS

    def old(d: dict) -> bool:
        made = d.get("InstanceCreateTime")
        return bool(made) and made <= since

    usable = [d for d in dbs if d.get("DBInstanceStatus") == "available" and old(d)]
    for d in usable:
        src = d.get("ReadReplicaSourceDBInstanceIdentifier")
        if not src or d["Engine"].startswith("aurora"):
            continue
        if src.startswith("arn:") and src.split(":")[3] != region:
            continue  # a copy in another region: disaster recovery, idle by design
        if idle(d["DBInstanceIdentifier"]):
            out.append({"rule": "rds_replica_idle", "res": d["DBInstanceIdentifier"], "severity": "medium",
                        "title": "Read replica nobody reads",
                        "note": f"Replica of {src}, {d['DBInstanceClass']}; at most {IDLE_CONNS} connection in "
                                f"{REPLICA_DAYS} days.",
                        "why": "A full database instance paid for and kept in step with its source, but no application "
                               "connects to it. Either point reads at it, keep it on purpose as a standby (and say so "
                               "in a tag), or remove it."})  # fmt: skip
    clusters: dict[str, list[dict]] = {}
    for d in usable:
        if d["Engine"].startswith("aurora") and d.get("DBClusterIdentifier"):
            clusters.setdefault(d["DBClusterIdentifier"], []).append(d)
    for cl, members in clusters.items():
        writer = [d for d in members if d.get("_writer")]
        readers = [d for d in members if not d.get("_writer")]
        if not readers:
            continue
        verdict = {d["DBInstanceIdentifier"]: idle(d["DBInstanceIdentifier"]) for d in readers}
        if any(v is None for v in verdict.values()):
            continue
        quiet = [d for d in readers if verdict[d["DBInstanceIdentifier"]]]
        if len(quiet) == len(readers) and writer:
            pts = cpu.get(writer[0]["DBInstanceIdentifier"]) or []
            top = max((v for _, v in pts), default=0.0)
            if top >= WRITER_HOT:
                out.append({"rule": "aurora_reads_on_writer", "res": cl, "severity": "medium",
                            "title": "Reads stay on a busy writer while the readers sit idle",
                            "note": f"Writer {writer[0]['DBInstanceIdentifier']} reached {top:.0f}% CPU (daily "
                                    f"average); {len(readers)} reader(s) had no connections in {REPLICA_DAYS} days.",
                            "why": "Aurora readers can take read queries off the writer through the reader "
                                   "endpoint. Here every query goes to the writer, so the writer runs hotter than it "
                                   "needs to and has less headroom at peak."})  # fmt: skip
        # keep the first failover target; any further idle reader is spend with no use
        keep = min(readers, key=lambda d: (d.get("PromotionTier", 15), d["DBInstanceIdentifier"]))
        for d in quiet:
            if d is keep or len(readers) < 2:
                continue
            out.append({"rule": "rds_replica_idle", "res": d["DBInstanceIdentifier"], "severity": "medium",
                        "title": "Aurora reader nobody reads",
                        "note": f"In cluster {cl}, {d['DBInstanceClass']}; no connections in {REPLICA_DAYS} days. "
                                f"{keep['DBInstanceIdentifier']} is kept as the failover target.",
                        "why": "One idle reader is a sensible failover target. Further readers with no connections "
                               "are paid for and do no work: send reads to them through the reader endpoint, or "
                               "remove them."})  # fmt: skip
    for f in out:
        f.update(region=region, area="usage", service_label="Amazon RDS")
    return out


def check_replicas(ctx: Ctx, region: str) -> None:
    """Read replicas and Aurora readers with no connections for two weeks, and hot writers they could relieve."""
    rds = ctx.client("rds", region)
    dbs = list(_pages(rds, "describe_db_instances", "DBInstances"))
    if not any(d.get("ReadReplicaSourceDBInstanceIdentifier") or d.get("DBClusterIdentifier") for d in dbs):
        return
    with contextlib.suppress(ClientError):
        for c in _pages(rds, "describe_db_clusters", "DBClusters"):
            writers = {m["DBInstanceIdentifier"] for m in c.get("DBClusterMembers") or [] if m.get("IsClusterWriter")}
            for d in dbs:
                if d.get("DBClusterIdentifier") == c["DBClusterIdentifier"]:
                    d["_writer"] = d["DBInstanceIdentifier"] in writers
    end = ctx.end
    since = end - timedelta(days=REPLICA_DAYS)
    probe = {"ns": "AWS/RDS", "dims": RDS_I}
    q = [{"Id": i, "Expression": hc._search(probe, m, st, 86400), "Label": hc._label(RDS_I), "ReturnData": True}
         for i, m, st in (("c", "DatabaseConnections", "Maximum"), ("u", "CPUUtilization", "Average"))]  # fmt: skip
    got = _metric_data(ctx.client("cloudwatch", region), q, since, end)
    rows = replica_findings(dbs, got.get("c") or {}, got.get("u") or {}, region, since)
    with ctx._lock:
        ctx.risks.extend({"account": ctx.account, "account_name": ctx.name, **r} for r in rows)


REGION_CHECKS = [
    ("rds_deep", check_rds_deep),
    ("replicas", check_replicas),
    ("db_logs", check_db_logs),
    ("storage", check_storage),
    ("routes", check_routes),
    ("shared", check_shared),
    ("msk", check_msk),
    ("dynamodb", check_dynamodb),
    ("elasticache_deep", check_elasticache_deep),
    ("lambda_deep", check_lambda_deep),
    ("sqs", check_sqs),
    ("eks_deep", check_eks_deep),
    ("traces", check_traces),
]
CHECK_LABELS = {
    "rds_deep": "database connections, IOPS, storage, vacuum and Performance Insights",
    "replicas": "read replicas and Aurora readers nobody reads",
    "db_logs": "database engine logs",
    "storage": "EBS volumes, EFS, FSx, disk and memory (CloudWatch agent)",
    "routes": "blackhole routes and VPC endpoints",
    "shared": "shared network owners and DNS forwarding rules",
    "msk": "Kafka (MSK) cluster state",
    "dynamodb": "DynamoDB tables, indexes and replicas",
    "elasticache_deep": "ElastiCache cluster state",
    "lambda_deep": "Lambda timeouts, account concurrency and event source mappings",
    "sqs": "SQS queues nobody reads",
    "eks_deep": "EKS add-ons, pods and nodes",
    "traces": "X-Ray service graph",
    "athena": "flow logs in S3 (Athena)",
}


hc._merge_deep(sys.modules[__name__])
