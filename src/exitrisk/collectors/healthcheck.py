"""Health Check: a deep, read-only look at one or a few accounts while something is wrong.

Everything is read for a time window (the last hours) and, for metrics, the same window a day earlier, so
a fault that was already there yesterday is marked chronic instead of being blamed for today. Each finding
is a *signal*: a ``symptom`` (errors, unhealthy targets, alarms) or a possible ``cause`` (a change, an AWS
event, a capacity or quota failure, an expired certificate). The report (``exitrisk.healthcheck``) links
symptoms to causes by time and ranks the likely causes.

Read in each active region:
- CloudWatch: alarms in ALARM, and one GetMetricData call of SEARCH expressions over every resource for the
  error, saturation and health metrics in ``PROBES`` (no per-resource calls);
- AWS Health events (open, or closed inside the window);
- CloudTrail write events: changes made, and calls AWS refused (capacity, quotas, throttling);
- ECS services and stopped tasks, EKS clusters and node groups, Auto Scaling activities, EC2 status checks,
  RDS and ElastiCache events, Lambda function state, subnets out of addresses, target health, VPN, Direct
  Connect and transit gateway attachments, certificates, Route 53 health checks, and quotas in use (the
  AWS/Usage metrics against SERVICE_QUOTA).
A check that could not be read is listed as a gap, never treated as healthy.
"""

from __future__ import annotations

import contextlib
import json
import math
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import BOTO_CONFIG, ClientCache, with_backoff
from ..issues import describe_exception
from ..logging_config import get_logger

log = get_logger("healthcheck")

TASK_WORKERS = 16  # checks run at once across the accounts and regions of one health check
MAX_ITEMS = 400  # resources of one kind read per region
TRAIL_PAGES = 40  # pages of 50 write events per region (about 20 seconds)
STOPPED_TASKS = 100  # stopped ECS tasks read per cluster
HEALTH_CHECKS = 200  # Route 53 health checks read per account
METRIC_QUERIES = 500  # GetMetricData's limit per call
SUSTAIN = 3  # periods in a row a level must hold to count (15 minutes at the 5 minute period)

# Namespaces every account has; a region showing only these runs no workload.
BACKGROUND_NS = {
    "AWS/Config",
    "AWS/Events",
    "AWS/GuardDuty",
    "AWS/KMS",
    "AWS/Logs",
    "AWS/Usage",
    "AWS/TrustedAdvisor",
    "AWS/STS",
    "AWS/CloudTrail",
    "AWS/SecurityHub",
    "AWS/SSM-RunCommand",
    "AWS/Inspector2",
    "AWS/S3",
    "AWS/Billing",
    "AWS/AccessAnalyzer",
    "AWS/Backup",
    "CloudWatchSynthetics",
    "AWS/Firehose",
}

_NOT_HERE = {
    "OptInRequired",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "AuthFailure",
    "SubscriptionRequiredException",
    "UnsupportedOperation",
    "InvalidAction",
}


def _t(dt: datetime | str | None) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def period_for(hours: float) -> int:
    return 60 if hours <= 3 else 300


# ---------------------------------------------------------------------------------------------- probes
# One SEARCH per metric over every resource in the region. Kinds:
#   ratio   numerator / denominator per period (errors / requests), rated on the worst 3 periods in a row
#   count   a total that should be zero or near it (throttles, failed invocations, port allocation errors)
#   high    a level held for SUSTAIN periods at or above ``at`` (CPU, unhealthy hosts, a red cluster)
#   low     a level held for SUSTAIN periods at or below ``at`` (burst balance, free storage, health check)
#   spike   the window's peak at least ``x`` times yesterday's peak and above ``at`` (queue age, latency)
# ``sev`` is the severity when it fires; ratio probes rate themselves (2% medium, 10% high, 50% critical).
PROBES: list[dict] = [
    # Load balancers
    {
        "id": "alb_5xx",
        "ns": "AWS/ApplicationELB",
        "dims": ["LoadBalancer"],
        "metric": "HTTPCode_ELB_5XX_Count",
        "den": "RequestCount",
        "stat": "Sum",
        "kind": "ratio",
        "min": 20,
        "area": "Load balancer",
        "svc": "elb",
        "title": "Load balancer {r} answers with its own 5xx errors",
        "next": "5xx from the load balancer itself (502, 503, 504) means no healthy target or targets timing out: "
        "check target health and the targets' logs.",
    },
    {
        "id": "alb_t5xx",
        "ns": "AWS/ApplicationELB",
        "dims": ["LoadBalancer"],
        "metric": "HTTPCode_Target_5XX_Count",
        "den": "RequestCount",
        "stat": "Sum",
        "kind": "ratio",
        "min": 20,
        "area": "Load balancer",
        "svc": "app",
        "title": "Targets behind {r} return 5xx errors",
        "next": "The application behind the load balancer is failing: check its logs and what it calls "
        "(database, downstream APIs).",
    },
    {
        "id": "alb_unhealthy",
        "ns": "AWS/ApplicationELB",
        "dims": ["TargetGroup", "LoadBalancer"],
        "metric": "UnHealthyHostCount",
        "den": "HealthyHostCount",
        "stat": "Maximum",
        "den_stat": "Minimum",
        "kind": "unhealthy",
        "area": "Load balancer",
        "svc": "elb",
        "title": "Target group {r} has unhealthy targets",
        "next": "See the health check reason on each target (below) and the target's own logs.",
    },
    {
        "id": "nlb_unhealthy",
        "ns": "AWS/NetworkELB",
        "dims": ["TargetGroup", "LoadBalancer"],
        "metric": "UnHealthyHostCount",
        "den": "HealthyHostCount",
        "stat": "Maximum",
        "den_stat": "Minimum",
        "kind": "unhealthy",
        "area": "Load balancer",
        "svc": "elb",
        "title": "Target group {r} has unhealthy targets",
        "next": "See the health check reason on each target and whether the target's port answers.",
    },
    {
        "id": "elb_5xx",
        "ns": "AWS/ELB",
        "dims": ["LoadBalancerName"],
        "metric": "HTTPCode_ELB_5XX",
        "den": "RequestCount",
        "stat": "Sum",
        "kind": "ratio",
        "min": 20,
        "area": "Load balancer",
        "svc": "elb",
        "title": "Classic load balancer {r} answers with 5xx errors",
        "next": "Check the instances behind it: health check status and their logs.",
    },
    {
        "id": "elb_unhealthy",
        "ns": "AWS/ELB",
        "dims": ["LoadBalancerName"],
        "metric": "UnHealthyHostCount",
        "den": "HealthyHostCount",
        "stat": "Maximum",
        "den_stat": "Minimum",
        "kind": "unhealthy",
        "area": "Load balancer",
        "svc": "elb",
        "title": "Classic load balancer {r} has unhealthy instances",
        "next": "Check the instances' health check and their logs.",
    },
    # APIs and functions
    {
        "id": "apigw_5xx",
        "ns": "AWS/ApiGateway",
        "dims": ["ApiName"],
        "metric": "5XXError",
        "den": "Count",
        "stat": "Sum",
        "kind": "ratio",
        "min": 20,
        "area": "API Gateway",
        "svc": "app",
        "title": "API {r} returns 5xx errors",
        "next": "Check the integration behind the API (Lambda, load balancer, VPC link) and its execution logs.",
    },
    {
        "id": "apigw2_5xx",
        "ns": "AWS/ApiGateway",
        "dims": ["ApiId"],
        "metric": "5xx",
        "den": "Count",
        "stat": "Sum",
        "kind": "ratio",
        "min": 20,
        "area": "API Gateway",
        "svc": "app",
        "title": "HTTP API {r} returns 5xx errors",
        "next": "Check the integration behind the API and its logs.",
    },
    {
        "id": "lambda_errors",
        "ns": "AWS/Lambda",
        "dims": ["FunctionName"],
        "metric": "Errors",
        "den": "Invocations",
        "stat": "Sum",
        "kind": "ratio",
        "min": 10,
        "area": "Lambda",
        "svc": "app",
        "title": "Lambda function {r} is failing",
        "next": "Read the function's log group for the error; check what it calls and its recent deployments.",
    },
    {
        "id": "lambda_throttles",
        "ns": "AWS/Lambda",
        "dims": ["FunctionName"],
        "metric": "Throttles",
        "stat": "Sum",
        "kind": "count",
        "at": 10,
        "sev": "high",
        "area": "Lambda",
        "svc": "capacity",
        "role": "cause",
        "title": "Lambda function {r} is throttled",
        "next": "The function hit its reserved concurrency or the account's concurrency quota: check both.",
    },
    {
        "id": "states_failed",
        "ns": "AWS/States",
        "dims": ["StateMachineArn"],
        "metric": "ExecutionsFailed",
        "stat": "Sum",
        "kind": "count",
        "at": 5,
        "sev": "medium",
        "area": "Step Functions",
        "svc": "app",
        "title": "Step Functions {r} executions fail",
        "next": "Open a failed execution to see which step failed and why.",
    },
    {
        "id": "states_throttled",
        "ns": "AWS/States",
        "dims": ["StateMachineArn"],
        "metric": "ExecutionThrottled",
        "stat": "Sum",
        "kind": "count",
        "at": 5,
        "sev": "high",
        "area": "Step Functions",
        "svc": "capacity",
        "role": "cause",
        "title": "Step Functions {r} is throttled",
        "next": "Check the state transition quota.",
    },
    {
        "id": "events_failed",
        "ns": "AWS/Events",
        "dims": ["RuleName"],
        "metric": "FailedInvocations",
        "stat": "Sum",
        "kind": "count",
        "at": 5,
        "sev": "medium",
        "area": "EventBridge",
        "svc": "app",
        "title": "EventBridge rule {r} cannot deliver to its target",
        "next": "Check the target exists and the rule's role may invoke it; add a dead-letter queue to see the error.",
    },
    {
        "id": "events_failed_bus",
        "ns": "AWS/Events",
        "dims": ["EventBusName", "RuleName"],
        "metric": "FailedInvocations",
        "stat": "Sum",
        "kind": "count",
        "at": 5,
        "sev": "medium",
        "area": "EventBridge",
        "svc": "app",
        "title": "EventBridge rule {r} cannot deliver to its target",
        "next": "Check the target exists and the rule's role may invoke it.",
    },
    {
        "id": "sns_failed",
        "ns": "AWS/SNS",
        "dims": ["TopicName"],
        "metric": "NumberOfNotificationsFailed",
        "stat": "Sum",
        "kind": "count",
        "at": 5,
        "sev": "medium",
        "area": "SNS",
        "svc": "app",
        "title": "SNS topic {r} fails to deliver",
        "next": "Check the subscriptions' endpoints and delivery status logging.",
    },
    # Queues and streams
    {
        "id": "sqs_age",
        "ns": "AWS/SQS",
        "dims": ["QueueName"],
        "metric": "ApproximateAgeOfOldestMessage",
        "stat": "Maximum",
        "kind": "spike",
        "at": 600,
        "x": 3,
        "sev": "high",
        "area": "SQS",
        "svc": "app",
        "title": "Queue {r} is backing up",
        "unit": "s",
        "next": "Consumers stopped or slowed: check the consumer (Lambda, ECS, EC2) for errors or scaling.",
    },
    {
        "id": "sqs_dlq",
        "ns": "AWS/SQS",
        "dims": ["QueueName"],
        "metric": "NumberOfMessagesSent",
        "stat": "Sum",
        "kind": "count",
        "at": 1,
        "sev": "high",
        "area": "SQS",
        "svc": "app",
        "name": r"(?i)(dlq|dead|deadletter)",
        "title": "Messages are going to dead-letter queue {r}",
        "next": "Read a message from the dead-letter queue: the consumer keeps failing on it.",
    },
    {
        "id": "kinesis_write",
        "ns": "AWS/Kinesis",
        "dims": ["StreamName"],
        "metric": "WriteProvisionedThroughputExceeded",
        "stat": "Sum",
        "kind": "count",
        "at": 10,
        "sev": "high",
        "area": "Kinesis",
        "svc": "capacity",
        "role": "cause",
        "title": "Kinesis stream {r} rejects writes",
        "next": "The stream is at its shard limit: add shards or use on-demand.",
    },
    {
        "id": "kinesis_age",
        "ns": "AWS/Kinesis",
        "dims": ["StreamName"],
        "metric": "GetRecords.IteratorAgeMilliseconds",
        "stat": "Maximum",
        "kind": "spike",
        "at": 60000,
        "x": 3,
        "sev": "high",
        "area": "Kinesis",
        "svc": "app",
        "title": "Consumers of Kinesis stream {r} are falling behind",
        "unit": "ms",
        "next": "Check the stream's consumers for errors or throttling.",
    },
    # Databases and caches
    {
        "id": "rds_cpu",
        "ns": "AWS/RDS",
        "dims": ["DBInstanceIdentifier"],
        "metric": "CPUUtilization",
        "stat": "Maximum",
        "kind": "high",
        "at": 90,
        "sev": "high",
        "area": "Database",
        "svc": "db",
        "role": "cause",
        "title": "Database {r} is out of CPU",
        "unit": "%",
        "next": "Find the queries using it (Performance Insights); a new deployment or a missing index is typical.",
    },
    {
        "id": "rds_storage",
        "ns": "AWS/RDS",
        "dims": ["DBInstanceIdentifier"],
        "metric": "FreeStorageSpace",
        "stat": "Minimum",
        "kind": "low",
        "at": 2 * 1024**3,
        "sev": "critical",
        "area": "Database",
        "svc": "db",
        "role": "cause",
        "title": "Database {r} is running out of storage",
        "unit": "bytes",
        "next": "Raise the allocated storage or turn on storage autoscaling now; a full database stops writing.",
    },
    {
        "id": "rds_acu",
        "ns": "AWS/RDS",
        "dims": ["DBInstanceIdentifier"],
        "metric": "ACUUtilization",
        "stat": "Maximum",
        "kind": "high",
        "at": 95,
        "sev": "high",
        "area": "Database",
        "svc": "db",
        "role": "cause",
        "title": "Aurora Serverless {r} is at its maximum capacity",
        "unit": "%",
        "next": "Raise the cluster's maximum ACUs.",
    },
    {
        "id": "ddb_read_throttle",
        "ns": "AWS/DynamoDB",
        "dims": ["TableName"],
        "metric": "ReadThrottleEvents",
        "stat": "Sum",
        "kind": "count",
        "at": 20,
        "sev": "high",
        "area": "DynamoDB",
        "svc": "capacity",
        "role": "cause",
        "title": "DynamoDB table {r} throttles reads",
        "next": "Raise provisioned reads, use on-demand, or look for a hot partition key.",
    },
    {
        "id": "ddb_write_throttle",
        "ns": "AWS/DynamoDB",
        "dims": ["TableName"],
        "metric": "WriteThrottleEvents",
        "stat": "Sum",
        "kind": "count",
        "at": 20,
        "sev": "high",
        "area": "DynamoDB",
        "svc": "capacity",
        "role": "cause",
        "title": "DynamoDB table {r} throttles writes",
        "next": "Raise provisioned writes, use on-demand, or look for a hot partition key.",
    },
    {
        "id": "ddb_errors",
        "ns": "AWS/DynamoDB",
        "dims": ["TableName", "Operation"],
        "metric": "SystemErrors",
        "stat": "Sum",
        "kind": "count",
        "at": 10,
        "sev": "high",
        "area": "DynamoDB",
        "svc": "aws",
        "role": "cause",
        "title": "DynamoDB returns internal errors on {r}",
        "next": "Check the AWS Health Dashboard for DynamoDB.",
    },
    {
        "id": "cache_cpu",
        "ns": "AWS/ElastiCache",
        "dims": ["CacheClusterId"],
        "metric": "EngineCPUUtilization",
        "stat": "Maximum",
        "kind": "high",
        "at": 90,
        "sev": "high",
        "area": "Cache",
        "svc": "db",
        "role": "cause",
        "title": "Cache {r} is out of CPU",
        "unit": "%",
        "next": "Look for expensive commands (KEYS, large sorted sets) or scale up.",
    },
    {
        "id": "cache_mem",
        "ns": "AWS/ElastiCache",
        "dims": ["CacheClusterId"],
        "metric": "DatabaseMemoryUsagePercentage",
        "stat": "Maximum",
        "kind": "high",
        "at": 95,
        "sev": "high",
        "area": "Cache",
        "svc": "db",
        "role": "cause",
        "title": "Cache {r} is out of memory",
        "unit": "%",
        "next": "Evictions follow: scale up or shorten TTLs.",
    },
    {
        "id": "os_red",
        "ns": "AWS/ES",
        "dims": ["DomainName", "ClientId"],
        "metric": "ClusterStatus.red",
        "stat": "Maximum",
        "kind": "high",
        "at": 1,
        "sev": "critical",
        "area": "OpenSearch",
        "svc": "db",
        "role": "cause",
        "title": "OpenSearch domain {r} is red",
        "next": "A primary shard is unassigned: check node health and free storage.",
    },
    {
        "id": "os_blocked",
        "ns": "AWS/ES",
        "dims": ["DomainName", "ClientId"],
        "metric": "ClusterIndexWritesBlocked",
        "stat": "Maximum",
        "kind": "high",
        "at": 1,
        "sev": "critical",
        "area": "OpenSearch",
        "svc": "db",
        "role": "cause",
        "title": "OpenSearch domain {r} blocks writes",
        "next": "Usually low free storage or memory pressure: add storage or nodes.",
    },
    # Compute, storage and network
    {
        "id": "ec2_credit",
        "ns": "AWS/EC2",
        "dims": ["InstanceId"],
        "metric": "CPUCreditBalance",
        "stat": "Minimum",
        "kind": "low",
        "at": 1,
        "sev": "medium",
        "area": "EC2",
        "svc": "capacity",
        "role": "cause",
        "title": "Instance {r} has no CPU credits left and is held to its baseline",
        "next": "Turn on unlimited mode or move to a non-burstable instance type.",
    },
    {
        "id": "ebs_burst",
        "ns": "AWS/EBS",
        "dims": ["VolumeId"],
        "metric": "BurstBalance",
        "stat": "Minimum",
        "kind": "low",
        "at": 5,
        "sev": "medium",
        "area": "EBS",
        "svc": "capacity",
        "role": "cause",
        "title": "Volume {r} has used its burst balance and is slow",
        "unit": "%",
        "next": "Move the volume to gp3 with the IOPS it needs.",
    },
    {
        "id": "ebs_stalled",
        "ns": "AWS/EBS",
        "dims": ["VolumeId"],
        "metric": "VolumeStalledIOCheck",
        "stat": "Maximum",
        "kind": "high",
        "at": 1,
        "sev": "critical",
        "area": "EBS",
        "svc": "aws",
        "role": "cause",
        "title": "Volume {r} has stalled I/O",
        "next": "AWS-side volume impairment: check AWS Health, fail over.",
    },
    {
        "id": "nat_ports",
        "ns": "AWS/NATGateway",
        "dims": ["NatGatewayId"],
        "metric": "ErrorPortAllocation",
        "stat": "Sum",
        "kind": "count",
        "at": 1,
        "sev": "high",
        "area": "Network",
        "svc": "network",
        "role": "cause",
        "title": "NAT gateway {r} has run out of ports",
        "next": "Too many connections to one destination: add NAT gateways, reuse connections, or use VPC endpoints.",
    },
    {
        "id": "nat_drops",
        "ns": "AWS/NATGateway",
        "dims": ["NatGatewayId"],
        "metric": "PacketsDropCount",
        "stat": "Sum",
        "kind": "count",
        "at": 1000,
        "sev": "medium",
        "area": "Network",
        "svc": "network",
        "role": "cause",
        "title": "NAT gateway {r} is dropping packets",
        "next": "Check the NAT gateway's bandwidth and connection limits.",
    },
    {
        "id": "ecs_cpu",
        "ns": "AWS/ECS",
        "dims": ["ClusterName", "ServiceName"],
        "metric": "CPUUtilization",
        "stat": "Maximum",
        "kind": "high",
        "at": 95,
        "sev": "medium",
        "area": "ECS",
        "svc": "capacity",
        "role": "cause",
        "title": "ECS service {r} is out of CPU",
        "unit": "%",
        "next": "Scale out the service or raise the task size.",
    },
    {
        "id": "ecs_mem",
        "ns": "AWS/ECS",
        "dims": ["ClusterName", "ServiceName"],
        "metric": "MemoryUtilization",
        "stat": "Maximum",
        "kind": "high",
        "at": 95,
        "sev": "high",
        "area": "ECS",
        "svc": "capacity",
        "role": "cause",
        "title": "ECS service {r} is out of memory",
        "unit": "%",
        "next": "Tasks will be killed (OutOfMemory): raise the memory or find the leak.",
    },
    {
        "id": "dx_down",
        "ns": "AWS/DX",
        "dims": ["ConnectionId"],
        "metric": "ConnectionState",
        "stat": "Minimum",
        "kind": "low",
        "at": 0,
        "sev": "critical",
        "area": "Network",
        "svc": "network",
        "role": "cause",
        "title": "Direct Connect {r} went down",
        "next": "Check the connection with the provider; traffic fails over to VPN if set up.",
    },
    # Amazon Connect
    {
        "id": "connect_throttled",
        "ns": "AWS/Connect",
        "dims": ["InstanceId", "MetricGroup"],
        "metric": "ThrottledCalls",
        "stat": "Sum",
        "kind": "count",
        "at": 1,
        "sev": "critical",
        "area": "Connect",
        "svc": "capacity",
        "role": "cause",
        "title": "Amazon Connect {r} is throttling calls",
        "next": "Calls are refused: raise the instance's call rate quota.",
    },
    {
        "id": "connect_concurrency",
        "ns": "AWS/Connect",
        "dims": ["InstanceId", "MetricGroup"],
        "metric": "CallsBreachingConcurrencyQuota",
        "stat": "Sum",
        "kind": "count",
        "at": 1,
        "sev": "critical",
        "area": "Connect",
        "svc": "capacity",
        "role": "cause",
        "title": "Amazon Connect {r} is at its concurrent call quota",
        "next": "Raise the concurrent calls quota for the instance.",
    },
    # Edge (read in us-east-1)
    {
        "id": "cf_5xx",
        "ns": "AWS/CloudFront",
        "dims": ["DistributionId", "Region"],
        "metric": "5xxErrorRate",
        "stat": "Average",
        "kind": "high",
        "at": 5,
        "sev": "high",
        "area": "CloudFront",
        "svc": "app",
        "global": True,
        "title": "CloudFront distribution {r} returns 5xx errors",
        "unit": "%",
        "next": "Check the origin behind the distribution.",
    },
]

# CloudTrail events that can break a running service, by name. Changes by AWS services themselves are left out.
RISKY_EVENTS = re.compile(
    r"^(Revoke|Delete|Disable|Deregister|Detach|Disassociate|Terminate|Stop|Reboot|Failover|Replace|Remove|"
    r"ScheduleKeyDeletion|PutFunctionConcurrency|DeleteFunctionConcurrency|UpdateFunctionCode|"
    r"UpdateFunctionConfiguration|PublishVersion|UpdateAlias|ModifyListener|ModifyRule|ModifyTargetGroup|"
    r"ModifyLoadBalancerAttributes|SetSecurityGroups|SetSubnets|CreateDeployment|UpdateStage|UpdateService|"
    r"UpdateAutoScalingGroup|SetDesiredCapacity|PutScalingPolicy|UpdateNodegroupConfig|UpdateNodegroupVersion|"
    r"UpdateClusterVersion|UpdateClusterConfig|ModifyDBInstance|ModifyDBCluster|ModifyDBParameterGroup|"
    r"ModifyDBClusterParameterGroup|ModifyReplicationGroup|ModifyCacheCluster|UpdateTable|PutKeyPolicy|"
    r"PutBucketPolicy|PutBucketAcl|PutPublicAccessBlock|PutRolePolicy|AttachRolePolicy|UpdateAssumeRolePolicy|"
    r"CreatePolicyVersion|SetDefaultPolicyVersion|PutUserPolicy|AttachUserPolicy|PutSecretValue|UpdateSecret|"
    r"RotateSecret|PutParameter|ChangeResourceRecordSets|UpdateDistribution|UpdateWebACL|UpdateRuleGroup|"
    r"UpdateIPSet|AuthorizeSecurityGroupIngress|AuthorizeSecurityGroupEgress|ModifySecurityGroupRules|"
    r"CreateNetworkAclEntry|ReplaceNetworkAclEntry|ReplaceNetworkAclAssociation|CreateRoute|ReplaceRoute|"
    r"ReplaceRouteTableAssociation|ModifyVpcEndpoint|ModifyInstanceAttribute|ModifyNetworkInterfaceAttribute|"
    r"UpdateFirewallRuleGroup|UpdateRuleGroup|ModifyTransitGatewayVpcAttachment|ModifyVpnConnection|"
    r"UpdateEventSourceMapping|PutLifecycleHook|UpdateContainerAgent|RegisterTaskDefinition|UpdateCapacityProvider|"
    r"PutClusterCapacityProviders|UpdateDomainConfig|UpdateBroker|RebootBroker|UpdateApi|UpdateIntegration|"
    r"UpdateRoute|UpdateCertificateOptions|ImportCertificate|SetLoadBalancerPoliciesOfListener|SetVpcEndpoint)"
)
# Changes that cut capacity or access outright; the others are ordinary deployments.
SHARP_EVENTS = re.compile(
    r"^(Revoke|Delete|Disable|Deregister|Detach|Disassociate|Terminate|Stop|ScheduleKeyDeletion|"
    r"PutFunctionConcurrency|ReplaceNetworkAclEntry|ReplaceRoute|SetDesiredCapacity|PutKeyPolicy|"
    r"UpdateAssumeRolePolicy|ChangeResourceRecordSets|ModifyListener|ModifyRule|Failover|Reboot)"
)
# Calls AWS refused for want of capacity, quota or rate, or because the network is full.
REFUSED = re.compile(
    r"(InsufficientInstanceCapacity|InsufficientCapacity|InsufficientFreeAddresses|UnfulfillableCapacity|"
    r"LimitExceeded|QuotaExceeded|VcpuLimitExceeded|InstanceLimitExceeded|Throttl|RequestLimitExceeded|"
    r"TooManyRequests|SubnetOutOfIPAddresses|InsufficientDBInstanceCapacity|InsufficientCacheClusterCapacity|"
    r"KMS\.|KMSAccessDenied|KMSDisabled|KMSInvalidState|KMSNotFound|DisabledException|KeyUnavailable)",
    re.I,
)
ACCESS_DENIED = re.compile(r"(AccessDenied|UnauthorizedOperation|Forbidden)", re.I)
AWS_ACTORS = re.compile(r"\.amazonaws\.com$")


class Ctx:
    """One account's health check: its session, window and what was found."""

    def __init__(self, session: boto3.Session, account_id: str, name: str, start: datetime, end: datetime):
        self.clients = ClientCache(session)
        self.account = account_id
        self.name = name
        self.start, self.end = start, end
        self.hours = (end - start).total_seconds() / 3600
        self.period = period_for(self.hours)
        shift = timedelta(days=max(1, math.ceil(self.hours / 24)))
        self.base_start, self.base_end = start - shift, end - shift
        self.signals: list[dict] = []
        self.changes: list[dict] = []
        self.gaps: list[dict] = []
        self.checked: list[str] = []
        self.unhealthy_tgs: list[tuple[str, dict]] = []
        self.readiness: list[dict] = []  # data sources that are off, so the next check can see more
        self.risks: list[dict] = []  # Outage Risk findings in this account, beside the live faults
        self.scanned_gb = 0.0  # Logs Insights data read, the part of a health check AWS charges for
        self.deep = True  # also run the Outage Risk checks for other issues
        self._lock = threading.Lock()

    def client(self, service: str, region: str):
        return self.clients.client(service, region_name=region)

    def add(self, region: str, **sig) -> None:
        sig.setdefault("role", "symptom")
        sig.setdefault("chronic", False)
        with self._lock:
            self.signals.append({"account": self.account, "account_name": self.name, "region": region, **sig})

    def ready(self, region: str, item: str, why: str, how: str, *, permission: str = "") -> None:
        """Something to turn on: without it this check cannot look there."""
        with self._lock:
            self.readiness.append({"account": self.account, "account_name": self.name, "region": region,
                                   "item": item, "why": why, "how": how, "permission": permission})  # fmt: skip

    def gap(self, region: str, check: str, exc: BaseException) -> None:
        code, msg, hint = describe_exception(exc)
        with self._lock:
            self.gaps.append(
                {
                    "account": self.account,
                    "account_name": self.name,
                    "region": region,
                    "check": check,
                    "code": code,
                    "message": msg[:300],
                    "hint": hint,
                }
            )


def _pages(client, op: str, key: str, cap: int = MAX_ITEMS, **kwargs) -> list:
    out: list = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key) or [])
        if len(out) >= cap:
            return out[:cap]
    return out


# ----------------------------------------------------------------------------------------- regions
def active_regions(session: boto3.Session, wanted: list[str] | None = None) -> list[str]:
    """Enabled regions that show a workload metric in the last 3 hours (us-east-1 always, for global services)."""
    ec2 = session.client("ec2", region_name="us-east-1", config=BOTO_CONFIG)
    enabled = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
    if wanted:
        return [r for r in enabled if r in wanted]

    def busy(region: str) -> bool:
        try:
            cw = session.client("cloudwatch", region_name=region, config=BOTO_CONFIG)
            for i, page in enumerate(cw.get_paginator("list_metrics").paginate(RecentlyActive="PT3H")):
                if any(m["Namespace"] not in BACKGROUND_NS for m in page.get("Metrics") or []):
                    return True
                if i >= 9:
                    return False
        except (ClientError, BotoCoreError):
            return False
        return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        found = dict(zip(enabled, pool.map(busy, enabled), strict=True))
    return [r for r in enabled if found[r] or r == "us-east-1"]


# ------------------------------------------------------------------------------------------ metrics
def _label(dims: list[str]) -> str:
    return "|".join(f"${{PROP('Dim.{d}')}}" for d in dims)


def _search(probe: dict, metric: str, stat: str, period: int) -> str:
    schema = ",".join([probe["ns"], *probe["dims"]])
    return f"SEARCH('{{{schema}}} MetricName=\"{metric}\"', '{stat}', {period})"


def _metric_data(cw, queries: list[dict], start: datetime, end: datetime) -> dict[str, dict[str, list]]:
    """{query id: {label: [(time, value), ...] oldest first}} for SEARCH queries, every page read."""
    out: dict[str, dict[str, list]] = {}
    for at in range(0, len(queries), METRIC_QUERIES):
        kwargs = {
            "MetricDataQueries": queries[at : at + METRIC_QUERIES],
            "StartTime": start,
            "EndTime": end,
            "ScanBy": "TimestampAscending",
        }
        while True:
            resp = with_backoff(cw.get_metric_data, transient=True, **kwargs)
            for r in resp.get("MetricDataResults") or []:
                series = out.setdefault(r["Id"], {}).setdefault(r.get("Label") or "", [])
                series.extend(zip(r.get("Timestamps") or [], r.get("Values") or [], strict=False))
            if not resp.get("NextToken"):
                break
            kwargs["NextToken"] = resp["NextToken"]
    return out


def _queries(probes: list[dict], period: int) -> list[dict]:
    q = []
    for i, p in enumerate(probes):
        q.append(
            {
                "Id": f"n{i}",
                "Expression": _search(p, p["metric"], p["stat"], period),
                "Label": _label(p["dims"]),
                "ReturnData": True,
            }
        )
        if p.get("den"):
            q.append(
                {
                    "Id": f"d{i}",
                    "Expression": _search(p, p["den"], p.get("den_stat", p["stat"]), period),
                    "Label": _label(p["dims"]),
                    "ReturnData": True,
                }
            )
    return q


def _runs(points: list, test, need: int) -> tuple[datetime | None, int, float | None]:
    """(start of the first run of ``need`` periods in a row passing ``test``, periods passing, worst value)."""
    first, streak, hits, worst = None, 0, 0, None
    run_start = None
    for ts, v in points:
        if test(v):
            hits += 1
            worst = v if worst is None else worst
            streak += 1
            run_start = run_start or ts
            if streak >= need and first is None:
                first = run_start
        else:
            streak, run_start = 0, None
    return first, hits, worst


def _rolling_ratio(num: list, den: list, min_den: float) -> tuple[float, datetime | None, int, float, float]:
    """(worst 3-period error ratio, first period at 2% or more, bad periods, total errors, total requests)."""
    d = {ts: v for ts, v in den}
    pairs = [(ts, n, d.get(ts, 0.0)) for ts, n in num]
    worst, onset, bad = 0.0, None, 0
    for i in range(len(pairs)):
        win = pairs[max(0, i - 2) : i + 1]
        n, r = sum(p[1] for p in win), sum(p[2] for p in win)
        if r >= min_den:
            worst = max(worst, n / r)
        ts, n1, r1 = pairs[i]
        if r1 > 0 and n1 / r1 >= 0.02 and n1 >= 2:
            bad += 1
            onset = onset or ts
    return worst, onset, bad, sum(p[1] for p in pairs), sum(p[2] for p in pairs)


def _ratio_sev(r: float) -> str | None:
    return "critical" if r >= 0.5 else "high" if r >= 0.10 else "medium" if r >= 0.02 else None


def _fmt(v: float, unit: str | None) -> str:
    if unit == "bytes":
        return f"{v / 1024**3:.1f} GiB"
    if unit == "ms":
        return f"{v / 1000:.0f} s"
    if unit == "s":
        return f"{v / 60:.0f} min" if v >= 120 else f"{v:.0f} s"
    if unit == "%":
        return f"{v:.0f}%"
    return f"{v:,.0f}"


def judge(probe: dict, now: dict, base: dict, period: int) -> list[dict]:
    """Signals from one probe: ``now`` and ``base`` are {label: points} for the window and a day earlier
    (for ratio and unhealthy probes, {"n": {...}, "d": {...}})."""
    out: list[dict] = []
    kind = probe["kind"]
    name_re = re.compile(probe["name"]) if probe.get("name") else None
    nums = now["n"] if "n" in now else now
    for label, pts in nums.items():
        if not pts or not label:
            continue
        res = label.split("|")[0] if probe["id"].endswith("unhealthy") else label.replace("|", " / ")
        if name_re and not name_re.search(label):
            continue
        sig = None
        if kind == "ratio":
            worst, onset, bad, n, r = _rolling_ratio(pts, now["d"].get(label, []), probe.get("min", 20) * 3)
            sev = _ratio_sev(worst) if n >= probe.get("min", 20) else None
            if sev:
                bw, *_ = _rolling_ratio(base["n"].get(label, []), base["d"].get(label, []), probe.get("min", 20) * 3)
                chronic = bw >= worst * 0.5 and bw >= 0.02
                sig = {
                    "severity": sev,
                    "started": onset,
                    "chronic": chronic,
                    "evidence": f"{n:,.0f} errors in {r:,.0f} requests; worst 3 periods {worst:.0%}"
                    + (f"; a day earlier the worst was {bw:.0%}" if chronic else ""),
                    "ongoing": _still(pts, lambda v: v > 0),
                }
        elif kind == "unhealthy":
            healthy = dict(now["d"].get(label, []))
            first, hits, _ = _runs(pts, lambda v: v >= 1, SUSTAIN)
            if first:
                zero = [ts for ts, v in pts if v >= 1 and healthy.get(ts, 1) < 1]
                bfirst, *_ = _runs(base["n"].get(label, []), lambda v: v >= 1, SUSTAIN)
                worst = max(v for _, v in pts)
                sig = {
                    "severity": "critical" if zero else "high",
                    "started": first,
                    "chronic": bfirst is not None,
                    "evidence": f"up to {worst:.0f} unhealthy for {hits * period // 60} min"
                    + ("; no healthy target at all at times" if zero else "")
                    + ("; also unhealthy a day earlier" if bfirst else ""),
                    "ongoing": _still(pts, lambda v: v >= 1),
                    "tg": label,
                }
        elif kind == "count":
            total = sum(v for _, v in pts)
            if total >= probe["at"]:
                btotal = sum(v for _, v in base.get(label, []))
                mean = btotal / max(len(base.get(label, [])), 1)
                onset = next((ts for ts, v in pts if v > max(0.0, 3 * mean)), None)
                chronic = btotal >= probe["at"] and total < 3 * btotal
                sig = {
                    "severity": probe["sev"],
                    "started": onset,
                    "chronic": chronic,
                    "evidence": f"{total:,.0f} in the window; {btotal:,.0f} in the same hours a day earlier",
                    "ongoing": _still(pts, lambda v: v > 0),
                }
        elif kind in ("high", "low"):
            at = probe["at"]
            test = (lambda v, a=at: v >= a) if kind == "high" else (lambda v, a=at: v <= a)
            first, hits, _ = _runs(pts, test, SUSTAIN if probe["at"] not in (0, 1) or kind == "low" else 2)
            if first:
                vals = [v for _, v in pts]
                peak = max(vals) if kind == "high" else min(vals)
                bfirst, *_ = _runs(base.get(label, []), test, SUSTAIN)
                sig = {
                    "severity": probe["sev"],
                    "started": first,
                    "chronic": bfirst is not None,
                    "evidence": f"{'peak' if kind == 'high' else 'lowest'} {_fmt(peak, probe.get('unit'))} "
                    f"(limit {_fmt(at, probe.get('unit'))}), {hits * period // 60} min past it"
                    + ("; same a day earlier" if bfirst else ""),
                    "ongoing": _still(pts, test),
                }
        elif kind == "spike":
            peak = max(v for _, v in pts)
            bpeak = max((v for _, v in base.get(label, [])), default=0.0)
            if peak >= probe["at"] and peak >= probe["x"] * bpeak:
                bar = max(probe["at"], probe["x"] * bpeak)
                onset = next((ts for ts, v in pts if v >= bar), None)
                sig = {
                    "severity": probe["sev"],
                    "started": onset,
                    "chronic": False,
                    "evidence": f"peak {_fmt(peak, probe.get('unit'))}; a day earlier {_fmt(bpeak, probe.get('unit'))}",
                    "ongoing": _still(pts, lambda v, b=bar: v >= b),
                }
        if sig:
            sig["started"] = _t(sig["started"])
            out.append(
                {
                    "area": probe["area"],
                    "service": probe["svc"],
                    "role": probe.get("role", "symptom"),
                    "title": probe["title"].format(r=res),
                    "resource": res,
                    "next": probe["next"],
                    "source": f"CloudWatch {probe['ns']} {probe['metric']}",
                    "check": probe["id"],
                    **sig,
                }
            )
    return out


def _still(pts: list, test) -> bool:
    return bool(pts) and any(test(v) for _, v in pts[-2:])


def check_metrics(ctx: Ctx, region: str) -> None:
    probes = [p for p in PROBES if not p.get("global") or region == "us-east-1"]
    cw = ctx.client("cloudwatch", region)
    qs = _queries(probes, ctx.period)
    now = _metric_data(cw, qs, ctx.start, ctx.end)
    base = _metric_data(cw, qs, ctx.base_start, ctx.base_end)
    for i, p in enumerate(probes):
        if p.get("den"):
            n = {"n": now.get(f"n{i}", {}), "d": now.get(f"d{i}", {})}
            b = {"n": base.get(f"n{i}", {}), "d": base.get(f"d{i}", {})}
        else:
            n, b = now.get(f"n{i}", {}), base.get(f"n{i}", {})
        for sig in judge(p, n, b, ctx.period):
            tg = sig.pop("tg", None)
            ctx.add(region, **sig)
            if tg:
                ctx.unhealthy_tgs.append((tg, ctx.signals[-1]))


# ------------------------------------------------------------------------------------------ alarms
def check_alarms(ctx: Ctx, region: str) -> None:
    cw = ctx.client("cloudwatch", region)
    for page in cw.get_paginator("describe_alarms").paginate(
        StateValue="ALARM", AlarmTypes=["MetricAlarm", "CompositeAlarm"]
    ):
        for a in (page.get("MetricAlarms") or []) + (page.get("CompositeAlarms") or []):
            if a["AlarmName"].startswith("TargetTracking-"):
                continue  # scaling alarms sit in ALARM by design (scale in when idle): not a fault
            since = a.get("StateUpdatedTimestamp") or a.get("StateTransitionedTimestamp")
            fresh = since is not None and since >= ctx.start
            old = since is not None and since < ctx.start - timedelta(days=2)
            ctx.add(
                region,
                area="Alarm",
                service=_svc_of_ns(a.get("Namespace", "")),
                title=f"Alarm {a['AlarmName']} is firing",
                resource=a["AlarmName"],
                severity="high" if fresh else "low" if old else "medium",
                started=_t(since),
                chronic=old,
                ongoing=True,
                evidence=(a.get("StateReason") or "")[:300],
                next="Read what the alarm watches; its team's runbook usually names the fix.",
                source="CloudWatch alarm",
                check="alarm",
            )


def _svc_of_ns(ns: str) -> str:
    ns = ns.lower()
    if "elb" in ns:
        return "elb"
    if any(k in ns for k in ("rds", "dynamodb", "elasticache", "/es", "docdb")):
        return "db"
    if any(k in ns for k in ("natgateway", "vpn", "/dx", "transitgateway")):
        return "network"
    return "app"


# ------------------------------------------------------------------------------------------ AWS Health
def check_health(ctx: Ctx, regions: list[str]) -> None:
    """AWS's own events for this account: open now, or closed inside the window."""
    h = ctx.client("health", "us-east-1")
    seen = set()
    for status, extra in (("open", {}), ("closed", {"endTimes": [{"from": ctx.start}]})):
        flt = {
            "eventStatusCodes": [status],
            "eventTypeCategories": ["issue", "scheduledChange"],
            **extra,
        }
        for page in h.get_paginator("describe_events").paginate(filter=flt):
            for e in page.get("events") or []:
                if e["arn"] in seen or (e.get("region") or "global") not in {*regions, "global"}:
                    continue
                seen.add(e["arn"])
                start = e.get("startTime")
                if e["eventTypeCategory"] == "scheduledChange" and (
                    "LIFECYCLE" in e["eventTypeCode"]
                    or not start
                    or not ctx.start - timedelta(hours=1) <= start <= ctx.end
                ):
                    continue  # only maintenance that ran in the window, not notices of retirements to come
                issue = e["eventTypeCategory"] == "issue"
                ctx.add(
                    e.get("region") or "global",
                    area="AWS Health",
                    service="aws",
                    role="cause",
                    title=f"AWS reports {e['eventTypeCode'].replace('_', ' ').lower()} ({e['service']})",
                    resource=e["service"],
                    severity=("critical" if status == "open" else "high") if issue else "medium",
                    started=_t(e.get("startTime")),
                    ongoing=status == "open",
                    evidence=f"{e['eventTypeCategory']}, {status}"
                    + (f", ended {_t(e['endTime'])}" if e.get("endTime") else ""),
                    next="Open the event in the AWS Health Dashboard for the affected resources and AWS's guidance.",
                    source="AWS Health",
                    check="health",
                    keywords=[e["service"].lower()],
                )


# ------------------------------------------------------------------------------------------ CloudTrail
def _resource_of(ev: dict, detail: dict) -> str:
    for r in ev.get("Resources") or []:
        if r.get("ResourceName"):
            return r["ResourceName"]
    params = detail.get("requestParameters") or {}
    for k in (
        "groupId",
        "functionName",
        "service",
        "cluster",
        "loadBalancerArn",
        "listenerArn",
        "ruleArn",
        "targetGroupArn",
        "dBInstanceIdentifier",
        "dBClusterIdentifier",
        "tableName",
        "keyId",
        "bucketName",
        "roleName",
        "secretId",
        "name",
        "hostedZoneId",
        "autoScalingGroupName",
        "instanceId",
        "routeTableId",
        "networkAclId",
        "vpcEndpointId",
        "restApiId",
        "id",
        "nodegroupName",
    ):
        v = params.get(k)
        if isinstance(v, str):
            return v
    inst = (params.get("instancesSet") or {}).get("items") or []
    if inst and isinstance(inst[0], dict):
        return inst[0].get("instanceId", "")
    return ""


def _who(detail: dict) -> str:
    u = detail.get("userIdentity") or {}
    arn = u.get("arn") or ""
    if u.get("type") == "AssumedRole" and "/" in arn:
        parts = arn.split("/")
        return f"{parts[1]} ({parts[-1]})" if len(parts) > 2 else parts[-1]
    return arn.split("/")[-1] or u.get("invokedBy") or u.get("type") or ""


def check_trail(ctx: Ctx, region: str) -> None:
    ct = ctx.client("cloudtrail", region)
    refused: dict[tuple, dict] = {}
    denied: dict[tuple, dict] = {}
    pages = ct.get_paginator("lookup_events").paginate(
        LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
        StartTime=ctx.start,
        EndTime=ctx.end,
        PaginationConfig={"MaxItems": TRAIL_PAGES * 50, "PageSize": 50},
    )
    for page in pages:
        for ev in page.get("Events") or []:
            try:
                d = json.loads(ev.get("CloudTrailEvent") or "{}")
            except ValueError:
                continue
            ident = d.get("userIdentity") or {}
            by_aws = ident.get("type") == "AWSService" or AWS_ACTORS.search(ident.get("invokedBy") or "") is not None
            name, source = ev["EventName"], (d.get("eventSource") or "").replace(".amazonaws.com", "")
            err = d.get("errorCode") or ""
            when = ev["EventTime"]
            if err:
                group = refused if REFUSED.search(err) else denied if ACCESS_DENIED.search(err) else None
                if group is not None and not by_aws:
                    k = (err, source, name)
                    g = group.setdefault(
                        k, {"n": 0, "first": when, "last": when, "who": set(), "msg": d.get("errorMessage")}
                    )
                    g["n"] += 1
                    g["first"], g["last"] = min(g["first"], when), max(g["last"], when)
                    g["who"].add(_who(d))
                continue
            if by_aws or not RISKY_EVENTS.match(name):
                continue
            ctx.changes.append(
                {
                    "account": ctx.account,
                    "account_name": ctx.name,
                    "region": region,
                    "time": _t(when),
                    "event": name,
                    "service": source,
                    "who": _who(d),
                    "resource": _resource_of(ev, d),
                    "sharp": bool(SHARP_EVENTS.match(name)),
                }
            )
    for (err, source, name), g in refused.items():
        if g["n"] < 2:
            continue
        cap = bool(re.search(r"Capacity|FreeAddresses|OutOfIP", err, re.I))
        ctx.add(
            region,
            area="Refused by AWS",
            service="capacity" if not err.upper().startswith("KMS") else "security",
            role="cause",
            title=f"AWS refused {source} {name}: {err}",
            resource=f"{source}:{name}",
            severity="high" if cap or g["n"] >= 10 else "medium",
            started=_t(g["first"]),
            ongoing=g["last"] >= ctx.end - timedelta(minutes=30),
            evidence=f"{g['n']} refused calls by {', '.join(sorted(w for w in g['who'] if w))[:120]}; "
            f"{(g['msg'] or '')[:160]}",
            next="Capacity: try another instance type or zone. Quota: raise it. Throttling: back off or raise the "
            "rate quota. KMS: check the key's state and policy.",
            source="CloudTrail",
            check="refused",
        )
    for (err, source, name), g in denied.items():
        if g["n"] < 10:
            continue  # scanners and pipelines are refused now and then; a burst is what matters
        ctx.add(
            region,
            area="Access denied",
            service="security",
            role="cause",
            title=f"{source} {name} is denied ({err})",
            resource=f"{source}:{name}",
            severity="low",
            started=_t(g["first"]),
            ongoing=g["last"] >= ctx.end - timedelta(minutes=30),
            evidence=f"{g['n']} denied calls by {', '.join(sorted(w for w in g['who'] if w))[:120]}",
            next="If a workload is denied, look for a recent IAM, key policy or guardrail (SCP) change.",
            source="CloudTrail",
            check="denied",
        )


# ------------------------------------------------------------------------------------------ compute
def check_ecs(ctx: Ctx, region: str) -> None:
    ecs = ctx.client("ecs", region)
    for cluster in _pages(ecs, "list_clusters", "clusterArns", 50):
        cname = cluster.split("/")[-1]
        arns = _pages(ecs, "list_services", "serviceArns", MAX_ITEMS, cluster=cluster)
        for at in range(0, len(arns), 10):
            for s in ecs.describe_services(cluster=cluster, services=arns[at : at + 10]).get("services") or []:
                name = f"{cname}/{s['serviceName']}"
                if s.get("desiredCount", 0) > 0 and s.get("runningCount", 0) < s["desiredCount"]:
                    ev = next(
                        (e for e in s.get("events") or [] if e.get("createdAt") and e["createdAt"] >= ctx.start), None
                    )
                    ctx.add(
                        region,
                        area="ECS",
                        service="app",
                        title=f"ECS service {name} runs fewer tasks than it needs",
                        resource=name,
                        severity="critical" if s.get("runningCount", 0) == 0 else "high",
                        started=_t(ev["createdAt"]) if ev else None,
                        ongoing=True,
                        evidence=f"{s.get('runningCount', 0)} of {s['desiredCount']} running"
                        + (f"; latest event: {ev['message'][:200]}" if ev else ""),
                        next="Read the service events and the stopped tasks' reasons.",
                        source="ECS",
                        check="ecs_service",
                    )
                for dep in s.get("deployments") or []:
                    if dep.get("rolloutState") == "FAILED" and (dep.get("updatedAt") or ctx.start) >= ctx.start:
                        ctx.add(
                            region,
                            area="ECS",
                            service="deploy",
                            role="cause",
                            title=f"Deployment of ECS service {name} failed",
                            resource=name,
                            severity="high",
                            started=_t(dep.get("createdAt")),
                            ongoing=False,
                            evidence=(dep.get("rolloutStateReason") or "")[:300],
                            next="Roll back to the previous task definition; read why the new tasks stopped.",
                            source="ECS",
                            check="ecs_deploy",
                        )
        stopped = _pages(ecs, "list_tasks", "taskArns", STOPPED_TASKS, cluster=cluster, desiredStatus="STOPPED")
        reasons: dict[str, dict] = {}
        for at in range(0, len(stopped), 100):
            for t in ecs.describe_tasks(cluster=cluster, tasks=stopped[at : at + 100]).get("tasks") or []:
                if not t.get("stoppedAt") or t["stoppedAt"] < ctx.start or t.get("stopCode") == "UserInitiated":
                    continue
                why = t.get("stoppedReason") or ""
                for c in t.get("containers") or []:
                    if c.get("reason"):
                        why = f"{why}; {c['name']}: {c['reason']}"
                    elif c.get("exitCode") not in (None, 0):
                        why = f"{why}; {c['name']} exit code {c['exitCode']}"
                key = re.sub(r"[0-9a-f]{12,}", "…", why)[:200]
                r = reasons.setdefault(key, {"n": 0, "first": t["stoppedAt"], "group": t.get("group", "")})
                r["n"] += 1
                r["first"] = min(r["first"], t["stoppedAt"])
        for why, r in reasons.items():
            if r["n"] < 3 or "Scaling activity" in why:
                continue
            res = f"{cname}/{r['group'].replace('service:', '')}"
            ctx.add(
                region,
                area="ECS",
                service="app",
                role="cause",
                title=f"ECS tasks in {res} keep stopping: {why.split(';')[0][:90]}",
                resource=res,
                severity="high" if r["n"] >= 5 else "medium",
                started=_t(r["first"]),
                ongoing=True,
                evidence=f"{r['n']} tasks stopped: {why}",
                next="OutOfMemory: raise memory. CannotPull: check the image and ECR access. Health check failed: "
                "check the container's health endpoint. Exit code: read the container log.",
                source="ECS",
                check="ecs_stopped",
                keywords=_words(why),
            )


def check_eks(ctx: Ctx, region: str) -> None:
    eks = ctx.client("eks", region)
    for name in _pages(eks, "list_clusters", "clusters", 50):
        c = eks.describe_cluster(name=name)["cluster"]
        issues = (c.get("health") or {}).get("issues") or []
        if c.get("status") not in ("ACTIVE", "UPDATING") or issues:
            ctx.add(
                region,
                area="EKS",
                service="platform",
                role="cause",
                title=f"EKS cluster {name} is not healthy",
                resource=name,
                severity="critical" if c.get("status") == "FAILED" else "high",
                started=None,
                ongoing=True,
                evidence=f"status {c.get('status')}; "
                + "; ".join(f"{i.get('code')}: {i.get('message', '')[:120]}" for i in issues[:3]),
                next="Fix the issue AWS names (often a deleted role, subnet or security group).",
                source="EKS",
                check="eks",
            )
        for ng in _pages(eks, "list_nodegroups", "nodegroups", 100, clusterName=name):
            g = eks.describe_nodegroup(clusterName=name, nodegroupName=ng)["nodegroup"]
            issues = (g.get("health") or {}).get("issues") or []
            if g.get("status") in ("DEGRADED", "CREATE_FAILED", "DELETE_FAILED") or issues:
                ctx.add(
                    region,
                    area="EKS",
                    service="capacity",
                    role="cause",
                    title=f"EKS node group {name}/{ng} is degraded",
                    resource=f"{name}/{ng}",
                    severity="high",
                    started=_t(g.get("modifiedAt")),
                    ongoing=True,
                    evidence=f"status {g.get('status')}; "
                    + "; ".join(f"{i.get('code')}: {i.get('message', '')[:120]}" for i in issues[:3]),
                    next="Typical: no capacity for the instance type, subnet out of addresses, or a launch template "
                    "problem. Fix what AWS names.",
                    source="EKS",
                    check="eks_nodegroup",
                    keywords=[str(i.get("code", "")).lower() for i in issues],
                )


def check_asg(ctx: Ctx, region: str) -> None:
    asg = ctx.client("autoscaling", region)
    groups = _pages(asg, "describe_auto_scaling_groups", "AutoScalingGroups")
    for g in groups:
        live = sum(1 for i in g.get("Instances") or [] if i.get("LifecycleState") == "InService")
        if g.get("DesiredCapacity", 0) > 0 and live < g["DesiredCapacity"]:
            ctx.add(
                region,
                area="Auto Scaling",
                service="capacity",
                title=f"Auto Scaling group {g['AutoScalingGroupName']} is short of instances",
                resource=g["AutoScalingGroupName"],
                severity="high" if live == 0 else "medium",
                started=None,
                ongoing=True,
                evidence=f"{live} of {g['DesiredCapacity']} in service",
                next="Read the group's activity history for why launches fail.",
                source="Auto Scaling",
                check="asg_short",
            )
    failed: dict[tuple, dict] = {}
    for a in _pages(asg, "describe_scaling_activities", "Activities", 500):
        if a.get("StartTime") and a["StartTime"] < ctx.start:
            break
        if a.get("StatusCode") not in ("Failed", "Cancelled"):
            continue
        msg = re.sub(r"[0-9a-f]{8,}|\d+", "#", a.get("StatusMessage") or "")[:200]
        k = (a["AutoScalingGroupName"], msg)
        f = failed.setdefault(k, {"n": 0, "first": a["StartTime"], "msg": a.get("StatusMessage") or ""})
        f["n"] += 1
        f["first"] = min(f["first"], a["StartTime"])
    for (name, _), f in failed.items():
        ctx.add(
            region,
            area="Auto Scaling",
            service="capacity",
            role="cause",
            title=f"Auto Scaling group {name} cannot launch instances",
            resource=name,
            severity="high",
            started=_t(f["first"]),
            ongoing=True,
            evidence=f"{f['n']} failed activities: {f['msg'][:250]}",
            next="InsufficientInstanceCapacity: add instance types or zones. Quota: raise it. Launch template or AMI "
            "missing: fix the template.",
            source="Auto Scaling",
            check="asg_failed",
            keywords=_words(f["msg"]),
        )


def check_ec2(ctx: Ctx, region: str) -> None:
    ec2 = ctx.client("ec2", region)
    for s in _pages(ec2, "describe_instance_status", "InstanceStatuses", MAX_ITEMS, IncludeAllInstances=False):
        sysbad = (s.get("SystemStatus") or {}).get("Status") == "impaired"
        insbad = (s.get("InstanceStatus") or {}).get("Status") == "impaired"
        if sysbad or insbad:
            since = next(
                (
                    d.get("ImpairedSince")
                    for d in ((s.get("SystemStatus") if sysbad else s.get("InstanceStatus")) or {}).get("Details") or []
                    if d.get("ImpairedSince")
                ),
                None,
            )
            ctx.add(
                region,
                area="EC2",
                service="aws" if sysbad else "app",
                role="cause",
                title=f"Instance {s['InstanceId']} fails its {'system' if sysbad else 'instance'} status check",
                resource=s["InstanceId"],
                severity="high",
                started=_t(since),
                ongoing=True,
                evidence="AWS hardware or network behind the instance"
                if sysbad
                else "the operating system is not answering",
                next="System check: stop and start the instance to move it to new hardware. Instance check: read the "
                "console output (out of memory, full disk, kernel).",
                source="EC2",
                check="ec2_status",
            )
        for e in s.get("Events") or []:
            nb = e.get("NotBefore")
            if nb and ctx.start <= nb <= ctx.end and "[Completed]" not in (e.get("Description") or ""):
                ctx.add(
                    region,
                    area="EC2",
                    service="aws",
                    role="cause",
                    title=f"AWS scheduled {e.get('Code')} on instance {s['InstanceId']}",
                    resource=s["InstanceId"],
                    severity="medium",
                    started=_t(nb),
                    ongoing=False,
                    evidence=(e.get("Description") or "")[:200],
                    next="The instance was rebooted or retired by AWS: check it came back.",
                    source="EC2",
                    check="ec2_event",
                )


def check_subnets(ctx: Ctx, region: str) -> None:
    ec2 = ctx.client("ec2", region)
    for s in _pages(ec2, "describe_subnets", "Subnets", 2000):
        free = s.get("AvailableIpAddressCount", 1)
        size = 2 ** (32 - int(s["CidrBlock"].split("/")[1])) - 5
        if free == 0 or (size >= 251 and free < size * 0.02):
            name = next((t["Value"] for t in s.get("Tags") or [] if t["Key"] == "Name"), "")
            ctx.add(
                region,
                area="Network",
                service="network",
                role="cause",
                title=f"Subnet {name or s['SubnetId']} is {'out of' if free == 0 else 'nearly out of'} IP addresses",
                resource=s["SubnetId"],
                severity="high" if free == 0 else "medium",
                started=None,
                ongoing=True,
                evidence=f"{free} of {size} addresses free in {s['CidrBlock']} ({s['AvailabilityZone']})",
                next="New Lambda, EKS pod, ECS task and instance network interfaces fail here: add a subnet or "
                "free addresses.",
                source="EC2",
                check="subnet_ips",
                keywords=["ip", "address", "eni", "subnet"],
            )


def check_lambda(ctx: Ctx, region: str) -> None:
    lam = ctx.client("lambda", region)
    for f in _pages(lam, "list_functions", "Functions", 2000):
        bad = f.get("State") == "Failed" or f.get("LastUpdateStatus") == "Failed"
        if bad:
            ctx.add(
                region,
                area="Lambda",
                service="app",
                role="cause",
                title=f"Lambda function {f['FunctionName']} is in a failed state",
                resource=f["FunctionName"],
                severity="high",
                started=_t(f.get("LastModified")),
                ongoing=True,
                evidence=f"{f.get('StateReasonCode') or f.get('LastUpdateStatusReasonCode')}: "
                f"{(f.get('StateReason') or f.get('LastUpdateStatusReason') or '')[:200]}",
                next="Fix what AWS names (subnet out of addresses, deleted image, missing role or key), then update "
                "the function.",
                source="Lambda",
                check="lambda_state",
            )


def check_target_health(ctx: Ctx, region: str) -> None:
    """Why each unhealthy target group's targets fail (from the metric probe's list)."""
    elb = ctx.client("elbv2", region)
    for tg, sig in [(t, s) for t, s in ctx.unhealthy_tgs if s["region"] == region][:30]:
        arn = f"arn:aws:elasticloadbalancing:{region}:{ctx.account}:{tg}"
        try:
            th = elb.describe_target_health(TargetGroupArn=arn).get("TargetHealthDescriptions") or []
        except ClientError:
            continue
        why = {}
        for t in th:
            h = t.get("TargetHealth") or {}
            if h.get("State") != "healthy":
                k = f"{h.get('State')}: {h.get('Reason', '')} {h.get('Description', '')}".strip()
                why[k] = why.get(k, 0) + 1
        if why:
            sig["evidence"] += "; now: " + "; ".join(
                f"{n} {k}" for k, n in sorted(why.items(), key=lambda x: -x[1])[:3]
            )


def check_rds(ctx: Ctx, region: str) -> None:
    rds = ctx.client("rds", region)
    good = {
        "available",
        "stopped",
        "stopping",
        "starting",
        "backing-up",
        "maintenance",
        "modifying",
        "upgrading",
        "configuring-enhanced-monitoring",
        "configuring-iam-database-auth",
        "configuring-log-exports",
        "storage-optimization",
        "renaming",
        "resetting-master-credentials",
        "creating",
    }
    for db in _pages(rds, "describe_db_instances", "DBInstances"):
        st = db.get("DBInstanceStatus")
        if st not in good:
            ctx.add(
                region,
                area="Database",
                service="db",
                role="cause",
                title=f"Database {db['DBInstanceIdentifier']} is {st}",
                resource=db["DBInstanceIdentifier"],
                severity="critical",
                started=None,
                ongoing=True,
                evidence=f"status {st}",
                next="storage-full: add storage. inaccessible-encryption-credentials: restore the KMS key. "
                "failed or incompatible-*: open a case with AWS and restore from backup if needed.",
                source="RDS",
                check="rds_status",
            )
    minutes = int((ctx.end - ctx.start).total_seconds() // 60) + 1
    bad = re.compile(
        r"(fail|error|storage|restart|reboot|recover|shut|not available|unavailable|crash|full|"
        r"replication.*(stop|error)|out of)",
        re.I,
    )
    for e in _pages(rds, "describe_events", "Events", 500, Duration=min(minutes, 20160)):
        cats = set(e.get("EventCategories") or [])
        msg = e.get("Message") or ""
        if not (cats & {"failover", "failure", "low storage", "recovery", "availability"} or bad.search(msg)):
            continue
        if re.search(r"(Finished|completed|snapshot|backup|Backing up)", msg, re.I) and "failover" not in cats:
            continue
        sharp = bool(cats & {"failover", "failure", "low storage"})
        ctx.add(
            region,
            area="Database",
            service="db",
            role="cause",
            title=f"{e.get('SourceIdentifier')}: {msg[:110]}",
            resource=e.get("SourceIdentifier") or "",
            severity="high" if sharp else "medium",
            started=_t(e.get("Date")),
            ongoing=False,
            evidence=f"RDS event ({', '.join(sorted(cats)) or 'notification'}): {msg[:250]}",
            next="During a failover or restart connections drop for 30 to 120 seconds; applications must reconnect.",
            source="RDS events",
            check="rds_event",
            keywords=["database", "db", "rds", "failover"],
        )


def check_elasticache(ctx: Ctx, region: str) -> None:
    ec = ctx.client("elasticache", region)
    minutes = int((ctx.end - ctx.start).total_seconds() // 60) + 1
    for e in _pages(ec, "describe_events", "Events", 300, Duration=min(minutes, 20160)):
        msg = e.get("Message") or ""
        if not re.search(r"(fail|reboot|replac|recover|error|promot|not available)", msg, re.I):
            continue
        ctx.add(
            region,
            area="Cache",
            service="db",
            role="cause",
            title=f"{e.get('SourceIdentifier')}: {msg[:110]}",
            resource=e.get("SourceIdentifier") or "",
            severity="high" if re.search(r"fail|promot", msg, re.I) else "medium",
            started=_t(e.get("Date")),
            ongoing=False,
            evidence=msg[:250],
            next="Clients must reconnect after a cache failover or node replacement.",
            source="ElastiCache events",
            check="cache_event",
            keywords=["cache", "redis"],
        )


# ------------------------------------------------------------------------------------------ network
def check_network(ctx: Ctx, region: str) -> None:
    ec2 = ctx.client("ec2", region)
    for v in ec2.describe_vpn_connections().get("VpnConnections") or []:
        if v.get("State") != "available":
            continue
        tel = v.get("VgwTelemetry") or []
        down = [t for t in tel if t.get("Status") == "DOWN"]
        if not down:
            continue
        name = next((t["Value"] for t in v.get("Tags") or [] if t["Key"] == "Name"), v["VpnConnectionId"])
        last = max((t["LastStatusChange"] for t in down if t.get("LastStatusChange")), default=None)
        everything = len(down) == len(tel)
        ctx.add(
            region,
            area="Network",
            service="network",
            role="cause",
            title=f"VPN {name}: {'every tunnel is down' if everything else f'{len(down)} of {len(tel)} tunnels down'}",
            resource=v["VpnConnectionId"],
            severity="critical" if everything else ("high" if last and last >= ctx.start else "low"),
            started=_t(last),
            ongoing=True,
            chronic=bool(last and last < ctx.start - timedelta(days=2)),
            evidence="; ".join(f"{t.get('OutsideIpAddress')}: {t.get('StatusMessage') or 'DOWN'}" for t in down),
            next="Check the customer gateway device and its IKE settings; with one tunnel left there is no redundancy.",
            source="EC2 VPN",
            check="vpn",
            keywords=["vpn", "network", "on-prem", "onprem"],
        )
    for a in _pages(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments"):
        if a.get("State") in ("failed", "failing", "rejected", "rejecting", "deleting", "rollingBack"):
            ctx.add(
                region,
                area="Network",
                service="network",
                role="cause",
                title=f"Transit gateway attachment {a['TransitGatewayAttachmentId']} is {a['State']}",
                resource=a["TransitGatewayAttachmentId"],
                severity="critical",
                started=_t(a.get("CreationTime")),
                ongoing=True,
                evidence=f"{a.get('ResourceType')} {a.get('ResourceId')} ({a.get('ResourceOwnerId')})",
                next="Traffic through the transit gateway to this VPC stops: restore the attachment.",
                source="EC2",
                check="tgw",
            )
    dx = ctx.client("directconnect", region)
    for c in dx.describe_connections().get("connections") or []:
        if c.get("connectionState") in ("down", "deleting", "deleted", "rejected", "unknown"):
            ctx.add(
                region,
                area="Network",
                service="network",
                role="cause",
                title=f"Direct Connect {c.get('connectionName')} is {c['connectionState']}",
                resource=c["connectionId"],
                severity="critical",
                started=None,
                ongoing=True,
                evidence=f"{c.get('location')} {c.get('bandwidth')}",
                next="Raise it with the provider and AWS.",
                source="Direct Connect",
                check="dx",
            )
    for vi in dx.describe_virtual_interfaces().get("virtualInterfaces") or []:
        peers = [p for p in vi.get("bgpPeers") or [] if p.get("bgpStatus") == "down"]
        if vi.get("virtualInterfaceState") == "down" or peers:
            ctx.add(
                region,
                area="Network",
                service="network",
                role="cause",
                title=f"Direct Connect interface {vi.get('virtualInterfaceName')} is down",
                resource=vi["virtualInterfaceId"],
                severity="high",
                started=None,
                ongoing=True,
                evidence=f"state {vi.get('virtualInterfaceState')}; {len(peers)} BGP peers down",
                next="Check BGP on the router side.",
                source="Direct Connect",
                check="dx_vif",
            )


def check_certs(ctx: Ctx, region: str) -> None:
    acm = ctx.client("acm", region)
    soon = ctx.end + timedelta(days=3)
    for c in _pages(
        acm,
        "list_certificates",
        "CertificateSummaryList",
        2000,
        Includes={
            "keyTypes": [
                "RSA_1024",
                "RSA_2048",
                "RSA_3072",
                "RSA_4096",
                "EC_prime256v1",
                "EC_secp384r1",
                "EC_secp521r1",
            ]
        },
    ):
        exp = c.get("NotAfter")
        if not c.get("InUse") or not exp or exp > soon:
            continue
        gone = exp <= ctx.end
        old = exp < ctx.start - timedelta(days=2)  # expired long before: real, but not today's outage
        ctx.add(
            region,
            area="Certificate",
            service="security",
            role="cause",
            title=f"Certificate for {c.get('DomainName')} "
            f"{'expired' if gone else 'expires within 3 days'} and is in use",
            resource=c.get("DomainName") or c["CertificateArn"],
            severity="low" if old else "critical" if gone else "medium",
            chronic=old,
            started=_t(exp) if gone else None,
            ongoing=gone,
            evidence=f"not after {_t(exp)}; status {c.get('Status')}",
            next="Renew or import a new certificate and attach it to the listeners and distributions using it.",
            source="ACM",
            check="cert",
            keywords=["tls", "ssl", "certificate", "https", "handshake"],
        )


def check_route53(ctx: Ctx) -> None:
    r53 = ctx.client("route53", "us-east-1")
    for hc in _pages(r53, "list_health_checks", "HealthChecks", HEALTH_CHECKS):
        cfg = hc.get("HealthCheckConfig") or {}
        if cfg.get("Type") in ("CALCULATED", "CLOUDWATCH_METRIC") or cfg.get("Disabled"):
            continue
        obs = r53.get_health_check_status(HealthCheckId=hc["Id"]).get("HealthCheckObservations") or []
        failing = [o for o in obs if not str((o.get("StatusReport") or {}).get("Status", "")).startswith("Success")]
        if obs and len(failing) * 2 > len(obs):
            target = cfg.get("FullyQualifiedDomainName") or cfg.get("IPAddress") or hc["Id"]
            when = max(
                (o["StatusReport"]["CheckedTime"] for o in failing if (o.get("StatusReport") or {}).get("CheckedTime")),
                default=None,
            )
            ctx.add(
                "global",
                area="DNS",
                service="network",
                title=f"Route 53 health check on {target} is failing",
                resource=target,
                severity="high",
                started=None,
                ongoing=True,
                evidence=f"{len(failing)} of {len(obs)} checkers fail"
                + (f"; e.g. {failing[0]['StatusReport'].get('Status', '')[:160]}" if failing else "")
                + (f" (checked {_t(when)})" if when else ""),
                next="DNS failover records using this check now route away from it: check the endpoint.",
                source="Route 53",
                check="r53_health",
            )


# ------------------------------------------------------------------------------------------ quotas
QUOTA_BATCH = 100  # SERVICE_QUOTA functions GetMetricData allows in one call


# The Service dimension of AWS/Usage metrics, to the Service Quotas code whose default list names the metric.
USAGE_CODES = {
    "EC2": ["ec2", "vpc"], "EBSDirect": ["ebs"], "Elastic Load Balancing": ["elasticloadbalancing"],
    "AutoScaling": ["autoscaling"], "KMS": ["kms"], "CloudFormation": ["cloudformation"], "Logs": ["logs"],
    "RDS": ["rds"], "DynamoDB": ["dynamodb"], "Connect": ["connect"], "ElastiCache": ["elasticache"],
    "Kinesis Data Streams": ["kinesis"], "SNS": ["sns"], "Fargate": ["fargate"], "AWS Step Functions": ["states"],
    "EventBridge": ["events"], "ECR": ["ecr"], "AWS WAF": ["wafv2"], "Cognito User Pool": ["cognito-idp"],
    "SSM": ["ssm"], "Athena": ["athena"], "SageMaker": ["sagemaker"], "SES": ["ses"], "EMR": ["elasticmapreduce"],
    "AppSync": ["appsync"],
}  # fmt: skip


def _quota_metrics(ctx: Ctx, region: str, services: set[str]) -> dict[tuple, dict]:
    """{(metric name, dimensions): the quota} for the AWS/Usage metrics of ``services`` that have a quota, from
    the default quota lists (the same in every account, read once per region for the whole process)."""
    from .outage import _default_quotas

    sq = ctx.client("service-quotas", region)
    out: dict[tuple, dict] = {}
    for code in sorted({c for s in services for c in USAGE_CODES.get(s, [])}):
        try:
            quotas = _default_quotas(sq, region, code)
        except ClientError:
            continue
        for q in quotas:
            m = q.get("UsageMetric") or {}
            if m.get("MetricNamespace") == "AWS/Usage" and m.get("MetricName"):
                out[(m["MetricName"], tuple(sorted((m.get("MetricDimensions") or {}).items())))] = q
    return out


def check_quotas(ctx: Ctx, region: str) -> None:
    """Quotas in use: the peak of each AWS/Usage metric in the window against its applied value (SERVICE_QUOTA).
    Only metrics a default quota names are asked for; SERVICE_QUOTA fails the whole call on any other."""
    cw = ctx.client("cloudwatch", region)
    metrics = _pages(cw, "list_metrics", "Metrics", 3000, Namespace="AWS/Usage", RecentlyActive="PT3H")
    services = {d["Value"] for m in metrics for d in m.get("Dimensions") or [] if d["Name"] == "Service"}
    known = _quota_metrics(ctx, region, services)
    picked = []
    for m in metrics:
        dims = {d["Name"]: d["Value"] for d in m.get("Dimensions") or []}
        q = known.get((m["MetricName"], tuple(sorted(dims.items()))))
        if q:
            picked.append((m, dims, q))
    for at in range(0, len(picked), QUOTA_BATCH):
        batch = picked[at : at + QUOTA_BATCH]
        for _ in range(5):  # a metric AWS no longer ties to a quota fails the call: drop it, ask again
            try:
                _quota_batch(ctx, cw, region, batch)
                break
            except ClientError as exc:
                bad = re.search(r"expression 'r(\d+)'", str(exc))
                if describe_exception(exc)[0] != "ValidationError" or not bad:
                    raise
                batch = [x for i, x in enumerate(batch) if i != int(bad.group(1))]


def _quota_batch(ctx: Ctx, cw, region: str, batch: list) -> None:
    queries = []
    for i, (m, _, q) in enumerate(batch):
        stat = (q.get("UsageMetric") or {}).get("MetricStatisticRecommendation") or "Maximum"
        queries += [
            {"Id": f"m{i}", "ReturnData": False, "MetricStat": {"Metric": m, "Period": ctx.period, "Stat": stat}},
            {"Id": f"q{i}", "ReturnData": False, "Expression": f"SERVICE_QUOTA(m{i})"},
            {"Id": f"r{i}", "ReturnData": True, "Expression": f"100*m{i}/q{i}"},
        ]
    resp = {}
    kwargs = {"MetricDataQueries": queries, "StartTime": ctx.start, "EndTime": ctx.end, "ScanBy": "TimestampAscending"}
    results: dict[str, list] = {}
    while True:
        resp = with_backoff(cw.get_metric_data, transient=True, **kwargs)
        for r in resp.get("MetricDataResults") or []:
            results.setdefault(r["Id"], []).extend(zip(r.get("Timestamps") or [], r.get("Values") or [], strict=False))
        if not resp.get("NextToken"):
            break
        kwargs["NextToken"] = resp["NextToken"]
    for rid, vals in results.items():
        vals = [(t, v) for t, v in vals if not (math.isinf(v) or math.isnan(v))]
        if not vals:
            continue
        peak_t, peak = max(vals, key=lambda x: x[1])
        if peak < 90:
            continue
        _, dims, q = batch[int(rid[1:])]
        what = q.get("QuotaName") or f"{dims.get('Service')} {dims.get('Resource')}"
        first = next(ts for ts, v in vals if v >= 90)
        ctx.add(
            region,
            area="Quota",
            service="capacity",
            role="cause",
            title=f"{q.get('ServiceName') or dims.get('Service')}: {what} is "
            f"{'at' if peak >= 100 else 'close to'} its quota",
            resource=what,
            severity="critical" if peak >= 100 else "high",
            started=_t(first),
            ongoing=vals[-1][1] >= 90,
            evidence=f"peak {peak:.0f}% of the applied quota at {_t(peak_t)}"
            + (" (requests per period against the rate quota)" if dims.get("Type") == "API" else ""),
            next="Request a quota increase in Service Quotas; new resources or calls are refused at 100%.",
            source="CloudWatch AWS/Usage",
            check="quota",
            keywords=["quota", "limit", (dims.get("Service") or "").lower()],
        )


def _words(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z][a-z0-9]{2,}", (text or "").lower())][:20]


# ------------------------------------------------------------------------------- deep dive: logs
INSIGHTS_WAIT = 150  # seconds one Logs Insights query may run
INSIGHTS_GROUPS = 50  # log groups one query may read (the AWS limit)
LOG_GROUPS = 20  # busiest application log groups searched for an error spike per region
SCAN_CAP_GB = 60.0  # Logs Insights data one check may read in a region (about US$0.30 at US$0.005 a GB)
# Words that mark a failure, and an HTTP 5xx status. Not a bare 5xx number: ids and counts match that.
ERROR_RE = (
    r"/(?i)(\berror\b|exception|\bfatal\b|\bpanic\b|timed out|timeout|connection refused|unavailable|"
    r"status(code)?\W{0,4}5\d\d\b)/"
)


def _redact(text: str) -> str:
    """A log line fit for a report: long numbers (ids, account and card numbers) and emails masked."""
    text = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "<email>", text or "")
    return re.sub(r"\d{6,}", "<n>", text).strip()[:140]


NOT_APP_LOGS = re.compile(r"(flow|vpc|resolver|querylog|query-log|cloudtrail|aws-waf-logs|/aws/route53)", re.I)
DEFAULT_FLOW_FORMAT = (
    "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} "
    "${packets} ${bytes} ${start} ${end} ${action} ${log-status}"
)


def _group_name(arn_or_name: str) -> str:
    """A log group's name from its ARN (arn:aws:logs:r:a:log-group:NAME[:*]) or the name itself."""
    if ":log-group:" in arn_or_name:
        return arn_or_name.split(":log-group:", 1)[1].removesuffix(":*")
    return arn_or_name


def _ingest_gb(ctx: Ctx, region: str, start: datetime, end: datetime) -> dict[str, float]:
    """{log group: GB ingested between start and end}, from AWS/Logs IncomingBytes: what a query will read."""
    secs = max(60, int((end - start).total_seconds()) // 60 * 60)
    q = [{"Id": "b", "Expression": f"SEARCH('{{AWS/Logs,LogGroupName}} MetricName=\"IncomingBytes\"', 'Sum', {secs})",
          "ReturnData": True}]  # fmt: skip
    got = _metric_data(ctx.client("cloudwatch", region), q, start, end).get("b") or {}
    return {label: sum(v for _t, v in pts) / 1e9 for label, pts in got.items()}


def _insights(ctx: Ctx, region: str, groups: list[str], query: str, start: datetime, end: datetime, gb: float = 0):
    """Rows of one Logs Insights query as dicts. Raises TimeoutError when AWS takes too long."""
    logs = ctx.client("logs", region)
    qid = with_backoff(
        logs.start_query, transient=True, logGroupNames=groups[:INSIGHTS_GROUPS], queryString=query,
        startTime=int(start.timestamp()), endTime=int(end.timestamp()), limit=1000,
    )["queryId"]  # fmt: skip
    with ctx._lock:
        ctx.scanned_gb += gb
    waited = 0.0
    while waited < INSIGHTS_WAIT:
        resp = logs.get_query_results(queryId=qid)
        if resp.get("status") in ("Complete", "Failed", "Cancelled", "Timeout"):
            if resp.get("status") != "Complete":
                raise TimeoutError(f"Logs Insights query {resp.get('status')}")
            return [{c["field"]: c.get("value") for c in row} for row in resp.get("results") or []]
        time.sleep(1.5)
        waited += 1.5
    with contextlib.suppress(ClientError):
        logs.stop_query(queryId=qid)
    raise TimeoutError(f"Logs Insights query ran over {INSIGHTS_WAIT} s")


def _bin(ctx: Ctx) -> str:
    return f"{max(1, ctx.period // 60)}m"


def _first_bin(rows: list[dict], key: str, over: float) -> datetime | None:
    """The earliest bin whose ``key`` count passes ``over``."""
    hits = sorted(r["bin"] for r in rows if r.get("bin") and float(r.get(key) or 0) > over)
    return (
        _parse(hits[0].replace(" ", "T") + ("" if "+" in hits[0] or hits[0].endswith("Z") else "Z")) if hits else None
    )


def _spike(now: float, base: float, floor: float, factor: float) -> bool:
    return now >= floor and now >= factor * (base + floor / 10)


def _bins(ctx: Ctx) -> int:
    return max(1, int(ctx.hours * 3600 // ctx.period))


def _fit(groups: dict[str, float], cap: float) -> tuple[list[str], list[str]]:
    """(groups to read, groups too big), the smallest first, so most groups fit under the cap."""
    keep, big, total = [], [], 0.0
    for g, size in sorted(groups.items(), key=lambda kv: kv[1]):
        if total + size * 2 > cap:  # the window and the day-before baseline are both read
            big.append(g)
        else:
            keep.append(g)
            total += size * 2
    return keep, big


def check_flowlogs(ctx: Ctx, region: str) -> None:
    """VPC flow logs: rejected traffic now against the same window a day earlier. Turned off means a readiness item."""
    ec2 = ctx.client("ec2", region)
    vpcs = {v["VpcId"]: v for v in _pages(ec2, "describe_vpcs", "Vpcs")}
    if not vpcs:
        return
    subnet_vpc = {s["SubnetId"]: s["VpcId"] for s in _pages(ec2, "describe_subnets", "Subnets")}
    flows = [f for f in _pages(ec2, "describe_flow_logs", "FlowLogs") if f.get("FlowLogStatus", "ACTIVE") == "ACTIVE"]
    covered, to_cw, to_s3 = set(), {}, set()
    for f in flows:
        vpc = f.get("ResourceId") if f.get("ResourceId", "").startswith("vpc-") else subnet_vpc.get(f.get("ResourceId"))
        if not vpc:
            continue
        covered.add(vpc)
        if f.get("LogDestinationType", "cloud-watch-logs") == "cloud-watch-logs" and f.get("LogGroupName"):
            to_cw.setdefault(f["LogGroupName"], {"vpcs": set(), "format": f.get("LogFormat") or DEFAULT_FLOW_FORMAT})
            to_cw[f["LogGroupName"]]["vpcs"].add(vpc)
        else:
            to_s3.add(vpc)
    off = sorted(v for v, d in vpcs.items() if v not in covered and not d.get("IsDefault"))
    if off:
        ctx.ready(region, f"VPC flow logs are off in {len(off)} VPC{'s' if len(off) > 1 else ''}",
                  f"Rejected and dropped traffic in {', '.join(off[:6])}{' and more' if len(off) > 6 else ''} "
                  "cannot be seen.",
                  "Create a flow log per VPC to CloudWatch Logs (EC2 > VPC > Flow logs; about US$0.50 a GB).",
                  permission="ec2:CreateFlowLogs, logs:CreateLogGroup, iam:PassRole")  # fmt: skip
    only_s3 = sorted(to_s3 - {v for g in to_cw.values() for v in g["vpcs"]})
    if only_s3:
        ctx.ready(region, f"Flow logs of {len(only_s3)} VPC{'s' if len(only_s3) > 1 else ''} go to S3 only",
                  "A health check reads flow logs through CloudWatch Logs Insights, not from S3.",
                  "Add a second flow log to CloudWatch Logs during the incident, or query the S3 copy "
                  "with Athena.")  # fmt: skip
    if not to_cw:
        return
    sizes = _ingest_gb(ctx, region, ctx.start, ctx.end)
    keep, big = _fit({g: sizes.get(g, 0.0) for g in to_cw}, SCAN_CAP_GB)
    if big:
        ctx.ready(region, f"Flow log group{'s' if len(big) > 1 else ''} too large to search in this window",
                  f"{', '.join(big[:3])} hold more than {SCAN_CAP_GB:.0f} GB for the window and the day before.",
                  "Choose a shorter window, or search the group by hand in Logs Insights.")  # fmt: skip
    if not keep:
        return
    gb = sum(sizes.get(g, 0.0) for g in keep)
    q = f"filter @message like / REJECT / | stats count(*) as n by @log, bin({_bin(ctx)}) as bin"
    now_rows = _insights(ctx, region, keep, q, ctx.start, ctx.end, gb)
    base_rows = _insights(ctx, region, keep, "filter @message like / REJECT / | stats count(*) as n by @log",
                          ctx.base_start, ctx.base_end, gb)  # fmt: skip
    base = {_group_name(r["@log"].split(":", 1)[-1]): float(r.get("n") or 0) for r in base_rows if r.get("@log")}
    for g in keep:
        rows = [r for r in now_rows if _group_name((r.get("@log") or "").split(":", 1)[-1]) == g]
        now, before = sum(float(r.get("n") or 0) for r in rows), base.get(g, 0.0)
        if not _spike(now, before, 500, 3):
            continue
        started = _first_bin(rows, "n", max(20.0, 3 * before / _bins(ctx)))
        top = ""
        if to_cw[g]["format"].strip() == DEFAULT_FLOW_FORMAT:
            tq = ('filter @message like / REJECT / | parse @message "* * * * * * * * * * * * * *" as v, a, eni, src, '
                  "dst, sport, dport, proto, pk, by, st, en, act, ls | stats count(*) as n by dst, dport "
                  "| sort n desc | limit 5")  # fmt: skip
            with contextlib.suppress(Exception):
                hits = _insights(ctx, region, [g], tq, ctx.start, ctx.end, sizes.get(g, 0.0))
                top = "; most refused: " + ", ".join(f"{h.get('dst')}:{h.get('dport')} ×{int(float(h['n']))}"
                                                     for h in hits[:3] if h.get("n"))  # fmt: skip
        vpcs_txt = ", ".join(sorted(to_cw[g]["vpcs"]))
        ctx.add(
            region,
            area="Network",
            service="network",
            title=f"Rejected traffic jumped in {vpcs_txt}",
            resource=vpcs_txt,
            severity="high" if now >= 10 * (before + 50) else "medium",
            started=_t(started),
            ongoing=True,
            evidence=f"{int(now):,} rejected flows in the window against {int(before):,} the day before{top}",
            next="A security group, network ACL or firewall change usually explains a jump in refusals: compare "
            "the refused ports with recent changes.",
            source="VPC flow logs",
            check="flow_rejects",
        )


def check_dns(ctx: Ctx, region: str) -> None:
    """Route 53 Resolver endpoints, and SERVFAIL, NXDOMAIN and DNS Firewall blocks in the query logs."""
    r = ctx.client("route53resolver", region)
    for ep in _pages(r, "list_resolver_endpoints", "ResolverEndpoints"):
        name = ep.get("Name") or ep["Id"]
        kind = (ep.get("Direction") or "").lower()
        st = ep.get("Status", "")
        if st in ("ACTION_NEEDED", "AUTO_RECOVERING"):
            ctx.add(region, area="DNS", service="network", title=f"Resolver {kind} endpoint {name} is {st.lower()}",
                    resource=name, severity="high", started=None, ongoing=True,
                    evidence=(ep.get("StatusMessage") or "")[:300],
                    next="Lookups through this endpoint fail or slow down: check its subnets, security group and "
                    "the on premises DNS servers it forwards to.",
                    source="Route 53 Resolver", check="resolver_endpoint")  # fmt: skip
            continue
        if st != "OPERATIONAL":
            continue
        ips = _pages(r, "list_resolver_endpoint_ip_addresses", "IpAddresses", ResolverEndpointId=ep["Id"])
        bad = [i for i in ips if i.get("Status") not in ("ATTACHED", "CREATING", "UPDATING", "ATTACHING")]
        if bad:
            ctx.add(region, area="DNS", service="network",
                    title=f"{len(bad)} of {len(ips)} addresses of resolver endpoint {name} are not attached",
                    resource=name, severity="medium", started=None, ongoing=True,
                    evidence="; ".join(f"{i.get('Ip')} {i.get('Status')}: {i.get('StatusMessage', '')}"
                                       for i in bad[:3])[:300],
                    next="The endpoint runs with less capacity and fewer zones: replace the failed addresses.",
                    source="Route 53 Resolver", check="resolver_ip")  # fmt: skip
    configs = _pages(r, "list_resolver_query_log_configs", "ResolverQueryLogConfigs")
    assoc = _pages(r, "list_resolver_query_log_config_associations", "ResolverQueryLogConfigAssociations")
    logged = {a.get("ResourceId") for a in assoc if a.get("Status") in ("ACTIVE", "CREATING")}
    ec2 = ctx.client("ec2", region)
    vpcs = [v["VpcId"] for v in _pages(ec2, "describe_vpcs", "Vpcs") if not v.get("IsDefault")]
    off = [v for v in vpcs if v not in logged]
    if off:
        ctx.ready(region, f"DNS query logging is off in {len(off)} VPC{'s' if len(off) > 1 else ''}",
                  "Failed lookups (SERVFAIL, NXDOMAIN) and DNS Firewall blocks cannot be seen.",
                  "Route 53 > Resolver > Query logging: log these VPCs to CloudWatch Logs.",
                  permission="route53resolver:CreateResolverQueryLogConfig, "
                  "route53resolver:AssociateResolverQueryLogConfig, logs:CreateLogDelivery")  # fmt: skip
    groups = sorted({_group_name(c["DestinationArn"]) for c in configs
                     if ":logs:" in (c.get("DestinationArn") or "") and c.get("Status") == "CREATED"})  # fmt: skip
    if not groups:
        return
    sizes = _ingest_gb(ctx, region, ctx.start, ctx.end)
    keep, big = _fit({g: sizes.get(g, 0.0) for g in groups}, SCAN_CAP_GB)
    if big:
        ctx.ready(region, "DNS query logs too large to search in this window",
                  f"{', '.join(big[:3])} hold more than {SCAN_CAP_GB:.0f} GB for the window and the day before.",
                  "Choose a shorter window, or search the group by hand in Logs Insights.")  # fmt: skip
    if not keep:
        return
    gb = sum(sizes.get(g, 0.0) for g in keep)
    q = f"stats count(*) as n by rcode, firewall_rule_action, bin({_bin(ctx)}) as bin"
    now_rows = _insights(ctx, region, keep, q, ctx.start, ctx.end, gb)
    base_rows = _insights(ctx, region, keep, "stats count(*) as n by rcode, firewall_rule_action",
                          ctx.base_start, ctx.base_end, gb)  # fmt: skip

    def total(rows, test):
        return sum(float(x.get("n") or 0) for x in rows if test(x))

    looks = [
        ("SERVFAIL", lambda x: x.get("rcode") == "SERVFAIL", 200, 3, "high",
         "Lookups are failing (SERVFAIL)", "The resolver could not get an answer: check forwarding rules, resolver "
         "endpoints and the DNS servers they forward to.", 'filter rcode = "SERVFAIL"'),
        ("NXDOMAIN", lambda x: x.get("rcode") == "NXDOMAIN", 1000, 5, "medium",
         "Lookups for names that do not exist jumped (NXDOMAIN)", "A deleted record, a wrong endpoint name in a "
         "release, or a private hosted zone no longer associated with the VPC.", 'filter rcode = "NXDOMAIN"'),
        ("BLOCK", lambda x: x.get("firewall_rule_action") == "BLOCK", 100, 3, "medium",
         "DNS Firewall is blocking more lookups", "A new block list entry or rule can stop real traffic: read the "
         "names below against the rule groups.", 'filter firewall_rule_action = "BLOCK"'),
    ]  # fmt: skip
    for key, test, floor, factor, sev, title, nxt, flt in looks:
        now, before = total(now_rows, test), total(base_rows, test)
        if not _spike(now, before, floor, factor):
            continue
        per_bin = [{"bin": x["bin"], "n": x["n"]} for x in now_rows if test(x)]
        merged: dict[str, float] = {}
        for x in per_bin:
            merged[x["bin"]] = merged.get(x["bin"], 0.0) + float(x["n"] or 0)
        started = _first_bin([{"bin": b, "n": n} for b, n in merged.items()], "n",
                             max(5.0, factor * before / _bins(ctx)))  # fmt: skip
        names = ""
        with contextlib.suppress(Exception):
            hits = _insights(ctx, region, keep, f"{flt} | stats count(*) as n by query_name | sort n desc | limit 5",
                             ctx.start, ctx.end, gb)  # fmt: skip
            names = "; most: " + ", ".join(f"{h.get('query_name')} ×{int(float(h['n']))}" for h in hits[:4])
        ctx.add(region, area="DNS", service="network", title=title, resource=", ".join(keep[:2]),
                severity=sev if now < 10 * (before + floor / 10) or sev == "high" else "high",
                started=_t(started), ongoing=True,
                evidence=f"{int(now):,} {key} answers in the window against {int(before):,} the day before{names}",
                next=nxt, source="Route 53 Resolver query logs", check=f"dns_{key.lower()}")  # fmt: skip


def check_log_errors(ctx: Ctx, region: str) -> None:
    """Error lines in the busiest application log groups, now against the same window a day earlier."""
    sizes = {
        g: gb for g, gb in _ingest_gb(ctx, region, ctx.start, ctx.end).items() if gb > 0 and not NOT_APP_LOGS.search(g)
    }
    busiest = dict(sorted(sizes.items(), key=lambda kv: -kv[1])[: LOG_GROUPS * 2])
    keep, _big = _fit(busiest, SCAN_CAP_GB)
    keep = sorted(keep, key=lambda g: -sizes[g])[:LOG_GROUPS]
    if not keep:
        return
    gb = sum(sizes[g] for g in keep)
    now_rows = _insights(ctx, region, keep, f"filter @message like {ERROR_RE} | stats count(*) as n by @log, "
                         f"bin({_bin(ctx)}) as bin", ctx.start, ctx.end, gb)  # fmt: skip
    base_rows = _insights(ctx, region, keep, f"filter @message like {ERROR_RE} | stats count(*) as n by @log",
                          ctx.base_start, ctx.base_end, gb)  # fmt: skip

    def name(r):
        return _group_name((r.get("@log") or "").split(":", 1)[-1])

    base = {name(r): float(r.get("n") or 0) for r in base_rows}
    found = []
    for g in keep:
        rows = [r for r in now_rows if name(r) == g]
        now, before = sum(float(r.get("n") or 0) for r in rows), base.get(g, 0.0)
        if _spike(now, before, 100, 4):
            found.append((g, rows, now, before))
    for g, rows, now, before in sorted(found, key=lambda x: -(x[2] / (x[3] + 25)))[:8]:
        sample = ""
        with contextlib.suppress(Exception):
            hits = _insights(ctx, region, [g], f"fields substr(@message, 0, 160) as msg | filter @message like "
                             f"{ERROR_RE} | stats count(*) as n by msg | sort n desc | limit 3",
                             ctx.start, ctx.end, sizes[g])  # fmt: skip
            sample = "; most common: " + " | ".join(f"{_redact(h.get('msg') or '')} ×{int(float(h['n']))}"
                                                    for h in hits[:2])  # fmt: skip
        ctx.add(
            region,
            area="Logs",
            service="app",
            title=f"Errors jumped in log group {g}",
            resource=g,
            severity="high" if now >= 20 * (before + 25) else "medium",
            started=_t(_first_bin(rows, "n", max(5.0, 4 * before / _bins(ctx)))),
            ongoing=True,
            evidence=(f"{int(now):,} error lines in the window against {int(before):,} the day before{sample}")[:500],
            next="Read the first errors after the start time: they usually name the dependency that failed.",
            source="CloudWatch Logs Insights",
            check="log_errors",
        )


def check_risks(ctx: Ctx, regions: list[str]) -> None:
    """The Outage Risk checks for this account: quotas near their limit, single points of failure, hot
    databases. Not the live fault, but other issues the deep dive should name."""
    from .. import outage as outage_report
    from .outage import account_checks

    raw, _issues = account_checks(ctx.clients.session, ctx.account, regions)
    if not raw:
        return
    scan = {"accounts": [{"id": ctx.account, "name": ctx.name, "status": "ACTIVE", "ou_path": "-"}],
            "outage": {"accounts": {ctx.account: raw}}}  # fmt: skip
    # An account in an outage is treated as production: its name is its own production pattern.
    report = outage_report.build_outage(
        scan, a=outage_report.OutageAnswers(production_patterns=(ctx.name or ctx.account).replace(",", " ")[:200])
    )
    keys = ("rule", "title", "res", "region", "severity", "why", "note", "service_label", "area")
    with ctx._lock:
        ctx.risks.extend(
            {"account": ctx.account, "account_name": ctx.name, **{k: f.get(k) for k in keys}}
            for f in report.get("findings") or []
            if f.get("severity") in ("critical", "high", "medium")
        )


# ------------------------------------------------------------------------------------------ runner
def chain_metrics(ctx: Ctx, region: str) -> None:
    check_metrics(ctx, region)
    run_check(ctx, region, "targets", check_target_health)


REGION_CHECKS = [  # the slowest first
    ("quotas", check_quotas),
    ("logs", check_log_errors),
    ("flowlogs", check_flowlogs),
    ("dns", check_dns),
    ("cloudtrail", check_trail),
    ("metrics", chain_metrics),
    ("alarms", check_alarms),
    ("ecs", check_ecs),
    ("eks", check_eks),
    ("autoscaling", check_asg),
    ("ec2", check_ec2),
    ("subnets", check_subnets),
    ("lambda", check_lambda),
    ("rds", check_rds),
    ("elasticache", check_elasticache),
    ("network", check_network),
    ("certificates", check_certs),
]
CHECK_LABELS = {
    "metrics": "error, saturation and health metrics",
    "alarms": "CloudWatch alarms",
    "cloudtrail": "changes and refused calls (CloudTrail)",
    "ecs": "ECS services and stopped tasks",
    "eks": "EKS clusters and node groups",
    "autoscaling": "Auto Scaling activity",
    "ec2": "EC2 status checks and scheduled events",
    "subnets": "subnet IP addresses",
    "lambda": "Lambda function state",
    "rds": "RDS status and events",
    "elasticache": "ElastiCache events",
    "network": "VPN, Direct Connect and transit gateway",
    "certificates": "certificates in use",
    "quotas": "quotas in use",
    "health": "AWS Health events",
    "route53": "Route 53 health checks",
    "targets": "target health reasons",
    "logs": "error spikes in application logs (Logs Insights)",
    "flowlogs": "rejected traffic in VPC flow logs",
    "dns": "Route 53 Resolver and DNS query logs",
    "risks": "other risks (the Outage Risk checks)",
}


def run_check(ctx: Ctx, region: str, name: str, fn) -> None:
    try:
        fn(ctx, region) if region != "global" else fn(ctx)
    except (ClientError, BotoCoreError) as exc:
        code = describe_exception(exc)[0]
        if code in _NOT_HERE and name not in ("health",):
            return
        log.warning("health check %s %s %s failed: %s", ctx.account, region, name, code)
        ctx.gap(region, CHECK_LABELS.get(name, name), exc)
        if code == "SubscriptionRequiredException":
            ctx.gaps[-1]["message"] = (
                "The AWS Health API needs a Business, Enterprise On-Ramp or Enterprise support plan."
            )
            ctx.gaps[-1]["hint"] = (
                "Open the AWS Health Dashboard in the console for this account to see AWS's own events."
            )
    except Exception as exc:  # one odd answer must not lose the rest
        log.exception("health check %s %s %s failed", ctx.account, region, name)
        ctx.gap(region, CHECK_LABELS.get(name, name), exc)


def account_tasks(ctx: Ctx, regions: list[str]) -> list[tuple]:
    """(region, name, fn) for one account; target health runs after the metrics, so it is chained there."""
    tasks = [(r, n, f) for r in regions for n, f in REGION_CHECKS]
    tasks.append(("us-east-1", "health", lambda c, _r, regs=regions: check_health(c, regs)))
    tasks.append(("global", "route53", check_route53))
    if ctx.deep:
        tasks.insert(0, ("global", "risks", lambda c, regs=regions: check_risks(c, regs)))
    return tasks


def result(ctx: Ctx, regions: list[str]) -> dict:
    return {
        "account": ctx.account,
        "name": ctx.name,
        "regions": regions,
        "signals": ctx.signals,
        "changes": sorted(ctx.changes, key=lambda c: c["time"], reverse=True),
        "gaps": ctx.gaps,
        "readiness": ctx.readiness,
        "risks": ctx.risks,
        "scanned_gb": round(ctx.scanned_gb, 2),
    }
