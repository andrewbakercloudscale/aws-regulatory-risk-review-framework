"""The per-service reviews against AWS's own API models, with data in the answers.

No AWS account here can hold every service, so a wrong call or a misnamed field would only show on a real
scan: as a read that silently finds nothing. Each call's parameters are checked against botocore's model,
and each field read from an answer must exist in it.
"""

import re
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.validate import ParamValidator

from exitrisk.collectors import outage as collector
from exitrisk.outage import catalog

NOW = datetime.now(timezone.utc)
GIB = 1024**3

ANSWERS = {
    "cloudwatch": {
        "describe_alarms": {
            "MetricAlarms": [
                {
                    "Namespace": "AWS/Lambda",
                    "MetricName": "Errors",
                    "Dimensions": [{"Name": "FunctionName", "Value": "other"}],
                }
            ]
        },
    },
    "kafka": {
        "list_clusters_v2": {
            "ClusterInfoList": [
                {
                    "ClusterName": "res1",
                    "ClusterArn": "arn:aws:kafka:eu-west-1:1:cluster/res1/x",
                    "ClusterType": "PROVISIONED",
                    "State": "ACTIVE",
                    "Provisioned": {
                        "NumberOfBrokerNodes": 3,
                        "EnhancedMonitoring": "PER_BROKER",
                        "BrokerNodeGroupInfo": {
                            "InstanceType": "kafka.m5.large",
                            "ClientSubnets": ["a", "b", "c"],
                            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1000}},
                        },
                        "CurrentBrokerSoftwareInfo": {
                            "KafkaVersion": "3.6.0",
                            "ConfigurationArn": "arn:c",
                            "ConfigurationRevision": 1,
                        },
                        "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
                    },
                }
            ]
        },
        "describe_configuration_revision": {
            "ServerProperties": b"unclean.leader.election.enable=true\ndefault.replication.factor=2\n"
            b"min.insync.replicas=1\n"
        },
    },
    "rds": {
        "describe_db_instances": {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "res1",
                    "DBInstanceClass": "db.r6g.large",
                    "Engine": "postgres",
                    "EngineVersion": "15.8",
                    "MultiAZ": False,
                    "AllocatedStorage": 100,
                    "StorageType": "gp3",
                    "Iops": 3000,
                    "BackupRetentionPeriod": 7,
                    "DBParameterGroups": [{"DBParameterGroupName": "pg"}],
                },
                {
                    "DBInstanceIdentifier": "aur1",
                    "DBClusterIdentifier": "cl1",
                    "DBInstanceClass": "db.r6g.large",
                    "Engine": "aurora-postgresql",
                    "EngineVersion": "15.8",
                    "DBParameterGroups": [{"DBParameterGroupName": "pg"}],
                },
            ]
        },
        "describe_db_parameters": {"Parameters": [{"ParameterName": "max_connections", "ParameterValue": "100"}]},
        "describe_pending_maintenance_actions": {
            "PendingMaintenanceActions": [
                {
                    "ResourceIdentifier": "arn:aws:rds:eu-west-1:1:db:res1",
                    "PendingMaintenanceActionDetails": [
                        {"Action": "system-update", "CurrentApplyDate": NOW + timedelta(days=5), "Description": "patch"}
                    ],
                }
            ]
        },
    },
    "ec2": {
        "describe_instances": {
            "Reservations": [{"Instances": [{"InstanceId": "res1", "InstanceType": "t3.medium", "Tags": []}]}]
        },
        "describe_volumes": {
            "Volumes": [
                {
                    "VolumeId": "res1",
                    "VolumeType": "gp3",
                    "Iops": 3000,
                    "Throughput": 125,
                    "Size": 100,
                    "Attachments": [{"InstanceId": "res1"}],
                }
            ]
        },
        "describe_instance_credit_specifications": {
            "InstanceCreditSpecifications": [{"InstanceId": "res1", "CpuCredits": "standard"}]
        },
        "describe_instance_types": {
            "InstanceTypes": [{"InstanceType": "r6g.large", "MemoryInfo": {"SizeInMiB": 16384}}]
        },
        "describe_nat_gateways": {
            "NatGateways": [{"NatGatewayId": "res1", "SubnetId": "s1", "State": "available", "VpcId": "v1"}]
        },
        "describe_subnets": {
            "Subnets": [
                {
                    "SubnetId": "s1",
                    "AvailabilityZone": "eu-west-1a",
                    "VpcId": "v1",
                    "CidrBlock": "10.0.0.0/24",
                    "AvailableIpAddressCount": 200,
                },
                {
                    "SubnetId": "s2",
                    "AvailabilityZone": "eu-west-1b",
                    "VpcId": "v1",
                    "CidrBlock": "10.0.1.0/24",
                    "AvailableIpAddressCount": 200,
                },
            ]
        },
        "describe_transit_gateways": {"TransitGateways": [{"TransitGatewayId": "res1", "State": "available"}]},
        "describe_vpc_endpoints": {
            "VpcEndpoints": [
                {
                    "VpcEndpointId": "res1",
                    "VpcEndpointType": "Interface",
                    "VpcId": "v1",
                    "ServiceName": "com.amazonaws.eu-west-1.sts",
                    "State": "available",
                    "SubnetIds": ["s1"],
                }
            ]
        },
        "describe_vpn_connections": {
            "VpnConnections": [
                {
                    "VpnConnectionId": "vpn1",
                    "State": "available",
                    "Options": {"StaticRoutesOnly": True},
                    "VgwTelemetry": [{"Status": "UP"}, {"Status": "DOWN"}],
                }
            ]
        },
    },
    "elasticache": {
        "describe_replication_groups": {
            "ReplicationGroups": [
                {
                    "ReplicationGroupId": "res1",
                    "Engine": "redis",
                    "CacheNodeType": "cache.r6g.large",
                    "AutomaticFailover": "disabled",
                    "MultiAZ": "disabled",
                    "ClusterEnabled": False,
                    "MemberClusters": ["res1", "res1-002"],
                    "NodeGroups": [{"NodeGroupId": "0001", "NodeGroupMembers": [{"CacheClusterId": "res1"}]}],
                },
                {
                    "ReplicationGroupId": "two",
                    "CacheNodeType": "cache.t4g.small",
                    "AutomaticFailover": "enabled",
                    "MultiAZ": "disabled",
                    "MemberClusters": [],
                },
            ]
        },
    },
    "lambda": {
        "list_functions": {
            "Functions": [{"FunctionName": "res1", "Timeout": 3, "MemorySize": 512, "Runtime": "python3.12"}]
        }
    },
    "dynamodb": {
        "list_tables": {"TableNames": ["res1"]},
        "describe_limits": {
            "TableMaxReadCapacityUnits": 1000,
            "TableMaxWriteCapacityUnits": 1000,
            "AccountMaxReadCapacityUnits": 80000,
            "AccountMaxWriteCapacityUnits": 80000,
        },
        "describe_table": {
            "Table": {
                "TableName": "res1",
                "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
                "TableSizeBytes": GIB,
                "GlobalSecondaryIndexes": [{"IndexName": "i"}],
                "Replicas": [],
                "OnDemandThroughput": {"MaxReadRequestUnits": 100},
            }
        },
    },
    "opensearch": {
        "list_domain_names": {"DomainNames": [{"DomainName": "res1"}]},
        "describe_domains": {
            "DomainStatusList": [
                {
                    "DomainName": "res1",
                    "DomainId": "d",
                    "ARN": "arn:d",
                    "EngineVersion": "OpenSearch_2.11",
                    "ClusterConfig": {
                        "InstanceType": "t3.medium.search",
                        "InstanceCount": 3,
                        "ZoneAwarenessEnabled": False,
                        "DedicatedMasterEnabled": False,
                    },
                    "EBSOptions": {"EBSEnabled": True, "VolumeSize": 100, "VolumeType": "gp3"},
                }
            ]
        },
    },
    "kinesis": {
        "list_streams": {
            "StreamNames": ["res1"],
            "HasMoreStreams": False,
            "StreamSummaries": [{"StreamName": "res1", "StreamARN": "arn:k", "StreamStatus": "ACTIVE"}],
        },
        "describe_stream_summary": {
            "StreamDescriptionSummary": {
                "StreamName": "res1",
                "StreamARN": "arn:k",
                "StreamStatus": "ACTIVE",
                "StreamModeDetails": {"StreamMode": "PROVISIONED"},
                "RetentionPeriodHours": 24,
                "StreamCreationTimestamp": NOW,
                "EnhancedMonitoring": [],
                "OpenShardCount": 1,
                "ConsumerCount": 1,
            }
        },
    },
    "sqs": {
        "list_queues": {"QueueUrls": ["https://sqs.eu-west-1.amazonaws.com/1/res1"]},
        "get_queue_attributes": {"Attributes": {"MessageRetentionPeriod": "345600", "VisibilityTimeout": "30"}},
    },
    "mq": {
        "list_brokers": {
            "BrokerSummaries": [
                {
                    "BrokerName": "res1",
                    "BrokerId": "b",
                    "DeploymentMode": "SINGLE_INSTANCE",
                    "EngineType": "ACTIVEMQ",
                    "HostInstanceType": "mq.m5.large",
                }
            ]
        }
    },
    "apigateway": {
        "get_account": {"throttleSettings": {"rateLimit": 100.0, "burstLimit": 200}},
        "get_rest_apis": {"items": [{"id": "a", "name": "res1", "endpointConfiguration": {"types": ["REGIONAL"]}}]},
    },
    "apigatewayv2": {
        "get_apis": {"Items": [{"ApiId": "b", "Name": "res1", "ProtocolType": "HTTP", "RouteSelectionExpression": "x"}]}
    },
    "elbv2": {
        "describe_load_balancers": {
            "LoadBalancers": [
                {
                    "LoadBalancerName": "res1",
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/res1/x",
                    "Type": "application",
                    "Scheme": "internal",
                    "AvailabilityZones": [{"ZoneName": "eu-west-1a"}],
                }
            ]
        },
    },
    "redshift": {
        "describe_clusters": {
            "Clusters": [
                {
                    "ClusterIdentifier": "res1",
                    "NodeType": "ra3.xlplus",
                    "NumberOfNodes": 1,
                    "ClusterVersion": "1.0",
                    "MultiAZ": "Disabled",
                }
            ]
        }
    },
    "fsx": {
        "describe_file_systems": {
            "FileSystems": [
                {
                    "FileSystemId": "res1",
                    "FileSystemType": "WINDOWS",
                    "StorageCapacity": 100,
                    "WindowsConfiguration": {"DeploymentType": "SINGLE_AZ_2", "ThroughputCapacity": 64},
                }
            ]
        }
    },
    "efs": {
        "describe_file_systems": {
            "FileSystems": [
                {
                    "FileSystemId": "res1",
                    "Name": "n",
                    "PerformanceMode": "generalPurpose",
                    "ThroughputMode": "elastic",
                    "SizeInBytes": {"Value": GIB},
                    "OwnerId": "1",
                    "CreationToken": "c",
                    "CreationTime": NOW,
                    "LifeCycleState": "available",
                    "NumberOfMountTargets": 2,
                    "Tags": [],
                }
            ]
        }
    },
    "cloudfront": {
        "list_distributions": {
            "DistributionList": {
                "Marker": "",
                "MaxItems": 100,
                "IsTruncated": False,
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "res1",
                        "DomainName": "d.example",
                        "Enabled": True,
                        "Comment": "c",
                        "Origins": {"Quantity": 1, "Items": [{"Id": "o", "DomainName": "o.example"}]},
                        "OriginGroups": {"Quantity": 0},
                    }
                ],
            }
        }
    },
    "directconnect": {
        "describe_connections": {
            "connections": [
                {
                    "connectionId": "res1",
                    "connectionName": "dc1",
                    "connectionState": "available",
                    "location": "LD5",
                    "bandwidth": "10Gbps",
                }
            ]
        },
        "describe_virtual_interfaces": {
            "virtualInterfaces": [
                {
                    "virtualInterfaceId": "vif1",
                    "virtualInterfaceName": "transit",
                    "virtualInterfaceType": "transit",
                    "virtualInterfaceState": "available",
                    "bgpPeers": [{"bgpPeerId": "p1", "bgpStatus": "down"}],
                }
            ]
        },
    },
    "route53resolver": {
        "list_resolver_endpoints": {
            "ResolverEndpoints": [
                {
                    "Id": "res1",
                    "Name": "inbound",
                    "Direction": "INBOUND",
                    "IpAddressCount": 2,
                    "HostVPCId": "v1",
                    "Status": "OPERATIONAL",
                }
            ]
        },
        "list_resolver_endpoint_ip_addresses": {
            "IpAddresses": [{"IpId": "a", "SubnetId": "s1"}, {"IpId": "b", "SubnetId": "s1"}]
        },
    },
    "s3": {"list_buckets": {"Buckets": [{"Name": "res1", "CreationDate": NOW}]}},
}


class Answer(dict):
    """An answer that records a read of any field its API does not have."""

    def __init__(self, data, shape, where, wrong):
        super().__init__(data)
        self.shape, self.where, self.wrong = shape, where, wrong

    def _check(self, key):
        if key not in self.shape.members:
            self.wrong.append(f"{self.where}: no field {key}")

    def _wrap(self, key, value):
        return wrap(value, self.shape.members[key], self.where, self.wrong) if key in self.shape.members else value

    def get(self, key, default=None):
        self._check(key)
        return self._wrap(key, super().get(key, default))

    def __getitem__(self, key):
        self._check(key)
        return self._wrap(key, super().__getitem__(key))


def wrap(value, shape, where, wrong):
    if shape.type_name == "structure" and isinstance(value, dict):
        return Answer(value, shape, where, wrong)
    if shape.type_name == "list" and isinstance(value, list):
        return [wrap(v, shape.member, where, wrong) for v in value]
    return value


class _Pages:
    def __init__(self, call):
        self.call = call

    def paginate(self, **kwargs):
        return [self.call(**kwargs)]


class Client:
    def __init__(self, name, region, log):
        self.real = boto3.client(name, region_name=region, aws_access_key_id="x", aws_secret_access_key="x")
        self.name, self.log = name, log

    def can_paginate(self, op):
        return False

    def get_paginator(self, op):
        return _Pages(getattr(self, op))

    def __getattr__(self, op):
        model = self.real.meta.service_model
        api = (
            model.operation_model(self.real.meta.method_to_api_mapping[op])
            if op in self.real.meta.method_to_api_mapping
            else None
        )
        if api is None:
            raise AttributeError(op)

        def call(**kwargs):
            where = f"{self.name}.{op}"
            self.log["calls"].add(where)
            report = ParamValidator().validate(kwargs, api.input_shape) if api.input_shape else None
            if report and report.has_errors():
                self.log["wrong"].append(f"{where}: {report.generate_report()}")
            if op == "get_metric_data":
                return _metric_answer(kwargs)
            answer = ANSWERS.get(self.name, {}).get(op, {})
            return wrap(answer, api.output_shape, where, self.log["wrong"]) if api.output_shape else answer

        return call


def _metric_answer(kwargs):
    """Every metric searched for has a figure, on a resource called res1 in every dimension."""
    results = []
    for q in kwargs["MetricDataQueries"]:
        label = re.sub(r"\$\{PROP\('Dim\.[^']+'\)\}", "res1", q.get("Label") or "")
        results.append(
            {
                "Id": q["Id"],
                "Label": label,
                "Timestamps": [NOW - timedelta(days=d) for d in (3, 2, 1)],
                "Values": [1000.0, 2000.0, 3000.0],
                "StatusCode": "Complete",
            }
        )
    return {"MetricDataResults": results, "Messages": []}


class Session:
    region_name = "eu-west-1"

    def __init__(self):
        self.log = {"calls": set(), "wrong": []}

    def client(self, name, region_name="eu-west-1", config=None):
        return Client(name, region_name, self.log)


@pytest.fixture(scope="module")
def read():
    session = Session()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("exitrisk.collectors.inventory.enabled_regions", lambda s, r: ["eu-west-1"])
        out, _ = collector.account_checks(
            session, "111111111111", ["eu-west-1"], {"home": "eu-west-1", "services": None}
        )
    return out, session.log


def test_every_call_and_every_field_read_is_in_the_api(read):
    _, log = read
    assert not sorted(set(log["wrong"]))


def test_the_reviews_reach_every_service(read):
    out, _ = read
    have = {p["svc"] for p in out["profiles"]}
    want = {
        "msk",
        "rds",
        "elasticache",
        "lambda",
        "dynamodb",
        "opensearch",
        "kinesis",
        "sqs",
        "mq",
        "apigateway",
        "elb",
        "vpc",
        "transit_gateway",
        "redshift",
        "fsx",
        "efs",
        "cloudfront",
        "route53",
    }
    assert want <= have, want - have


def test_no_check_failed_on_the_answers(read):
    out, _ = read
    down = {
        k: v["note"]
        for k, v in out["checks"].items()
        if v["status"] == "unknown" or "not measured" in (v.get("note") or "")
    }
    assert not down


def test_the_rules_for_what_the_answers_hold_fire(read):
    out, _ = read
    rules = {r["rule"] for r in out["rows"]}
    want = {
        "msk_unclean_leader", "msk_low_replication", "rds_connections", "rds_maintenance", "aurora_no_reader",
        "cache_no_failover", "cache_no_multi_az", "lambda_timeout", "search_no_zone", "search_no_master", "sqs_no_dlq",
        "mq_single", "lb_one_az", "nat_one_az", "vpn_tunnel_down", "redshift_single_node", "fsx_single_az",
        "cf_no_failover", "no_alarm", "ec2_burstable", "cache_burstable", "search_burstable", "resolver_one_az",
        "dx_no_redundancy", "dx_vif_down", "vpce_one_az", "vpce_drops", "ec2_net_allowance", "ec2_dns_allowance",
    }  # fmt: skip
    assert want <= rules, want - rules
    assert rules <= {r["id"] for r in catalog()["rules"]}


@pytest.mark.parametrize(
    "billed",
    [
        ["Amazon Elastic File System"],
        ["Amazon FSx"],
        ["Amazon Relational Database Service"],
        ["Amazon Managed Streaming for Apache Kafka"],
        ["Amazon Simple Queue Service"],
        [],
    ],
)
def test_a_task_runs_with_only_its_own_service_billed(billed):
    """Metrics are read only for billed services, so a task sharing several must not assume all of them."""
    session = Session()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("exitrisk.collectors.inventory.enabled_regions", lambda s, r: ["eu-west-1"])
        out, _ = collector.account_checks(
            session, "111111111111", ["eu-west-1"], {"home": "eu-west-1", "services": billed}
        )
    down = {
        k: v["note"]
        for k, v in out["checks"].items()
        if v["status"] == "unknown" or "not measured" in (v.get("note") or "")
    }
    assert not down
