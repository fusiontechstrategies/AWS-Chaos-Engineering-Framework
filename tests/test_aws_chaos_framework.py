"""Offline tests for the one-file AWS Chaos Engineering Framework.

These tests never use ambient credentials and never contact AWS. Service reads
are answered by deterministic fakes, and any unexpected write in plan mode fails
the test immediately.
"""

from __future__ import annotations

import ast
import copy
import json
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import boto3
import pytest
from botocore import xform_name

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import aws_chaos_framework as framework  # noqa: E402

ACCOUNT_ID = "111122223333"
REGION = "us-gov-west-1"
BREAK_GLASS_ARN = f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/ChaosBreakGlass"
INSTANCE_ID = "i-0123456789abcdef0"
VOLUME_ID = "vol-0123456789abcdef0"
TEST_ACCESS_KEY = "ASIA" + "ABCDEFGHIJKLMNOP"
OTHER_ACCESS_KEY = "ASIA" + ("Z" * 16)


class FakeClientError(Exception):
    """Minimal stand-in for botocore client exceptions."""

    def __init__(self, code: str):
        self.response = {"Error": {"Code": code}}
        super().__init__(code)


class FakeAWS:
    """Deterministic, account-free AWS response model."""

    def __init__(self, reject_writes: bool = True):
        self.reject_writes = reject_writes
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.clients: dict[str, FakeClient] = {}
        self.read_overrides: dict[tuple[str, str], list[Any]] = {}

    def client(self, service: str) -> FakeClient:
        return self.clients.setdefault(service, FakeClient(self, service))

    def respond(self, service: str, operation: str, request: dict[str, Any]) -> Any:
        self.calls.append((service, operation, request))
        is_read = operation in framework.READ_ONLY_OPERATIONS.get(service, ())
        if self.reject_writes and not is_read:
            raise AssertionError(
                f"Plan mode attempted an AWS write: {service}.{operation}"
            )
        override_key = (service, operation)
        if is_read and self.read_overrides.get(override_key):
            return self.read_overrides[override_key].pop(0)

        policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ExistingAccess",
                        "Effect": "Allow",
                        "Principal": {"AWS": BREAK_GLASS_ARN},
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        )

        responses: dict[tuple[str, str], Any] = {
            ("ecr", "batch_delete_image"): {
                "failures": [],
                "imageIds": [{"imageDigest": "sha256:" + "1" * 64}],
            },
            ("ec2", "describe_security_groups"): {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-0123456789abcdef0",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "IpRanges": [{"CidrIp": "192.0.2.0/24"}],
                            }
                        ],
                    }
                ]
            },
            ("cloudwatch", "get_metric_statistics"): {"Datapoints": []},
            ("cloudwatch", "describe_alarms"): {
                "MetricAlarms": [
                    {
                        "AlarmArn": f"arn:aws-us-gov:cloudwatch:{REGION}:{ACCOUNT_ID}:alarm:chaos-stop",
                        "StateValue": "OK",
                    }
                ]
            },
            ("ec2", "describe_instances"): {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": INSTANCE_ID,
                                "InstanceType": "t3.micro",
                                "RootDeviceName": "/dev/xvda",
                                "State": {"Name": "running"},
                                "Placement": {"AvailabilityZone": f"{REGION}a"},
                                "BlockDeviceMappings": [
                                    {
                                        "Ebs": {
                                            "VolumeId": VOLUME_ID,
                                            "DeleteOnTermination": False,
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
            ("ec2", "describe_volumes"): {
                "Volumes": [
                    {
                        "VolumeId": VOLUME_ID,
                        "Size": 8,
                        "VolumeType": "io2",
                        "State": "in-use",
                        "Iops": 3000,
                        "Throughput": 125,
                        "Attachments": [
                            {
                                "InstanceId": INSTANCE_ID,
                                "Device": "/dev/xvdf",
                                "State": "attached",
                            }
                        ],
                    }
                ]
            },
            ("ec2", "describe_snapshots"): {
                "Snapshots": [
                    {"SnapshotId": "snap-0123456789abcdef0", "State": "completed"}
                ]
            },
            ("ec2", "describe_network_acls"): {
                "NetworkAcls": [
                    {
                        "NetworkAclId": "acl-0123456789abcdef0",
                        "Associations": [
                            {
                                "NetworkAclAssociationId": "aclassoc-0123456789abcdef0",
                                "SubnetId": "subnet-0123456789abcdef0",
                            }
                        ],
                        "Entries": [
                            {
                                "RuleNumber": 50,
                                "Protocol": "-1",
                                "RuleAction": "allow",
                                "Egress": False,
                                "CidrBlock": "0.0.0.0/0",
                            }
                        ],
                    }
                ]
            },
            ("ec2", "describe_route_tables"): {
                "RouteTables": [
                    {
                        "RouteTableId": "rtb-0123456789abcdef0",
                        "Routes": [
                            {
                                "DestinationCidrBlock": "10.20.0.0/16",
                                "GatewayId": "igw-0123456789abcdef0",
                                "Origin": "CreateRoute",
                                "State": "active",
                            }
                        ],
                    }
                ]
            },
            ("ec2", "describe_vpc_peering_connections"): {
                "VpcPeeringConnections": [
                    {
                        "VpcPeeringConnectionId": "pcx-0123456789abcdef0",
                        "RequesterVpcInfo": {"VpcId": "vpc-0123456789abcdef0"},
                        "AccepterVpcInfo": {"VpcId": "vpc-0fedcba9876543210"},
                        "Status": {"Code": "active"},
                    }
                ]
            },
            ("ec2", "describe_vpc_endpoints"): {
                "VpcEndpoints": [
                    {
                        "VpcEndpointId": "vpce-0123456789abcdef0",
                        "VpcId": "vpc-0123456789abcdef0",
                        "ServiceName": "com.amazonaws.us-gov-west-1.s3",
                        "VpcEndpointType": "Gateway",
                    }
                ]
            },
            ("efs", "describe_mount_targets"): {
                "MountTargets": [
                    {
                        "MountTargetId": "fsmt-0123456789abcdef0",
                        "FileSystemId": "fs-0123456789abcdef0",
                        "SubnetId": "subnet-0123456789abcdef0",
                        "IpAddress": "10.20.1.10",
                    }
                ]
            },
            ("efs", "describe_file_systems"): {
                "FileSystems": [
                    {
                        "FileSystemId": "fs-0123456789abcdef0",
                        "ThroughputMode": "provisioned",
                        "ProvisionedThroughputInMibps": 2.0,
                        "LifeCycleState": "available",
                    }
                ]
            },
            ("rds", "describe_db_clusters"): {
                "DBClusters": [
                    {
                        "DBClusterIdentifier": "chaos-test-cluster",
                        "Status": "available",
                        "Endpoint": "writer.test.invalid",
                        "ReaderEndpoint": "reader.test.invalid",
                        "DBClusterMembers": [
                            {
                                "DBInstanceIdentifier": "chaos-test-db",
                                "IsClusterWriter": True,
                                "DBClusterParameterGroupStatus": "in-sync",
                            },
                            {
                                "DBInstanceIdentifier": "chaos-test-reader",
                                "IsClusterWriter": False,
                                "DBClusterParameterGroupStatus": "in-sync",
                            },
                        ],
                    }
                ]
            },
            ("rds", "describe_db_instances"): {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "chaos-test-db",
                        "DBInstanceStatus": "available",
                        "BackupRetentionPeriod": 7,
                        "MultiAZ": True,
                    }
                ]
            },
            ("rds", "describe_db_parameters"): {
                "Parameters": [
                    {
                        "ParameterName": "max_connections",
                        "ParameterValue": "100",
                        "ApplyType": "dynamic",
                    }
                ]
            },
            ("lambda", "get_function_concurrency"): {"ReservedConcurrentExecutions": 5},
            ("lambda", "get_function_configuration"): {
                "FunctionName": "chaos-test-function",
                "LastUpdateStatus": "Successful",
                "Timeout": 30,
                "MemorySize": 256,
                "Environment": {"Variables": {"MODE": "normal"}},
            },
            ("s3", "get_bucket_policy"): {"Policy": policy},
            ("s3", "get_bucket_versioning"): {"Status": "Enabled"},
            ("s3", "get_bucket_encryption"): {
                "ServerSideEncryptionConfiguration": {"Rules": []}
            },
            ("s3", "list_objects_v2"): {
                "Contents": [{"Key": "chaos-test/object.txt", "Size": 4}]
            },
            ("s3", "get_bucket_lifecycle_configuration"): {
                "Rules": [
                    {
                        "ID": "existing-rule",
                        "Status": "Enabled",
                        "Filter": {"Prefix": "archive/"},
                        "Expiration": {"Days": 30},
                    }
                ]
            },
            ("sqs", "get_queue_attributes"): {
                "Attributes": {
                    "Policy": policy,
                    "QueueArn": f"arn:aws-us-gov:sqs:{REGION}:{ACCOUNT_ID}:chaos-test-queue",
                    "DelaySeconds": "0",
                    "VisibilityTimeout": "30",
                    "ApproximateNumberOfMessages": "1",
                }
            },
            ("sns", "get_subscription_attributes"): {
                "Attributes": {
                    "TopicArn": f"arn:aws-us-gov:sns:{REGION}:{ACCOUNT_ID}:chaos-test-topic",
                    "Protocol": "sqs",
                    "Endpoint": f"arn:aws-us-gov:sqs:{REGION}:{ACCOUNT_ID}:chaos-test-queue",
                    "RawMessageDelivery": "false",
                }
            },
            ("sns", "get_topic_attributes"): {"Attributes": {"Policy": policy}},
            ("elbv2", "describe_target_group_attributes"): {
                "Attributes": [
                    {"Key": "deregistration_delay.timeout_seconds", "Value": "300"}
                ]
            },
            ("elbv2", "describe_target_health"): {
                "TargetHealthDescriptions": [
                    {
                        "Target": {"Id": INSTANCE_ID, "Port": 443},
                        "TargetHealth": {"State": "healthy"},
                    }
                ]
            },
            ("elbv2", "describe_target_groups"): {
                "TargetGroups": [
                    {
                        "TargetGroupArn": f"arn:aws-us-gov:elasticloadbalancing:{REGION}:{ACCOUNT_ID}:targetgroup/chaos-test/0123456789abcdef",
                        "HealthCheckIntervalSeconds": 30,
                        "HealthCheckTimeoutSeconds": 5,
                    }
                ]
            },
            ("elbv2", "describe_rules"): {
                "Rules": [
                    {
                        "RuleArn": f"arn:aws-us-gov:elasticloadbalancing:{REGION}:{ACCOUNT_ID}:listener-rule/app/chaos-test/1/2/3",
                        "Actions": [
                            {
                                "Type": "fixed-response",
                                "FixedResponseConfig": {
                                    "StatusCode": "200",
                                    "ContentType": "text/plain",
                                },
                            }
                        ],
                    }
                ]
            },
            ("ecs", "describe_tasks"): {
                "tasks": [
                    {
                        "taskArn": f"arn:aws-us-gov:ecs:{REGION}:{ACCOUNT_ID}:task/chaos-test/0123456789abcdef",
                        "lastStatus": "RUNNING",
                    }
                ],
                "failures": [],
            },
            ("ecs", "describe_services"): {
                "services": [{"serviceName": "chaos-test-service", "desiredCount": 1}],
                "failures": [],
            },
            ("ecs", "describe_container_instances"): {
                "containerInstances": [
                    {
                        "containerInstanceArn": f"arn:aws-us-gov:ecs:{REGION}:{ACCOUNT_ID}:container-instance/chaos-test/0123456789abcdef",
                        "status": "ACTIVE",
                    }
                ],
                "failures": [],
            },
            ("ecs", "describe_task_definition"): {
                "taskDefinition": {
                    "family": "chaos-test",
                    "containerDefinitions": [
                        {"name": "app", "image": "example.invalid/test:latest"}
                    ],
                    "cpu": "256",
                    "memory": "512",
                    "networkMode": "awsvpc",
                }
            },
            ("kinesis", "describe_stream"): {
                "StreamDescription": {
                    "RetentionPeriodHours": 48,
                    "StreamStatus": "ACTIVE",
                    "Shards": [{"ShardId": "shardId-000000000000"}],
                }
            },
            ("kinesis", "describe_stream_summary"): {
                "StreamDescriptionSummary": {
                    "OpenShardCount": 2,
                    "StreamStatus": "ACTIVE",
                }
            },
            ("opensearch", "describe_domain"): {
                "DomainStatus": {
                    "DomainName": "chaos-test-domain",
                    "Processing": False,
                    "ClusterConfig": {
                        "InstanceType": "t3.small.search",
                        "InstanceCount": 2,
                        "DedicatedMasterEnabled": False,
                        "ZoneAwarenessEnabled": False,
                    },
                }
            },
            ("cloudfront", "get_distribution_config"): {
                "ETag": "etag-1",
                "DistributionConfig": {
                    "CallerReference": "chaos-test",
                    "Comment": "test",
                    "Enabled": True,
                    "Origins": {"Quantity": 1, "Items": []},
                    "DefaultCacheBehavior": {
                        "TargetOriginId": "origin-1",
                        "ViewerProtocolPolicy": "https-only",
                    },
                },
            },
            ("wafv2", "get_web_acl"): {
                "LockToken": "lock-1",
                "WebACL": {
                    "Name": "chaos-test-acl",
                    "Id": "11111111-2222-3333-4444-555555555555",
                    "DefaultAction": {"Allow": {}},
                    "Description": "test",
                    "Rules": [
                        {
                            "Name": "chaos-test-rule",
                            "Priority": 1,
                            "Statement": {
                                "RateBasedStatement": {
                                    "Limit": 2000,
                                    "AggregateKeyType": "IP",
                                }
                            },
                            "Action": {"Block": {}},
                            "VisibilityConfig": {
                                "SampledRequestsEnabled": True,
                                "CloudWatchMetricsEnabled": True,
                                "MetricName": "chaos-test-rule",
                            },
                        }
                    ],
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "chaos-test-acl",
                    },
                },
            },
            ("wafv2", "get_ip_set"): {
                "LockToken": "lock-1",
                "IPSet": {
                    "Name": "chaos-test-ip-set",
                    "Id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "Description": "test",
                    "IPAddressVersion": "IPV4",
                    "Addresses": ["192.0.2.0/32"],
                },
            },
            ("kms", "describe_key"): {
                "KeyMetadata": {"KeyId": "alias/chaos-test", "Enabled": True}
            },
            ("kms", "get_key_policy"): {"Policy": policy},
            ("kms", "list_grants"): {
                "Grants": [
                    {
                        "GrantId": "0123456789abcdef0123456789abcdef",
                        "KeyId": f"arn:aws-us-gov:kms:{REGION}:{ACCOUNT_ID}:key/01234567-89ab-cdef-0123-456789abcdef",
                        "GranteePrincipal": BREAK_GLASS_ARN,
                        "Operations": ["Decrypt"],
                    }
                ]
            },
            ("iam", "list_attached_role_policies"): {
                "AttachedPolicies": [
                    {
                        "PolicyName": "ChaosTestPolicy",
                        "PolicyArn": f"arn:aws-us-gov:iam::{ACCOUNT_ID}:policy/ChaosTestPolicy",
                    }
                ]
            },
            ("iam", "get_role"): {
                "Role": {
                    "RoleName": "ChaosTestRole",
                    "Arn": f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/ChaosTestRole",
                    "MaxSessionDuration": 3600,
                }
            },
            ("iam", "list_access_keys"): {
                "AccessKeyMetadata": [
                    {
                        "UserName": "chaos-test-user",
                        "AccessKeyId": TEST_ACCESS_KEY,
                        "Status": "Active",
                    }
                ]
            },
            ("ds", "describe_trusts"): {
                "Trusts": [
                    {
                        "TrustId": "t-1234567890",
                        "DirectoryId": "d-1234567890",
                        "RemoteDomainName": "test.example.invalid",
                        "TrustDirection": "Two-Way",
                        "TrustType": "Forest",
                    }
                ]
            },
            ("ds", "describe_conditional_forwarders"): {
                "ConditionalForwarders": [
                    {
                        "RemoteDomainName": "test.example.invalid",
                        "DnsIpAddrs": ["192.0.2.10"],
                        "ReplicationScope": "Domain",
                    }
                ]
            },
            ("appstream", "describe_fleets"): {
                "Fleets": [{"Name": "chaos-test-fleet", "State": "RUNNING"}]
            },
            ("appstream", "list_associated_fleets"): {"Names": ["chaos-test-fleet"]},
            ("ecr", "get_repository_policy"): {"policyText": policy},
            ("ecr", "describe_images"): {
                "imageDetails": [
                    {
                        "imageDigest": "sha256:" + "1" * 64,
                        "registryId": ACCOUNT_ID,
                        "repositoryName": "chaos-test-repository",
                        "imageTags": ["chaos-test"],
                    }
                ]
            },
            ("codecommit", "get_repository_triggers"): {
                "configurationId": "config-1",
                "triggers": [
                    {
                        "name": "chaos-test-trigger",
                        "destinationArn": f"arn:aws-us-gov:sns:{REGION}:{ACCOUNT_ID}:chaos-test-topic",
                        "events": ["all"],
                    }
                ],
            },
            ("ses", "describe_configuration_set"): {
                "ConfigurationSet": {"Name": "chaos-test-config"}
            },
            ("fis", "get_experiment_template"): {
                "experimentTemplate": {
                    "id": "EXT1234567890abcdef0",
                    "roleArn": f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/ChaosFisRole",
                    "actions": {
                        "stop": {
                            "actionId": "aws:ec2:stop-instances",
                            "parameters": {"startInstancesAfterDuration": "PT1M"},
                        }
                    },
                    "targets": {
                        "Instances": {
                            "resourceType": "aws:ec2:instance",
                            "resourceArns": [
                                f"arn:aws-us-gov:ec2:{REGION}:{ACCOUNT_ID}:instance/{INSTANCE_ID}"
                            ],
                            "selectionMode": "COUNT(1)",
                        }
                    },
                    "stopConditions": [
                        {
                            "source": "aws:cloudwatch:alarm",
                            "value": f"arn:aws-us-gov:cloudwatch:{REGION}:{ACCOUNT_ID}:alarm:chaos-stop",
                        }
                    ],
                }
            },
        }
        return responses.get((service, operation), {})


class FakeClient:
    """Dynamic fake SDK client backed by FakeAWS."""

    def __init__(self, aws: FakeAWS, service: str):
        self.aws = aws
        self.service = service
        self.meta = SimpleNamespace(
            region_name="aws-us-gov-global" if service == "iam" else REGION
        )
        self.exceptions = SimpleNamespace(
            ClientError=FakeClientError,
            NoSuchBucketPolicy=FakeClientError,
            NoSuchLifecycleConfiguration=FakeClientError,
            RepositoryPolicyNotFoundException=FakeClientError,
        )

    def __getattr__(self, operation: str):
        def call(**kwargs: Any) -> Any:
            return self.aws.respond(self.service, operation, kwargs)

        return call


class FakeSafetyController:
    """Safety controller with no network-capable state."""

    def __init__(self, aws: FakeAWS, *, live: bool = False):
        self.aws = aws
        self.live = live
        self.emergency_stop = threading.Event()
        self.config = {
            "fail_closed": True,
            "max_blast_radius": 1,
            "safety_alarms": ["chaos-stop"],
            "required_target_tags": {"ChaosReady": "true"},
            "target_allowlist": [
                f"arn:aws-us-gov:ec2:{REGION}:{ACCOUNT_ID}:instance/{INSTANCE_ID}"
            ],
            "_runtime_allow_fis_without_stop_conditions": False,
            "_runtime_allow_fis_unbounded_targets": False,
        }
        self.started = 0

    def client(
        self,
        service: str,
        owner: framework.ChaosExperiment | None = None,
        region_name: str | None = None,
    ) -> framework.AwsClientProxy:
        del region_name
        return framework.AwsClientProxy(service, self.aws.client(service), owner)

    def log_experiment_to_cloudtrail(
        self, _experiment_type: str, _resources: list[str]
    ) -> None:
        return None

    def check_safety_conditions(self) -> tuple[bool, list[str]]:
        return True, []

    def emergency_stop_all(self) -> None:
        self.emergency_stop.set()

    def experiment_started(self) -> None:
        self.started += 1

    def experiment_finished(self) -> None:
        self.started -= 1


def action_configs() -> dict[framework.ChaosType, dict[str, Any]]:
    """Return one bounded example for every directly executable action."""
    target_group = (
        f"arn:aws-us-gov:elasticloadbalancing:{REGION}:{ACCOUNT_ID}:"
        "targetgroup/chaos-test/0123456789abcdef"
    )
    task_arn = (
        f"arn:aws-us-gov:ecs:{REGION}:{ACCOUNT_ID}:task/chaos-test/0123456789abcdef"
    )
    container_instance = (
        f"arn:aws-us-gov:ecs:{REGION}:{ACCOUNT_ID}:"
        "container-instance/chaos-test/0123456789abcdef"
    )
    return {
        framework.ChaosType.FIS_TEMPLATE: {
            "experiment_template_id": "EXT1234567890abcdef0"
        },
        framework.ChaosType.EC2_TERMINATE: {
            "instance_ids": [INSTANCE_ID],
            "delete_on_termination_volumes": {INSTANCE_ID: []},
        },
        framework.ChaosType.EC2_STOP: {"instance_ids": [INSTANCE_ID]},
        framework.ChaosType.EC2_REBOOT: {"instance_ids": [INSTANCE_ID]},
        framework.ChaosType.EBS_DETACH_VOLUME: {
            "volume_id": VOLUME_ID,
            "attachment": {"instance_id": INSTANCE_ID, "device": "/dev/xvdf"},
        },
        framework.ChaosType.EBS_THROTTLE_IOPS: {"volume_id": VOLUME_ID, "iops": 100},
        framework.ChaosType.EFS_THROTTLE_THROUGHPUT: {
            "file_system_id": "fs-0123456789abcdef0",
            "throughput_mode": "provisioned",
            "provisioned_throughput": 1.0,
        },
        framework.ChaosType.EFS_MOUNT_TARGET_DELETE: {
            "mount_target_id": "fsmt-0123456789abcdef0"
        },
        framework.ChaosType.VPC_SUBNET_ACL_MODIFY: {
            "subnet_id": "subnet-0123456789abcdef0",
            "nacl_id": "acl-0fedcba9876543210",
        },
        framework.ChaosType.VPC_ROUTE_TABLE_MODIFY: {
            "route_table_id": "rtb-0123456789abcdef0",
            "destination_cidr": "10.20.0.0/16",
            "blackhole": True,
        },
        framework.ChaosType.VPC_SECURITY_GROUP_MODIFY: {
            "group_id": "sg-0123456789abcdef0",
            "remove_rule": {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "192.0.2.0/24"}],
            },
        },
        framework.ChaosType.VPC_NACL_BLOCK_TRAFFIC: {
            "nacl_id": "acl-0123456789abcdef0",
            "rule_number": 100,
            "protocol": "-1",
            "cidr_block": "192.0.2.0/24",
        },
        framework.ChaosType.VPC_PEERING_DELETE: {
            "peering_connection_id": "pcx-0123456789abcdef0"
        },
        framework.ChaosType.VPC_ENDPOINT_DELETE: {
            "endpoint_id": "vpce-0123456789abcdef0"
        },
        framework.ChaosType.RDS_FAILOVER: {"cluster_identifier": "chaos-test-cluster"},
        framework.ChaosType.RDS_REBOOT: {"db_instance_identifier": "chaos-test-db"},
        framework.ChaosType.RDS_BACKUP_RETENTION_MODIFY: {
            "db_identifier": "chaos-test-db",
            "retention_period": 0,
        },
        framework.ChaosType.RDS_PARAMETER_GROUP_MODIFY: {
            "parameter_group_name": "chaos-test-parameters",
            "parameters": [
                {
                    "ParameterName": "max_connections",
                    "ParameterValue": "50",
                    "ApplyMethod": "immediate",
                }
            ],
        },
        framework.ChaosType.LAMBDA_THROTTLE: {
            "function_name": "chaos-test-function",
            "reserved_concurrent_executions": 0,
        },
        framework.ChaosType.LAMBDA_ERROR_INJECTION: {
            "function_name": "chaos-test-function",
            "instrumented": True,
            "error_rate": 0.5,
        },
        framework.ChaosType.LAMBDA_TIMEOUT_MODIFY: {
            "function_name": "chaos-test-function",
            "timeout_seconds": 1,
        },
        framework.ChaosType.LAMBDA_MEMORY_LIMIT: {
            "function_name": "chaos-test-function",
            "memory_mb": 128,
        },
        framework.ChaosType.LAMBDA_ENVIRONMENT_CORRUPT: {
            "function_name": "chaos-test-function",
            "corrupt_vars": {"MODE": "chaos"},
        },
        framework.ChaosType.S3_BUCKET_POLICY_DENY: {
            "bucket_name": "chaos-test-bucket",
            "break_glass_principal_arn": BREAK_GLASS_ARN,
        },
        framework.ChaosType.S3_BUCKET_VERSIONING_SUSPEND: {
            "bucket_name": "chaos-test-bucket"
        },
        framework.ChaosType.S3_OBJECT_DELETE: {
            "bucket_name": "chaos-test-bucket",
            "prefix": "chaos-test/",
            "max_objects": 1,
        },
        framework.ChaosType.S3_LIFECYCLE_MODIFY: {
            "bucket_name": "chaos-test-bucket",
            "expire_days": 1,
        },
        framework.ChaosType.SQS_QUEUE_PURGE: {
            "queue_url": f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT_ID}/chaos-test-queue"
        },
        framework.ChaosType.SQS_QUEUE_POLICY_RESTRICT: {
            "queue_url": f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT_ID}/chaos-test-queue",
            "break_glass_principal_arn": BREAK_GLASS_ARN,
        },
        framework.ChaosType.SQS_MESSAGE_DELAY: {
            "queue_url": f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT_ID}/chaos-test-queue",
            "delay_seconds": 60,
        },
        framework.ChaosType.SQS_VISIBILITY_TIMEOUT: {
            "queue_url": f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT_ID}/chaos-test-queue",
            "timeout_seconds": 60,
        },
        framework.ChaosType.SNS_SUBSCRIPTION_DELETE: {
            "subscription_arn": f"arn:aws-us-gov:sns:{REGION}:{ACCOUNT_ID}:chaos-test-topic:00000000-1111-2222-3333-444444444444"
        },
        framework.ChaosType.SNS_TOPIC_POLICY_RESTRICT: {
            "topic_arn": f"arn:aws-us-gov:sns:{REGION}:{ACCOUNT_ID}:chaos-test-topic",
            "break_glass_principal_arn": BREAK_GLASS_ARN,
        },
        framework.ChaosType.ELB_REMOVE_TARGETS: {
            "target_group_arn": target_group,
            "target_ids": [INSTANCE_ID],
        },
        framework.ChaosType.ELB_MODIFY_ATTRIBUTES: {
            "target_group_arn": target_group,
            "deregistration_delay": 60,
        },
        framework.ChaosType.ELB_LISTENER_RULE_MODIFY: {
            "rule_arn": f"arn:aws-us-gov:elasticloadbalancing:{REGION}:{ACCOUNT_ID}:listener-rule/app/chaos-test/1/2/3",
            "action_type": "fixed-response",
            "status_code": "503",
        },
        framework.ChaosType.ELB_HEALTH_CHECK_MODIFY: {
            "target_group_arn": target_group,
            "interval": 60,
            "timeout": 10,
        },
        framework.ChaosType.ECS_TASK_STOP: {
            "cluster": "chaos-test-cluster",
            "task_arns": [task_arn],
        },
        framework.ChaosType.ECS_SERVICE_UPDATE: {
            "cluster": "chaos-test-cluster",
            "service": "chaos-test-service",
            "desired_count": 0,
        },
        framework.ChaosType.ECS_CONTAINER_INSTANCE_DRAIN: {
            "cluster": "chaos-test-cluster",
            "container_instance_arn": container_instance,
        },
        framework.ChaosType.KINESIS_RETENTION_MODIFY: {
            "stream_name": "chaos-test-stream",
            "retention_hours": 24,
        },
        framework.ChaosType.OPENSEARCH_CLUSTER_CONFIG_MODIFY: {
            "domain_name": "chaos-test-domain",
            "instance_count": 1,
        },
        framework.ChaosType.CLOUDFRONT_CACHE_INVALIDATE: {
            "distribution_id": "E1ABCDEFGHIJKL",
            "paths": ["/chaos-test/*"],
        },
        framework.ChaosType.WAF_RULE_MODIFY: {
            "web_acl_id": "11111111-2222-3333-4444-555555555555",
            "web_acl_name": "chaos-test-acl",
            "rule_name": "chaos-test-rule",
            "action": "COUNT",
            "scope": "REGIONAL",
        },
        framework.ChaosType.WAF_RATE_LIMIT_MODIFY: {
            "web_acl_id": "11111111-2222-3333-4444-555555555555",
            "web_acl_name": "chaos-test-acl",
            "rule_name": "chaos-test-rule",
            "limit": 100,
            "scope": "REGIONAL",
        },
        framework.ChaosType.WAF_IP_SET_MODIFY: {
            "ip_set_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "ip_set_name": "chaos-test-ip-set",
            "addresses_to_add": ["198.51.100.10/32"],
            "scope": "REGIONAL",
        },
        framework.ChaosType.KMS_KEY_DISABLE: {"key_id": "alias/chaos-test"},
        framework.ChaosType.KMS_KEY_POLICY_RESTRICT: {
            "key_id": "alias/chaos-test",
            "break_glass_principal_arn": BREAK_GLASS_ARN,
        },
        framework.ChaosType.KMS_GRANT_REVOKE: {
            "key_id": f"arn:aws-us-gov:kms:{REGION}:{ACCOUNT_ID}:key/01234567-89ab-cdef-0123-456789abcdef",
            "grant_id": "0123456789abcdef0123456789abcdef",
        },
        framework.ChaosType.IAM_POLICY_DETACH: {
            "role_name": "ChaosTestRole",
            "policy_arn": f"arn:aws-us-gov:iam::{ACCOUNT_ID}:policy/ChaosTestPolicy",
        },
        framework.ChaosType.IAM_ROLE_MODIFY: {
            "role_name": "ChaosTestRole",
            "max_session_duration": 7200,
        },
        framework.ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE: {
            "user_name": "chaos-test-user",
            "access_key_id": TEST_ACCESS_KEY,
        },
        framework.ChaosType.DS_TRUST_DELETE: {"trust_id": "t-1234567890"},
        framework.ChaosType.DS_CONDITIONAL_FORWARDER_DELETE: {
            "directory_id": "d-1234567890",
            "remote_domain_name": "test.example.invalid",
        },
        framework.ChaosType.APPSTREAM_FLEET_STOP: {"fleet_name": "chaos-test-fleet"},
        framework.ChaosType.APPSTREAM_STACK_DISASSOCIATE: {
            "fleet_name": "chaos-test-fleet",
            "stack_name": "chaos-test-stack",
        },
        framework.ChaosType.ECR_IMAGE_DELETE: {
            "repository_name": "chaos-test-repository",
            "image_ids": [{"imageTag": "chaos-test"}],
        },
        framework.ChaosType.ECR_REPOSITORY_POLICY_RESTRICT: {
            "repository_name": "chaos-test-repository",
            "break_glass_principal_arn": BREAK_GLASS_ARN,
        },
        framework.ChaosType.CODECOMMIT_TRIGGER_DELETE: {
            "repository_name": "chaos-test-repository",
            "trigger_name": "chaos-test-trigger",
        },
        framework.ChaosType.SES_CONFIGURATION_SET_DELETE: {
            "config_set_name": "chaos-test-config"
        },
    }


def make_experiment(
    experiment_type: framework.ChaosType,
    action_config: dict[str, Any],
    fake_aws: FakeAWS,
    *,
    dry_run: bool = True,
) -> framework.ChaosExperiment:
    """Create an experiment through the production dispatch table."""
    orchestrator = object.__new__(framework.ChaosOrchestrator)
    orchestrator.config = {
        "global": {
            "region": REGION,
            "account_id": ACCOUNT_ID,
            "dry_run": dry_run,
            "operator_principal_arn": BREAK_GLASS_ARN,
            "active_access_key_id": OTHER_ACCESS_KEY,
        }
    }
    orchestrator.safety_controller = FakeSafetyController(fake_aws, live=not dry_run)
    if experiment_type in {
        framework.ChaosType.EC2_TERMINATE,
        framework.ChaosType.EBS_DETACH_VOLUME,
        framework.ChaosType.CLOUDFRONT_CACHE_INVALIDATE,
        framework.ChaosType.WAF_IP_SET_MODIFY,
        framework.ChaosType.ECR_IMAGE_DELETE,
        framework.ChaosType.KMS_GRANT_REVOKE,
    }:
        orchestrator.safety_controller.config["target_allowlist"] = sorted(
            framework.ChaosOrchestrator._target_values(
                {"type": experiment_type.value, **action_config}
            )
        )
        orchestrator.safety_controller.config["max_blast_radius"] = (
            framework.ChaosOrchestrator._blast_radius(experiment_type, action_config)
        )
    experiment = orchestrator._create_experiment(experiment_type, action_config)
    experiment.rollback_mode = framework.experiment_metadata(experiment_type).rollback
    return experiment


@pytest.mark.parametrize(
    ("experiment_type", "action_config"),
    sorted(action_configs().items(), key=lambda item: item[0].value),
    ids=lambda value: value.value if isinstance(value, framework.ChaosType) else None,
)
def test_every_supported_action_plans_without_aws_writes(
    experiment_type: framework.ChaosType,
    action_config: dict[str, Any],
) -> None:
    fake_aws = FakeAWS(reject_writes=True)
    experiment = make_experiment(experiment_type, action_config, fake_aws)
    orchestrator = object.__new__(framework.ChaosOrchestrator)

    result = orchestrator._execute_experiment(
        experiment, experiment_type, action_config
    )

    assert result.status in {"planned", "completed"}, result.errors
    assert not result.errors
    assert experiment.mutation_attempts == []
    assert all(
        operation in framework.READ_ONLY_OPERATIONS.get(service, ())
        for service, operation, _request in fake_aws.calls
    )


def test_action_matrix_covers_every_live_supported_type() -> None:
    supported = {
        item
        for item in framework.ChaosType
        if framework.experiment_metadata(item).live_supported
    }
    assert set(
        action_configs()
    ) == supported | framework.CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS | {
        framework.ChaosType.FIS_TEMPLATE
    }


def test_declared_unsupported_actions_are_not_live_supported() -> None:
    gated = framework.UNSUPPORTED_EXPERIMENTS | framework.FIS_TEMPLATE_ONLY_EXPERIMENTS
    assert gated
    assert all(not framework.experiment_metadata(item).live_supported for item in gated)


def test_every_experiment_has_complete_safety_metadata() -> None:
    valid_rollbacks = {"automatic", "managed", "none", "not-required"}
    for experiment_type in framework.ChaosType:
        metadata = framework.experiment_metadata(experiment_type)
        assert metadata.provider
        assert metadata.rollback in valid_rollbacks


def test_sample_configuration_is_valid() -> None:
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    framework.validate_config_data(config)


def test_release_metadata_and_example_are_in_sync() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{framework.__version__}"' in pyproject
    assert (ROOT / "example-config.yaml").read_text(encoding="utf-8") == (
        framework.SAMPLE_CONFIG
    )


def test_version_output_is_stable_when_runtime_is_renamed(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        framework.main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out == (
        f"{framework.TOOL_NAME} {framework.__version__}\n"
    )


def test_type_specific_timeout_validation() -> None:
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    suite = next(iter(config["experiment_suites"].values()))
    suite["experiments"] = [
        {
            "type": "sqs_visibility_timeout",
            "queue_url": "https://sqs.us-gov-west-1.amazonaws.com/000000000000/test",
            "timeout_seconds": 43_200,
        }
    ]
    framework.validate_config_data(config)

    suite["experiments"] = [
        {
            "type": "lambda_timeout_modify",
            "function_name": "chaos-test",
            "timeout_seconds": 901,
        }
    ]
    with pytest.raises(framework.ConfigurationError, match="timeout_seconds"):
        framework.validate_config_data(config)


def test_health_check_timeout_must_be_less_than_interval() -> None:
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    suite = next(iter(config["experiment_suites"].values()))
    suite["experiments"] = [
        {
            "type": "elb_health_check_modify",
            "target_group_arn": "arn:aws-us-gov:elasticloadbalancing:us-gov-west-1:000000000000:targetgroup/test/0123456789abcdef",
            "interval": 30,
            "timeout": 30,
        }
    ]
    with pytest.raises(framework.ConfigurationError, match="less than interval"):
        framework.validate_config_data(config)


def test_runtime_text_redacts_arns_accounts_and_access_keys() -> None:
    text = (
        f"target={INSTANCE_ID} account={ACCOUNT_ID} principal={BREAK_GLASS_ARN} "
        f"key={TEST_ACCESS_KEY}"
    )
    framework.register_sensitive_log_values([INSTANCE_ID])

    redacted = framework.redact_runtime_text(text)

    assert INSTANCE_ID not in redacted
    assert ACCOUNT_ID not in redacted
    assert BREAK_GLASS_ARN not in redacted
    assert TEST_ACCESS_KEY not in redacted


def test_atomic_report_write_refuses_overwrite(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    framework.atomic_write_json(report, {"safe": True})

    with pytest.raises(FileExistsError):
        framework.atomic_write_json(report, {"safe": False})

    assert json.loads(report.read_text(encoding="utf-8")) == {"safe": True}


def test_evidence_report_redacts_identity_and_targets_by_default(
    tmp_path: Path,
) -> None:
    orchestrator = object.__new__(framework.ChaosOrchestrator)
    orchestrator.config = {"reporting": {"include_diagnostics": True}}
    orchestrator.results = [
        framework.ExperimentResult(
            experiment_id="test-result",
            experiment_type=framework.ChaosType.EC2_STOP,
            start_time=framework.utc_now(),
            end_time=framework.utc_now(),
            status="planned",
            affected_resources=[INSTANCE_ID],
            errors=[f"target {INSTANCE_ID} in account {ACCOUNT_ID}"],
            additional_info={
                "snapshot_id": "snap-derived-not-configured",
                "writer_endpoint": "derived-database.internal.invalid",
                "invalidation_id": "DERIVEDCF123",
            },
            metrics_before={"endpoint": "metrics-db.internal.invalid"},
            metrics_after={"members": ["metrics-derived-reader"]},
        )
    ]
    orchestrator.run_id = "offline-test-run"
    orchestrator.suite_name = "offline-test"
    orchestrator.live = False
    orchestrator.region = REGION
    orchestrator.seed = 7
    orchestrator.actual_account = ACCOUNT_ID
    orchestrator.expected_account = ACCOUNT_ID
    orchestrator.caller_arn = BREAK_GLASS_ARN
    orchestrator.vpc_id = "vpc-0123456789abcdef0"
    orchestrator._failed_future_count = 0
    orchestrator.discovered_resources = {"instances": [INSTANCE_ID]}
    orchestrator._sensitive_values_lock = threading.Lock()
    orchestrator._report_sensitive_values = {INSTANCE_ID, ACCOUNT_ID}
    orchestrator.output_dir = tmp_path

    report_path = orchestrator._generate_report()
    report_text = report_path.read_text(encoding="utf-8")
    report = json.loads(report_text)

    assert INSTANCE_ID not in report_text
    assert ACCOUNT_ID not in report_text
    assert BREAK_GLASS_ARN not in report_text
    for derived in (
        "snap-derived-not-configured",
        "derived-database.internal.invalid",
        "DERIVEDCF123",
        "metrics-db.internal.invalid",
        "metrics-derived-reader",
    ):
        assert derived not in report_text
    assert "affected_resources" not in report["experiments"][0]
    assert report["experiments"][0]["affected_resource_count"] == 1


def test_automatic_rollback_failure_is_reported_as_experiment_failure() -> None:
    class BrokenRollbackExperiment:
        mutation_attempts = ["lambda.put_function_concurrency"]
        mutation_operations = ["lambda.put_function_concurrency"]
        rollback_attempts: list[str] = []
        rollback_operations: list[str] = []
        rollback_errors: list[str] = []
        rollback_verified = False
        rollback_mode = "automatic"

        def run_rollback(self) -> None:
            self.rollback_attempts.append("lambda.delete_function_concurrency")
            raise RuntimeError("simulated rollback failure")

    experiment = BrokenRollbackExperiment()
    orchestrator = object.__new__(framework.ChaosOrchestrator)
    orchestrator.config = {"global": {}, "safety": {}}
    orchestrator.region = REGION
    orchestrator.dry_run = False
    orchestrator.live = True
    orchestrator.operator_principal_arn = BREAK_GLASS_ARN
    orchestrator.active_access_key_id = OTHER_ACCESS_KEY
    orchestrator._report_sensitive_values = set()
    orchestrator._sensitive_values_lock = threading.Lock()
    orchestrator._active_experiments_lock = threading.Lock()
    orchestrator.active_experiments = []
    orchestrator.safety_controller = FakeSafetyController(
        FakeAWS(reject_writes=False), live=True
    )
    orchestrator._validate_target_scope = lambda *_args: None
    orchestrator._create_experiment = lambda *_args: experiment
    orchestrator._execute_experiment = lambda *_args: framework.ExperimentResult(
        experiment_id="rollback-test",
        experiment_type=framework.ChaosType.LAMBDA_THROTTLE,
        start_time=framework.utc_now(),
        status="completed",
    )

    result = orchestrator._run_single_experiment(
        {
            "type": "lambda_throttle",
            "function_name": "chaos-test-function",
            "auto_rollback": True,
        }
    )

    assert result.status == "failed"
    assert result.rollback_successful is False
    assert result.rollback_errors == ["simulated rollback failure"]
    assert any("Rollback failed" in error for error in result.errors)


def test_configuration_rejects_gated_action() -> None:
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    suite = next(iter(config["experiment_suites"].values()))
    suite["experiments"] = [
        {"type": "cloudfront_behavior_modify", "distribution_id": "EXAMPLE"}
    ]
    with pytest.raises(framework.ConfigurationError, match="not safely implemented"):
        framework.validate_config_data(config)


def test_live_s3_policy_preserves_policy_and_rolls_back_exactly() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    respond = fake_aws.respond

    def current_policy(service, operation, request):
        writes = [call for call in fake_aws.calls if call[1] == "put_bucket_policy"]
        if operation == "get_bucket_policy" and writes:
            fake_aws.calls.append((service, operation, request))
            return {"Policy": writes[-1][2]["Policy"]}
        return respond(service, operation, request)

    fake_aws.respond = current_policy
    action_config = action_configs()[framework.ChaosType.S3_BUCKET_POLICY_DENY]
    experiment = make_experiment(
        framework.ChaosType.S3_BUCKET_POLICY_DENY,
        action_config,
        fake_aws,
        dry_run=False,
    )

    result = experiment.deny_bucket_policy(**action_config)
    experiment.run_rollback()

    assert result.status == "completed"
    writes = [call for call in fake_aws.calls if call[1] == "put_bucket_policy"]
    assert len(writes) == 2
    applied = json.loads(writes[0][2]["Policy"])
    assert any(item.get("Sid") == "ExistingAccess" for item in applied["Statement"])
    deny = next(
        item for item in applied["Statement"] if item.get("Sid") == "ChaosFrameworkDeny"
    )
    assert deny["Condition"]["ArnNotEquals"]["aws:PrincipalArn"] == BREAK_GLASS_ARN
    assert json.loads(writes[1][2]["Policy"]) == json.loads(experiment.original_policy)
    assert experiment.mutation_attempts == ["s3.put_bucket_policy"]
    assert experiment.rollback_attempts == ["s3.put_bucket_policy"]


def test_live_route_removal_restores_exact_route() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    fake_aws.read_overrides[("ec2", "describe_route_tables")] = [
        fake_aws.respond("ec2", "describe_route_tables", {}),
        {"RouteTables": [{"Routes": []}]},
    ]
    fake_aws.calls.clear()
    action_config = action_configs()[framework.ChaosType.VPC_ROUTE_TABLE_MODIFY]
    experiment = make_experiment(
        framework.ChaosType.VPC_ROUTE_TABLE_MODIFY,
        action_config,
        fake_aws,
        dry_run=False,
    )

    result = experiment.modify_route_table(**action_config)
    experiment.run_rollback()

    assert result.status == "completed"
    delete_call = next(call for call in fake_aws.calls if call[1] == "delete_route")
    create_call = next(call for call in fake_aws.calls if call[1] == "create_route")
    assert delete_call[2]["DestinationCidrBlock"] == "10.20.0.0/16"
    assert create_call[2]["GatewayId"] == "igw-0123456789abcdef0"
    assert create_call[2]["DestinationCidrBlock"] == "10.20.0.0/16"


def test_live_ebs_detach_creates_no_snapshot_and_restores_attachment() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    initial_volume = fake_aws.respond("ec2", "describe_volumes", {})
    available_volume = {
        "Volumes": [
            {
                "VolumeId": VOLUME_ID,
                "VolumeType": "io2",
                "Iops": 3000,
                "State": "available",
                "Attachments": [],
            }
        ]
    }
    restored_volume = {
        "Volumes": [
            {
                "VolumeId": VOLUME_ID,
                "VolumeType": "io2",
                "Iops": 3000,
                "State": "in-use",
                "Attachments": [
                    {
                        "InstanceId": INSTANCE_ID,
                        "Device": "/dev/xvdf",
                        "State": "attached",
                    }
                ],
            }
        ]
    }
    fake_aws.read_overrides[("ec2", "describe_volumes")] = [
        initial_volume,
        copy.deepcopy(initial_volume),
        available_volume,
        available_volume,
        restored_volume,
    ]
    fake_aws.calls.clear()
    original_respond = fake_aws.respond

    def respond(service: str, operation: str, request: dict[str, Any]) -> Any:
        if service == "ec2" and operation == "create_snapshot":
            raise AssertionError("An approved detach must not create data copies")
        return original_respond(service, operation, request)

    fake_aws.respond = respond  # type: ignore[method-assign]
    action_config = action_configs()[framework.ChaosType.EBS_DETACH_VOLUME]
    experiment = make_experiment(
        framework.ChaosType.EBS_DETACH_VOLUME,
        action_config,
        fake_aws,
        dry_run=False,
    )

    result = experiment.detach_volume(**action_config)
    experiment.run_rollback()

    assert result.status == "completed"
    assert "safety_snapshot_id" not in result.additional_info
    operation_names = [operation for _service, operation, _request in fake_aws.calls]
    assert "create_snapshot" not in operation_names
    assert "detach_volume" in operation_names
    assert "attach_volume" in operation_names
    assert experiment.rollback_verified is True


def test_live_efs_throughput_waits_and_restores_original_mode() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    initial = fake_aws.respond("efs", "describe_file_systems", {})
    changed = {
        "FileSystems": [
            {
                "FileSystemId": "fs-0123456789abcdef0",
                "ThroughputMode": "provisioned",
                "ProvisionedThroughputInMibps": 1.0,
                "LifeCycleState": "available",
            }
        ]
    }
    restored = {
        "FileSystems": [
            {
                "FileSystemId": "fs-0123456789abcdef0",
                "ThroughputMode": "provisioned",
                "ProvisionedThroughputInMibps": 2.0,
                "LifeCycleState": "available",
            }
        ]
    }
    fake_aws.read_overrides[("efs", "describe_file_systems")] = [
        initial,
        changed,
        changed,
        restored,
    ]
    fake_aws.calls.clear()
    action_config = action_configs()[framework.ChaosType.EFS_THROTTLE_THROUGHPUT]
    experiment = make_experiment(
        framework.ChaosType.EFS_THROTTLE_THROUGHPUT,
        action_config,
        fake_aws,
        dry_run=False,
    )

    result = experiment.throttle_throughput(**action_config)
    experiment.run_rollback()

    assert result.status == "completed"
    updates = [call for call in fake_aws.calls if call[1] == "update_file_system"]
    assert updates[0][2]["ThroughputMode"] == "provisioned"
    assert updates[0][2]["ProvisionedThroughputInMibps"] == 1.0
    assert updates[1][2] == {
        "FileSystemId": "fs-0123456789abcdef0",
        "ThroughputMode": "provisioned",
        "ProvisionedThroughputInMibps": 2.0,
    }
    assert experiment.rollback_verified is True


def test_live_opensearch_reduction_waits_and_restores_node_count() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    initial = fake_aws.respond("opensearch", "describe_domain", {})
    changed = {
        "DomainStatus": {
            "DomainName": "chaos-test-domain",
            "Processing": False,
            "ClusterConfig": {"InstanceCount": 1},
        }
    }
    restored = {
        "DomainStatus": {
            "DomainName": "chaos-test-domain",
            "Processing": False,
            "ClusterConfig": {"InstanceCount": 2},
        }
    }
    fake_aws.read_overrides[("opensearch", "describe_domain")] = [
        initial,
        changed,
        changed,
        restored,
    ]
    fake_aws.calls.clear()
    action_config = action_configs()[
        framework.ChaosType.OPENSEARCH_CLUSTER_CONFIG_MODIFY
    ]
    experiment = make_experiment(
        framework.ChaosType.OPENSEARCH_CLUSTER_CONFIG_MODIFY,
        action_config,
        fake_aws,
        dry_run=False,
    )

    result = experiment.modify_cluster_config(**action_config)
    experiment.run_rollback()

    assert result.status == "completed"
    updates = [call for call in fake_aws.calls if call[1] == "update_domain_config"]
    assert updates[0][2]["ClusterConfig"] == {"InstanceCount": 1}
    assert updates[1][2]["ClusterConfig"] == {"InstanceCount": 2}
    assert experiment.rollback_verified is True


def test_live_appstream_stop_waits_and_restores_running_state() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    fake_aws.read_overrides[("appstream", "describe_fleets")] = [
        {"Fleets": [{"Name": "chaos-test-fleet", "State": "RUNNING"}]},
        {"Fleets": [{"Name": "chaos-test-fleet", "State": "STOPPED"}]},
        {"Fleets": [{"Name": "chaos-test-fleet", "State": "STOPPED"}]},
        {"Fleets": [{"Name": "chaos-test-fleet", "State": "RUNNING"}]},
    ]
    action_config = action_configs()[framework.ChaosType.APPSTREAM_FLEET_STOP]
    experiment = make_experiment(
        framework.ChaosType.APPSTREAM_FLEET_STOP,
        action_config,
        fake_aws,
        dry_run=False,
    )

    result = experiment.stop_fleet(**action_config)
    experiment.run_rollback()

    assert result.status == "completed"
    operations = [operation for _service, operation, _request in fake_aws.calls]
    assert "stop_fleet" in operations
    assert "start_fleet" in operations
    assert experiment.rollback_verified is True


def test_route_rollback_refuses_to_overwrite_conflict() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    fake_aws.read_overrides[("ec2", "describe_route_tables")] = [
        fake_aws.respond("ec2", "describe_route_tables", {}),
        {
            "RouteTables": [
                {
                    "Routes": [
                        {
                            "DestinationCidrBlock": "10.20.0.0/16",
                            "NatGatewayId": "nat-0123456789abcdef0",
                            "Origin": "CreateRoute",
                        }
                    ]
                }
            ]
        },
    ]
    fake_aws.calls.clear()
    action_config = action_configs()[framework.ChaosType.VPC_ROUTE_TABLE_MODIFY]
    experiment = make_experiment(
        framework.ChaosType.VPC_ROUTE_TABLE_MODIFY,
        action_config,
        fake_aws,
        dry_run=False,
    )
    assert experiment.modify_route_table(**action_config).status == "completed"

    with pytest.raises(framework.SafetyViolation, match="conflicting route"):
        experiment.run_rollback()

    assert not any(call[1] == "create_route" for call in fake_aws.calls)


def test_live_waf_rule_change_uses_lock_token_and_restores() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    original = fake_aws.respond("wafv2", "get_web_acl", {})
    changed = copy.deepcopy(original)
    changed["WebACL"]["Rules"][0]["Action"] = {"Count": {}}
    fake_aws.read_overrides[("wafv2", "get_web_acl")] = [original, changed]
    action_config = action_configs()[framework.ChaosType.WAF_RULE_MODIFY]
    experiment = make_experiment(
        framework.ChaosType.WAF_RULE_MODIFY,
        action_config,
        fake_aws,
        dry_run=False,
    )

    result = experiment.modify_rule(**action_config)
    experiment.run_rollback()

    assert result.status == "completed"
    updates = [call for call in fake_aws.calls if call[1] == "update_web_acl"]
    assert len(updates) == 2
    assert updates[0][2]["LockToken"] == "lock-1"
    assert updates[0][2]["Rules"][0]["Action"] == {"Count": {}}
    assert updates[1][2]["Rules"][0]["Action"] == {"Block": {}}


def test_iam_self_protection_blocks_active_role_and_access_key() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    role_config = {
        **action_configs()[framework.ChaosType.IAM_POLICY_DETACH],
        "operator_principal_arn": f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/ChaosTestRole",
        "dry_run": False,
    }
    role_experiment = make_experiment(
        framework.ChaosType.IAM_POLICY_DETACH,
        role_config,
        fake_aws,
        dry_run=False,
    )
    role_result = role_experiment.detach_policy(
        role_config["role_name"], role_config["policy_arn"]
    )

    key_config = {
        **action_configs()[framework.ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE],
        "active_access_key_id": TEST_ACCESS_KEY,
        "dry_run": False,
    }
    key_experiment = make_experiment(
        framework.ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE,
        key_config,
        fake_aws,
        dry_run=False,
    )
    key_result = key_experiment.deactivate_access_key(
        key_config["user_name"], key_config["access_key_id"]
    )

    assert role_result.status == "failed"
    assert key_result.status == "failed"
    assert not any(
        call[1] in {"detach_role_policy", "update_access_key"}
        for call in fake_aws.calls
    )


def test_fis_template_live_guardrails_require_stop_condition() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    action_config = {
        **action_configs()[framework.ChaosType.FIS_TEMPLATE],
        "region": REGION,
        "account_id": ACCOUNT_ID,
        "dry_run": False,
    }
    experiment = make_experiment(
        framework.ChaosType.FIS_TEMPLATE,
        action_config,
        fake_aws,
        dry_run=False,
    )
    template = fake_aws.respond("fis", "get_experiment_template", {})[
        "experimentTemplate"
    ]
    template["stopConditions"] = [{"source": "none"}]
    fake_aws.read_overrides[("fis", "get_experiment_template")] = [
        {"experimentTemplate": template}
    ]
    fake_aws.calls.clear()

    result = experiment.run_template(action_config["experiment_template_id"])

    assert result.status == "failed"
    assert any("no CloudWatch alarm" in error for error in result.errors)
    assert not any(call[1] == "start_experiment" for call in fake_aws.calls)


def test_fis_template_live_start_is_disabled_without_immutable_binding() -> None:
    fake_aws = FakeAWS(reject_writes=False)
    fake_aws.read_overrides[("fis", "get_experiment")] = [
        {"experiment": {"state": {"status": "completed"}}}
    ]
    original_respond = fake_aws.respond

    def respond(service: str, operation: str, request: dict[str, Any]) -> Any:
        if service == "fis" and operation == "start_experiment":
            fake_aws.calls.append((service, operation, request))
            return {"experiment": {"id": "EXP1234567890abcdef0"}}
        return original_respond(service, operation, request)

    fake_aws.respond = respond  # type: ignore[method-assign]
    action_config = {
        **action_configs()[framework.ChaosType.FIS_TEMPLATE],
        "region": REGION,
        "account_id": ACCOUNT_ID,
        "dry_run": False,
    }
    experiment = make_experiment(
        framework.ChaosType.FIS_TEMPLATE,
        action_config,
        fake_aws,
        dry_run=False,
    )

    result = experiment.run_template(action_config["experiment_template_id"])

    assert result.status == "failed"
    assert any("immutable reviewed template" in error for error in result.errors)
    assert not any(call[1] == "start_experiment" for call in fake_aws.calls)
    assert experiment.mutation_operations == []


@pytest.mark.parametrize(
    ("experiment_type", "read_key", "empty_response"),
    [
        (
            framework.ChaosType.EBS_DETACH_VOLUME,
            ("ec2", "describe_volumes"),
            {"Volumes": []},
        ),
        (
            framework.ChaosType.VPC_ENDPOINT_DELETE,
            ("ec2", "describe_vpc_endpoints"),
            {"VpcEndpoints": []},
        ),
        (
            framework.ChaosType.S3_OBJECT_DELETE,
            ("s3", "list_objects_v2"),
            {},
        ),
        (
            framework.ChaosType.ECS_TASK_STOP,
            ("ecs", "describe_tasks"),
            {"tasks": [], "failures": []},
        ),
    ],
    ids=["ebs-volume", "vpc-endpoint", "s3-object", "ecs-task"],
)
def test_missing_targets_fail_instead_of_claiming_success(
    experiment_type: framework.ChaosType,
    read_key: tuple[str, str],
    empty_response: dict[str, Any],
) -> None:
    fake_aws = FakeAWS(reject_writes=True)
    fake_aws.read_overrides[read_key] = [empty_response]
    action_config = action_configs()[experiment_type]
    experiment = make_experiment(experiment_type, action_config, fake_aws)
    orchestrator = object.__new__(framework.ChaosOrchestrator)

    result = orchestrator._execute_experiment(
        experiment, experiment_type, action_config
    )

    assert result.status == "failed"
    assert result.errors
    assert experiment.mutation_attempts == []


def test_static_sdk_operations_and_keyword_names_match_botocore_models() -> None:
    """Catch misspelled AWS operations and request fields without calling AWS."""
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    service_by_attribute = {
        "ec2": "ec2",
        "ssm": "ssm",
        "cloudwatch": "cloudwatch",
        "efs": "efs",
        "rds": "rds",
        "lambda_client": "lambda",
        "s3": "s3",
        "sqs": "sqs",
        "sns": "sns",
        "elbv2": "elbv2",
        "ecs": "ecs",
        "kinesis": "kinesis",
        "opensearch": "opensearch",
        "cloudfront": "cloudfront",
        "wafv2": "wafv2",
        "kms": "kms",
        "iam": "iam",
        "ds": "ds",
        "appstream": "appstream",
        "ecr": "ecr",
        "codecommit": "codecommit",
        "ses": "ses",
        "fis": "fis",
    }
    session = boto3.Session(
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
        aws_session_token="offline",
        region_name=REGION,
    )
    models = {
        service: session.client(service).meta.service_model
        for service in set(service_by_attribute.values())
    }
    source = (ROOT / "aws_chaos_framework.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    findings: list[str] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "self"
        ):
            continue
        attribute = node.func.value.attr
        service = service_by_attribute.get(attribute)
        if service is None:
            continue
        operation_by_method = {
            xform_name(operation): operation
            for operation in models[service].operation_names
        }
        api_operation = operation_by_method.get(node.func.attr)
        if api_operation is None:
            findings.append(f"{service}.{node.func.attr}: unknown operation")
            continue
        operation_model = models[service].operation_model(api_operation)
        allowed = (
            set(operation_model.input_shape.members)
            if operation_model.input_shape is not None
            else set()
        )
        for keyword in node.keywords:
            if keyword.arg is not None and keyword.arg not in allowed:
                findings.append(
                    f"{service}.{node.func.attr}: unknown field {keyword.arg}"
                )

    assert findings == []


def test_repository_text_uses_ascii_dashes() -> None:
    forbidden = {chr(0x2013), chr(0x2014)}
    text_suffixes = {".py", ".md", ".txt", ".toml", ".yaml", ".yml", ".cff"}
    special_names = {"LICENSE", ".gitignore", ".gitattributes", ".editorconfig"}
    findings = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix not in text_suffixes and path.name not in special_names:
            continue
        content = path.read_text(encoding="utf-8")
        if any(character in content for character in forbidden):
            findings.append(str(path.relative_to(ROOT)))
    assert findings == []
