#!/usr/bin/env python3
"""AWS Chaos Engineering Framework.

One-file orchestration for AWS Fault Injection Service experiments and guarded
extensions for AWS services that FIS does not cover directly. The framework is
safe by default: live execution requires account binding, an exact confirmation
token, bounded targets, and additional approval for irreversible operations.
"""

from __future__ import annotations

import argparse
import atexit
import copy
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import signal
import sys
import tempfile
import threading
import time
import unicodedata
import uuid
from collections.abc import Iterable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    import boto3
    import yaml
    from botocore.config import Config as BotocoreConfig
    from botocore.exceptions import ClientError
except ImportError as exc:  # pragma: no cover - exercised by packaging smoke tests
    raise SystemExit(
        "Missing dependency. Install boto3, botocore, and PyYAML before running this tool."
    ) from exc


__version__ = "2.0.4"
TOOL_NAME = "AWS Chaos Engineering Framework"
MAX_CONFIG_BYTES = 1_048_576
DEFAULT_REGION = "us-gov-west-1"
GOVCLOUD_REGIONS = frozenset({"us-gov-west-1", "us-gov-east-1"})
READ_ONLY_OPERATION_PREFIXES = (
    "batch_get_",
    "can_paginate",
    "describe_",
    "generate_presigned_",
    "get_",
    "head_",
    "list_",
    "lookup_",
    "search_",
    "test_",
    "validate_",
)
SECRET_KEY_PATTERN = re.compile(
    r"(?:secret|password|token|credential|private|access[_-]?key|session[_-]?key)",
    re.IGNORECASE,
)
ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")
VPC_ID_PATTERN = re.compile(r"^vpc-[0-9a-f]{8,17}$", re.IGNORECASE)
ARN_PATTERN = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):[^\s,;\]\[{}\"']+")
ACCESS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
ACCOUNT_IN_TEXT_PATTERN = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")

logger = logging.getLogger("aws_chaos_framework")
_SENSITIVE_LOG_VALUES: ContextVar[frozenset[str]] = ContextVar(
    "chaos_sensitive_log_values", default=frozenset()
)
MAX_SENSITIVE_LOG_VALUES = 4096
# No live baseline capture may overlap another live mutation or recovery in this
# process, even when callers use different orchestrators or target aliases.
_LIVE_EXPERIMENT_LOCK = threading.RLock()
# Recovery uncertainty persists across orchestrators. Only reconciliation and a
# new process may permit another live baseline after this latch is set.
_LIVE_RECOVERY_BLOCKED = threading.Event()
# Signals and safety failures stop forward work across every controller.
_PROCESS_EMERGENCY_STOP = threading.Event()


class ConfigurationError(ValueError):
    """Raised when configuration cannot be executed safely."""


class SafetyViolation(RuntimeError):
    """Raised when a live safety guardrail is not satisfied."""


class EmergencyStop(RuntimeError):
    """Raised when an experiment must stop and roll back."""


class RiskLevel(Enum):
    """Risk classification for an experiment."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    IRREVERSIBLE = "irreversible"


def _experiment_id(prefix: str) -> str:
    """Generate a unique experiment ID using timestamp + short UUID."""
    return f"{prefix}-{utc_now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"


class ChaosType(Enum):
    """Types of chaos experiments"""

    # Native AWS Fault Injection Service orchestration
    FIS_TEMPLATE = "fis_template"

    # EC2 Chaos
    EC2_TERMINATE = "ec2_terminate"
    EC2_STOP = "ec2_stop"
    EC2_REBOOT = "ec2_reboot"
    EC2_NETWORK_LATENCY = "ec2_network_latency"
    EC2_NETWORK_PACKET_LOSS = "ec2_network_packet_loss"
    EC2_CPU_STRESS = "ec2_cpu_stress"
    EC2_MEMORY_STRESS = "ec2_memory_stress"
    EC2_DISK_STRESS = "ec2_disk_stress"
    EC2_DISK_FILL = "ec2_disk_fill"

    # EBS Chaos
    EBS_DETACH_VOLUME = "ebs_detach_volume"
    EBS_SNAPSHOT_DELAY = "ebs_snapshot_delay"
    EBS_THROTTLE_IOPS = "ebs_throttle_iops"

    # EFS Chaos
    EFS_THROTTLE_THROUGHPUT = "efs_throttle_throughput"
    EFS_MOUNT_TARGET_DELETE = "efs_mount_target_delete"

    # VPC Chaos
    VPC_SUBNET_ACL_MODIFY = "vpc_subnet_acl_modify"
    VPC_ROUTE_TABLE_MODIFY = "vpc_route_table_modify"
    VPC_SECURITY_GROUP_MODIFY = "vpc_security_group_modify"
    VPC_NACL_BLOCK_TRAFFIC = "vpc_nacl_block_traffic"
    VPC_PEERING_DELETE = "vpc_peering_delete"
    VPC_ENDPOINT_DELETE = "vpc_endpoint_delete"

    # RDS Chaos
    RDS_FAILOVER = "rds_failover"
    RDS_REBOOT = "rds_reboot"
    RDS_BACKUP_RETENTION_MODIFY = "rds_backup_retention_modify"
    RDS_PARAMETER_GROUP_MODIFY = "rds_parameter_group_modify"

    # Lambda Chaos
    LAMBDA_THROTTLE = "lambda_throttle"
    LAMBDA_ERROR_INJECTION = "lambda_error_injection"
    LAMBDA_TIMEOUT_MODIFY = "lambda_timeout_modify"
    LAMBDA_MEMORY_LIMIT = "lambda_memory_limit"
    LAMBDA_ENVIRONMENT_CORRUPT = "lambda_environment_corrupt"

    # S3 Chaos
    S3_BUCKET_POLICY_DENY = "s3_bucket_policy_deny"
    S3_BUCKET_VERSIONING_SUSPEND = "s3_bucket_versioning_suspend"
    S3_BUCKET_ENCRYPTION_DISABLE = "s3_bucket_encryption_disable"
    S3_OBJECT_DELETE = "s3_object_delete"
    S3_LIFECYCLE_MODIFY = "s3_lifecycle_modify"

    # SQS Chaos
    SQS_QUEUE_PURGE = "sqs_queue_purge"
    SQS_QUEUE_POLICY_RESTRICT = "sqs_queue_policy_restrict"
    SQS_MESSAGE_DELAY = "sqs_message_delay"
    SQS_VISIBILITY_TIMEOUT = "sqs_visibility_timeout"

    # SNS Chaos
    SNS_SUBSCRIPTION_DELETE = "sns_subscription_delete"
    SNS_TOPIC_POLICY_RESTRICT = "sns_topic_policy_restrict"
    SNS_MESSAGE_ATTRIBUTE_CORRUPT = "sns_message_attribute_corrupt"

    # ELB/ALB/NLB Chaos
    ELB_REMOVE_TARGETS = "elb_remove_targets"
    ELB_MODIFY_ATTRIBUTES = "elb_modify_attributes"
    ELB_LISTENER_RULE_MODIFY = "elb_listener_rule_modify"
    ELB_HEALTH_CHECK_MODIFY = "elb_health_check_modify"

    # ECS Chaos
    ECS_TASK_STOP = "ecs_task_stop"
    ECS_SERVICE_UPDATE = "ecs_service_update"
    ECS_CONTAINER_INSTANCE_DRAIN = "ecs_container_instance_drain"
    ECS_TASK_DEFINITION_MODIFY = "ecs_task_definition_modify"

    # Kinesis Chaos
    KINESIS_SHARD_SPLIT = "kinesis_shard_split"
    KINESIS_SHARD_MERGE = "kinesis_shard_merge"
    KINESIS_RETENTION_MODIFY = "kinesis_retention_modify"
    KINESIS_THROUGHPUT_LIMIT = "kinesis_throughput_limit"

    # OpenSearch Chaos
    OPENSEARCH_NODE_RESTART = "opensearch_node_restart"
    OPENSEARCH_CLUSTER_CONFIG_MODIFY = "opensearch_cluster_config_modify"
    OPENSEARCH_INDEX_DELETE = "opensearch_index_delete"

    # CloudFront Chaos
    CLOUDFRONT_BEHAVIOR_MODIFY = "cloudfront_behavior_modify"
    CLOUDFRONT_ORIGIN_FAILOVER = "cloudfront_origin_failover"
    CLOUDFRONT_CACHE_INVALIDATE = "cloudfront_cache_invalidate"

    # WAF Chaos
    WAF_RULE_MODIFY = "waf_rule_modify"
    WAF_RATE_LIMIT_MODIFY = "waf_rate_limit_modify"
    WAF_IP_SET_MODIFY = "waf_ip_set_modify"

    # KMS Chaos
    KMS_KEY_DISABLE = "kms_key_disable"
    KMS_KEY_POLICY_RESTRICT = "kms_key_policy_restrict"
    KMS_GRANT_REVOKE = "kms_grant_revoke"

    # IAM Chaos
    IAM_POLICY_DETACH = "iam_policy_detach"
    IAM_ROLE_MODIFY = "iam_role_modify"
    IAM_USER_ACCESS_KEY_DEACTIVATE = "iam_user_access_key_deactivate"

    # Directory Service Chaos
    DS_TRUST_DELETE = "ds_trust_delete"
    DS_CONDITIONAL_FORWARDER_DELETE = "ds_conditional_forwarder_delete"

    # AppStream Chaos
    APPSTREAM_FLEET_STOP = "appstream_fleet_stop"
    APPSTREAM_STACK_DISASSOCIATE = "appstream_stack_disassociate"

    # ECR Chaos
    ECR_IMAGE_DELETE = "ecr_image_delete"
    ECR_REPOSITORY_POLICY_RESTRICT = "ecr_repository_policy_restrict"

    # CodeCommit Chaos
    CODECOMMIT_TRIGGER_DELETE = "codecommit_trigger_delete"
    CODECOMMIT_BRANCH_PROTECT = "codecommit_branch_protect"

    # SES Chaos
    SES_CONFIGURATION_SET_DELETE = "ses_configuration_set_delete"
    SES_SENDING_QUOTA_LIMIT = "ses_sending_quota_limit"


@dataclass(frozen=True)
class ExperimentMetadata:
    """Safety and implementation metadata for an experiment type."""

    provider: str
    risk: RiskLevel
    live_supported: bool
    rollback: str
    fis_alternative: bool = False


UNSUPPORTED_EXPERIMENTS = frozenset(
    {
        ChaosType.EBS_SNAPSHOT_DELAY,
        ChaosType.SNS_MESSAGE_ATTRIBUTE_CORRUPT,
        ChaosType.S3_BUCKET_ENCRYPTION_DISABLE,
        ChaosType.ECS_TASK_DEFINITION_MODIFY,
        ChaosType.KINESIS_SHARD_SPLIT,
        ChaosType.KINESIS_SHARD_MERGE,
        ChaosType.KINESIS_THROUGHPUT_LIMIT,
        ChaosType.OPENSEARCH_NODE_RESTART,
        ChaosType.OPENSEARCH_INDEX_DELETE,
        ChaosType.CLOUDFRONT_BEHAVIOR_MODIFY,
        ChaosType.CLOUDFRONT_ORIGIN_FAILOVER,
        ChaosType.CODECOMMIT_BRANCH_PROTECT,
        ChaosType.SES_SENDING_QUOTA_LIMIT,
    }
)

FIS_TEMPLATE_ONLY_EXPERIMENTS = frozenset(
    {
        ChaosType.EC2_NETWORK_LATENCY,
        ChaosType.EC2_NETWORK_PACKET_LOSS,
        ChaosType.EC2_CPU_STRESS,
        ChaosType.EC2_MEMORY_STRESS,
        ChaosType.EC2_DISK_STRESS,
        ChaosType.EC2_DISK_FILL,
    }
)

IRREVERSIBLE_EXPERIMENTS = frozenset(
    {
        ChaosType.EC2_TERMINATE,
        ChaosType.RDS_BACKUP_RETENTION_MODIFY,
        ChaosType.S3_LIFECYCLE_MODIFY,
        ChaosType.EFS_MOUNT_TARGET_DELETE,
        ChaosType.VPC_PEERING_DELETE,
        ChaosType.VPC_ENDPOINT_DELETE,
        ChaosType.S3_OBJECT_DELETE,
        ChaosType.SQS_QUEUE_PURGE,
        ChaosType.SNS_SUBSCRIPTION_DELETE,
        ChaosType.ECS_TASK_STOP,
        ChaosType.KINESIS_RETENTION_MODIFY,
        ChaosType.KMS_GRANT_REVOKE,
        ChaosType.DS_TRUST_DELETE,
        ChaosType.ECR_IMAGE_DELETE,
        ChaosType.SES_CONFIGURATION_SET_DELETE,
    }
)

HIGH_RISK_EXPERIMENTS = frozenset(
    {
        ChaosType.EC2_DISK_FILL,
        ChaosType.EBS_DETACH_VOLUME,
        ChaosType.VPC_SUBNET_ACL_MODIFY,
        ChaosType.VPC_ROUTE_TABLE_MODIFY,
        ChaosType.VPC_SECURITY_GROUP_MODIFY,
        ChaosType.VPC_NACL_BLOCK_TRAFFIC,
        ChaosType.RDS_PARAMETER_GROUP_MODIFY,
        ChaosType.LAMBDA_ENVIRONMENT_CORRUPT,
        ChaosType.S3_BUCKET_POLICY_DENY,
        ChaosType.S3_BUCKET_VERSIONING_SUSPEND,
        ChaosType.S3_BUCKET_ENCRYPTION_DISABLE,
        ChaosType.SQS_QUEUE_POLICY_RESTRICT,
        ChaosType.SNS_TOPIC_POLICY_RESTRICT,
        ChaosType.WAF_RULE_MODIFY,
        ChaosType.WAF_RATE_LIMIT_MODIFY,
        ChaosType.WAF_IP_SET_MODIFY,
        ChaosType.KMS_KEY_DISABLE,
        ChaosType.KMS_KEY_POLICY_RESTRICT,
        ChaosType.IAM_POLICY_DETACH,
        ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE,
        ChaosType.DS_CONDITIONAL_FORWARDER_DELETE,
        ChaosType.ECR_REPOSITORY_POLICY_RESTRICT,
    }
)

LOW_RISK_EXPERIMENTS = frozenset(
    {
        ChaosType.EC2_REBOOT,
        ChaosType.RDS_FAILOVER,
        ChaosType.RDS_REBOOT,
        ChaosType.CLOUDFRONT_CACHE_INVALIDATE,
    }
)

NO_ROLLBACK_REQUIRED_EXPERIMENTS = frozenset(
    set(LOW_RISK_EXPERIMENTS)
    | {
        ChaosType.EC2_CPU_STRESS,
        ChaosType.EC2_MEMORY_STRESS,
        ChaosType.EC2_DISK_STRESS,
    }
)

FIS_PREFERRED_EXPERIMENTS = frozenset(
    {
        ChaosType.EC2_STOP,
        ChaosType.EC2_REBOOT,
        ChaosType.EC2_NETWORK_LATENCY,
        ChaosType.EC2_NETWORK_PACKET_LOSS,
        ChaosType.EC2_CPU_STRESS,
        ChaosType.EC2_MEMORY_STRESS,
        ChaosType.EC2_DISK_STRESS,
        ChaosType.EC2_DISK_FILL,
        ChaosType.EBS_DETACH_VOLUME,
        ChaosType.RDS_FAILOVER,
        ChaosType.RDS_REBOOT,
        ChaosType.ECS_TASK_STOP,
        ChaosType.KINESIS_THROUGHPUT_LIMIT,
        ChaosType.LAMBDA_ERROR_INJECTION,
    }
)

CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS = frozenset(
    {
        ChaosType.VPC_NACL_BLOCK_TRAFFIC,
        ChaosType.SQS_QUEUE_POLICY_RESTRICT,
        ChaosType.SQS_MESSAGE_DELAY,
        ChaosType.SQS_VISIBILITY_TIMEOUT,
        ChaosType.KMS_KEY_DISABLE,
        ChaosType.KMS_KEY_POLICY_RESTRICT,
        ChaosType.IAM_POLICY_DETACH,
        ChaosType.IAM_ROLE_MODIFY,
        ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE,
        ChaosType.ECR_REPOSITORY_POLICY_RESTRICT,
        ChaosType.CODECOMMIT_TRIGGER_DELETE,
    }
)
# These APIs have no conditional ownership/revision argument. A local lock or
# reread cannot distinguish another principal's identical change or close the
# read/write race. Keep planning, but do not create a fault requiring this recovery.
CONCURRENCY_UNSAFE_MUTATIONS = frozenset(
    {
        "ec2.create_network_acl_entry",
        "ec2.delete_network_acl_entry",
        "sqs.set_queue_attributes",
        "kms.disable_key",
        "kms.enable_key",
        "kms.put_key_policy",
        "iam.detach_role_policy",
        "iam.attach_role_policy",
        "iam.update_role",
        "iam.update_access_key",
        "ecr.set_repository_policy",
        "ecr.delete_repository_policy",
        "codecommit.put_repository_triggers",
    }
)

REQUIRED_PARAMETERS: dict[ChaosType, tuple[str, ...]] = {
    ChaosType.FIS_TEMPLATE: ("experiment_template_id",),
    ChaosType.EC2_TERMINATE: ("instance_ids", "delete_on_termination_volumes"),
    ChaosType.EC2_STOP: ("instance_ids",),
    ChaosType.EC2_REBOOT: ("instance_ids",),
    ChaosType.EC2_NETWORK_LATENCY: ("instance_ids",),
    ChaosType.EC2_NETWORK_PACKET_LOSS: ("instance_ids",),
    ChaosType.EC2_CPU_STRESS: ("instance_ids",),
    ChaosType.EC2_MEMORY_STRESS: ("instance_ids",),
    ChaosType.EC2_DISK_STRESS: ("instance_ids",),
    ChaosType.EC2_DISK_FILL: ("instance_ids",),
    ChaosType.EBS_DETACH_VOLUME: ("volume_id", "attachment"),
    ChaosType.EBS_THROTTLE_IOPS: ("volume_id",),
    ChaosType.EFS_MOUNT_TARGET_DELETE: ("mount_target_id",),
    ChaosType.EFS_THROTTLE_THROUGHPUT: ("file_system_id",),
    ChaosType.VPC_SUBNET_ACL_MODIFY: ("subnet_id", "nacl_id"),
    ChaosType.VPC_ROUTE_TABLE_MODIFY: ("route_table_id", "destination_cidr"),
    ChaosType.VPC_SECURITY_GROUP_MODIFY: ("group_id", "remove_rule"),
    ChaosType.VPC_NACL_BLOCK_TRAFFIC: ("nacl_id",),
    ChaosType.VPC_PEERING_DELETE: ("peering_connection_id",),
    ChaosType.VPC_ENDPOINT_DELETE: ("endpoint_id",),
    ChaosType.RDS_FAILOVER: ("cluster_identifier",),
    ChaosType.RDS_REBOOT: ("db_instance_identifier",),
    ChaosType.RDS_BACKUP_RETENTION_MODIFY: ("db_identifier",),
    ChaosType.RDS_PARAMETER_GROUP_MODIFY: ("parameter_group_name", "parameters"),
    ChaosType.LAMBDA_THROTTLE: ("function_name",),
    ChaosType.LAMBDA_ERROR_INJECTION: ("function_name",),
    ChaosType.LAMBDA_TIMEOUT_MODIFY: ("function_name",),
    ChaosType.LAMBDA_MEMORY_LIMIT: ("function_name",),
    ChaosType.LAMBDA_ENVIRONMENT_CORRUPT: ("function_name", "corrupt_vars"),
    ChaosType.S3_BUCKET_POLICY_DENY: ("bucket_name", "break_glass_principal_arn"),
    ChaosType.S3_BUCKET_VERSIONING_SUSPEND: ("bucket_name",),
    ChaosType.S3_BUCKET_ENCRYPTION_DISABLE: ("bucket_name",),
    ChaosType.S3_OBJECT_DELETE: ("bucket_name", "prefix"),
    ChaosType.S3_LIFECYCLE_MODIFY: ("bucket_name",),
    ChaosType.SQS_QUEUE_PURGE: ("queue_url", "queue_arn"),
    ChaosType.SQS_QUEUE_POLICY_RESTRICT: ("queue_url", "break_glass_principal_arn"),
    ChaosType.SQS_MESSAGE_DELAY: ("queue_url",),
    ChaosType.SQS_VISIBILITY_TIMEOUT: ("queue_url",),
    ChaosType.SNS_SUBSCRIPTION_DELETE: ("subscription_arn",),
    ChaosType.SNS_TOPIC_POLICY_RESTRICT: ("topic_arn", "break_glass_principal_arn"),
    ChaosType.ELB_REMOVE_TARGETS: ("target_group_arn", "target_ids"),
    ChaosType.ELB_MODIFY_ATTRIBUTES: ("target_group_arn",),
    ChaosType.ELB_LISTENER_RULE_MODIFY: ("rule_arn",),
    ChaosType.ELB_HEALTH_CHECK_MODIFY: ("target_group_arn",),
    ChaosType.ECS_TASK_STOP: ("cluster", "task_arns"),
    ChaosType.ECS_SERVICE_UPDATE: ("cluster", "service"),
    ChaosType.ECS_CONTAINER_INSTANCE_DRAIN: ("cluster", "container_instance_arn"),
    ChaosType.ECS_TASK_DEFINITION_MODIFY: ("task_definition",),
    ChaosType.KINESIS_SHARD_SPLIT: (
        "stream_name",
        "shard_to_split",
        "new_starting_hash_key",
    ),
    ChaosType.KINESIS_SHARD_MERGE: ("stream_name", "shard_to_merge", "adjacent_shard"),
    ChaosType.KINESIS_RETENTION_MODIFY: ("stream_name",),
    ChaosType.KINESIS_THROUGHPUT_LIMIT: ("stream_name",),
    ChaosType.OPENSEARCH_CLUSTER_CONFIG_MODIFY: ("domain_name",),
    ChaosType.CLOUDFRONT_BEHAVIOR_MODIFY: ("distribution_id",),
    ChaosType.CLOUDFRONT_CACHE_INVALIDATE: ("distribution_id",),
    ChaosType.WAF_RULE_MODIFY: ("web_acl_id", "web_acl_name", "rule_name"),
    ChaosType.WAF_RATE_LIMIT_MODIFY: (
        "web_acl_id",
        "web_acl_name",
        "rule_name",
    ),
    ChaosType.WAF_IP_SET_MODIFY: ("ip_set_id", "ip_set_name", "addresses_to_add"),
    ChaosType.KMS_KEY_DISABLE: ("key_id",),
    ChaosType.KMS_KEY_POLICY_RESTRICT: ("key_id", "break_glass_principal_arn"),
    ChaosType.KMS_GRANT_REVOKE: ("key_id", "grant_id"),
    ChaosType.IAM_POLICY_DETACH: ("role_name", "policy_arn"),
    ChaosType.IAM_ROLE_MODIFY: ("role_name",),
    ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE: ("user_name", "access_key_id"),
    ChaosType.DS_TRUST_DELETE: ("trust_id",),
    ChaosType.DS_CONDITIONAL_FORWARDER_DELETE: ("directory_id", "remote_domain_name"),
    ChaosType.APPSTREAM_FLEET_STOP: ("fleet_name",),
    ChaosType.APPSTREAM_STACK_DISASSOCIATE: ("fleet_name", "stack_name"),
    ChaosType.ECR_IMAGE_DELETE: ("repository_name", "image_ids"),
    ChaosType.ECR_REPOSITORY_POLICY_RESTRICT: (
        "repository_name",
        "break_glass_principal_arn",
    ),
    ChaosType.CODECOMMIT_TRIGGER_DELETE: ("repository_name", "trigger_name"),
    ChaosType.SES_CONFIGURATION_SET_DELETE: ("config_set_name",),
}

TARGET_PARAMETER_KEYS = frozenset(
    {
        "web_acl_name",
        "rule_name",
        "ip_set_name",
        "route_table_id",
        "destination_cidr",
        "remote_domain_name",
        "trigger_name",
        "shard_to_merge",
        "shard_to_split",
        "adjacent_shard",
        "image_ids",
        "objects",
        "prefix",
        "access_key_id",
        "branch_name",
        "bucket_name",
        "cluster",
        "cluster_identifier",
        "config_set_name",
        "container_instance_arn",
        "db_identifier",
        "db_instance_identifier",
        "directory_id",
        "distribution_id",
        "domain_name",
        "endpoint_id",
        "experiment_template_id",
        "file_system_id",
        "fleet_name",
        "function_name",
        "grant_id",
        "group_id",
        "instance_id",
        "instance_ids",
        "ip_set_id",
        "key_id",
        "mount_target_id",
        "nacl_id",
        "parameter_group_name",
        "peering_connection_id",
        "policy_arn",
        "queue_url",
        "repository_name",
        "role_name",
        "rule_arn",
        "service",
        "stack_name",
        "stream_name",
        "subnet_id",
        "subscription_arn",
        "target_group_arn",
        "target_ids",
        "task_arns",
        "task_definition",
        "topic_arn",
        "trust_id",
        "user_name",
        "volume_id",
        "web_acl_id",
    }
)

PRIMARY_TARGET_KEYS: dict[ChaosType, tuple[str, ...]] = {
    ChaosType.EC2_TERMINATE: ("instance_ids",),
    ChaosType.EC2_STOP: ("instance_ids",),
    ChaosType.EC2_REBOOT: ("instance_ids",),
    ChaosType.EC2_NETWORK_LATENCY: ("instance_ids",),
    ChaosType.EC2_NETWORK_PACKET_LOSS: ("instance_ids",),
    ChaosType.EC2_CPU_STRESS: ("instance_ids",),
    ChaosType.EC2_MEMORY_STRESS: ("instance_ids",),
    ChaosType.EC2_DISK_STRESS: ("instance_ids",),
    ChaosType.EC2_DISK_FILL: ("instance_ids",),
    ChaosType.ELB_REMOVE_TARGETS: ("target_ids",),
    ChaosType.ECS_TASK_STOP: ("task_arns",),
    ChaosType.ECR_IMAGE_DELETE: ("image_ids",),
}


def experiment_metadata(experiment_type: ChaosType) -> ExperimentMetadata:
    """Return authoritative support and risk metadata."""
    if experiment_type == ChaosType.FIS_TEMPLATE:
        return ExperimentMetadata("fis", RiskLevel.MEDIUM, False, "managed")
    if experiment_type in FIS_TEMPLATE_ONLY_EXPERIMENTS:
        risk = (
            RiskLevel.HIGH
            if experiment_type in HIGH_RISK_EXPERIMENTS
            else RiskLevel.MEDIUM
        )
        return ExperimentMetadata("fis-template", risk, False, "managed", True)
    if experiment_type in UNSUPPORTED_EXPERIMENTS:
        return ExperimentMetadata("extension", RiskLevel.HIGH, False, "none")
    if experiment_type in CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS:
        return ExperimentMetadata("extension", RiskLevel.HIGH, False, "none")
    risk = RiskLevel.MEDIUM
    rollback = "automatic"
    if experiment_type in IRREVERSIBLE_EXPERIMENTS:
        risk = RiskLevel.IRREVERSIBLE
    elif experiment_type in HIGH_RISK_EXPERIMENTS:
        risk = RiskLevel.HIGH
    elif experiment_type in LOW_RISK_EXPERIMENTS:
        risk = RiskLevel.LOW

    if experiment_type in IRREVERSIBLE_EXPERIMENTS:
        rollback = "none"
    elif experiment_type in NO_ROLLBACK_REQUIRED_EXPERIMENTS:
        rollback = "not-required"
    return ExperimentMetadata(
        "extension",
        risk,
        True,
        rollback,
        experiment_type in FIS_PREFERRED_EXPERIMENTS,
    )


def derived_target_scope(
    experiment_type: ChaosType, config: dict[str, Any]
) -> set[str]:
    """Validate the explicit, digest-bound child resources and attachment tuple."""
    if experiment_type == ChaosType.EC2_TERMINATE:
        expected = config.get("delete_on_termination_volumes")
        instances = config.get("instance_ids")
        if (
            not isinstance(instances, list)
            or not instances
            or not isinstance(expected, dict)
            or set(expected) != set(instances)
        ):
            raise ConfigurationError(
                "EC2 termination needs an exact delete_on_termination_volumes mapping for every instance"
            )
        volumes: list[str] = []
        for instance, children in expected.items():
            if (
                not isinstance(instance, str)
                or not re.fullmatch(r"i-[0-9a-f]{8,17}", instance)
                or not isinstance(children, list)
            ):
                raise ConfigurationError("Invalid EC2 derived resource approval")
            if any(
                not isinstance(child, str)
                or not re.fullmatch(r"vol-[0-9a-f]{8,17}", child)
                for child in children
            ):
                raise ConfigurationError(
                    "Invalid EC2 DeleteOnTermination volume approval"
                )
            volumes.extend(children)
        if len(volumes) != len(set(volumes)):
            raise ConfigurationError("EC2 derived volume approvals must be unique")
        return set(volumes)
    if experiment_type == ChaosType.EBS_DETACH_VOLUME:
        expected = config.get("attachment")
        if not isinstance(expected, dict) or set(expected) != {"instance_id", "device"}:
            raise ConfigurationError(
                "EBS detach needs the exact approved instance/device attachment"
            )
        instance, device = expected["instance_id"], expected["device"]
        if (
            not isinstance(instance, str)
            or not re.fullmatch(r"i-[0-9a-f]{8,17}", instance)
            or not isinstance(device, str)
            or not re.fullmatch(r"/dev/[A-Za-z0-9_./-]{1,100}", device)
        ):
            raise ConfigurationError("Invalid approved EBS attachment tuple")
        return {instance, f"attachment:{instance}:{device}"}
    return set()


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def sanitize_for_log(value: Any, key: str = "") -> Any:
    """Redact credential-like fields before logging or reporting config data."""
    if key and SECRET_KEY_PATTERN.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): sanitize_for_log(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_for_log(item, key) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_for_log(item, key) for item in value)
    return value


def register_sensitive_log_values(values: Iterable[Any]) -> None:
    """Register exact values in the current run/worker context, including short IDs."""
    candidates = _SENSITIVE_LOG_VALUES.get() | frozenset(
        str(value) for value in values if value is not None and str(value)
    )
    if len(candidates) > MAX_SENSITIVE_LOG_VALUES:
        raise ConfigurationError("Too many sensitive log values in one run")
    _SENSITIVE_LOG_VALUES.set(candidates)


@contextmanager
def sensitive_log_scope(values: Iterable[Any]):
    """Give one run or worker a fresh registry and restore its caller on exit."""
    token = _SENSITIVE_LOG_VALUES.set(frozenset())
    try:
        register_sensitive_log_values(values)
        yield
    finally:
        _SENSITIVE_LOG_VALUES.reset(token)


def safe_display(value: Any) -> str:
    """Escape record separators, terminal controls, and Unicode format controls."""
    return "".join(
        json.dumps(char, ensure_ascii=True)[1:-1]
        if unicodedata.category(char).startswith("C")
        or unicodedata.category(char) in {"Zl", "Zp"}
        else char
        for char in str(value)
    )


def redact_runtime_text(
    value: Any, protected_values: Iterable[str] | None = None
) -> str:
    """Redact common AWS identifiers and registered target values from text."""
    protected = (
        _SENSITIVE_LOG_VALUES.get() if protected_values is None else protected_values
    )
    values = sorted({item for item in protected if item}, key=len, reverse=True)
    alternatives = [
        f"(?P<ARN>{ARN_PATTERN.pattern})",
        f"(?P<ACCESS_KEY>{ACCESS_KEY_PATTERN.pattern})",
        f"(?P<ACCOUNT>{ACCOUNT_IN_TEXT_PATTERN.pattern})",
    ]
    if values:
        alternatives.append(
            r"(?P<RESOURCE>(?<!\w)(?:"
            + "|".join(re.escape(item) for item in values)
            + r")(?!\w))"
        )
    # One pass protects only markers we emit. Raw bracketed names and marker-
    # shaped target names remain eligible, while generated markers are never
    # reprocessed by another target replacement.
    text_value = re.sub(
        "|".join(alternatives), lambda match: f"[{match.lastgroup}]", str(value)
    )
    return safe_display(text_value)


def canonical_caller_principal(caller_arn: str | None) -> str | None:
    """Convert a common STS assumed-role ARN to the matching IAM role ARN."""
    if not caller_arn:
        return None
    parts = caller_arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        return caller_arn
    resource = parts[5]
    if parts[2] == "sts" and resource.startswith("assumed-role/"):
        role_name = resource.split("/", 2)[1]
        return f"arn:{parts[1]}:iam::{parts[4]}:role/{role_name}"
    return caller_arn


class PrivacyFormatter(logging.Formatter):
    """Formatter that redacts AWS identities and selected target values."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_runtime_text(super().format(record))


class StrictConfigLoader(yaml.SafeLoader):
    """Reject ambiguous configuration mappings and alias/merge expansion."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.constructor.ConstructorError(
                None, None, "Configuration aliases are forbidden", event.start_mark
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "Configuration merge keys are forbidden",
                    key_node.start_mark,
                )
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in mapping:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "Ambiguous configuration mapping key",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def load_yaml_config(config_file: str) -> dict[str, Any]:
    """Load one bounded, unambiguous YAML mapping without source diagnostics."""
    path = Path(config_file).expanduser().resolve()
    if not path.is_file():
        raise ConfigurationError(f"Configuration file not found: {path}")
    size = path.stat().st_size
    if size > MAX_CONFIG_BYTES:
        raise ConfigurationError(
            f"Configuration file is {size} bytes; maximum is {MAX_CONFIG_BYTES}."
        )
    try:
        loader = StrictConfigLoader(path.read_text(encoding="utf-8"))
        try:
            config = loader.get_single_data()
        finally:
            loader.dispose()
    except UnicodeDecodeError as exc:
        raise ConfigurationError("Configuration must be UTF-8 encoded.") from exc
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = (
            f" at line {mark.line + 1}, column {mark.column + 1}"
            if mark is not None
            else ""
        )
        # Never include the exception, problem text, context, or Mark.buffer.
        raise ConfigurationError(f"Invalid YAML configuration{location}.") from None
    if not isinstance(config, dict):
        raise ConfigurationError("Configuration root must be a mapping.")
    return config


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON atomically without overwriting an existing report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing report: {path}")
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(payload, handle, indent=2, default=str, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            logger.debug("Could not set restrictive report permissions", exc_info=True)
        os.link(temp_path, path)
        temp_path.unlink()
    except Exception:
        try:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        except OSError:
            logger.debug("Could not remove temporary report file", exc_info=True)
        raise


def require_runtime_safety(
    controller: Any, context: str, error_type: type[Exception] = EmergencyStop
) -> None:
    """Every live guard failure latches process stop, including failed guard reads."""
    if _PROCESS_EMERGENCY_STOP.is_set() or controller.emergency_stop.is_set():
        raise error_type("Emergency stop requested")
    try:
        safe, violations = controller.check_safety_conditions()
    except Exception:
        _PROCESS_EMERGENCY_STOP.set()
        controller.emergency_stop_all()
        raise error_type(f"{context} evaluation failed") from None
    if not safe:
        _PROCESS_EMERGENCY_STOP.set()
        controller.emergency_stop_all()
        raise error_type(f"{context} check failed: " + "; ".join(violations))
    # Safety calls can block while another controller receives a signal.
    if _PROCESS_EMERGENCY_STOP.is_set() or controller.emergency_stop.is_set():
        raise error_type("Emergency stop requested")


class AwsClientProxy:
    """Record successful AWS mutations without logging request arguments."""

    def __init__(self, service: str, client: Any, owner: ChaosExperiment | None):
        self._service = service
        self._client = client
        self._owner = owner

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._client, name)
        if not callable(attribute) or name.startswith(READ_ONLY_OPERATION_PREFIXES):
            return attribute

        def invoke(*args: Any, **kwargs: Any) -> Any:
            if self._owner is not None:
                if (
                    not self._owner.dry_run
                    and f"{self._service}.{name}" in CONCURRENCY_UNSAFE_MUTATIONS
                ):
                    raise SafetyViolation(
                        "Live mutation is disabled: AWS provides no conditional ownership proof for safe concurrent recovery"
                    )
                self._owner._check_forward_safety()
                if (
                    not self._owner._in_rollback
                    and self._owner.safety_controller.emergency_stop.is_set()
                ):
                    raise EmergencyStop("Emergency stop prevents further AWS mutations")
                if self._service == "sqs" and name == "purge_queue":
                    expected = str(self._owner.config.get("queue_arn", ""))
                    url = str(kwargs.get("QueueUrl", ""))
                    validate_queue_identity(self._owner.config, url, expected)
                    current = self._client.get_queue_attributes(
                        QueueUrl=url, AttributeNames=["QueueArn"]
                    )
                    if current.get("Attributes", {}).get("QueueArn") != expected:
                        raise SafetyViolation(
                            "SQS QueueArn changed before purge dispatch"
                        )
                if not self._owner._in_rollback and (
                    _PROCESS_EMERGENCY_STOP.is_set()
                    or self._owner.safety_controller.emergency_stop.is_set()
                ):
                    raise EmergencyStop(
                        "Emergency stop prevents dispatch after safety or ownership read"
                    )
                self._owner._record_mutation_attempt(f"{self._service}.{name}")
            response = attribute(*args, **kwargs)
            if self._owner is not None:
                self._owner._record_mutation(f"{self._service}.{name}")
            return response

        return invoke


@dataclass
class ExperimentResult:
    """Results from a chaos experiment"""

    experiment_id: str
    experiment_type: ChaosType
    start_time: datetime
    end_time: datetime | None = None
    status: str = "running"
    affected_resources: list[str] = field(default_factory=list)
    metrics_before: dict[str, Any] = field(default_factory=dict)
    metrics_after: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    rollback_successful: bool | None = None
    provider: str = "extension"
    risk_level: str = RiskLevel.MEDIUM.value
    mutation_operations: list[str] = field(default_factory=list)
    mutation_attempts: list[str] = field(default_factory=list)
    rollback_operations: list[str] = field(default_factory=list)
    rollback_attempts: list[str] = field(default_factory=list)
    rollback_errors: list[str] = field(default_factory=list)
    additional_info: dict[str, Any] = field(default_factory=dict)


class SafetyController:
    """Controls AWS clients and fail-closed runtime safety checks."""

    def __init__(
        self,
        config: dict[str, Any],
        session: Any,
        region: str,
        live: bool,
    ):
        self.config = config
        self.session = session
        self.region = region
        self.live = live
        self.emergency_stop = _PROCESS_EMERGENCY_STOP
        self._active_count = 0
        self._active_lock = threading.Lock()
        self._clients: dict[tuple[str, str], Any] = {}
        self._client_lock = threading.Lock()
        self._sdk_config = BotocoreConfig(
            connect_timeout=5,
            read_timeout=60,
            retries={"max_attempts": 3, "mode": "standard"},
            user_agent_extra=f"aws-chaos-framework/{__version__}",
        )

    def client(
        self,
        service: str,
        owner: ChaosExperiment | None = None,
        region_name: str | None = None,
    ) -> AwsClientProxy:
        """Return a cached SDK client wrapped with mutation tracking."""
        client_region = region_name or self.region
        key = (service, client_region)
        with self._client_lock:
            if key not in self._clients:
                self._clients[key] = self.session.client(
                    service,
                    region_name=client_region,
                    config=self._sdk_config,
                )
            raw_client = self._clients[key]
        return AwsClientProxy(service, raw_client, owner)

    def experiment_started(self) -> None:
        """Increment the in-process active experiment counter."""
        with self._active_lock:
            self._active_count += 1

    def experiment_finished(self) -> None:
        """Decrement the in-process active experiment counter."""
        with self._active_lock:
            self._active_count = max(0, self._active_count - 1)

    def check_safety_conditions(self) -> tuple[bool, list[str]]:
        """Check if it's safe to run experiments"""
        violations: list[str] = []

        # Check time window
        if not self._check_time_window():
            violations.append("Outside allowed time window")

        # Check CloudWatch alarms
        alarm_violations = self._check_cloudwatch_alarms()
        violations.extend(alarm_violations)

        if self.config.get("guardduty_check", False):
            violations.extend(self._check_guardduty_findings())

        if self.config.get("security_hub_check", False):
            violations.extend(self._check_security_hub())

        # Check resource limits
        if not self._check_resource_limits():
            violations.append("Resource limits exceeded")

        return len(violations) == 0, violations

    def _check_time_window(self) -> bool:
        """Check if current time is within allowed window (UTC)"""
        allowed_days = self.config.get("allowed_days")
        if allowed_days and utc_now().strftime("%A").upper() not in allowed_days:
            return False
        if "allowed_hours" not in self.config:
            return True

        current_hour = utc_now().hour
        allowed_hours = self.config["allowed_hours"]
        start = int(allowed_hours["start"])
        end = int(allowed_hours["end"])
        if start == end:
            return True
        if start < end:
            return start <= current_hour < end
        return current_hour >= start or current_hour < end

    def _check_cloudwatch_alarms(self) -> list[str]:
        """Check CloudWatch alarms for safety"""
        violations: list[str] = []
        alarm_names = self.config.get("safety_alarms", [])
        if not alarm_names:
            return violations

        try:
            cloudwatch = self.client("cloudwatch")
            response = cloudwatch.describe_alarms(AlarmNames=alarm_names)
            alarms = response.get("MetricAlarms", []) + response.get(
                "CompositeAlarms", []
            )
            alarms_by_name = {alarm.get("AlarmName"): alarm for alarm in alarms}
            blocking_states = {"ALARM"}
            if self.config.get("block_on_insufficient_data", True):
                blocking_states.add("INSUFFICIENT_DATA")
            for alarm_name in alarm_names:
                alarm = alarms_by_name.get(alarm_name)
                if alarm is None:
                    violations.append(f"CloudWatch alarm not found: {alarm_name}")
                elif alarm.get("StateValue") in blocking_states:
                    violations.append(
                        f"CloudWatch alarm {alarm_name} is {alarm.get('StateValue')}"
                    )
        except Exception as exc:
            logger.error("Error checking CloudWatch alarms: %s", exc)
            if self.config.get("fail_closed", True):
                violations.append(f"CloudWatch safety check failed: {exc}")

        return violations

    @staticmethod
    def _security_pages(operation: Any, **request: Any) -> Iterable[dict[str, Any]]:
        """Exhaust safety pages without accepting a cycle or unbounded API scan."""
        seen = set()
        for _ in range(100):
            page = operation(**request)
            yield page
            token = page.get("NextToken")
            if not token:
                return
            if not isinstance(token, str) or token in seen:
                raise SafetyViolation("Security finding pagination is ambiguous")
            seen.add(token)
            request["NextToken"] = token
        raise SafetyViolation("Security finding pagination exceeded its safe bound")

    def _check_guardduty_findings(self) -> list[str]:
        """Check GuardDuty for high severity findings"""
        violations: list[str] = []
        try:
            guardduty = self.client("guardduty")
            detector_ids = []
            for page in self._security_pages(guardduty.list_detectors):
                detector_ids.extend(page.get("DetectorIds", []))
            if not detector_ids:
                return ["GuardDuty check is enabled but no detector was found"]
            for detector_id in detector_ids:
                for page in self._security_pages(
                    guardduty.list_findings,
                    DetectorId=detector_id,
                    FindingCriteria={
                        "Criterion": {
                            "severity": {"Gte": 7},
                            "service.archived": {"Eq": ["false"]},
                        }
                    },
                ):
                    if page.get("FindingIds"):
                        return ["GuardDuty has active high severity findings"]

        except Exception as exc:
            logger.error("Error checking GuardDuty: %s", exc)
            if self.config.get("fail_closed", True):
                violations.append(f"GuardDuty safety check failed: {exc}")

        return violations

    def _check_security_hub(self) -> list[str]:
        """Check Security Hub for critical findings"""
        violations: list[str] = []
        try:
            securityhub = self.client("securityhub")
            for page in self._security_pages(
                securityhub.get_findings,
                Filters={
                    "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
                    "WorkflowStatus": [
                        {"Value": "NEW", "Comparison": "EQUALS"},
                        {"Value": "NOTIFIED", "Comparison": "EQUALS"},
                    ],
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                },
                MaxResults=100,
            ):
                if page.get("Findings"):
                    return ["Security Hub has active critical findings"]

        except Exception as exc:
            logger.error("Error checking Security Hub: %s", exc)
            if self.config.get("fail_closed", True):
                violations.append(f"Security Hub safety check failed: {exc}")

        return violations

    def _check_resource_limits(self) -> bool:
        """Check if we're within resource limits"""
        limit = int(self.config.get("max_concurrent_experiments", 1))
        with self._active_lock:
            return self._active_count <= limit

    def emergency_stop_all(self) -> None:
        """Emergency stop all experiments"""
        logger.warning("EMERGENCY STOP TRIGGERED")
        self.emergency_stop.set()

    def log_experiment_to_cloudtrail(
        self,
        experiment_type: str,
        resources: list[str],
    ) -> None:
        """Emit a local audit event. CloudTrail records the AWS API calls separately."""
        logger.info(
            "Audit event experiment=%s target_count=%d",
            experiment_type,
            len(resources),
        )


class ChaosExperiment:
    """Base class for chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        self.config = config
        self.safety_controller = safety_controller
        self.region = config.get("region", DEFAULT_REGION)
        self.dry_run = bool(config.get("dry_run", True))
        self.result = None
        self.mutation_operations: list[str] = []
        self.mutation_attempts: list[str] = []
        self.rollback_operations: list[str] = []
        self.rollback_attempts: list[str] = []
        self.rollback_errors: list[str] = []
        self.rollback_verified = False
        self._in_rollback = False
        self.rollback_mode = "none"

    def client(self, service: str, region_name: str | None = None) -> AwsClientProxy:
        """Return an SDK client whose successful writes are recorded."""
        return self.safety_controller.client(service, self, region_name)

    def _record_mutation(self, operation: str) -> None:
        """Record a successful forward or rollback operation."""
        if self._in_rollback:
            self.rollback_operations.append(operation)
        else:
            self.mutation_operations.append(operation)

    def _record_mutation_attempt(self, operation: str) -> None:
        """Record a write attempt, including ambiguous network failures."""
        if self._in_rollback:
            self.rollback_attempts.append(operation)
        else:
            self.mutation_attempts.append(operation)

    def run_rollback(self) -> None:
        """Run rollback while separating forward and rollback SDK operations."""
        self._in_rollback = True
        try:
            self.rollback()
            self._verify_additional_recovery()
        except Exception as exc:
            self.rollback_errors.append(str(exc))
            raise
        finally:
            self._in_rollback = False

    def _verify_additional_recovery(self) -> None:
        """Read back extension recovery state independently of successful writes."""
        checks: list[bool] = []
        if isinstance(self, VPCChaosExperiment):
            if hasattr(self, "route_table_id"):
                routes = self.ec2.describe_route_tables(
                    RouteTableIds=[self.route_table_id]
                )["RouteTables"][0].get("Routes", [])
                checks.append(
                    any(
                        route.get("DestinationCidrBlock") == self.destination_cidr
                        and all(
                            route.get(key) == value
                            for key, value in self.original_route_target.items()
                        )
                        for route in routes
                    )
                )
            if hasattr(self, "removed_rule"):
                groups = self.ec2.describe_security_groups(GroupIds=[self.group_id])[
                    "SecurityGroups"
                ]
                checks.append(
                    len(groups) == 1
                    and self.removed_rule in groups[0].get("IpPermissions", [])
                )
            if hasattr(self, "rule_number"):
                acls = self.ec2.describe_network_acls(NetworkAclIds=[self.nacl_id])[
                    "NetworkAcls"
                ]
                checks.append(
                    len(acls) == 1
                    and not any(
                        entry.get("RuleNumber") == self.rule_number
                        and not entry.get("Egress", False)
                        for entry in acls[0].get("Entries", [])
                    )
                )
        elif isinstance(self, SQSChaosExperiment) and hasattr(self, "queue_url"):
            expected = {}
            for attribute, field in (
                ("original_policy", "Policy"),
                ("original_delay", "DelaySeconds"),
                ("original_timeout", "VisibilityTimeout"),
            ):
                if hasattr(self, attribute):
                    expected[field] = getattr(self, attribute) or ""
            if expected:
                actual = self.sqs.get_queue_attributes(
                    QueueUrl=self.queue_url, AttributeNames=list(expected)
                )["Attributes"]
                checks.append(
                    all(actual.get(key, "") == value for key, value in expected.items())
                )
        elif isinstance(self, ELBChaosExperiment):
            if hasattr(self, "original_attributes"):
                actual = {
                    item["Key"]: item["Value"]
                    for item in self.elbv2.describe_target_group_attributes(
                        TargetGroupArn=self.target_group_arn
                    )["Attributes"]
                }
                key = "deregistration_delay.timeout_seconds"
                checks.append(actual.get(key) == self.original_attributes.get(key))
            if hasattr(self, "original_health_check"):
                groups = self.elbv2.describe_target_groups(
                    TargetGroupArns=[self.target_group_arn]
                )["TargetGroups"]
                checks.append(
                    len(groups) == 1
                    and all(
                        groups[0].get(key) == value
                        for key, value in self.original_health_check.items()
                    )
                )
            if hasattr(self, "original_actions"):
                rules = self.elbv2.describe_rules(RuleArns=[self.rule_arn])["Rules"]
                checks.append(
                    len(rules) == 1 and rules[0].get("Actions") == self.original_actions
                )
        elif isinstance(self, ECSChaosExperiment) and hasattr(self, "original_status"):
            instances = self.ecs.describe_container_instances(
                cluster=self.cluster, containerInstances=[self.container_instance_arn]
            )["containerInstances"]
            checks.append(
                len(instances) == 1
                and instances[0].get("status") == self.original_status
            )
        elif isinstance(self, WAFChaosExperiment):
            if hasattr(self, "changed_rule_name"):
                acl = self.wafv2.get_web_acl(
                    Scope=self.web_acl_scope, Name=self.web_acl_name, Id=self.web_acl_id
                )["WebACL"]
                matches = [
                    rule
                    for rule in acl.get("Rules", [])
                    if rule.get("Name") == self.changed_rule_name
                ]
                restored = None
                if len(matches) == 1:
                    restored = (
                        matches[0]
                        .get("Statement", {})
                        .get("RateBasedStatement", {})
                        .get("Limit")
                        if self.changed_rule_field == "RateBasedStatement.Limit"
                        else matches[0].get("Action")
                    )
                checks.append(restored == self.original_rule_value)
            if hasattr(self, "original_addresses"):
                ip_set = self.wafv2.get_ip_set(
                    Scope=self.ip_set_scope, Name=self.ip_set_name, Id=self.ip_set_id
                )["IPSet"]
                checks.append(
                    hasattr(self, "rollback_ip_set_state")
                    and set(ip_set.get("Addresses", []))
                    == set(self.rollback_ip_set_state["Addresses"])
                    and ip_set.get("Description")
                    == self.rollback_ip_set_state.get("Description")
                )
        elif isinstance(self, KMSChaosExperiment):
            if hasattr(self, "original_enabled"):
                checks.append(
                    self.kms.describe_key(KeyId=self.key_id)["KeyMetadata"].get(
                        "Enabled"
                    )
                    == self.original_enabled
                )
            if hasattr(self, "original_policy"):
                actual = self.kms.get_key_policy(
                    KeyId=self.key_id, PolicyName="default"
                )["Policy"]
                checks.append(json.loads(actual) == json.loads(self.original_policy))
        elif isinstance(self, IAMChaosExperiment):
            if hasattr(self, "policy_arn"):
                policies = self.iam.list_attached_role_policies(
                    RoleName=self.role_name
                )["AttachedPolicies"]
                checks.append(
                    any(item.get("PolicyArn") == self.policy_arn for item in policies)
                )
            if hasattr(self, "original_max_session"):
                checks.append(
                    self.iam.get_role(RoleName=self.role_name)["Role"].get(
                        "MaxSessionDuration"
                    )
                    == self.original_max_session
                )
            if hasattr(self, "access_key_id"):
                keys = self.iam.list_access_keys(UserName=self.user_name)[
                    "AccessKeyMetadata"
                ]
                checks.append(
                    any(
                        item.get("AccessKeyId") == self.access_key_id
                        and item.get("Status") == "Active"
                        for item in keys
                    )
                )
        elif isinstance(self, DirectoryServiceChaosExperiment) and hasattr(
            self, "forwarder_details"
        ):
            forwarders = self.ds.describe_conditional_forwarders(
                DirectoryId=self.directory_id,
                RemoteDomainNames=[self.remote_domain_name],
            )["ConditionalForwarders"]
            checks.append(
                len(forwarders) == 1
                and forwarders[0].get("RemoteDomainName") == self.remote_domain_name
                and set(forwarders[0].get("DnsIpAddrs", []))
                == set(self.forwarder_details.get("DnsIpAddrs", []))
                and set(forwarders[0].get("DnsIpv6Addrs", []))
                == set(self.forwarder_details.get("DnsIpv6Addrs", []))
                and forwarders[0].get("ReplicationScope")
                == self.forwarder_details.get("ReplicationScope")
            )
        elif isinstance(self, AppStreamChaosExperiment) and hasattr(self, "stack_name"):
            checks.append(
                self.fleet_name
                in self.appstream.list_associated_fleets(StackName=self.stack_name).get(
                    "Names", []
                )
            )
        elif isinstance(self, ECRChaosExperiment) and hasattr(self, "had_policy"):
            try:
                actual = self.ecr.get_repository_policy(
                    repositoryName=self.repository_name
                )["policyText"]
            except ClientError as exc:
                if (
                    exc.response.get("Error", {}).get("Code")
                    != "RepositoryPolicyNotFoundException"
                ):
                    raise
                checks.append(not self.had_policy)
            else:
                checks.append(
                    self.had_policy
                    and json.loads(actual) == json.loads(self.original_policy)
                )
        elif isinstance(self, CodeCommitChaosExperiment) and hasattr(
            self, "deleted_trigger"
        ):
            triggers = self.codecommit.get_repository_triggers(
                repositoryName=self.repository_name
            )["triggers"]
            checks.append(
                sum(item == self.deleted_trigger for item in triggers) == 1
                and sum(
                    item.get("name") == self.deleted_trigger["name"]
                    for item in triggers
                )
                == 1
            )
        if checks:
            if not all(checks):
                self.rollback_verified = False
                raise SafetyViolation(
                    "Recovery read-back did not match the expected original state"
                )
            self.rollback_verified = True

    def run(self) -> ExperimentResult:
        """Run the experiment"""
        raise NotImplementedError

    def rollback(self):
        """Rollback the experiment"""
        raise NotImplementedError

    def collect_metrics(self) -> dict[str, Any]:
        """Collect metrics before/after experiment"""
        return {}

    def _check_forward_safety(self) -> None:
        """Poll all configured guards during forward work; recovery is exempt."""
        if self.dry_run or self._in_rollback:
            return
        require_runtime_safety(self.safety_controller, "Runtime safety")

    def _wait_forward(self, seconds: float) -> None:
        """Wake and poll no later than the configured monitor interval."""
        interval = max(
            1, int(self.safety_controller.config.get("monitor_interval_seconds", 15))
        )
        deadline = time.monotonic() + seconds
        self._check_forward_safety()
        while time.monotonic() < deadline:
            if self.safety_controller.emergency_stop.wait(
                min(interval, deadline - time.monotonic())
            ):
                raise EmergencyStop("Emergency stop requested")
            self._check_forward_safety()

    def _require_derived_scope(
        self, kind: ChaosType, config: dict[str, Any]
    ) -> set[str]:
        """Require child IDs and tuple approval even for direct class callers."""
        targets = ChaosOrchestrator._target_values({"type": kind.value, **config})
        if not self.dry_run:
            safety = self.safety_controller.config
            if targets - set(safety.get("target_allowlist", [])):
                raise SafetyViolation(
                    "Derived resources are absent from the exact target allowlist"
                )
            if ChaosOrchestrator._blast_radius(kind, config) > int(
                safety.get("max_blast_radius", 1)
            ):
                raise SafetyViolation("Derived resources exceed max_blast_radius")
            for pattern in safety.get("denied_target_patterns", []):
                if any(re.search(str(pattern), target) for target in targets):
                    raise SafetyViolation("A derived target matches a denied pattern")
        return targets


class EC2ChaosExperiment(ChaosExperiment):
    """EC2-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.ec2 = self.client("ec2")
        self.ssm = self.client("ssm")
        self.cloudwatch = self.client("cloudwatch")

    def _instance_details(self, instance_ids: list[str]) -> list[dict[str, Any]]:
        """Require an exact, nonduplicated response for the requested instances."""
        response = self.ec2.describe_instances(InstanceIds=instance_ids)
        instances = [
            instance
            for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]
        if len(instances) != len(instance_ids) or {
            item.get("InstanceId") for item in instances
        } != set(instance_ids):
            raise SafetyViolation("EC2 did not return the exact selected instance set")
        return instances

    def _instance_states(self, instance_ids: list[str]) -> dict[str, str]:
        """Return current state for every selected instance."""
        return {
            instance["InstanceId"]: instance["State"]["Name"]
            for instance in self._instance_details(instance_ids)
        }

    def _termination_children(self, instance_ids: list[str]) -> dict[str, list[str]]:
        """Read the exact deletion relationships immediately before termination."""
        children: dict[str, list[str]] = {}
        for instance in self._instance_details(instance_ids):
            mappings = instance.get("BlockDeviceMappings")
            if not isinstance(mappings, list):
                raise SafetyViolation(
                    "EC2 did not return complete block-device mappings"
                )
            volumes = []
            for mapping in mappings:
                ebs = mapping.get("Ebs")
                if ebs is None:
                    continue
                if not isinstance(ebs.get("DeleteOnTermination"), bool) or not ebs.get(
                    "VolumeId"
                ):
                    raise SafetyViolation(
                        "EC2 returned an incomplete EBS deletion relationship"
                    )
                if ebs["DeleteOnTermination"]:
                    volumes.append(ebs["VolumeId"])
            children[instance["InstanceId"]] = sorted(volumes)
        return children

    def _wait_for_instance_state(
        self,
        instance_ids: list[str],
        desired_state: str,
        interruptible: bool,
    ) -> None:
        """Wait cooperatively for an EC2 state transition."""
        timeout_seconds = int(self.config.get("state_timeout_seconds", 600))
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            states = self._instance_states(instance_ids)
            if set(states) != set(instance_ids):
                raise RuntimeError("EC2 did not return every selected instance")
            if all(state == desired_state for state in states.values()):
                return
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError(f"Timed out waiting for EC2 state {desired_state}")

    def terminate_instances(
        self,
        instance_ids: list[str],
        delete_on_termination_volumes: dict[str, list[str]] | None = None,
    ) -> ExperimentResult:
        """Terminate EC2 instances"""
        experiment_id = _experiment_id("ec2-terminate")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EC2_TERMINATE,
            start_time=utc_now(),
        )

        try:
            # Log to CloudTrail
            self.safety_controller.log_experiment_to_cloudtrail(
                "EC2_TERMINATE", instance_ids
            )

            # Collect metrics before
            result.metrics_before = self._collect_instance_metrics(instance_ids)

            config = {**self.config, "instance_ids": instance_ids}
            if delete_on_termination_volumes is not None:
                config["delete_on_termination_volumes"] = delete_on_termination_volumes
            approved = config.get("delete_on_termination_volumes")
            self._require_derived_scope(ChaosType.EC2_TERMINATE, config)
            observed = self._termination_children(instance_ids)
            expected = {
                instance: sorted(volumes) for instance, volumes in approved.items()
            }
            if observed != expected:
                raise SafetyViolation(
                    "EC2 DeleteOnTermination relationships differ from the reviewed approval"
                )
            affected = sorted(
                set(instance_ids)
                | {volume for volumes in observed.values() for volume in volumes}
            )
            result.additional_info["delete_on_termination_volumes"] = observed

            if not self.dry_run:
                # Termination is irreversible. Backups must be approved and
                # created separately; do not copy attached volumes implicitly.
                self.ec2.terminate_instances(InstanceIds=instance_ids)
                result.affected_resources = affected
                logger.info(f"Terminated instances: {instance_ids}")
            else:
                logger.info(f"DRY RUN: Would terminate instances: {instance_ids}")
                result.affected_resources = affected

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error terminating instances: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def stop_instances(self, instance_ids: list[str]) -> ExperimentResult:
        """Stop EC2 instances"""
        experiment_id = _experiment_id("ec2-stop")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EC2_STOP,
            start_time=utc_now(),
        )

        try:
            self.safety_controller.log_experiment_to_cloudtrail(
                "EC2_STOP", instance_ids
            )
            states = self._instance_states(instance_ids)
            if set(states) != set(instance_ids) or any(
                state != "running" for state in states.values()
            ):
                raise SafetyViolation("EC2 stop targets must all be running")

            if not self.dry_run:
                self.stopped_instances = list(instance_ids)
                self.ec2.stop_instances(InstanceIds=instance_ids)
                self._wait_for_instance_state(instance_ids, "stopped", True)
                result.affected_resources = instance_ids
                logger.info(f"Stopped instances: {instance_ids}")
            else:
                logger.info(f"DRY RUN: Would stop instances: {instance_ids}")
                result.affected_resources = instance_ids

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error stopping instances: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def reboot_instances(self, instance_ids: list[str]) -> ExperimentResult:
        """Reboot EC2 instances"""
        experiment_id = _experiment_id("ec2-reboot")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EC2_REBOOT,
            start_time=utc_now(),
        )

        try:
            states = self._instance_states(instance_ids)
            if set(states) != set(instance_ids) or any(
                state != "running" for state in states.values()
            ):
                raise SafetyViolation("EC2 reboot targets must all be running")
            if not self.dry_run:
                self.ec2.reboot_instances(InstanceIds=instance_ids)
                result.affected_resources = instance_ids
                logger.info(f"Rebooted instances: {instance_ids}")
            else:
                logger.info(f"DRY RUN: Would reboot instances: {instance_ids}")
                result.affected_resources = instance_ids

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error rebooting instances: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def inject_network_latency(
        self, instance_ids: list[str], latency_ms: int = 100
    ) -> ExperimentResult:
        """Inject network latency using SSM"""
        experiment_id = _experiment_id("ec2-latency")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EC2_NETWORK_LATENCY,
            start_time=utc_now(),
        )

        try:
            command = f"""
            sudo tc qdisc add dev eth0 root netem delay {latency_ms}ms
            echo "Network latency of {latency_ms}ms added"
            """

            if not self.dry_run:
                self.ssm.send_command(
                    InstanceIds=instance_ids,
                    DocumentName="AWS-RunShellScript",
                    Parameters={"commands": [command]},
                )
                result.affected_resources = instance_ids
                logger.info(
                    f"Injected {latency_ms}ms latency on instances: {instance_ids}"
                )

                # Store for rollback
                self.latency_instances = instance_ids
            else:
                logger.info(
                    f"DRY RUN: Would inject {latency_ms}ms latency on instances: {instance_ids}"
                )
                result.affected_resources = instance_ids

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error injecting latency: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def inject_packet_loss(
        self, instance_ids: list[str], loss_percent: int = 10
    ) -> ExperimentResult:
        """Inject network packet loss using SSM"""
        experiment_id = _experiment_id("ec2-packet-loss")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EC2_NETWORK_PACKET_LOSS,
            start_time=utc_now(),
        )

        try:
            command = f"""
            sudo tc qdisc add dev eth0 root netem loss {loss_percent}%
            echo "Packet loss of {loss_percent}% added"
            """

            if not self.dry_run:
                self.ssm.send_command(
                    InstanceIds=instance_ids,
                    DocumentName="AWS-RunShellScript",
                    Parameters={"commands": [command]},
                )
                result.affected_resources = instance_ids
                logger.info(
                    f"Injected {loss_percent}% packet loss on instances: {instance_ids}"
                )

                # Store for rollback
                self.packet_loss_instances = instance_ids
            else:
                logger.info(
                    f"DRY RUN: Would inject {loss_percent}% packet loss on instances: {instance_ids}"
                )
                result.affected_resources = instance_ids

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error injecting packet loss: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def inject_cpu_stress(
        self,
        instance_ids: list[str],
        cpu_percent: int = 80,
        duration_seconds: int = 300,
    ) -> ExperimentResult:
        """Inject CPU stress using SSM"""
        experiment_id = _experiment_id("ec2-cpu-stress")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EC2_CPU_STRESS,
            start_time=utc_now(),
        )

        try:
            command = f"""
            # Install stress-ng if not present
            which stress-ng || sudo yum install -y stress-ng || sudo apt-get install -y stress-ng

            # Run CPU stress test
            stress-ng --cpu 0 --cpu-load {cpu_percent} --timeout {duration_seconds}s
            """

            if not self.dry_run:
                self.ssm.send_command(
                    InstanceIds=instance_ids,
                    DocumentName="AWS-RunShellScript",
                    Parameters={"commands": [command]},
                    TimeoutSeconds=duration_seconds + 60,
                )
                result.affected_resources = instance_ids
                logger.info(
                    f"Injected CPU stress ({cpu_percent}%) on instances: {instance_ids}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would inject CPU stress ({cpu_percent}%) on instances: {instance_ids}"
                )
                result.affected_resources = instance_ids

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error injecting CPU stress: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def inject_memory_stress(
        self,
        instance_ids: list[str],
        memory_percent: int = 80,
        duration_seconds: int = 300,
    ) -> ExperimentResult:
        """Inject memory stress using SSM"""
        experiment_id = _experiment_id("ec2-memory-stress")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EC2_MEMORY_STRESS,
            start_time=utc_now(),
        )

        try:
            command = f"""
            # Install stress-ng if not present
            which stress-ng || sudo yum install -y stress-ng || sudo apt-get install -y stress-ng

            # Get total memory and calculate stress amount
            TOTAL_MEM=$(free -m | awk 'NR==2{{print $2}}')
            STRESS_MEM=$((TOTAL_MEM * {memory_percent} / 100))

            # Run memory stress test
            stress-ng --vm 1 --vm-bytes ${{STRESS_MEM}}M --timeout {duration_seconds}s
            """

            if not self.dry_run:
                self.ssm.send_command(
                    InstanceIds=instance_ids,
                    DocumentName="AWS-RunShellScript",
                    Parameters={"commands": [command]},
                    TimeoutSeconds=duration_seconds + 60,
                )
                result.affected_resources = instance_ids
                logger.info(
                    f"Injected memory stress ({memory_percent}%) on instances: {instance_ids}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would inject memory stress ({memory_percent}%) on instances: {instance_ids}"
                )
                result.affected_resources = instance_ids

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error injecting memory stress: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def inject_disk_stress(
        self, instance_ids: list[str], io_percent: int = 80, duration_seconds: int = 300
    ) -> ExperimentResult:
        """Inject disk I/O stress using SSM"""
        experiment_id = _experiment_id("ec2-disk-stress")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EC2_DISK_STRESS,
            start_time=utc_now(),
        )

        try:
            command = f"""
            # Install stress-ng if not present
            which stress-ng || sudo yum install -y stress-ng || sudo apt-get install -y stress-ng

            # Run disk I/O stress test
            stress-ng --iomix 4 --iomix-bytes {io_percent}% --timeout {duration_seconds}s
            """

            if not self.dry_run:
                self.ssm.send_command(
                    InstanceIds=instance_ids,
                    DocumentName="AWS-RunShellScript",
                    Parameters={"commands": [command]},
                    TimeoutSeconds=duration_seconds + 60,
                )
                result.affected_resources = instance_ids
                logger.info(
                    f"Injected disk I/O stress ({io_percent}%) on instances: {instance_ids}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would inject disk I/O stress ({io_percent}%) on instances: {instance_ids}"
                )
                result.affected_resources = instance_ids

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error injecting disk stress: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def fill_disk(
        self, instance_ids: list[str], fill_percent: int = 90
    ) -> ExperimentResult:
        """Fill disk to specified percentage using SSM"""
        experiment_id = _experiment_id("ec2-disk-fill")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EC2_DISK_FILL,
            start_time=utc_now(),
        )

        try:
            command = f"""
            # Create chaos directory
            CHAOS_DIR="/tmp/chaos_disk_fill"
            mkdir -p $CHAOS_DIR

            # Get disk usage and calculate fill size
            DISK_SIZE=$(df -BG / | awk 'NR==2{{print $2}}' | sed 's/G//')
            CURRENT_USED=$(df -BG / | awk 'NR==2{{print $3}}' | sed 's/G//')
            TARGET_USED=$((DISK_SIZE * {fill_percent} / 100))
            FILL_SIZE=$((TARGET_USED - CURRENT_USED))

            if [ $FILL_SIZE -gt 0 ]; then
                # Create file to fill disk
                dd if=/dev/zero of=$CHAOS_DIR/fill_file bs=1G count=$FILL_SIZE
                echo "Filled disk to approximately {fill_percent}%"
            else
                echo "Disk already at or above {fill_percent}% capacity"
            fi
            """

            if not self.dry_run:
                self.ssm.send_command(
                    InstanceIds=instance_ids,
                    DocumentName="AWS-RunShellScript",
                    Parameters={"commands": [command]},
                )
                result.affected_resources = instance_ids
                logger.info(
                    f"Filled disk to {fill_percent}% on instances: {instance_ids}"
                )

                # Store for rollback
                self.disk_fill_instances = instance_ids
            else:
                logger.info(
                    f"DRY RUN: Would fill disk to {fill_percent}% on instances: {instance_ids}"
                )
                result.affected_resources = instance_ids

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error filling disk: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def _collect_instance_metrics(self, instance_ids: list[str]) -> dict[str, Any]:
        """Collect metrics for instances"""
        metrics = {}
        try:
            response = self.ec2.describe_instances(InstanceIds=instance_ids)
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    metrics[instance["InstanceId"]] = {
                        "state": instance["State"]["Name"],
                        "type": instance["InstanceType"],
                        "az": instance["Placement"]["AvailabilityZone"],
                        "launch_time": instance.get("LaunchTime", "").isoformat()
                        if instance.get("LaunchTime")
                        else None,
                    }
        except Exception as e:
            logger.error(f"Error collecting instance metrics: {e}")
            raise

        return metrics

    def _get_instance_volumes(self, instance_id: str) -> list[str]:
        """Get volumes attached to an instance"""
        volumes = []
        try:
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    for mapping in instance.get("BlockDeviceMappings", []):
                        if "Ebs" in mapping:
                            volumes.append(mapping["Ebs"]["VolumeId"])
        except Exception as e:
            logger.error(f"Error getting instance volumes: {e}")
            raise

        return volumes

    def rollback(self):
        """Rollback EC2 experiments"""
        try:
            if hasattr(self, "stopped_instances"):
                states = self._instance_states(self.stopped_instances)
                if set(states) != set(self.stopped_instances):
                    raise SafetyViolation(
                        "EC2 recovery did not return the exact selected instance set"
                    )
                if all(state == "running" for state in states.values()):
                    self.rollback_verified = True
                else:
                    invalid = set(states.values()) - {
                        "stopped",
                        "stopping",
                        "pending",
                        "running",
                    }
                    if invalid:
                        raise RuntimeError(
                            "EC2 rollback found an unexpected instance state"
                        )
                    stopping_ids = [
                        instance_id
                        for instance_id, state in states.items()
                        if state == "stopping"
                    ]
                    if stopping_ids:
                        self._wait_for_instance_state(stopping_ids, "stopped", False)
                        states = self._instance_states(self.stopped_instances)
                    stopped_ids = [
                        instance_id
                        for instance_id, state in states.items()
                        if state == "stopped"
                    ]
                    if stopped_ids:
                        self.ec2.start_instances(InstanceIds=stopped_ids)
                    self._wait_for_instance_state(
                        self.stopped_instances, "running", False
                    )
                    self.rollback_verified = True
                logger.info("Restored stopped EC2 instances to running")

            if hasattr(self, "latency_instances"):
                self._remove_network_latency(self.latency_instances)

            if hasattr(self, "packet_loss_instances"):
                self._remove_packet_loss(self.packet_loss_instances)

            if hasattr(self, "disk_fill_instances"):
                self._cleanup_disk_fill(self.disk_fill_instances)

        except Exception as e:
            logger.error(f"Error during EC2 rollback: {e}")
            raise

    def _remove_network_latency(self, instance_ids: list[str]):
        """Remove network latency"""
        try:
            command = """
            sudo tc qdisc del dev eth0 root netem
            echo "Network latency removed"
            """

            self.ssm.send_command(
                InstanceIds=instance_ids,
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [command]},
            )
            logger.info(f"Removed network latency from instances: {instance_ids}")

        except Exception as e:
            logger.error(f"Error removing latency: {e}")
            raise

    def _remove_packet_loss(self, instance_ids: list[str]):
        """Remove packet loss"""
        try:
            command = """
            sudo tc qdisc del dev eth0 root netem
            echo "Packet loss removed"
            """

            self.ssm.send_command(
                InstanceIds=instance_ids,
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [command]},
            )
            logger.info(f"Removed packet loss from instances: {instance_ids}")

        except Exception as e:
            logger.error(f"Error removing packet loss: {e}")
            raise

    def _cleanup_disk_fill(self, instance_ids: list[str]):
        """Clean up disk fill"""
        try:
            command = """
            rm -rf /tmp/chaos_disk_fill
            echo "Disk fill cleaned up"
            """

            self.ssm.send_command(
                InstanceIds=instance_ids,
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [command]},
            )
            logger.info(f"Cleaned up disk fill on instances: {instance_ids}")

        except Exception as e:
            logger.error(f"Error cleaning up disk fill: {e}")
            raise


class EBSChaosExperiment(ChaosExperiment):
    """EBS-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.ec2 = self.client("ec2")

    def _wait_for_volume_state(
        self, volume_id: str, desired_state: str, interruptible: bool
    ) -> dict[str, Any]:
        """Wait cooperatively for one EBS volume state."""
        deadline = time.monotonic() + int(self.config.get("state_timeout_seconds", 600))
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            volumes = self.ec2.describe_volumes(VolumeIds=[volume_id]).get(
                "Volumes", []
            )
            if len(volumes) != 1:
                raise RuntimeError("EC2 did not return the selected EBS volume")
            if volumes[0].get("State") == desired_state:
                return volumes[0]
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError(f"Timed out waiting for EBS state {desired_state}")

    def _wait_for_iops(
        self, volume_id: str, expected_iops: int, interruptible: bool
    ) -> None:
        """Wait for the EBS control plane to expose the requested IOPS value."""
        deadline = time.monotonic() + int(self.config.get("state_timeout_seconds", 600))
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            volumes = self.ec2.describe_volumes(VolumeIds=[volume_id]).get(
                "Volumes", []
            )
            if len(volumes) != 1:
                raise RuntimeError("EC2 did not return the selected EBS volume")
            if volumes[0].get("Iops") == expected_iops:
                return
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError("Timed out waiting for the EBS IOPS update")

    def detach_volume(
        self, volume_id: str, attachment: dict[str, str] | None = None
    ) -> ExperimentResult:
        """Detach EBS volume"""
        experiment_id = _experiment_id("ebs-detach")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EBS_DETACH_VOLUME,
            start_time=utc_now(),
        )

        try:
            config = {**self.config, "volume_id": volume_id}
            if attachment is not None:
                config["attachment"] = attachment
            self._require_derived_scope(ChaosType.EBS_DETACH_VOLUME, config)
            expected = config["attachment"]
            # Get volume details before detaching
            volume_info = self.ec2.describe_volumes(VolumeIds=[volume_id])
            volumes = volume_info.get("Volumes", [])
            if (
                len(volumes) != 1
                or volumes[0].get("VolumeId") != volume_id
                or len(volumes[0].get("Attachments", [])) != 1
            ):
                raise SafetyViolation(
                    "EBS detach requires exactly one matching volume and attachment"
                )
            if volume_info["Volumes"] and volume_info["Volumes"][0]["Attachments"]:
                attachment = volume_info["Volumes"][0]["Attachments"][0]
                if (
                    attachment.get("InstanceId") != expected["instance_id"]
                    or attachment.get("Device") != expected["device"]
                ):
                    raise SafetyViolation(
                        "The EBS attachment differs from the reviewed approval"
                    )
                if attachment.get("State") != "attached":
                    raise SafetyViolation("The selected EBS volume is not attached")
                instance_response = self.ec2.describe_instances(
                    InstanceIds=[attachment["InstanceId"]]
                )
                instances = [
                    instance
                    for reservation in instance_response.get("Reservations", [])
                    for instance in reservation.get("Instances", [])
                ]
                if (
                    len(instances) != 1
                    or instances[0].get("InstanceId") != expected["instance_id"]
                    or not instances[0].get("RootDeviceName")
                ):
                    raise SafetyViolation(
                        "Could not verify the root device for the EBS attachment"
                    )
                if attachment.get("Device") == instances[0]["RootDeviceName"]:
                    raise SafetyViolation("Refusing to detach an instance root volume")
                self.original_instance = attachment["InstanceId"]
                self.original_device = attachment["Device"]
                self.volume_id = volume_id

                if not self.dry_run:
                    # Recheck after all other reads, then constrain the write to
                    # the approved tuple so a changed attachment is not detached.
                    current = self.ec2.describe_volumes(VolumeIds=[volume_id]).get(
                        "Volumes", []
                    )
                    if (
                        len(current) != 1
                        or current[0].get("VolumeId") != volume_id
                        or current[0].get("Attachments", [])
                        != volumes[0]["Attachments"]
                    ):
                        raise SafetyViolation(
                            "The EBS attachment changed before the mutation"
                        )
                    # Detach volume
                    self.ec2.detach_volume(
                        VolumeId=volume_id,
                        InstanceId=expected["instance_id"],
                        Device=expected["device"],
                    )
                    self._wait_for_volume_state(volume_id, "available", True)
                    result.affected_resources = [volume_id, expected["instance_id"]]
                    logger.info(f"Detached volume: {volume_id}")
                else:
                    logger.info(f"DRY RUN: Would detach volume: {volume_id}")
                    result.affected_resources = [volume_id, expected["instance_id"]]
                result.additional_info["attachment"] = expected
            else:
                raise ConfigurationError(f"Volume {volume_id} is not attached")

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error detaching volume: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def throttle_iops(self, volume_id: str, iops: int = 3_000) -> ExperimentResult:
        """Throttle volume IOPS"""
        experiment_id = _experiment_id("ebs-throttle")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EBS_THROTTLE_IOPS,
            start_time=utc_now(),
        )

        try:
            # Get current IOPS
            volume_info = self.ec2.describe_volumes(VolumeIds=[volume_id])
            if volume_info["Volumes"]:
                volume = volume_info["Volumes"][0]
                if volume.get("VolumeType") not in {"io1", "io2", "gp3"}:
                    raise ConfigurationError(
                        "The selected EBS volume type does not support an IOPS setting"
                    )
                self.original_iops = volume.get("Iops")
                if self.original_iops is None:
                    raise ConfigurationError(
                        "The selected EBS volume has no IOPS value"
                    )
                self.volume_id = volume_id
                minimum_iops = 3_000 if volume.get("VolumeType") == "gp3" else 100
                if not minimum_iops <= iops < self.original_iops:
                    raise ConfigurationError(
                        "EBS throttle IOPS must be below the current value and valid "
                        "for the selected volume type"
                    )

                if not self.dry_run:
                    # Modify volume IOPS
                    self.ec2.modify_volume(VolumeId=volume_id, Iops=iops)
                    self._wait_for_iops(volume_id, iops, True)
                    result.affected_resources = [volume_id]
                    logger.info(f"Throttled IOPS to {iops} for volume: {volume_id}")
                else:
                    logger.info(
                        f"DRY RUN: Would throttle IOPS to {iops} for volume: {volume_id}"
                    )
                    result.affected_resources = [volume_id]

            else:
                raise ConfigurationError(f"EBS volume not found: {volume_id}")

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error throttling IOPS: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback EBS experiments"""
        try:
            if hasattr(self, "volume_id") and hasattr(self, "original_instance"):
                volumes = self.ec2.describe_volumes(VolumeIds=[self.volume_id]).get(
                    "Volumes", []
                )
                if len(volumes) != 1:
                    raise RuntimeError("EC2 did not return the selected EBS volume")
                volume = volumes[0]
                attachments = volume.get("Attachments", [])
                already_restored = any(
                    item.get("InstanceId") == self.original_instance
                    and item.get("Device") == self.original_device
                    and item.get("State") == "attached"
                    for item in attachments
                )
                if already_restored:
                    self.rollback_verified = True
                else:
                    if attachments:
                        raise SafetyViolation(
                            "EBS rollback found an unexpected volume attachment"
                        )
                    state = volume.get("State")
                    if state == "in-use":
                        raise SafetyViolation(
                            "EBS rollback found an in-use volume with no expected attachment"
                        )
                    if state != "available":
                        self._wait_for_volume_state(self.volume_id, "available", False)
                    self.ec2.attach_volume(
                        VolumeId=self.volume_id,
                        InstanceId=self.original_instance,
                        Device=self.original_device,
                    )
                    restored = self._wait_for_volume_state(
                        self.volume_id, "in-use", False
                    )
                    if not any(
                        item.get("InstanceId") == self.original_instance
                        and item.get("Device") == self.original_device
                        for item in restored.get("Attachments", [])
                    ):
                        raise RuntimeError(
                            "EBS rollback could not verify the restored attachment"
                        )
                    self.rollback_verified = True
                logger.info(
                    f"Re-attached volume {self.volume_id} to instance {self.original_instance}"
                )

            if hasattr(self, "original_iops") and self.original_iops:
                # Restore original IOPS
                self.ec2.modify_volume(VolumeId=self.volume_id, Iops=self.original_iops)
                self._wait_for_iops(self.volume_id, self.original_iops, False)
                self.rollback_verified = True
                logger.info(
                    f"Restored IOPS to {self.original_iops} for volume {self.volume_id}"
                )

        except Exception as e:
            logger.error(f"Error during EBS rollback: {e}")
            raise


class EFSChaosExperiment(ChaosExperiment):
    """EFS-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.efs = self.client("efs")

    def _wait_for_throughput(
        self,
        file_system_id: str,
        throughput_mode: str,
        provisioned_throughput: float | None,
        interruptible: bool,
    ) -> None:
        """Wait for an EFS throughput update to become available."""
        deadline = time.monotonic() + int(self.config.get("state_timeout_seconds", 600))
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            systems = self.efs.describe_file_systems(FileSystemId=file_system_id).get(
                "FileSystems", []
            )
            if len(systems) != 1:
                raise RuntimeError("EFS did not return the selected file system")
            current = systems[0]
            throughput_matches = current.get("ThroughputMode") == throughput_mode
            if throughput_mode == "provisioned":
                throughput_matches = throughput_matches and float(
                    current.get("ProvisionedThroughputInMibps", -1)
                ) == float(provisioned_throughput)
            if (
                current.get("LifeCycleState", "available") == "available"
                and throughput_matches
            ):
                return
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError("Timed out waiting for the EFS throughput update")

    def delete_mount_target(self, mount_target_id: str) -> ExperimentResult:
        """Delete EFS mount target"""
        experiment_id = _experiment_id("efs-mount-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EFS_MOUNT_TARGET_DELETE,
            start_time=utc_now(),
        )

        try:
            # Get mount target details
            mt_info = self.efs.describe_mount_targets(MountTargetId=mount_target_id)
            if mt_info["MountTargets"]:
                mt = mt_info["MountTargets"][0]
                self.file_system_id = mt["FileSystemId"]
                self.subnet_id = mt["SubnetId"]
                self.security_groups = mt.get("SecurityGroups", [])
                self.mount_target_id = mount_target_id

                if not self.dry_run:
                    # Delete mount target
                    self.efs.delete_mount_target(MountTargetId=mount_target_id)
                    result.affected_resources = [mount_target_id]
                    logger.info(f"Deleted mount target: {mount_target_id}")
                else:
                    logger.info(
                        f"DRY RUN: Would delete mount target: {mount_target_id}"
                    )
                    result.affected_resources = [mount_target_id]
            else:
                raise ConfigurationError(
                    f"EFS mount target not found: {mount_target_id}"
                )

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting mount target: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def throttle_throughput(
        self,
        file_system_id: str,
        throughput_mode: str = "provisioned",
        provisioned_throughput: float = 1.0,
    ) -> ExperimentResult:
        """Throttle EFS throughput"""
        experiment_id = _experiment_id("efs-throttle")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.EFS_THROTTLE_THROUGHPUT,
            start_time=utc_now(),
        )

        try:
            # Get current throughput settings
            fs_info = self.efs.describe_file_systems(FileSystemId=file_system_id)
            if fs_info["FileSystems"]:
                fs = fs_info["FileSystems"][0]
                if fs.get("LifeCycleState", "available") != "available":
                    raise SafetyViolation(
                        "The selected EFS file system is not available"
                    )
                original_mode = fs.get("ThroughputMode", "bursting")
                original_throughput = fs.get("ProvisionedThroughputInMibps")
                if (
                    original_mode != "provisioned"
                    or throughput_mode != "provisioned"
                    or not original_throughput
                    or not 0 < provisioned_throughput < original_throughput
                ):
                    raise SafetyViolation(
                        "EFS throttle requires a reduction in existing provisioned throughput"
                    )
                self.file_system_id = file_system_id
                self.original_throughput_mode = original_mode
                self.original_provisioned_throughput = original_throughput
                if throughput_mode not in {"bursting", "provisioned", "elastic"}:
                    raise ConfigurationError("Unsupported EFS throughput mode")
                if throughput_mode == self.original_throughput_mode and (
                    throughput_mode != "provisioned"
                    or float(provisioned_throughput)
                    == float(self.original_provisioned_throughput or -1)
                ):
                    raise ConfigurationError(
                        "The requested EFS throughput setting matches the current setting"
                    )

                if not self.dry_run:
                    # Update throughput settings
                    update_request: dict[str, Any] = {
                        "FileSystemId": file_system_id,
                        "ThroughputMode": throughput_mode,
                    }
                    if throughput_mode == "provisioned":
                        update_request["ProvisionedThroughputInMibps"] = (
                            provisioned_throughput
                        )
                    self.owned_throughput = (
                        throughput_mode,
                        provisioned_throughput
                        if throughput_mode == "provisioned"
                        else None,
                    )
                    self.efs.update_file_system(**update_request)
                    self._wait_for_throughput(
                        file_system_id,
                        throughput_mode,
                        provisioned_throughput,
                        True,
                    )
                    result.affected_resources = [file_system_id]
                    logger.info(
                        f"Throttled throughput to {provisioned_throughput} MiB/s for filesystem: {file_system_id}"
                    )
                else:
                    logger.info(
                        f"DRY RUN: Would throttle throughput for filesystem: {file_system_id}"
                    )
                    result.affected_resources = [file_system_id]
            else:
                raise ConfigurationError(f"EFS file system not found: {file_system_id}")

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error throttling throughput: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback EFS experiments"""
        try:
            if hasattr(self, "original_throughput_mode"):
                current = self.efs.describe_file_systems(
                    FileSystemId=self.file_system_id
                )["FileSystems"][0]
                original = (
                    self.original_throughput_mode,
                    self.original_provisioned_throughput,
                )
                current_state = (
                    current.get("ThroughputMode"),
                    current.get("ProvisionedThroughputInMibps"),
                )
                if not restoration_required(
                    current_state, original, getattr(self, "owned_throughput", None)
                ):
                    self.rollback_verified = True
                    return
                # Restore original throughput
                update_params = {
                    "FileSystemId": self.file_system_id,
                    "ThroughputMode": self.original_throughput_mode,
                }
                if self.original_provisioned_throughput:
                    update_params["ProvisionedThroughputInMibps"] = (
                        self.original_provisioned_throughput
                    )

                self.efs.update_file_system(**update_params)
                self._wait_for_throughput(
                    self.file_system_id,
                    self.original_throughput_mode,
                    self.original_provisioned_throughput,
                    False,
                )
                self.rollback_verified = True
                logger.info(
                    f"Restored throughput settings for filesystem {self.file_system_id}"
                )

        except Exception as e:
            logger.error(f"Error during EFS rollback: {e}")
            raise


class VPCChaosExperiment(ChaosExperiment):
    """VPC-based chaos experiments"""

    ROUTE_TARGET_FIELDS = (
        "VpcEndpointId",
        "TransitGatewayId",
        "LocalGatewayId",
        "CarrierGatewayId",
        "CoreNetworkArn",
        "OdbNetworkArn",
        "GatewayId",
        "EgressOnlyInternetGatewayId",
        "InstanceId",
        "NetworkInterfaceId",
        "VpcPeeringConnectionId",
        "NatGatewayId",
    )

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.ec2 = self.client("ec2")

    def modify_subnet_acl(self, subnet_id: str, nacl_id: str) -> ExperimentResult:
        """Modify subnet's network ACL"""
        experiment_id = _experiment_id("vpc-subnet-acl")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.VPC_SUBNET_ACL_MODIFY,
            start_time=utc_now(),
        )

        try:
            # Get current NACL association
            associations = self.ec2.describe_network_acls(
                Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
            )
            acls = associations.get("NetworkAcls", [])
            matching = [
                assoc
                for acl in acls
                for assoc in acl.get("Associations", [])
                if assoc.get("SubnetId") == subnet_id
            ]
            if (
                len(acls) != 1
                or len(matching) != 1
                or not matching[0].get("NetworkAclAssociationId")
                or not acls[0].get("NetworkAclId")
            ):
                raise ConfigurationError(
                    "The selected subnet needs one exact NACL association"
                )
            if acls[0]["NetworkAclId"] == nacl_id:
                raise ConfigurationError(
                    "The selected NACL is already associated; no fault would be applied"
                )
            if associations["NetworkAcls"]:
                self.original_nacl_id = associations["NetworkAcls"][0]["NetworkAclId"]
                self.subnet_id = subnet_id
                self.original_association_id = None
                for assoc in associations["NetworkAcls"][0]["Associations"]:
                    if assoc["SubnetId"] == subnet_id:
                        self.original_association_id = assoc["NetworkAclAssociationId"]
                        break

                if not self.dry_run and self.original_association_id:
                    # Replace NACL association
                    response = self.ec2.replace_network_acl_association(
                        AssociationId=self.original_association_id, NetworkAclId=nacl_id
                    )
                    self.current_association_id = response.get("NewAssociationId")
                    self.applied_nacl_id = nacl_id
                    if not self.current_association_id:
                        raise SafetyViolation(
                            "AWS did not confirm the new owned NACL association"
                        )
                    result.affected_resources = [subnet_id]
                    logger.info(f"Modified subnet {subnet_id} to use NACL {nacl_id}")
                else:
                    logger.info(
                        f"DRY RUN: Would modify subnet {subnet_id} to use NACL {nacl_id}"
                    )
                    result.affected_resources = [subnet_id]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying subnet ACL: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_route_table(
        self, route_table_id: str, destination_cidr: str, blackhole: bool = True
    ) -> ExperimentResult:
        """Remove one explicit route temporarily, producing a bounded routing fault."""
        experiment_id = _experiment_id("vpc-route-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.VPC_ROUTE_TABLE_MODIFY,
            start_time=utc_now(),
        )

        try:
            if not blackhole:
                raise ConfigurationError(
                    "vpc_route_table_modify requires blackhole=true"
                )
            self.route_table_id = route_table_id
            self.destination_cidr = destination_cidr

            # Get current route if exists
            routes = self.ec2.describe_route_tables(RouteTableIds=[route_table_id])
            self.original_route = None
            if routes["RouteTables"]:
                for route in routes["RouteTables"][0]["Routes"]:
                    if route.get("DestinationCidrBlock") == destination_cidr:
                        self.original_route = route
                        break

            if self.original_route is None:
                raise ConfigurationError("The selected route does not exist")
            if self.original_route.get("Origin") != "CreateRoute":
                raise SafetyViolation(
                    "Only routes created by CreateRoute can be restored safely"
                )
            target_values = {
                key: self.original_route[key]
                for key in self.ROUTE_TARGET_FIELDS
                if self.original_route.get(key)
            }
            if target_values.get("GatewayId") == "local" or len(target_values) != 1:
                raise SafetyViolation(
                    "The selected route has no uniquely restorable target"
                )
            self.original_route_target = target_values

            if not self.dry_run:
                self.ec2.delete_route(
                    RouteTableId=route_table_id,
                    DestinationCidrBlock=destination_cidr,
                )
                logger.info("Removed one explicit route to create a routing fault")

                result.affected_resources = [route_table_id]
            else:
                logger.info(f"DRY RUN: Would modify route table {route_table_id}")
                result.affected_resources = [route_table_id]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying route table: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_security_group(
        self, group_id: str, remove_rule: dict[str, Any]
    ) -> ExperimentResult:
        """Modify security group rules"""
        experiment_id = _experiment_id("vpc-sg-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.VPC_SECURITY_GROUP_MODIFY,
            start_time=utc_now(),
        )

        try:
            self.group_id = group_id
            groups = self.ec2.describe_security_groups(GroupIds=[group_id]).get(
                "SecurityGroups", []
            )
            if len(groups) != 1:
                raise SafetyViolation("Security group pre-state is unavailable")

            def permission_identity(value: Any) -> Any:
                if isinstance(value, dict):
                    return {
                        key: permission_identity(item)
                        for key, item in value.items()
                        if key != "Description" and item != []
                    }
                if isinstance(value, list):
                    return sorted(
                        (permission_identity(item) for item in value),
                        key=lambda item: json.dumps(item, sort_keys=True),
                    )
                if isinstance(value, str) and "/" in value:
                    try:
                        return str(ipaddress.ip_network(value, strict=False))
                    except ValueError:
                        pass
                return value

            wanted = permission_identity(remove_rule)
            matches = [
                rule
                for rule in groups[0].get("IpPermissions", [])
                if permission_identity(rule) == wanted
            ]
            if len(matches) != 1:
                raise SafetyViolation(
                    "The exact ingress rule is absent from security group pre-state"
                )
            actual_rule = copy.deepcopy(matches[0])

            if not self.dry_run:
                try:
                    response = self.ec2.revoke_security_group_ingress(
                        GroupId=group_id, IpPermissions=[actual_rule]
                    )
                finally:
                    remaining = self.ec2.describe_security_groups(
                        GroupIds=[group_id]
                    ).get("SecurityGroups", [])
                    if len(remaining) == 1 and not any(
                        permission_identity(rule) == wanted
                        for rule in remaining[0].get("IpPermissions", [])
                    ):
                        self.removed_rule = actual_rule
                if not hasattr(self, "removed_rule") or response.get(
                    "UnknownIpPermissions"
                ):
                    raise SafetyViolation("Ingress revoke could not be verified")
                result.affected_resources = [group_id]
                logger.info(f"Removed rule from security group: {group_id}")
            else:
                logger.info(f"DRY RUN: Would modify security group: {group_id}")
                result.affected_resources = [group_id]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying security group: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def block_traffic_nacl(
        self,
        nacl_id: str,
        rule_number: int = 100,
        protocol: str = "-1",
        cidr_block: str = "0.0.0.0/0",
    ) -> ExperimentResult:
        """Block traffic using Network ACL"""
        experiment_id = _experiment_id("vpc-nacl-block")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.VPC_NACL_BLOCK_TRAFFIC,
            start_time=utc_now(),
        )

        try:
            response = self.ec2.describe_network_acls(NetworkAclIds=[nacl_id])
            if not response.get("NetworkAcls"):
                raise ConfigurationError("The selected network ACL does not exist")
            if any(
                entry.get("RuleNumber") == rule_number and not entry.get("Egress")
                for entry in response["NetworkAcls"][0].get("Entries", [])
            ):
                raise SafetyViolation(
                    "The selected ingress rule number is already in use"
                )
            self.nacl_id = nacl_id
            self.rule_number = rule_number

            if not self.dry_run:
                # Add deny rule
                self.ec2.create_network_acl_entry(
                    NetworkAclId=nacl_id,
                    RuleNumber=rule_number,
                    Protocol=protocol,
                    RuleAction="deny",
                    Egress=False,
                    CidrBlock=cidr_block,
                )
                result.affected_resources = [nacl_id]
                logger.info(f"Added deny rule to NACL: {nacl_id}")
            else:
                logger.info(f"DRY RUN: Would add deny rule to NACL: {nacl_id}")
                result.affected_resources = [nacl_id]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying NACL: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def _wait_for_vpc_deletion(self, target: str, *, peering: bool) -> None:
        """Require exact-target absence or an authoritative EC2 deleted tombstone."""
        deadline = time.monotonic() + int(self.config.get("state_timeout_seconds", 600))
        while time.monotonic() < deadline:
            self._check_forward_safety()
            try:
                if peering:
                    items = self.ec2.describe_vpc_peering_connections(
                        VpcPeeringConnectionIds=[target]
                    ).get("VpcPeeringConnections")
                    key = "VpcPeeringConnectionId"
                else:
                    items = self.ec2.describe_vpc_endpoints(
                        VpcEndpointIds=[target]
                    ).get("VpcEndpoints")
                    key = "VpcEndpointId"
            except ClientError as exc:
                expected = (
                    "InvalidVpcPeeringConnectionID.NotFound"
                    if peering
                    else "InvalidVpcEndpointId.NotFound"
                )
                if exc.response.get("Error", {}).get("Code") == expected:
                    self._check_forward_safety()
                    return
                raise
            self._check_forward_safety()
            if not isinstance(items, list) or any(
                item.get(key) != target for item in items
            ):
                raise SafetyViolation(
                    "VPC deletion read-back did not identify the exact target"
                )
            if not items or (
                peering
                and len(items) == 1
                and items[0].get("Status", {}).get("Code") == "deleted"
            ):
                return
            self._wait_forward(min(5.0, max(0.1, deadline - time.monotonic())))
        raise TimeoutError("VPC deletion did not reach a verified deleted state")

    def delete_vpc_peering(self, peering_connection_id: str) -> ExperimentResult:
        """Delete VPC peering connection"""
        experiment_id = _experiment_id("vpc-peering-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.VPC_PEERING_DELETE,
            start_time=utc_now(),
        )

        try:
            # Get peering details for potential recreation
            peering_info = self.ec2.describe_vpc_peering_connections(
                VpcPeeringConnectionIds=[peering_connection_id]
            )
            if peering_info["VpcPeeringConnections"]:
                self.peering_details = peering_info["VpcPeeringConnections"][0]

                if not self.dry_run:
                    # Delete peering connection
                    response = self.ec2.delete_vpc_peering_connection(
                        VpcPeeringConnectionId=peering_connection_id
                    )
                    if response.get("Return") is not True:
                        raise SafetyViolation("AWS did not accept VPC peering deletion")
                    self._wait_for_vpc_deletion(peering_connection_id, peering=True)
                    result.affected_resources = [peering_connection_id]
                    logger.info(
                        f"Deleted VPC peering connection: {peering_connection_id}"
                    )
                else:
                    logger.info(
                        f"DRY RUN: Would delete VPC peering connection: {peering_connection_id}"
                    )
                    result.affected_resources = [peering_connection_id]
            else:
                raise ConfigurationError(
                    f"VPC peering connection not found: {peering_connection_id}"
                )

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting VPC peering: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def delete_vpc_endpoint(self, endpoint_id: str) -> ExperimentResult:
        """Delete VPC endpoint"""
        experiment_id = _experiment_id("vpc-endpoint-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.VPC_ENDPOINT_DELETE,
            start_time=utc_now(),
        )

        try:
            # Get endpoint details for potential recreation
            endpoint_info = self.ec2.describe_vpc_endpoints(
                VpcEndpointIds=[endpoint_id]
            )
            if endpoint_info["VpcEndpoints"]:
                self.endpoint_details = endpoint_info["VpcEndpoints"][0]

                if not self.dry_run:
                    # Delete endpoint
                    response = self.ec2.delete_vpc_endpoints(
                        VpcEndpointIds=[endpoint_id]
                    )
                    if response.get("Unsuccessful") != []:
                        raise SafetyViolation(
                            "AWS did not accept VPC endpoint deletion"
                        )
                    self._wait_for_vpc_deletion(endpoint_id, peering=False)
                    result.affected_resources = [endpoint_id]
                    logger.info(f"Deleted VPC endpoint: {endpoint_id}")
                else:
                    logger.info(f"DRY RUN: Would delete VPC endpoint: {endpoint_id}")
                    result.affected_resources = [endpoint_id]
            else:
                raise ConfigurationError(f"VPC endpoint not found: {endpoint_id}")

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting VPC endpoint: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback VPC experiments"""
        try:
            if hasattr(self, "original_association_id") and hasattr(
                self, "original_nacl_id"
            ):
                if not getattr(self, "current_association_id", None):
                    raise SafetyViolation(
                        "An unconfirmed NACL write cannot authorize recovery"
                    )
                associations = self.ec2.describe_network_acls(
                    Filters=[
                        {"Name": "association.subnet-id", "Values": [self.subnet_id]}
                    ]
                )["NetworkAcls"]
                current_ids = [
                    assoc["NetworkAclAssociationId"]
                    for acl in associations
                    for assoc in acl.get("Associations", [])
                    if assoc.get("SubnetId") == self.subnet_id
                ]
                if (
                    len(current_ids) != 1
                    or current_ids[0] != self.current_association_id
                    or len(associations) != 1
                    or associations[0].get("NetworkAclId") != self.applied_nacl_id
                ):
                    raise SafetyViolation(
                        "Cannot uniquely resolve the current subnet NACL association"
                    )
                self.ec2.replace_network_acl_association(
                    AssociationId=current_ids[0],
                    NetworkAclId=self.original_nacl_id,
                )
                restored = self.ec2.describe_network_acls(
                    Filters=[
                        {"Name": "association.subnet-id", "Values": [self.subnet_id]}
                    ]
                )["NetworkAcls"]
                if not any(
                    acl.get("NetworkAclId") == self.original_nacl_id
                    and any(
                        a.get("SubnetId") == self.subnet_id
                        for a in acl.get("Associations", [])
                    )
                    for acl in restored
                ):
                    raise SafetyViolation("Subnet NACL rollback was not verified")
                self.rollback_verified = True
                logger.info("Restored original NACL association")

            if hasattr(self, "route_table_id") and hasattr(self, "destination_cidr"):
                current = self.ec2.describe_route_tables(
                    RouteTableIds=[self.route_table_id]
                )["RouteTables"][0].get("Routes", [])
                existing = next(
                    (
                        route
                        for route in current
                        if route.get("DestinationCidrBlock") == self.destination_cidr
                    ),
                    None,
                )
                if existing is None:
                    self.ec2.create_route(
                        RouteTableId=self.route_table_id,
                        DestinationCidrBlock=self.destination_cidr,
                        **self.original_route_target,
                    )
                elif not all(
                    existing.get(key) == value
                    for key, value in self.original_route_target.items()
                ):
                    raise SafetyViolation(
                        "Rollback found a conflicting route and refused to overwrite it"
                    )
                logger.info("Restored route table")

            if hasattr(self, "group_id") and hasattr(self, "removed_rule"):
                # Re-add the removed rule
                self.ec2.authorize_security_group_ingress(
                    GroupId=self.group_id, IpPermissions=[self.removed_rule]
                )
                logger.info(f"Restored rule to security group: {self.group_id}")

            if hasattr(self, "nacl_id") and hasattr(self, "rule_number"):
                # Remove the deny rule
                self.ec2.delete_network_acl_entry(
                    NetworkAclId=self.nacl_id, RuleNumber=self.rule_number, Egress=False
                )
                logger.info(f"Removed deny rule from NACL: {self.nacl_id}")

        except Exception as e:
            logger.error(f"Error during VPC rollback: {e}")
            raise


class RDSChaosExperiment(ChaosExperiment):
    """RDS-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.rds = self.client("rds")

    def _wait_for_parameters(
        self,
        parameter_group_name: str,
        parameters: list[dict[str, Any]],
        interruptible: bool,
    ) -> None:
        """Wait for dynamic RDS parameter values to match the requested values."""
        expected = {
            str(item["ParameterName"]): str(item["ParameterValue"])
            for item in parameters
        }
        deadline = time.monotonic() + int(self.config.get("state_timeout_seconds", 600))
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            matched = True
            for name, value in expected.items():
                current = self.rds.describe_db_parameters(
                    DBParameterGroupName=parameter_group_name,
                    Filters=[{"Name": "parameter-name", "Values": [name]}],
                ).get("Parameters", [])
                if len(current) != 1 or str(current[0].get("ParameterValue")) != value:
                    matched = False
                    break
            if matched:
                return
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError("Timed out waiting for RDS parameter values")

    def failover_db_cluster(self, cluster_identifier: str) -> ExperimentResult:
        """Failover RDS cluster"""
        experiment_id = _experiment_id("rds-failover")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.RDS_FAILOVER,
            start_time=utc_now(),
        )

        try:
            # Get cluster info before failover
            result.metrics_before = self._get_cluster_metrics(cluster_identifier)
            if result.metrics_before["status"] != "available":
                raise SafetyViolation("The selected RDS cluster is not available")
            if len(result.metrics_before["members"]) < 2:
                raise SafetyViolation(
                    "RDS cluster failover requires at least two cluster members"
                )

            writers = [
                member["identifier"]
                for member in result.metrics_before["members"]
                if member["is_writer"]
            ]
            if len(writers) != 1 or not writers[0]:
                raise SafetyViolation("RDS pre-state must identify one exact writer")

            if not self.dry_run:
                self.rds.failover_db_cluster(DBClusterIdentifier=cluster_identifier)
                result.affected_resources = [cluster_identifier]
                logger.info(f"Initiated failover for RDS cluster: {cluster_identifier}")

                # An unchanged available response does not prove failover.
                result.metrics_after = self._wait_for_cluster_available(
                    cluster_identifier, original_writer=writers[0]
                )
            else:
                logger.info(
                    f"DRY RUN: Would failover RDS cluster: {cluster_identifier}"
                )
                result.affected_resources = [cluster_identifier]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error during RDS failover: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def reboot_db_instance(
        self, db_instance_identifier: str, force_failover: bool = False
    ) -> ExperimentResult:
        """Reboot RDS instance"""
        experiment_id = _experiment_id("rds-reboot")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.RDS_REBOOT,
            start_time=utc_now(),
        )

        try:
            instance_info = self.rds.describe_db_instances(
                DBInstanceIdentifier=db_instance_identifier
            ).get("DBInstances", [])
            if len(instance_info) != 1:
                raise ConfigurationError(
                    f"RDS DB instance not found: {db_instance_identifier}"
                )
            instance = instance_info[0]
            if instance.get("DBInstanceStatus") != "available":
                raise SafetyViolation("The selected RDS DB instance is not available")
            if force_failover and not instance.get("MultiAZ", False):
                raise SafetyViolation(
                    "Forced RDS failover requires a Multi-AZ instance"
                )

            if not self.dry_run:
                self.rds.reboot_db_instance(
                    DBInstanceIdentifier=db_instance_identifier,
                    ForceFailover=force_failover,
                )
                result.affected_resources = [db_instance_identifier]
                logger.info(f"Rebooted RDS instance: {db_instance_identifier}")
                self._wait_for_db_instance_available(
                    db_instance_identifier, True, require_transition=True
                )
            else:
                logger.info(
                    f"DRY RUN: Would reboot RDS instance: {db_instance_identifier}"
                )
                result.affected_resources = [db_instance_identifier]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error rebooting RDS instance: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_backup_retention(
        self, db_identifier: str, retention_period: int = 0
    ) -> ExperimentResult:
        """Change retention with an explicit irreversible data-loss classification."""
        logger.warning(
            "Backup retention changes can permanently delete backups; settings restoration cannot recover them"
        )
        experiment_id = _experiment_id("rds-backup-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.RDS_BACKUP_RETENTION_MODIFY,
            start_time=utc_now(),
        )
        result.additional_info["data_loss_warning"] = (
            "Retention changes may permanently delete backups; restoring settings does not recover deleted data."
        )

        try:
            # Get current retention period
            db_info = self.rds.describe_db_instances(DBInstanceIdentifier=db_identifier)
            if db_info["DBInstances"]:
                self.original_retention = db_info["DBInstances"][0][
                    "BackupRetentionPeriod"
                ]
                self.db_identifier = db_identifier
                self.owned_retention = retention_period

                if not self.dry_run:
                    self.rds.modify_db_instance(
                        DBInstanceIdentifier=db_identifier,
                        BackupRetentionPeriod=retention_period,
                        ApplyImmediately=True,
                    )
                    self._wait_for_db_instance_available(
                        db_identifier, True, expected_retention=retention_period
                    )
                    result.affected_resources = [db_identifier]
                    logger.info(
                        f"Modified backup retention to {retention_period} days for: {db_identifier}"
                    )
                else:
                    logger.info(
                        f"DRY RUN: Would modify backup retention for: {db_identifier}"
                    )
                    result.affected_resources = [db_identifier]
            else:
                raise ConfigurationError(f"RDS DB instance not found: {db_identifier}")

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying backup retention: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_parameter_group(
        self, parameter_group_name: str, parameters: list[dict[str, Any]]
    ) -> ExperimentResult:
        """Modify RDS parameter group"""
        experiment_id = _experiment_id("rds-param-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.RDS_PARAMETER_GROUP_MODIFY,
            start_time=utc_now(),
        )

        try:
            # Store original parameter values
            self.original_parameters = []
            self.parameter_group_name = parameter_group_name

            for param in parameters:
                if param.get("ApplyMethod") != "immediate":
                    raise ConfigurationError(
                        "RDS chaos parameters must use ApplyMethod=immediate"
                    )
                # Get current value
                current = self.rds.describe_db_parameters(
                    DBParameterGroupName=parameter_group_name,
                    Filters=[
                        {"Name": "parameter-name", "Values": [param["ParameterName"]]}
                    ],
                )
                if current["Parameters"]:
                    if current["Parameters"][0].get("ApplyType") != "dynamic":
                        raise SafetyViolation(
                            f"RDS parameter is not dynamically applicable: {param['ParameterName']}"
                        )
                    self.original_parameters.append(
                        {
                            "ParameterName": param["ParameterName"],
                            "ParameterValue": current["Parameters"][0].get(
                                "ParameterValue", ""
                            ),
                            "ApplyMethod": "immediate",
                        }
                    )
                else:
                    raise ConfigurationError(
                        f"RDS parameter not found: {param['ParameterName']}"
                    )

            if not self.dry_run:
                self.owned_parameters = copy.deepcopy(parameters)
                self.rds.modify_db_parameter_group(
                    DBParameterGroupName=parameter_group_name, Parameters=parameters
                )
                self._wait_for_parameters(parameter_group_name, parameters, True)
                result.affected_resources = [parameter_group_name]
                logger.info(f"Modified parameter group: {parameter_group_name}")
            else:
                logger.info(
                    f"DRY RUN: Would modify parameter group: {parameter_group_name}"
                )
                result.affected_resources = [parameter_group_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying parameter group: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def _get_cluster_metrics(self, cluster_identifier: str) -> dict[str, Any]:
        """Get RDS cluster metrics"""
        response = self.rds.describe_db_clusters(DBClusterIdentifier=cluster_identifier)
        clusters = response.get("DBClusters", [])
        if (
            len(clusters) != 1
            or clusters[0].get("DBClusterIdentifier") != cluster_identifier
        ):
            raise ConfigurationError(f"RDS cluster not found: {cluster_identifier}")
        cluster = clusters[0]
        return {
            "status": cluster.get("Status"),
            "primary_endpoint": cluster.get("Endpoint"),
            "reader_endpoint": cluster.get("ReaderEndpoint"),
            "members": [
                {
                    "identifier": member.get("DBInstanceIdentifier"),
                    "is_writer": member.get("IsClusterWriter", False),
                    "status": member.get("DBClusterParameterGroupStatus"),
                }
                for member in cluster.get("DBClusterMembers", [])
            ],
        }

    def _wait_for_cluster_available(
        self,
        cluster_identifier: str,
        interruptible: bool = True,
        original_writer: str | None = None,
    ) -> dict[str, Any]:
        """Return the exact available observation proving the writer transition."""
        timeout = int(self.config.get("state_timeout_seconds", 600))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            metrics = self._get_cluster_metrics(cluster_identifier)
            if interruptible:
                self._check_forward_safety()
            writers = [
                member["identifier"]
                for member in metrics["members"]
                if member["is_writer"]
            ]
            transitioned = original_writer is None or (
                len(writers) == 1 and bool(writers[0]) and writers[0] != original_writer
            )
            if metrics["status"] == "available" and transitioned:
                return metrics
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError("Timed out waiting for the RDS cluster to become available")

    def _wait_for_db_instance_available(
        self,
        db_instance_identifier: str,
        interruptible: bool,
        expected_retention: int | None = None,
        require_transition: bool = False,
    ) -> None:
        """Wait for availability after positive evidence of the requested transition."""
        timeout = int(self.config.get("state_timeout_seconds", 600))
        deadline = time.monotonic() + timeout
        transition_seen = not require_transition
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            instances = self.rds.describe_db_instances(
                DBInstanceIdentifier=db_instance_identifier
            ).get("DBInstances", [])
            if interruptible:
                self._check_forward_safety()
            if (
                len(instances) != 1
                or instances[0].get("DBInstanceIdentifier") != db_instance_identifier
            ):
                raise RuntimeError("RDS did not return the selected DB instance")
            if instances[0].get("DBInstanceStatus") == "rebooting":
                transition_seen = True
            if (
                transition_seen
                and instances[0].get("DBInstanceStatus") == "available"
                and (
                    expected_retention is None
                    or (
                        instances[0].get("BackupRetentionPeriod") == expected_retention
                        and "BackupRetentionPeriod"
                        not in instances[0].get("PendingModifiedValues", {})
                    )
                )
            ):
                return
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError(
            "Timed out waiting for the RDS DB instance to become available"
        )

    def rollback(self):
        """Rollback RDS experiments"""
        try:
            if hasattr(self, "original_retention") and hasattr(self, "db_identifier"):
                raise SafetyViolation(
                    "Backup retention is irreversible; settings restoration cannot recover deleted backups"
                )
            if (
                hasattr(self, "original_parameters")
                and hasattr(self, "parameter_group_name")
                and self.original_parameters
            ):
                for original, owned in zip(
                    self.original_parameters, self.owned_parameters, strict=True
                ):
                    current = self.rds.describe_db_parameters(
                        DBParameterGroupName=self.parameter_group_name,
                        Filters=[
                            {
                                "Name": "parameter-name",
                                "Values": [original["ParameterName"]],
                            }
                        ],
                    )["Parameters"]
                    if len(current) != 1:
                        raise SafetyViolation(
                            "RDS parameter recovery pre-state is unavailable"
                        )
                    restoration_required(
                        current[0].get("ParameterValue"),
                        original["ParameterValue"],
                        owned["ParameterValue"],
                    )
                # Restore original parameter values
                self.rds.modify_db_parameter_group(
                    DBParameterGroupName=self.parameter_group_name,
                    Parameters=self.original_parameters,
                )
                self._wait_for_parameters(
                    self.parameter_group_name, self.original_parameters, False
                )
                self.rollback_verified = True
                logger.info("Restored original parameter values")

        except Exception as e:
            logger.error(f"Error during RDS rollback: {e}")
            raise


class LambdaChaosExperiment(ChaosExperiment):
    """Lambda-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.lambda_client = self.client("lambda")

    def _wait_for_configuration(self, function_name: str, interruptible: bool) -> None:
        """Wait for a Lambda configuration update to reach a successful terminal state."""
        deadline = time.monotonic() + int(self.config.get("state_timeout_seconds", 600))
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            current = self.lambda_client.get_function_configuration(
                FunctionName=function_name
            )
            status = current.get("LastUpdateStatus", "Successful")
            if status == "Successful":
                return
            if status == "Failed":
                raise RuntimeError("Lambda configuration update failed")
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError("Timed out waiting for Lambda configuration update")

    def throttle_function(
        self, function_name: str, reserved_concurrent_executions: int = 0
    ) -> ExperimentResult:
        """Throttle Lambda function by setting reserved concurrent executions"""
        experiment_id = _experiment_id("lambda-throttle")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.LAMBDA_THROTTLE,
            start_time=utc_now(),
        )

        try:
            # Store original concurrency for rollback
            response = self.lambda_client.get_function_concurrency(
                FunctionName=function_name
            )
            original_concurrency = response.get("ReservedConcurrentExecutions")
            if (
                reserved_concurrent_executions < 0
                or (
                    original_concurrency is None and reserved_concurrent_executions != 0
                )
                or (
                    original_concurrency is not None
                    and reserved_concurrent_executions >= original_concurrency
                )
            ):
                raise SafetyViolation(
                    "Lambda throttle must reduce concurrency; unreserved functions may only be paused"
                )
            self.owned_concurrency = reserved_concurrent_executions
            self.original_concurrency = original_concurrency
            self.function_name = function_name

            if not self.dry_run:
                self.lambda_client.put_function_concurrency(
                    FunctionName=function_name,
                    ReservedConcurrentExecutions=reserved_concurrent_executions,
                )
                result.affected_resources = [function_name]
                logger.info(
                    f"Set reserved concurrent executions to {reserved_concurrent_executions} for {function_name}"
                )
            else:
                logger.info(f"DRY RUN: Would throttle Lambda function: {function_name}")
                result.affected_resources = [function_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error throttling Lambda: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def inject_error(
        self, function_name: str, error_rate: float = 0.5
    ) -> ExperimentResult:
        """Inject errors by updating function environment variables"""
        experiment_id = _experiment_id("lambda-error")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.LAMBDA_ERROR_INJECTION,
            start_time=utc_now(),
        )

        try:
            # Get current configuration
            response = self.lambda_client.get_function_configuration(
                FunctionName=function_name
            )
            self.original_env = response.get("Environment", {}).get("Variables", {})
            self.function_name = function_name

            # Add chaos environment variable
            new_env = self.original_env.copy()
            new_env["CHAOS_ERROR_RATE"] = str(error_rate)
            self.owned_env = copy.deepcopy(new_env)

            if not self.dry_run:
                self.lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    Environment={"Variables": new_env},
                    RevisionId=response["RevisionId"],
                )
                self._wait_for_configuration(function_name, True)
                result.affected_resources = [function_name]
                logger.info(
                    f"Injected error rate {error_rate} for Lambda: {function_name}"
                )
            else:
                logger.info(f"DRY RUN: Would inject errors in Lambda: {function_name}")
                result.affected_resources = [function_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error injecting Lambda errors: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_timeout(
        self, function_name: str, timeout_seconds: int = 1
    ) -> ExperimentResult:
        """Modify Lambda function timeout"""
        experiment_id = _experiment_id("lambda-timeout")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.LAMBDA_TIMEOUT_MODIFY,
            start_time=utc_now(),
        )

        try:
            # Get current timeout
            response = self.lambda_client.get_function_configuration(
                FunctionName=function_name
            )
            self.original_timeout = response["Timeout"]
            self.owned_timeout = timeout_seconds
            self.function_name = function_name

            if not self.dry_run:
                self.lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    Timeout=timeout_seconds,
                    RevisionId=response["RevisionId"],
                )
                self._wait_for_configuration(function_name, True)
                result.affected_resources = [function_name]
                logger.info(
                    f"Set timeout to {timeout_seconds}s for Lambda: {function_name}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would modify timeout for Lambda: {function_name}"
                )
                result.affected_resources = [function_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying Lambda timeout: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_memory_limit(
        self, function_name: str, memory_mb: int = 128
    ) -> ExperimentResult:
        """Modify Lambda function memory limit"""
        experiment_id = _experiment_id("lambda-memory")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.LAMBDA_MEMORY_LIMIT,
            start_time=utc_now(),
        )

        try:
            # Get current memory
            response = self.lambda_client.get_function_configuration(
                FunctionName=function_name
            )
            self.original_memory = response["MemorySize"]
            self.owned_memory = memory_mb
            self.function_name = function_name

            if not self.dry_run:
                self.lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    MemorySize=memory_mb,
                    RevisionId=response["RevisionId"],
                )
                self._wait_for_configuration(function_name, True)
                result.affected_resources = [function_name]
                logger.info(f"Set memory to {memory_mb}MB for Lambda: {function_name}")
            else:
                logger.info(f"DRY RUN: Would modify memory for Lambda: {function_name}")
                result.affected_resources = [function_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying Lambda memory: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def corrupt_environment(
        self, function_name: str, corrupt_vars: dict[str, str]
    ) -> ExperimentResult:
        """Corrupt Lambda environment variables"""
        experiment_id = _experiment_id("lambda-env-corrupt")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.LAMBDA_ENVIRONMENT_CORRUPT,
            start_time=utc_now(),
        )

        try:
            # Get current configuration
            response = self.lambda_client.get_function_configuration(
                FunctionName=function_name
            )
            self.original_env = response.get("Environment", {}).get("Variables", {})
            self.function_name = function_name

            # Corrupt environment variables
            new_env = self.original_env.copy()
            new_env.update(corrupt_vars)
            self.owned_env = copy.deepcopy(new_env)

            if not self.dry_run:
                self.lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    Environment={"Variables": new_env},
                    RevisionId=response["RevisionId"],
                )
                self._wait_for_configuration(function_name, True)
                result.affected_resources = [function_name]
                logger.info(
                    f"Corrupted environment variables for Lambda: {function_name}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would corrupt environment for Lambda: {function_name}"
                )
                result.affected_resources = [function_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error corrupting Lambda environment: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Restore owned fields with revision checks and preserve unrelated edits."""
        if not hasattr(self, "function_name") or not self.mutation_attempts:
            return
        current = self.lambda_client.get_function_configuration(
            FunctionName=self.function_name
        )
        if current.get("LastUpdateStatus") == "InProgress":
            self._wait_for_configuration(self.function_name, False)
            current = self.lambda_client.get_function_configuration(
                FunctionName=self.function_name
            )
        update = {}
        if hasattr(self, "original_env"):
            environment = copy.deepcopy(
                current.get("Environment", {}).get("Variables", {})
            )
            owned = self.owned_env
            missing = object()
            for key in set(owned) | set(self.original_env):
                if owned.get(key, missing) == self.original_env.get(key, missing):
                    continue
                if restoration_required(
                    environment.get(key, missing),
                    self.original_env.get(key, missing),
                    owned.get(key, missing),
                ):
                    if key in self.original_env:
                        environment[key] = self.original_env[key]
                    else:
                        environment.pop(key, None)
            update["Environment"] = {"Variables": environment}
        for attribute, property_name in (
            ("timeout", "Timeout"),
            ("memory", "MemorySize"),
        ):
            if hasattr(self, f"original_{attribute}"):
                original = getattr(self, f"original_{attribute}")
                if restoration_required(
                    current.get(property_name),
                    original,
                    getattr(self, f"owned_{attribute}"),
                ):
                    update[property_name] = original
        if update:
            revision = current.get("RevisionId")
            if not revision:
                raise SafetyViolation(
                    "Lambda recovery requires a configuration revision"
                )
            self.lambda_client.update_function_configuration(
                FunctionName=self.function_name, RevisionId=revision, **update
            )
            self._wait_for_configuration(self.function_name, False)
            restored = self.lambda_client.get_function_configuration(
                FunctionName=self.function_name
            )
            if any(
                restored.get(property_name) != value
                for property_name, value in update.items()
            ):
                raise SafetyViolation("Lambda configuration recovery is not verified")
        if hasattr(self, "original_concurrency"):
            current_limit = self.lambda_client.get_function_concurrency(
                FunctionName=self.function_name
            ).get("ReservedConcurrentExecutions")
            original = self.original_concurrency
            if restoration_required(current_limit, original, self.owned_concurrency):
                if original is None:
                    self.lambda_client.delete_function_concurrency(
                        FunctionName=self.function_name
                    )
                else:
                    self.lambda_client.put_function_concurrency(
                        FunctionName=self.function_name,
                        ReservedConcurrentExecutions=original,
                    )
            restored = self.lambda_client.get_function_concurrency(
                FunctionName=self.function_name
            ).get("ReservedConcurrentExecutions")
            if restored != original:
                raise SafetyViolation("Lambda concurrency recovery is not verified")
        self.rollback_verified = True


class S3ChaosExperiment(ChaosExperiment):
    """S3-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.s3 = self.client("s3")

    def deny_bucket_policy(
        self,
        bucket_name: str,
        break_glass_principal_arn: str,
    ) -> ExperimentResult:
        """Add deny-all bucket policy"""
        experiment_id = _experiment_id("s3-policy-deny")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.S3_BUCKET_POLICY_DENY,
            start_time=utc_now(),
        )

        try:
            # Get current bucket policy
            try:
                response = self.s3.get_bucket_policy(Bucket=bucket_name)
                self.original_policy = response["Policy"]
            except self.s3.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    self.original_policy = None
                else:
                    raise

            self.bucket_name = bucket_name

            partition = "aws-us-gov" if self.region in GOVCLOUD_REGIONS else "aws"
            deny_policy = (
                json.loads(self.original_policy)
                if self.original_policy
                else {"Version": "2012-10-17", "Statement": []}
            )
            statements = deny_policy.setdefault("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
                deny_policy["Statement"] = statements
            if any(item.get("Sid") == "ChaosFrameworkDeny" for item in statements):
                raise ConfigurationError(
                    "Bucket policy already contains ChaosFrameworkDeny"
                )
            statements.append(
                {
                    "Sid": "ChaosFrameworkDeny",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:{partition}:s3:::{bucket_name}",
                        f"arn:{partition}:s3:::{bucket_name}/*",
                    ],
                    "Condition": {
                        "ArnNotEquals": {"aws:PrincipalArn": break_glass_principal_arn}
                    },
                }
            )

            self.owned_policy_statement = copy.deepcopy(deny_policy["Statement"][-1])
            if not self.dry_run:
                self.s3.put_bucket_policy(
                    Bucket=bucket_name, Policy=json.dumps(deny_policy)
                )
                result.affected_resources = [bucket_name]
                logger.info(f"Applied deny-all policy to bucket: {bucket_name}")
            else:
                logger.info(
                    f"DRY RUN: Would apply deny-all policy to bucket: {bucket_name}"
                )
                result.affected_resources = [bucket_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying bucket policy: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def suspend_versioning(self, bucket_name: str) -> ExperimentResult:
        """Suspend bucket versioning"""
        experiment_id = _experiment_id("s3-versioning-suspend")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.S3_BUCKET_VERSIONING_SUSPEND,
            start_time=utc_now(),
        )

        try:
            # Get current versioning status
            response = self.s3.get_bucket_versioning(Bucket=bucket_name)
            self.original_versioning = response.get("Status")
            if self.original_versioning != "Enabled":
                raise ConfigurationError(
                    "S3 versioning suspension requires a currently enabled bucket"
                )
            self.bucket_name = bucket_name

            if not self.dry_run:
                self.s3.put_bucket_versioning(
                    Bucket=bucket_name, VersioningConfiguration={"Status": "Suspended"}
                )
                result.affected_resources = [bucket_name]
                logger.info(f"Suspended versioning for bucket: {bucket_name}")
            else:
                logger.info(
                    f"DRY RUN: Would suspend versioning for bucket: {bucket_name}"
                )
                result.affected_resources = [bucket_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error suspending versioning: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def disable_encryption(self, bucket_name: str) -> ExperimentResult:
        """Disable bucket encryption"""
        experiment_id = _experiment_id("s3-encryption-disable")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.S3_BUCKET_ENCRYPTION_DISABLE,
            start_time=utc_now(),
        )

        try:
            # Get current encryption configuration
            try:
                response = self.s3.get_bucket_encryption(Bucket=bucket_name)
                self.original_encryption = response["ServerSideEncryptionConfiguration"]
                self.had_encryption = True
            except self.s3.exceptions.ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    self.had_encryption = False
                else:
                    raise

            self.bucket_name = bucket_name

            if not self.dry_run:
                if self.had_encryption:
                    self.s3.delete_bucket_encryption(Bucket=bucket_name)
                    result.affected_resources = [bucket_name]
                    logger.info(f"Disabled encryption for bucket: {bucket_name}")
                else:
                    logger.info(f"Bucket {bucket_name} already has no encryption")
            else:
                logger.info(
                    f"DRY RUN: Would disable encryption for bucket: {bucket_name}"
                )
                result.affected_resources = [bucket_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error disabling encryption: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def delete_objects(
        self, bucket_name: str, prefix: str = "", max_objects: int = 10
    ) -> ExperimentResult:
        """Delete objects from bucket"""
        experiment_id = _experiment_id("s3-object-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.S3_OBJECT_DELETE,
            start_time=utc_now(),
        )

        try:
            if not isinstance(prefix, str) or not prefix.strip():
                raise SafetyViolation(
                    "S3 deletion requires an explicit nonempty prefix"
                )
            # List objects to delete
            response = self.s3.list_objects_v2(
                Bucket=bucket_name, Prefix=prefix, MaxKeys=max_objects
            )
            contents = response.get("Contents", [])
            if not contents:
                raise ConfigurationError(
                    "The selected S3 prefix contains no objects to delete"
                )
            self.deleted_objects = []
            objects_to_delete = []

            for obj in contents:
                # Store object details for evidence. This operation is irreversible.
                self.deleted_objects.append(
                    {"Key": obj["Key"], "VersionId": obj.get("VersionId")}
                )
                objects_to_delete.append({"Key": obj["Key"]})

            if not self.dry_run:
                deletion = self.s3.delete_objects(
                    Bucket=bucket_name, Delete={"Objects": objects_to_delete}
                )
                if deletion.get("Errors"):
                    raise RuntimeError(
                        "S3 reported one or more object deletion failures"
                    )
                result.affected_resources = [
                    f"{bucket_name}/{obj['Key']}" for obj in objects_to_delete
                ]
                logger.info(
                    f"Deleted {len(objects_to_delete)} objects from bucket: {bucket_name}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would delete {len(objects_to_delete)} objects from bucket: {bucket_name}"
                )
                result.affected_resources = [
                    f"{bucket_name}/{obj['Key']}" for obj in objects_to_delete
                ]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting objects: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_lifecycle(
        self, bucket_name: str, expire_days: int = 1
    ) -> ExperimentResult:
        """Apply expiration with an explicit irreversible data-loss classification."""
        logger.warning(
            "Lifecycle expiration can permanently delete objects; settings restoration cannot recover them"
        )
        experiment_id = _experiment_id("s3-lifecycle-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.S3_LIFECYCLE_MODIFY,
            start_time=utc_now(),
        )
        result.additional_info["data_loss_warning"] = (
            "Lifecycle expiration may permanently delete objects; restoring settings does not recover deleted data."
        )

        try:
            # Get current lifecycle configuration
            try:
                response = self.s3.get_bucket_lifecycle_configuration(
                    Bucket=bucket_name
                )
                self.original_lifecycle = response["Rules"]
                self.had_lifecycle = True
            except self.s3.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                    self.had_lifecycle = False
                else:
                    raise

            self.bucket_name = bucket_name

            # Create aggressive lifecycle rule
            lifecycle_config = {
                "Rules": [
                    {
                        "ID": "ChaosExpireAll",
                        "Status": "Enabled",
                        "Filter": {"Prefix": ""},
                        "Expiration": {"Days": expire_days},
                    }
                ]
            }

            self.owned_lifecycle = copy.deepcopy(lifecycle_config["Rules"])
            if not self.dry_run:
                self.s3.put_bucket_lifecycle_configuration(
                    Bucket=bucket_name, LifecycleConfiguration=lifecycle_config
                )
                result.affected_resources = [bucket_name]
                logger.info(
                    f"Modified lifecycle to expire objects after {expire_days} days for bucket: {bucket_name}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would modify lifecycle for bucket: {bucket_name}"
                )
                result.affected_resources = [bucket_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying lifecycle: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Restore only owned S3 changes, refusing conflicting concurrent state."""
        if hasattr(self, "owned_lifecycle"):
            raise SafetyViolation(
                "Lifecycle expiration is irreversible; settings restoration cannot recover deleted objects"
            )
        if not hasattr(self, "bucket_name") or not self.mutation_attempts:
            return
        bucket = self.bucket_name
        if hasattr(self, "owned_policy_statement"):
            current = self.s3.get_bucket_policy(Bucket=bucket)["Policy"]
            restored = remove_owned_policy_statement(
                current, self.owned_policy_statement
            )
            if restored != json.loads(current):
                if restored["Statement"]:
                    self.s3.put_bucket_policy(
                        Bucket=bucket, Policy=json.dumps(restored)
                    )
                    observed = json.loads(
                        self.s3.get_bucket_policy(Bucket=bucket)["Policy"]
                    )
                    if observed != restored:
                        raise SafetyViolation("S3 policy recovery is not verified")
                else:
                    self.s3.delete_bucket_policy(Bucket=bucket)
                    try:
                        self.s3.get_bucket_policy(Bucket=bucket)
                    except self.s3.exceptions.ClientError as error:
                        if error.response["Error"]["Code"] != "NoSuchBucketPolicy":
                            raise
                    else:
                        raise SafetyViolation("S3 policy deletion is not verified")
            self.rollback_verified = True
        if hasattr(self, "original_versioning"):
            current = self.s3.get_bucket_versioning(Bucket=bucket).get("Status")
            if restoration_required(current, self.original_versioning, "Suspended"):
                self.s3.put_bucket_versioning(
                    Bucket=bucket,
                    VersioningConfiguration={"Status": self.original_versioning},
                )
            if (
                self.s3.get_bucket_versioning(Bucket=bucket).get("Status")
                != self.original_versioning
            ):
                raise SafetyViolation("S3 versioning recovery is not verified")
            self.rollback_verified = True
        if getattr(self, "had_encryption", False):
            try:
                current = self.s3.get_bucket_encryption(Bucket=bucket)[
                    "ServerSideEncryptionConfiguration"
                ]
            except self.s3.exceptions.ClientError as error:
                if (
                    error.response["Error"]["Code"]
                    != "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    raise
                current = None
            if restoration_required(current, self.original_encryption, None):
                self.s3.put_bucket_encryption(
                    Bucket=bucket,
                    ServerSideEncryptionConfiguration=self.original_encryption,
                )
            if (
                self.s3.get_bucket_encryption(Bucket=bucket)[
                    "ServerSideEncryptionConfiguration"
                ]
                != self.original_encryption
            ):
                raise SafetyViolation("S3 encryption recovery is not verified")
            self.rollback_verified = True


class SQSChaosExperiment(ChaosExperiment):
    """SQS-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.sqs = self.client("sqs")

    def purge_queue(self, queue_url: str) -> ExperimentResult:
        """Purge all messages from queue"""
        experiment_id = _experiment_id("sqs-purge")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.SQS_QUEUE_PURGE,
            start_time=utc_now(),
        )

        try:
            # Get queue attributes before purge
            attrs = self.sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["ApproximateNumberOfMessages", "QueueArn"],
            )
            result.metrics_before = {
                "message_count": int(
                    attrs["Attributes"].get("ApproximateNumberOfMessages", 0)
                )
            }

            if not self.dry_run:
                expected = str(self.config.get("queue_arn", ""))
                validate_queue_identity(self.config, queue_url, expected)
                # Resolve owner again after safety polling, immediately before destructive call.
                self._check_forward_safety()
                current = self.sqs.get_queue_attributes(
                    QueueUrl=queue_url, AttributeNames=["QueueArn"]
                )
                if (
                    attrs.get("Attributes", {}).get("QueueArn") != expected
                    or current.get("Attributes", {}).get("QueueArn") != expected
                ):
                    raise SafetyViolation(
                        "SQS returned a QueueArn different from the reviewed owner"
                    )
                self.sqs.purge_queue(QueueUrl=queue_url)
                result.affected_resources = [queue_url]
                logger.info(f"Purged queue: {queue_url}")
            else:
                logger.info(f"DRY RUN: Would purge queue: {queue_url}")
                result.affected_resources = [queue_url]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error purging queue: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def restrict_queue_policy(
        self,
        queue_url: str,
        break_glass_principal_arn: str,
    ) -> ExperimentResult:
        """Restrict queue access policy"""
        experiment_id = _experiment_id("sqs-policy-restrict")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.SQS_QUEUE_POLICY_RESTRICT,
            start_time=utc_now(),
        )

        try:
            # Get current policy
            attrs = self.sqs.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["Policy", "QueueArn"]
            )
            self.original_policy = attrs["Attributes"].get("Policy")
            queue_arn = attrs["Attributes"]["QueueArn"]
            self.queue_url = queue_url

            restrictive_policy = (
                json.loads(self.original_policy)
                if self.original_policy
                else {"Version": "2012-10-17", "Statement": []}
            )
            statements = restrictive_policy.setdefault("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
                restrictive_policy["Statement"] = statements
            if any(item.get("Sid") == "ChaosFrameworkDeny" for item in statements):
                raise ConfigurationError(
                    "Queue policy already contains ChaosFrameworkDeny"
                )
            statements.append(
                {
                    "Sid": "ChaosFrameworkDeny",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "sqs:*",
                    "Resource": queue_arn,
                    "Condition": {
                        "ArnNotEquals": {"aws:PrincipalArn": break_glass_principal_arn}
                    },
                }
            )

            if not self.dry_run:
                self.sqs.set_queue_attributes(
                    QueueUrl=queue_url,
                    Attributes={"Policy": json.dumps(restrictive_policy)},
                )
                result.affected_resources = [queue_url]
                logger.info(f"Applied restrictive policy to queue: {queue_url}")
            else:
                logger.info(f"DRY RUN: Would restrict queue policy: {queue_url}")
                result.affected_resources = [queue_url]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error restricting queue policy: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_message_delay(
        self, queue_url: str, delay_seconds: int = 900
    ) -> ExperimentResult:
        """Modify queue message delay"""
        experiment_id = _experiment_id("sqs-delay-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.SQS_MESSAGE_DELAY,
            start_time=utc_now(),
        )

        try:
            # Get current delay
            attrs = self.sqs.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["DelaySeconds"]
            )
            self.original_delay = attrs["Attributes"].get("DelaySeconds", "0")
            self.queue_url = queue_url

            if not self.dry_run:
                self.sqs.set_queue_attributes(
                    QueueUrl=queue_url, Attributes={"DelaySeconds": str(delay_seconds)}
                )
                result.affected_resources = [queue_url]
                logger.info(
                    f"Set message delay to {delay_seconds}s for queue: {queue_url}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would modify message delay for queue: {queue_url}"
                )
                result.affected_resources = [queue_url]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying message delay: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_visibility_timeout(
        self, queue_url: str, timeout_seconds: int = 43200
    ) -> ExperimentResult:
        """Modify queue visibility timeout"""
        experiment_id = _experiment_id("sqs-visibility-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.SQS_VISIBILITY_TIMEOUT,
            start_time=utc_now(),
        )

        try:
            # Get current timeout
            attrs = self.sqs.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"]
            )
            self.original_timeout = attrs["Attributes"].get("VisibilityTimeout", "30")
            self.queue_url = queue_url

            if not self.dry_run:
                self.sqs.set_queue_attributes(
                    QueueUrl=queue_url,
                    Attributes={"VisibilityTimeout": str(timeout_seconds)},
                )
                result.affected_resources = [queue_url]
                logger.info(
                    f"Set visibility timeout to {timeout_seconds}s for queue: {queue_url}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would modify visibility timeout for queue: {queue_url}"
                )
                result.affected_resources = [queue_url]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying visibility timeout: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback SQS experiments"""
        try:
            if hasattr(self, "queue_url"):
                attributes = {}

                if hasattr(self, "original_policy"):
                    if self.original_policy:
                        attributes["Policy"] = self.original_policy
                    else:
                        # Remove policy by setting empty
                        attributes["Policy"] = ""

                if hasattr(self, "original_delay"):
                    attributes["DelaySeconds"] = self.original_delay

                if hasattr(self, "original_timeout"):
                    attributes["VisibilityTimeout"] = self.original_timeout

                if attributes:
                    self.sqs.set_queue_attributes(
                        QueueUrl=self.queue_url, Attributes=attributes
                    )
                    logger.info(f"Restored queue attributes for {self.queue_url}")

        except Exception as e:
            logger.error(f"Error during SQS rollback: {e}")
            raise


class SNSChaosExperiment(ChaosExperiment):
    """SNS-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.sns = self.client("sns")

    def delete_subscription(self, subscription_arn: str) -> ExperimentResult:
        """Delete SNS subscription"""
        experiment_id = _experiment_id("sns-subscription-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.SNS_SUBSCRIPTION_DELETE,
            start_time=utc_now(),
        )

        try:
            # Get subscription details for potential recreation
            attrs = self.sns.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            self.subscription_details = attrs["Attributes"]

            if not self.dry_run:
                self.sns.unsubscribe(SubscriptionArn=subscription_arn)
                result.affected_resources = [subscription_arn]
                logger.info(f"Deleted subscription: {subscription_arn}")
            else:
                logger.info(f"DRY RUN: Would delete subscription: {subscription_arn}")
                result.affected_resources = [subscription_arn]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting subscription: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def restrict_topic_policy(
        self,
        topic_arn: str,
        break_glass_principal_arn: str,
    ) -> ExperimentResult:
        """Restrict topic access policy"""
        experiment_id = _experiment_id("sns-policy-restrict")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.SNS_TOPIC_POLICY_RESTRICT,
            start_time=utc_now(),
        )

        try:
            # Get current policy
            attrs = self.sns.get_topic_attributes(TopicArn=topic_arn)
            self.original_policy = attrs["Attributes"].get("Policy")
            self.topic_arn = topic_arn

            restrictive_policy = (
                json.loads(self.original_policy)
                if self.original_policy
                else {"Version": "2012-10-17", "Statement": []}
            )
            statements = restrictive_policy.setdefault("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
                restrictive_policy["Statement"] = statements
            if any(item.get("Sid") == "ChaosFrameworkDeny" for item in statements):
                raise ConfigurationError(
                    "Topic policy already contains ChaosFrameworkDeny"
                )
            statements.append(
                {
                    "Sid": "ChaosFrameworkDeny",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "SNS:*",
                    "Resource": topic_arn,
                    "Condition": {
                        "ArnNotEquals": {"aws:PrincipalArn": break_glass_principal_arn}
                    },
                }
            )

            if not self.original_policy:
                raise SafetyViolation("SNS policy pre-state must be restorable")
            self.owned_policy_statement = copy.deepcopy(statements[-1])
            if not self.dry_run:
                self.sns.set_topic_attributes(
                    TopicArn=topic_arn,
                    AttributeName="Policy",
                    AttributeValue=json.dumps(restrictive_policy),
                )
                result.affected_resources = [topic_arn]
                logger.info(f"Applied restrictive policy to topic: {topic_arn}")
            else:
                logger.info(f"DRY RUN: Would restrict topic policy: {topic_arn}")
                result.affected_resources = [topic_arn]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error restricting topic policy: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback SNS experiments"""
        try:
            if hasattr(self, "subscription_details"):
                # Re-create subscription
                topic_arn = self.subscription_details["TopicArn"]
                protocol = self.subscription_details["Protocol"]
                endpoint = self.subscription_details["Endpoint"]

                self.sns.subscribe(
                    TopicArn=topic_arn, Protocol=protocol, Endpoint=endpoint
                )
                logger.info(f"Re-created subscription for topic {topic_arn}")

            if hasattr(self, "topic_arn") and hasattr(self, "owned_policy_statement"):
                current = self.sns.get_topic_attributes(TopicArn=self.topic_arn)[
                    "Attributes"
                ]["Policy"]
                restored = remove_owned_policy_statement(
                    current, self.owned_policy_statement
                )
                if restored != json.loads(current):
                    self.sns.set_topic_attributes(
                        TopicArn=self.topic_arn,
                        AttributeName="Policy",
                        AttributeValue=json.dumps(restored),
                    )
                observed = json.loads(
                    self.sns.get_topic_attributes(TopicArn=self.topic_arn)[
                        "Attributes"
                    ]["Policy"]
                )
                if observed != restored:
                    raise SafetyViolation("SNS policy recovery is not verified")
                self.rollback_verified = True

        except Exception as e:
            logger.error(f"Error during SNS rollback: {e}")
            raise


class ELBChaosExperiment(ChaosExperiment):
    """ELB/ALB/NLB-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.elbv2 = self.client("elbv2")

    def remove_targets(
        self,
        target_group_arn: str,
        target_ids: list[str],
        target_descriptors: list[dict[str, Any]] | None = None,
    ) -> ExperimentResult:
        """Remove targets from target group"""
        experiment_id = _experiment_id("elb-remove-targets")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ELB_REMOVE_TARGETS,
            start_time=utc_now(),
        )

        try:
            current = self.elbv2.describe_target_health(
                TargetGroupArn=target_group_arn,
            ).get("TargetHealthDescriptions", [])
            selected = [
                item
                for item in current
                if item.get("Target", {}).get("Id") in target_ids
            ]
            if not self.dry_run and not target_descriptors:
                raise SafetyViolation(
                    "Live ELB removal requires exact Id/Port/AvailabilityZone descriptors"
                )
            if target_descriptors:
                if any(
                    set(item) - {"Id", "Port", "AvailabilityZone"}
                    or item.get("Id") not in target_ids
                    or not isinstance(item.get("Port"), int)
                    or isinstance(item["Port"], bool)
                    or not 1 <= item["Port"] <= 65535
                    for item in target_descriptors
                ):
                    raise ConfigurationError("Invalid exact ELB target descriptor")
                identities = {
                    json.dumps(item, sort_keys=True) for item in target_descriptors
                }
                selected = [
                    item
                    for item in selected
                    if json.dumps(item["Target"], sort_keys=True) in identities
                ]
                if {
                    json.dumps(item["Target"], sort_keys=True) for item in selected
                } != identities:
                    raise SafetyViolation(
                        "An approved ELB registration is missing or changed"
                    )
            elif len(selected) != len(set(target_ids)):
                raise SafetyViolation("An ELB target ID selects multiple registrations")
            current = selected
            targets = [copy.deepcopy(item["Target"]) for item in selected]
            returned_ids = {str(item.get("Target", {}).get("Id")) for item in current}
            if returned_ids != set(target_ids):
                raise ConfigurationError(
                    "The target group does not contain every selected target"
                )
            # Store original targets for rollback
            self.original_targets = targets
            self.target_group_arn = target_group_arn

            if not self.dry_run:
                self.elbv2.deregister_targets(
                    TargetGroupArn=target_group_arn, Targets=targets
                )
                result.affected_resources = target_ids
                logger.info(f"Removed targets {target_ids} from target group")
            else:
                logger.info(
                    f"DRY RUN: Would remove targets {target_ids} from target group"
                )
                result.affected_resources = target_ids

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error removing targets: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_attributes(
        self, target_group_arn: str, deregistration_delay: int = 3600
    ) -> ExperimentResult:
        """Modify target group attributes"""
        experiment_id = _experiment_id("elb-attributes-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ELB_MODIFY_ATTRIBUTES,
            start_time=utc_now(),
        )

        try:
            # Get current attributes
            response = self.elbv2.describe_target_group_attributes(
                TargetGroupArn=target_group_arn
            )
            self.original_attributes = {
                attr["Key"]: attr["Value"] for attr in response["Attributes"]
            }
            self.target_group_arn = target_group_arn

            if not self.dry_run:
                self.elbv2.modify_target_group_attributes(
                    TargetGroupArn=target_group_arn,
                    Attributes=[
                        {
                            "Key": "deregistration_delay.timeout_seconds",
                            "Value": str(deregistration_delay),
                        }
                    ],
                )
                result.affected_resources = [target_group_arn]
                logger.info(f"Modified deregistration delay to {deregistration_delay}s")
            else:
                logger.info("DRY RUN: Would modify target group attributes")
                result.affected_resources = [target_group_arn]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying attributes: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_health_check(
        self, target_group_arn: str, interval: int = 300, timeout: int = 120
    ) -> ExperimentResult:
        """Modify health check settings"""
        experiment_id = _experiment_id("elb-health-check-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ELB_HEALTH_CHECK_MODIFY,
            start_time=utc_now(),
        )

        try:
            # Get current health check settings
            response = self.elbv2.describe_target_groups(
                TargetGroupArns=[target_group_arn]
            )
            groups = response.get("TargetGroups", [])
            if len(groups) != 1 or groups[0].get("TargetGroupArn") != target_group_arn:
                raise ConfigurationError(
                    "ELB did not return the exact selected target group"
                )
            if response["TargetGroups"]:
                tg = response["TargetGroups"][0]
                self.original_health_check = {
                    "HealthCheckIntervalSeconds": tg.get("HealthCheckIntervalSeconds"),
                    "HealthCheckTimeoutSeconds": tg.get("HealthCheckTimeoutSeconds"),
                }
                self.target_group_arn = target_group_arn

                if not self.dry_run:
                    self.elbv2.modify_target_group(
                        TargetGroupArn=target_group_arn,
                        HealthCheckIntervalSeconds=interval,
                        HealthCheckTimeoutSeconds=timeout,
                    )
                    result.affected_resources = [target_group_arn]
                    logger.info(
                        f"Modified health check: interval={interval}s, timeout={timeout}s"
                    )
                else:
                    logger.info("DRY RUN: Would modify health check settings")
                    result.affected_resources = [target_group_arn]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying health check: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_listener_rule(
        self,
        rule_arn: str,
        action_type: str = "fixed-response",
        status_code: str = "503",
    ) -> ExperimentResult:
        """Modify listener rule to return error"""
        experiment_id = _experiment_id("elb-listener-rule-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ELB_LISTENER_RULE_MODIFY,
            start_time=utc_now(),
        )

        try:
            # Get current rule
            response = self.elbv2.describe_rules(RuleArns=[rule_arn])
            rules = response.get("Rules", [])
            if (
                len(rules) != 1
                or rules[0].get("RuleArn") != rule_arn
                or not rules[0].get("Actions")
            ):
                raise ConfigurationError(
                    "ELB did not return one matching rule with actions"
                )
            if response["Rules"]:
                self.original_actions = response["Rules"][0]["Actions"]
                self.rule_arn = rule_arn

                if not self.dry_run:
                    # Modify to return error
                    self.elbv2.modify_rule(
                        RuleArn=rule_arn,
                        Actions=[
                            {
                                "Type": action_type,
                                "FixedResponseConfig": {
                                    "StatusCode": status_code,
                                    "ContentType": "text/plain",
                                    "MessageBody": "Service Unavailable - Chaos Experiment",
                                },
                            }
                        ],
                    )
                    result.affected_resources = [rule_arn]
                    logger.info(f"Modified listener rule to return {status_code}")
                else:
                    logger.info("DRY RUN: Would modify listener rule")
                    result.affected_resources = [rule_arn]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying listener rule: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback ELB experiments"""
        try:
            if hasattr(self, "original_targets") and hasattr(self, "target_group_arn"):
                # Re-register targets
                targets = copy.deepcopy(self.original_targets)
                self.elbv2.register_targets(
                    TargetGroupArn=self.target_group_arn, Targets=targets
                )
                restored = self.elbv2.describe_target_health(
                    TargetGroupArn=self.target_group_arn, Targets=targets
                ).get("TargetHealthDescriptions", [])
                for target in targets:
                    if not any(
                        item.get("Target") == target
                        and item.get("TargetHealth", {}).get("State") == "healthy"
                        for item in restored
                    ):
                        raise SafetyViolation(
                            "ELB target registration and health were not verified"
                        )
                self.rollback_verified = True
                logger.info(f"Re-registered targets: {self.original_targets}")

            if hasattr(self, "original_attributes") and hasattr(
                self, "target_group_arn"
            ):
                # Restore attributes
                attributes = []
                if "deregistration_delay.timeout_seconds" in self.original_attributes:
                    attributes.append(
                        {
                            "Key": "deregistration_delay.timeout_seconds",
                            "Value": self.original_attributes[
                                "deregistration_delay.timeout_seconds"
                            ],
                        }
                    )
                if attributes:
                    self.elbv2.modify_target_group_attributes(
                        TargetGroupArn=self.target_group_arn, Attributes=attributes
                    )
                    logger.info("Restored target group attributes")

            if hasattr(self, "original_health_check") and hasattr(
                self, "target_group_arn"
            ):
                # Restore health check
                self.elbv2.modify_target_group(
                    TargetGroupArn=self.target_group_arn, **self.original_health_check
                )
                logger.info("Restored health check settings")

            if hasattr(self, "original_actions") and hasattr(self, "rule_arn"):
                # Restore listener rule
                self.elbv2.modify_rule(
                    RuleArn=self.rule_arn, Actions=self.original_actions
                )
                logger.info("Restored listener rule")

        except Exception as e:
            logger.error(f"Error during ELB rollback: {e}")
            raise


class ECSChaosExperiment(ChaosExperiment):
    """ECS-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.ecs = self.client("ecs")

    def _wait_for_service_count(
        self, cluster: str, service: str, desired_count: int, interruptible: bool
    ) -> None:
        """Wait for the ECS service control plane to expose a desired count."""
        deadline = time.monotonic() + int(self.config.get("state_timeout_seconds", 600))
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            response = self.ecs.describe_services(cluster=cluster, services=[service])
            services = response.get("services", [])
            if response.get("failures") or len(services) != 1:
                raise RuntimeError("ECS did not return the selected service")
            service_state = services[0]
            unhealthy = any(
                deployment.get("rolloutState") == "FAILED"
                for deployment in service_state.get("deployments", [])
            )
            if unhealthy:
                raise SafetyViolation("ECS service has a failed deployment")
            if service_state.get("desiredCount") == desired_count and (
                interruptible
                or (
                    service_state.get("runningCount") == desired_count
                    and service_state.get("pendingCount") == 0
                    and all(
                        deployment.get("rolloutState") in {None, "COMPLETED"}
                        for deployment in service_state.get("deployments", [])
                    )
                )
            ):
                if not interruptible:
                    if len(service_state.get("deployments", [])) != 1:
                        time.sleep(min(2, max(0.1, deadline - time.monotonic())))
                        continue
                    self.rollback_verified = True
                return
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError("Timed out waiting for the ECS service desired count")

    def _wait_for_container_status(
        self,
        cluster: str,
        container_instance_arn: str,
        expected_status: str,
        interruptible: bool,
    ) -> None:
        """Wait for an ECS container instance status change."""
        deadline = time.monotonic() + int(self.config.get("state_timeout_seconds", 600))
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            response = self.ecs.describe_container_instances(
                cluster=cluster,
                containerInstances=[container_instance_arn],
            )
            instances = response.get("containerInstances", [])
            if response.get("failures") or len(instances) != 1:
                raise RuntimeError("ECS did not return the selected container instance")
            if instances[0].get("status") == expected_status:
                return
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError("Timed out waiting for the ECS container instance status")

    def stop_tasks(
        self, cluster: str, task_arns: list[str], reason: str = "Chaos experiment"
    ) -> ExperimentResult:
        """Stop ECS tasks"""
        experiment_id = _experiment_id("ecs-task-stop")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ECS_TASK_STOP,
            start_time=utc_now(),
        )

        try:
            # Get task details before stopping
            task_details = self.ecs.describe_tasks(cluster=cluster, tasks=task_arns)
            if task_details.get("failures"):
                raise ConfigurationError("ECS could not resolve every selected task")
            self.stopped_task_details = task_details.get("tasks", [])
            returned_tasks = {
                str(item.get("taskArn")) for item in self.stopped_task_details
            }
            if returned_tasks != set(task_arns):
                raise ConfigurationError("ECS did not return every selected task")
            if any(
                item.get("lastStatus") not in {"RUNNING", "PENDING"}
                for item in self.stopped_task_details
            ):
                raise SafetyViolation("Every selected ECS task must be active")

            if not self.dry_run:
                for task_arn in task_arns:
                    self.ecs.stop_task(cluster=cluster, task=task_arn, reason=reason)
                result.affected_resources = task_arns
                logger.info(f"Stopped tasks: {task_arns}")
            else:
                logger.info(f"DRY RUN: Would stop tasks: {task_arns}")
                result.affected_resources = task_arns

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error stopping tasks: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def update_service(
        self, cluster: str, service: str, desired_count: int = 0
    ) -> ExperimentResult:
        """Update ECS service desired count"""
        experiment_id = _experiment_id("ecs-service-update")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ECS_SERVICE_UPDATE,
            start_time=utc_now(),
        )

        try:
            # Get current desired count
            service_info = self.ecs.describe_services(
                cluster=cluster, services=[service]
            )
            if (
                service_info.get("failures")
                or len(service_info.get("services", [])) != 1
            ):
                raise ConfigurationError(f"ECS service not found: {service}")
            if service_info["services"]:
                original_desired_count = service_info["services"][0]["desiredCount"]
                if desired_count < 0 or desired_count >= original_desired_count:
                    raise SafetyViolation(
                        "ECS throttle must reduce the current desired count"
                    )
                self.original_desired_count = original_desired_count
                self.cluster = cluster
                self.service = service

                if not self.dry_run:
                    self.ecs.update_service(
                        cluster=cluster, service=service, desiredCount=desired_count
                    )
                    self._wait_for_service_count(cluster, service, desired_count, True)
                    result.affected_resources = [f"{cluster}/{service}"]
                    logger.info(
                        f"Updated service {service} desired count to {desired_count}"
                    )
                else:
                    logger.info(
                        f"DRY RUN: Would update service {service} desired count"
                    )
                    result.affected_resources = [f"{cluster}/{service}"]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error updating service: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def drain_container_instance(
        self, cluster: str, container_instance_arn: str
    ) -> ExperimentResult:
        """Drain ECS container instance"""
        experiment_id = _experiment_id("ecs-instance-drain")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ECS_CONTAINER_INSTANCE_DRAIN,
            start_time=utc_now(),
        )

        try:
            # Get current status
            instance_info = self.ecs.describe_container_instances(
                cluster=cluster, containerInstances=[container_instance_arn]
            )
            if (
                instance_info.get("failures")
                or len(instance_info.get("containerInstances", [])) != 1
            ):
                raise ConfigurationError(
                    f"ECS container instance not found: {container_instance_arn}"
                )
            if instance_info["containerInstances"]:
                self.original_status = instance_info["containerInstances"][0]["status"]
                if self.original_status != "ACTIVE":
                    raise SafetyViolation(
                        "The selected ECS container instance must be ACTIVE"
                    )
                self.cluster = cluster
                self.container_instance_arn = container_instance_arn

                if not self.dry_run:
                    self.ecs.update_container_instances_state(
                        cluster=cluster,
                        containerInstances=[container_instance_arn],
                        status="DRAINING",
                    )
                    self._wait_for_container_status(
                        cluster, container_instance_arn, "DRAINING", True
                    )
                    result.affected_resources = [container_instance_arn]
                    logger.info(
                        f"Set container instance to DRAINING: {container_instance_arn}"
                    )
                else:
                    logger.info(
                        f"DRY RUN: Would drain container instance: {container_instance_arn}"
                    )
                    result.affected_resources = [container_instance_arn]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error draining container instance: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_task_definition(
        self, task_definition: str, cpu: str = "256", memory: str = "512"
    ) -> ExperimentResult:
        """Modify task definition resource limits"""
        experiment_id = _experiment_id("ecs-taskdef-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ECS_TASK_DEFINITION_MODIFY,
            start_time=utc_now(),
        )

        try:
            # Get current task definition
            response = self.ecs.describe_task_definition(taskDefinition=task_definition)
            task_def = response["taskDefinition"]

            # Store original values
            self.original_cpu = task_def.get("cpu")
            self.original_memory = task_def.get("memory")
            self.task_family = task_def["family"]

            if not self.dry_run:
                # Create new revision with modified resources
                new_task_def = task_def.copy()
                new_task_def["cpu"] = cpu
                new_task_def["memory"] = memory

                # Remove fields that can't be in registration
                fields_to_remove = [
                    "taskDefinitionArn",
                    "revision",
                    "status",
                    "requiresAttributes",
                    "compatibilities",
                    "registeredAt",
                    "registeredBy",
                    "deregisteredAt",
                ]
                for field in fields_to_remove:
                    new_task_def.pop(field, None)

                response = self.ecs.register_task_definition(**new_task_def)
                result.affected_resources = [
                    response["taskDefinition"]["taskDefinitionArn"]
                ]
                logger.info(
                    f"Created new task definition revision with cpu={cpu}, memory={memory}"
                )
            else:
                logger.info("DRY RUN: Would modify task definition resources")
                result.affected_resources = [task_definition]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying task definition: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback ECS experiments"""
        try:
            if hasattr(self, "original_desired_count") and hasattr(self, "service"):
                # Restore service desired count
                self.ecs.update_service(
                    cluster=self.cluster,
                    service=self.service,
                    desiredCount=self.original_desired_count,
                )
                self._wait_for_service_count(
                    self.cluster, self.service, self.original_desired_count, False
                )
                logger.info(
                    f"Restored service {self.service} desired count to {self.original_desired_count}"
                )

            if (
                hasattr(self, "original_status")
                and hasattr(self, "container_instance_arn")
                and self.original_status == "ACTIVE"
            ):
                # Restore container instance status
                self.ecs.update_container_instances_state(
                    cluster=self.cluster,
                    containerInstances=[self.container_instance_arn],
                    status="ACTIVE",
                )
                self._wait_for_container_status(
                    self.cluster,
                    self.container_instance_arn,
                    "ACTIVE",
                    False,
                )
                logger.info("Restored container instance to ACTIVE")

        except Exception as e:
            logger.error(f"Error during ECS rollback: {e}")
            raise


class KinesisChaosExperiment(ChaosExperiment):
    """Kinesis-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.kinesis = self.client("kinesis")

    def _wait_for_retention(
        self, stream_name: str, retention_hours: int, interruptible: bool
    ) -> None:
        """Wait for a Kinesis retention decrease to become active."""
        deadline = time.monotonic() + int(self.config.get("state_timeout_seconds", 600))
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            description = self.kinesis.describe_stream(StreamName=stream_name).get(
                "StreamDescription", {}
            )
            if (
                description.get("StreamStatus") == "ACTIVE"
                and description.get("RetentionPeriodHours") == retention_hours
            ):
                return
            wait_seconds = min(5.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError("Timed out waiting for the Kinesis retention update")

    def split_shard(
        self, stream_name: str, shard_to_split: str, new_starting_hash_key: str
    ) -> ExperimentResult:
        """Split a Kinesis shard"""
        experiment_id = _experiment_id("kinesis-shard-split")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.KINESIS_SHARD_SPLIT,
            start_time=utc_now(),
        )

        try:
            if not self.dry_run:
                self.kinesis.split_shard(
                    StreamName=stream_name,
                    ShardToSplit=shard_to_split,
                    NewStartingHashKey=new_starting_hash_key,
                )
                result.affected_resources = [f"{stream_name}/{shard_to_split}"]
                logger.info(f"Split shard {shard_to_split} in stream {stream_name}")
            else:
                logger.info(f"DRY RUN: Would split shard {shard_to_split}")
                result.affected_resources = [f"{stream_name}/{shard_to_split}"]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error splitting shard: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def merge_shards(
        self, stream_name: str, shard_to_merge: str, adjacent_shard: str
    ) -> ExperimentResult:
        """Merge Kinesis shards"""
        experiment_id = _experiment_id("kinesis-shard-merge")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.KINESIS_SHARD_MERGE,
            start_time=utc_now(),
        )

        try:
            if not self.dry_run:
                self.kinesis.merge_shards(
                    StreamName=stream_name,
                    ShardToMerge=shard_to_merge,
                    AdjacentShardToMerge=adjacent_shard,
                )
                result.affected_resources = [
                    f"{stream_name}/{shard_to_merge}",
                    f"{stream_name}/{adjacent_shard}",
                ]
                logger.info(f"Merged shards {shard_to_merge} and {adjacent_shard}")
            else:
                logger.info("DRY RUN: Would merge shards")
                result.affected_resources = [
                    f"{stream_name}/{shard_to_merge}",
                    f"{stream_name}/{adjacent_shard}",
                ]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error merging shards: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_retention(
        self, stream_name: str, retention_hours: int = 168
    ) -> ExperimentResult:
        """Modify stream retention period"""
        experiment_id = _experiment_id("kinesis-retention-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.KINESIS_RETENTION_MODIFY,
            start_time=utc_now(),
        )

        try:
            # Get current retention
            stream_info = self.kinesis.describe_stream(StreamName=stream_name)
            stream_description = stream_info.get("StreamDescription", {})
            if stream_description.get("StreamStatus") != "ACTIVE":
                raise SafetyViolation("The selected Kinesis stream is not ACTIVE")
            self.original_retention = stream_description["RetentionPeriodHours"]
            self.stream_name = stream_name
            if retention_hours >= self.original_retention:
                raise ConfigurationError(
                    "Kinesis retention chaos requires a lower retention period"
                )

            if not self.dry_run:
                self.kinesis.decrease_stream_retention_period(
                    StreamName=stream_name, RetentionPeriodHours=retention_hours
                )
                self._wait_for_retention(stream_name, retention_hours, True)
                result.affected_resources = [stream_name]
                logger.info(
                    f"Modified retention to {retention_hours} hours for stream {stream_name}"
                )
            else:
                logger.info("DRY RUN: Would modify retention period")
                result.affected_resources = [stream_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying retention: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def limit_throughput(
        self, stream_name: str, shard_count: int = 1
    ) -> ExperimentResult:
        """Limit stream throughput by reducing shards"""
        experiment_id = _experiment_id("kinesis-throughput-limit")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.KINESIS_THROUGHPUT_LIMIT,
            start_time=utc_now(),
        )

        try:
            # Get current shard count
            stream_info = self.kinesis.describe_stream_summary(StreamName=stream_name)
            self.original_shard_count = stream_info["StreamDescriptionSummary"][
                "OpenShardCount"
            ]
            self.stream_name = stream_name

            if not self.dry_run:
                self.kinesis.update_shard_count(
                    StreamName=stream_name,
                    TargetShardCount=shard_count,
                    ScalingType="UNIFORM_SCALING",
                )
                result.affected_resources = [stream_name]
                logger.info(
                    f"Updated shard count to {shard_count} for stream {stream_name}"
                )
            else:
                logger.info("DRY RUN: Would limit throughput by reducing shards")
                result.affected_resources = [stream_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error limiting throughput: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Kinesis retention reduction is intentionally irreversible."""
        return None


class OpenSearchChaosExperiment(ChaosExperiment):
    """OpenSearch-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.opensearch = self.client("opensearch")

    def _wait_for_domain_idle(
        self, domain_name: str, interruptible: bool
    ) -> dict[str, Any]:
        """Wait for an OpenSearch domain configuration update to finish."""
        deadline = time.monotonic() + int(
            self.config.get("state_timeout_seconds", 7_200)
        )
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            status = self.opensearch.describe_domain(DomainName=domain_name).get(
                "DomainStatus", {}
            )
            if status and not status.get("Processing", False):
                return status
            wait_seconds = min(15.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError("Timed out waiting for the OpenSearch domain update")

    def restart_node(self, domain_name: str, instance_id: str) -> ExperimentResult:
        """Restart OpenSearch node"""
        experiment_id = _experiment_id("opensearch-node-restart")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.OPENSEARCH_NODE_RESTART,
            start_time=utc_now(),
        )

        try:
            raise ConfigurationError(
                "opensearch_node_restart is declared but not safely implemented"
            )

        except Exception as e:
            logger.error(f"Error restarting node: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_cluster_config(
        self, domain_name: str, instance_count: int = 1
    ) -> ExperimentResult:
        """Modify OpenSearch cluster configuration"""
        experiment_id = _experiment_id("opensearch-config-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.OPENSEARCH_CLUSTER_CONFIG_MODIFY,
            start_time=utc_now(),
        )

        try:
            # Get current configuration
            domain_info = self.opensearch.describe_domain(DomainName=domain_name)
            domain_status = domain_info.get("DomainStatus", {})
            if not domain_status or domain_status.get("Processing", False):
                raise SafetyViolation("The selected OpenSearch domain is not idle")
            cluster_config = domain_status["ClusterConfig"]
            self.original_instance_count = cluster_config["InstanceCount"]
            self.domain_name = domain_name
            self.requested_instance_count = instance_count
            if not 1 <= instance_count < self.original_instance_count:
                raise ConfigurationError(
                    "OpenSearch chaos must reduce the current data-node count"
                )

            if not self.dry_run:
                self.opensearch.update_domain_config(
                    DomainName=domain_name,
                    ClusterConfig={"InstanceCount": instance_count},
                )
                updated = self._wait_for_domain_idle(domain_name, True)
                if (
                    updated.get("ClusterConfig", {}).get("InstanceCount")
                    != instance_count
                ):
                    raise RuntimeError(
                        "OpenSearch did not apply the requested data-node count"
                    )
                result.affected_resources = [domain_name]
                logger.info(
                    f"Updated instance count to {instance_count} for domain {domain_name}"
                )
            else:
                logger.info("DRY RUN: Would modify cluster configuration")
                result.affected_resources = [domain_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying cluster config: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def delete_index(self, domain_endpoint: str, index_name: str) -> ExperimentResult:
        """Delete OpenSearch index"""
        experiment_id = _experiment_id("opensearch-index-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.OPENSEARCH_INDEX_DELETE,
            start_time=utc_now(),
        )

        try:
            raise ConfigurationError(
                "opensearch_index_delete is declared but not safely implemented"
            )

        except Exception as e:
            logger.error(f"Error deleting index: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback OpenSearch experiments"""
        try:
            if hasattr(self, "original_instance_count") and hasattr(
                self, "domain_name"
            ):
                current = self._wait_for_domain_idle(self.domain_name, False)
                current_count = current.get("ClusterConfig", {}).get("InstanceCount")
                if current_count != self.original_instance_count:
                    self.opensearch.update_domain_config(
                        DomainName=self.domain_name,
                        ClusterConfig={"InstanceCount": self.original_instance_count},
                    )
                    restored = self._wait_for_domain_idle(self.domain_name, False)
                    if (
                        restored.get("ClusterConfig", {}).get("InstanceCount")
                        != self.original_instance_count
                    ):
                        raise RuntimeError(
                            "OpenSearch rollback could not verify the data-node count"
                        )
                self.rollback_verified = True
                logger.info(
                    f"Restored instance count to {self.original_instance_count}"
                )

        except Exception as e:
            logger.error(f"Error during OpenSearch rollback: {e}")
            raise


class CloudFrontChaosExperiment(ChaosExperiment):
    """CloudFront-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.cloudfront = self.client("cloudfront", "us-east-1")

    def modify_behavior(
        self, distribution_id: str, path_pattern: str = "/*", error_code: int = 503
    ) -> ExperimentResult:
        """Modify CloudFront cache behavior"""
        experiment_id = _experiment_id("cloudfront-behavior-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.CLOUDFRONT_BEHAVIOR_MODIFY,
            start_time=utc_now(),
        )

        try:
            # Get current distribution config
            response = self.cloudfront.get_distribution_config(Id=distribution_id)
            self.original_config = response["DistributionConfig"].copy()
            self.distribution_id = distribution_id
            self.etag = response["ETag"]

            if not self.dry_run:
                # Modify config to add custom error response
                config = response["DistributionConfig"]
                config["CustomErrorResponses"] = {
                    "Quantity": 1,
                    "Items": [
                        {
                            "ErrorCode": error_code,
                            "ResponsePagePath": "/error.html",
                            "ResponseCode": str(error_code),
                            "ErrorCachingMinTTL": 300,
                        }
                    ],
                }

                self.cloudfront.update_distribution(
                    DistributionConfig=config, Id=distribution_id, IfMatch=self.etag
                )
                result.affected_resources = [distribution_id]
                logger.info(f"Modified behavior for distribution {distribution_id}")
            else:
                logger.info("DRY RUN: Would modify CloudFront behavior")
                result.affected_resources = [distribution_id]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying behavior: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def trigger_origin_failover(self, distribution_id: str) -> ExperimentResult:
        """Trigger origin failover by disabling primary origin"""
        experiment_id = _experiment_id("cloudfront-failover")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.CLOUDFRONT_ORIGIN_FAILOVER,
            start_time=utc_now(),
        )

        try:
            raise ConfigurationError(
                "cloudfront_origin_failover is declared but not safely implemented"
            )

        except Exception as e:
            logger.error(f"Error triggering failover: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def invalidate_cache(
        self, distribution_id: str, paths: list[str] | None = None
    ) -> ExperimentResult:
        """Create cache invalidation"""
        paths = paths or ["/*"]
        experiment_id = _experiment_id("cloudfront-invalidate")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.CLOUDFRONT_CACHE_INVALIDATE,
            start_time=utc_now(),
        )

        try:
            if not self.dry_run:
                response = self.cloudfront.create_invalidation(
                    DistributionId=distribution_id,
                    InvalidationBatch={
                        "Paths": {"Quantity": len(paths), "Items": paths},
                        "CallerReference": f"chaos-{experiment_id}",
                    },
                )
                result.affected_resources = [distribution_id]
                result.additional_info["invalidation_id"] = response["Invalidation"][
                    "Id"
                ]
                logger.info(f"Created invalidation for distribution {distribution_id}")
            else:
                logger.info("DRY RUN: Would invalidate cache")
                result.affected_resources = [distribution_id]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error creating invalidation: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback CloudFront experiments"""
        try:
            if hasattr(self, "original_config") and hasattr(self, "distribution_id"):
                # Get current ETag
                response = self.cloudfront.get_distribution_config(
                    Id=self.distribution_id
                )

                # Restore original config
                self.cloudfront.update_distribution(
                    DistributionConfig=self.original_config,
                    Id=self.distribution_id,
                    IfMatch=response["ETag"],
                )
                logger.info("Restored original distribution config")

        except Exception as e:
            logger.error(f"Error during CloudFront rollback: {e}")
            raise


class WAFChaosExperiment(ChaosExperiment):
    """WAF chaos experiments with complete optimistic-lock restoration."""

    UPDATE_FIELDS = (
        "Description",
        "DataProtectionConfig",
        "CustomResponseBodies",
        "CaptchaConfig",
        "ChallengeConfig",
        "TokenDomains",
        "AssociationConfig",
        "OnSourceDDoSProtectionConfig",
        "ApplicationConfig",
        "MonetizationConfig",
    )
    ACTIONS = {
        "ALLOW": "Allow",
        "BLOCK": "Block",
        "COUNT": "Count",
        "CAPTCHA": "Captcha",
        "CHALLENGE": "Challenge",
    }

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.wafv2 = self.client("wafv2")

    def _web_acl_update(
        self,
        web_acl: dict[str, Any],
        lock_token: str,
    ) -> None:
        """Submit all mutable Web ACL fields so unrelated settings are preserved."""
        request: dict[str, Any] = {
            "Scope": self.web_acl_scope,
            "Name": self.web_acl_name,
            "Id": self.web_acl_id,
            "DefaultAction": web_acl["DefaultAction"],
            "Rules": web_acl.get("Rules", []),
            "VisibilityConfig": web_acl["VisibilityConfig"],
            "LockToken": lock_token,
        }
        for field_name in self.UPDATE_FIELDS:
            if field_name in web_acl:
                request[field_name] = web_acl[field_name]
        self.wafv2.update_web_acl(**request)

    def _load_web_acl(
        self,
        web_acl_id: str,
        web_acl_name: str,
        scope: str,
    ) -> tuple[dict[str, Any], str]:
        """Load and remember a Web ACL for exact rollback."""
        response = self.wafv2.get_web_acl(
            Scope=scope,
            Name=web_acl_name,
            Id=web_acl_id,
        )
        self.original_web_acl = copy.deepcopy(response["WebACL"])
        self.web_acl_id = web_acl_id
        self.web_acl_name = web_acl_name
        self.web_acl_scope = scope
        return copy.deepcopy(response["WebACL"]), response["LockToken"]

    def modify_rule(
        self,
        web_acl_id: str,
        web_acl_name: str,
        rule_name: str,
        action: str = "BLOCK",
        scope: str = "REGIONAL",
    ) -> ExperimentResult:
        """Temporarily change the action of a standard WAF rule."""
        experiment_id = _experiment_id("waf-rule-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.WAF_RULE_MODIFY,
            start_time=utc_now(),
        )

        try:
            web_acl, lock_token = self._load_web_acl(web_acl_id, web_acl_name, scope)
            action_key = self.ACTIONS.get(action.upper())
            if action_key is None:
                raise ConfigurationError(f"Unsupported WAF action: {action}")
            matching_rule = next(
                (
                    rule
                    for rule in web_acl.get("Rules", [])
                    if rule["Name"] == rule_name
                ),
                None,
            )
            if matching_rule is None:
                raise ConfigurationError(f"WAF rule not found: {rule_name}")
            if "Action" not in matching_rule:
                raise ConfigurationError(
                    "The selected WAF rule uses OverrideAction and cannot use this experiment"
                )
            if not self.dry_run:
                self.changed_rule_name = rule_name
                self.changed_rule_field = "Action"
                self.original_rule_value = copy.deepcopy(matching_rule["Action"])
                self.changed_rule_value = {action_key: {}}
                matching_rule["Action"] = {action_key: {}}
                self._web_acl_update(web_acl, lock_token)
                result.affected_resources = [web_acl_id]
                logger.info(f"Modified rule {rule_name} to {action}")
            else:
                logger.info("DRY RUN: Would modify WAF rule")
                result.affected_resources = [web_acl_id]

            result.status = "completed"

        except Exception as exc:
            logger.error(f"Error modifying rule: {exc}")
            result.errors.append(str(exc))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_rate_limit(
        self,
        web_acl_id: str,
        web_acl_name: str,
        rule_name: str,
        limit: int = 100,
        scope: str = "REGIONAL",
    ) -> ExperimentResult:
        """Temporarily modify a WAF rate-based statement limit."""
        experiment_id = _experiment_id("waf-rate-limit-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.WAF_RATE_LIMIT_MODIFY,
            start_time=utc_now(),
        )

        try:
            web_acl, lock_token = self._load_web_acl(web_acl_id, web_acl_name, scope)
            matching_rule = next(
                (
                    rule
                    for rule in web_acl.get("Rules", [])
                    if rule["Name"] == rule_name
                ),
                None,
            )
            if matching_rule is None:
                raise ConfigurationError(f"WAF rule not found: {rule_name}")
            rate_statement = matching_rule.get("Statement", {}).get(
                "RateBasedStatement"
            )
            if not isinstance(rate_statement, dict):
                raise ConfigurationError("The selected WAF rule is not rate based")
            if not self.dry_run:
                self.changed_rule_name = rule_name
                self.changed_rule_field = "RateBasedStatement.Limit"
                self.original_rule_value = rate_statement["Limit"]
                self.changed_rule_value = limit
                rate_statement["Limit"] = limit
                self._web_acl_update(web_acl, lock_token)
            result.affected_resources = [web_acl_id]
            result.status = "completed"

        except Exception as exc:
            logger.error(f"Error modifying rate limit: {exc}")
            result.errors.append(str(exc))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_ip_set(
        self,
        ip_set_id: str,
        ip_set_name: str,
        addresses_to_add: list[str],
        scope: str = "REGIONAL",
    ) -> ExperimentResult:
        """Temporarily add addresses to a WAF IP set."""
        experiment_id = _experiment_id("waf-ipset-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.WAF_IP_SET_MODIFY,
            start_time=utc_now(),
        )

        try:
            response = self.wafv2.get_ip_set(
                Scope=scope,
                Name=ip_set_name,
                Id=ip_set_id,
            )
            ip_set = response["IPSet"]
            self.original_addresses = list(ip_set["Addresses"])
            self.ip_set_write_confirmed = False
            self.owned_address_additions = set(addresses_to_add) - set(
                self.original_addresses
            )
            self.ip_set_id = ip_set_id
            self.ip_set_name = ip_set_name
            self.ip_set_scope = scope
            self.ip_set_description = ip_set.get("Description")
            expected_version = 4 if ip_set["IPAddressVersion"] == "IPV4" else 6
            if any(
                ipaddress.ip_network(address, strict=False).version != expected_version
                for address in addresses_to_add
            ):
                raise ConfigurationError("An address does not match the IP set version")

            if not self.dry_run:
                request: dict[str, Any] = {
                    "Scope": scope,
                    "Name": ip_set_name,
                    "Id": ip_set_id,
                    "Addresses": sorted(
                        set(self.original_addresses + addresses_to_add)
                    ),
                    "LockToken": response["LockToken"],
                }
                if self.ip_set_description is not None:
                    request["Description"] = self.ip_set_description
                self.wafv2.update_ip_set(**request)
                self.ip_set_write_confirmed = True
                result.affected_resources = [ip_set_id]
                logger.info(f"Added {len(addresses_to_add)} addresses to IP set")
            else:
                logger.info("DRY RUN: Would modify IP set")
                result.affected_resources = [ip_set_id]

            result.status = "completed"

        except Exception as exc:
            logger.error(f"Error modifying IP set: {exc}")
            result.errors.append(str(exc))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback WAF experiments"""
        try:
            if hasattr(self, "changed_rule_name") and hasattr(self, "web_acl_id"):
                response = self.wafv2.get_web_acl(
                    Scope=self.web_acl_scope,
                    Name=self.web_acl_name,
                    Id=self.web_acl_id,
                )
                current_acl = copy.deepcopy(response["WebACL"])
                matches = [
                    rule
                    for rule in current_acl.get("Rules", [])
                    if rule.get("Name") == self.changed_rule_name
                ]
                if len(matches) != 1:
                    raise SafetyViolation("WAF rollback rule was removed or duplicated")
                container = matches[0]
                field = "Action"
                if self.changed_rule_field == "RateBasedStatement.Limit":
                    container = container.get("Statement", {}).get(
                        "RateBasedStatement", {}
                    )
                    field = "Limit"
                if container.get(field) not in (
                    self.original_rule_value,
                    self.changed_rule_value,
                ):
                    raise SafetyViolation(
                        "WAF rollback conflicts with a concurrent change"
                    )
                if container.get(field) != self.original_rule_value:
                    container[field] = copy.deepcopy(self.original_rule_value)
                    self._web_acl_update(current_acl, response["LockToken"])
                logger.info("Restored original WebACL configuration")

            if hasattr(self, "original_addresses") and hasattr(self, "ip_set_id"):
                if not self.ip_set_write_confirmed:
                    raise SafetyViolation(
                        "IP set forward write was not confirmed; "
                        "no cleanup is authorized, reconcile manually"
                    )
                response = self.wafv2.get_ip_set(
                    Scope=self.ip_set_scope,
                    Name=self.ip_set_name,
                    Id=self.ip_set_id,
                )
                request = {
                    "Scope": self.ip_set_scope,
                    "Name": self.ip_set_name,
                    "Id": self.ip_set_id,
                    "Addresses": sorted(
                        set(response["IPSet"]["Addresses"])
                        - self.owned_address_additions
                    ),
                    "LockToken": response["LockToken"],
                }
                current_description = response["IPSet"].get("Description")
                if current_description is not None:
                    request["Description"] = current_description
                self.rollback_ip_set_state = {
                    "Addresses": request["Addresses"],
                    "Description": current_description,
                }
                self.wafv2.update_ip_set(**request)
                logger.info("Removed experiment-owned IP set additions")

        except Exception as exc:
            logger.error(f"Error during WAF rollback: {exc}")
            raise


class KMSChaosExperiment(ChaosExperiment):
    """KMS-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.kms = self.client("kms")

    def disable_key(self, key_id: str) -> ExperimentResult:
        """Disable KMS key"""
        experiment_id = _experiment_id("kms-key-disable")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.KMS_KEY_DISABLE,
            start_time=utc_now(),
        )

        try:
            # Get key status
            key_info = self.kms.describe_key(KeyId=key_id)
            self.key_id = key_id
            self.original_enabled = key_info["KeyMetadata"]["Enabled"]
            if not self.original_enabled:
                raise SafetyViolation("The selected KMS key is already disabled")

            if not self.dry_run:
                self.kms.disable_key(KeyId=key_id)
                result.affected_resources = [key_id]
                logger.info(f"Disabled KMS key: {key_id}")
            else:
                logger.info(f"DRY RUN: Would disable KMS key: {key_id}")
                result.affected_resources = [key_id]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error disabling key: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def restrict_key_policy(
        self,
        key_id: str,
        break_glass_principal_arn: str,
    ) -> ExperimentResult:
        """Restrict KMS key policy"""
        experiment_id = _experiment_id("kms-policy-restrict")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.KMS_KEY_POLICY_RESTRICT,
            start_time=utc_now(),
        )

        try:
            # Get current policy
            response = self.kms.get_key_policy(KeyId=key_id, PolicyName="default")
            self.original_policy = response["Policy"]
            self.key_id = key_id

            restrictive_policy = json.loads(self.original_policy)
            statements = restrictive_policy.setdefault("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
                restrictive_policy["Statement"] = statements
            if any(item.get("Sid") == "ChaosFrameworkDeny" for item in statements):
                raise ConfigurationError(
                    "Key policy already contains ChaosFrameworkDeny"
                )
            statements.append(
                {
                    "Sid": "ChaosFrameworkDeny",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                    ],
                    "Resource": "*",
                    "Condition": {
                        "ArnNotEquals": {"aws:PrincipalArn": break_glass_principal_arn}
                    },
                }
            )

            if not self.dry_run:
                self.kms.put_key_policy(
                    KeyId=key_id,
                    PolicyName="default",
                    Policy=json.dumps(restrictive_policy),
                )
                result.affected_resources = [key_id]
                logger.info(f"Applied restrictive policy to KMS key: {key_id}")
            else:
                logger.info("DRY RUN: Would restrict KMS key policy")
                result.affected_resources = [key_id]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error restricting key policy: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def revoke_grant(self, key_id: str, grant_id: str) -> ExperimentResult:
        """Revoke KMS grant"""
        experiment_id = _experiment_id("kms-grant-revoke")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.KMS_GRANT_REVOKE,
            start_time=utc_now(),
        )

        try:
            grants = self.kms.list_grants(KeyId=key_id, GrantId=grant_id).get(
                "Grants", []
            )
            if len(grants) != 1 or str(grants[0].get("GrantId")) != grant_id:
                raise ConfigurationError("The selected KMS grant does not exist")
            if not self.dry_run:
                self.kms.revoke_grant(KeyId=key_id, GrantId=grant_id)
                result.affected_resources = [f"{key_id}/{grant_id}"]
                logger.info(f"Revoked grant {grant_id} for key {key_id}")
            else:
                logger.info("DRY RUN: Would revoke KMS grant")
                result.affected_resources = [f"{key_id}/{grant_id}"]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error revoking grant: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback KMS experiments"""
        try:
            if hasattr(self, "key_id"):
                if hasattr(self, "original_enabled") and self.original_enabled:
                    # Re-enable key
                    self.kms.enable_key(KeyId=self.key_id)
                    logger.info(f"Re-enabled KMS key: {self.key_id}")

                if hasattr(self, "original_policy"):
                    # Restore original policy
                    self.kms.put_key_policy(
                        KeyId=self.key_id,
                        PolicyName="default",
                        Policy=self.original_policy,
                    )
                    logger.info("Restored original KMS key policy")

        except Exception as e:
            logger.error(f"Error during KMS rollback: {e}")
            raise


class IAMChaosExperiment(ChaosExperiment):
    """IAM-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.iam = self.client("iam")

    def _reject_active_operator_role(self, role_name: str) -> None:
        """Prevent an experiment from changing the credentials used for recovery."""
        operator_arn = str(self.config.get("operator_principal_arn") or "")
        if ":role/" in operator_arn and operator_arn.rsplit("/", 1)[-1] == role_name:
            raise SafetyViolation("Refusing to modify the active operator role")

    def detach_policy(self, role_name: str, policy_arn: str) -> ExperimentResult:
        """Detach policy from IAM role"""
        experiment_id = _experiment_id("iam-policy-detach")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.IAM_POLICY_DETACH,
            start_time=utc_now(),
        )

        try:
            self._reject_active_operator_role(role_name)
            attached = self.iam.list_attached_role_policies(RoleName=role_name)
            if not any(
                item.get("PolicyArn") == policy_arn
                for item in attached.get("AttachedPolicies", [])
            ):
                raise ConfigurationError(
                    "The selected policy is not attached to the role"
                )
            self.role_name = role_name
            self.policy_arn = policy_arn

            if not self.dry_run:
                self.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                result.affected_resources = [f"{role_name}/{policy_arn}"]
                logger.info(f"Detached policy {policy_arn} from role {role_name}")
            else:
                logger.info("DRY RUN: Would detach policy from role")
                result.affected_resources = [f"{role_name}/{policy_arn}"]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error detaching policy: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_role(
        self, role_name: str, max_session_duration: int = 3600
    ) -> ExperimentResult:
        """Modify IAM role settings"""
        experiment_id = _experiment_id("iam-role-modify")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.IAM_ROLE_MODIFY,
            start_time=utc_now(),
        )

        try:
            self._reject_active_operator_role(role_name)
            # Get current role settings
            role_info = self.iam.get_role(RoleName=role_name)
            self.original_max_session = role_info["Role"]["MaxSessionDuration"]
            self.role_name = role_name

            if not self.dry_run:
                self.iam.update_role(
                    RoleName=role_name, MaxSessionDuration=max_session_duration
                )
                result.affected_resources = [role_name]
                logger.info(
                    f"Modified max session duration to {max_session_duration}s for role {role_name}"
                )
            else:
                logger.info("DRY RUN: Would modify IAM role")
                result.affected_resources = [role_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error modifying role: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def deactivate_access_key(
        self, user_name: str, access_key_id: str
    ) -> ExperimentResult:
        """Deactivate IAM user access key"""
        experiment_id = _experiment_id("iam-key-deactivate")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE,
            start_time=utc_now(),
        )

        try:
            if access_key_id == self.config.get("active_access_key_id"):
                raise SafetyViolation(
                    "Refusing to deactivate the active AWS access key"
                )
            keys = self.iam.list_access_keys(UserName=user_name).get(
                "AccessKeyMetadata", []
            )
            selected = next(
                (item for item in keys if item.get("AccessKeyId") == access_key_id),
                None,
            )
            if selected is None:
                raise ConfigurationError("The selected IAM access key does not exist")
            if selected.get("Status") != "Active":
                raise ConfigurationError("The selected IAM access key is not active")
            self.user_name = user_name
            self.access_key_id = access_key_id

            if not self.dry_run:
                self.iam.update_access_key(
                    UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
                )
                result.affected_resources = [f"{user_name}/{access_key_id}"]
                logger.info(
                    f"Deactivated access key {access_key_id} for user {user_name}"
                )
            else:
                logger.info("DRY RUN: Would deactivate access key")
                result.affected_resources = [f"{user_name}/{access_key_id}"]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deactivating access key: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback IAM experiments"""
        try:
            if hasattr(self, "role_name") and hasattr(self, "policy_arn"):
                # Re-attach policy
                self.iam.attach_role_policy(
                    RoleName=self.role_name, PolicyArn=self.policy_arn
                )
                logger.info(
                    f"Re-attached policy {self.policy_arn} to role {self.role_name}"
                )

            if hasattr(self, "role_name") and hasattr(self, "original_max_session"):
                # Restore max session duration
                self.iam.update_role(
                    RoleName=self.role_name,
                    MaxSessionDuration=self.original_max_session,
                )
                logger.info(f"Restored max session duration for role {self.role_name}")

            if hasattr(self, "user_name") and hasattr(self, "access_key_id"):
                # Re-activate access key
                self.iam.update_access_key(
                    UserName=self.user_name,
                    AccessKeyId=self.access_key_id,
                    Status="Active",
                )
                logger.info(f"Re-activated access key {self.access_key_id}")

        except Exception as e:
            logger.error(f"Error during IAM rollback: {e}")
            raise


class DirectoryServiceChaosExperiment(ChaosExperiment):
    """Directory Service-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.ds = self.client("ds")

    def delete_trust(self, trust_id: str) -> ExperimentResult:
        """Delete directory trust relationship"""
        experiment_id = _experiment_id("ds-trust-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.DS_TRUST_DELETE,
            start_time=utc_now(),
        )

        try:
            # Get trust details for potential recreation
            trust_info = self.ds.describe_trusts(TrustIds=[trust_id])
            if trust_info["Trusts"]:
                self.trust_details = trust_info["Trusts"][0]

                if not self.dry_run:
                    self.ds.delete_trust(TrustId=trust_id)
                    result.affected_resources = [trust_id]
                    logger.info(f"Deleted trust: {trust_id}")
                else:
                    logger.info(f"DRY RUN: Would delete trust: {trust_id}")
                    result.affected_resources = [trust_id]
            else:
                raise ConfigurationError(
                    f"Directory Service trust not found: {trust_id}"
                )

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting trust: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def delete_conditional_forwarder(
        self, directory_id: str, remote_domain_name: str
    ) -> ExperimentResult:
        """Delete conditional forwarder"""
        experiment_id = _experiment_id("ds-forwarder-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.DS_CONDITIONAL_FORWARDER_DELETE,
            start_time=utc_now(),
        )

        try:
            # Get forwarder details
            forwarders = self.ds.describe_conditional_forwarders(
                DirectoryId=directory_id, RemoteDomainNames=[remote_domain_name]
            )
            if forwarders["ConditionalForwarders"]:
                self.forwarder_details = copy.deepcopy(
                    forwarders["ConditionalForwarders"][0]
                )
                if self.forwarder_details.get("ReplicationScope") != "Domain":
                    raise SafetyViolation(
                        "Conditional forwarder replication scope cannot be restored"
                    )
                self.directory_id = directory_id
                self.remote_domain_name = remote_domain_name

                if not self.dry_run:
                    self.ds.delete_conditional_forwarder(
                        DirectoryId=directory_id, RemoteDomainName=remote_domain_name
                    )
                    result.affected_resources = [f"{directory_id}/{remote_domain_name}"]
                    logger.info(
                        f"Deleted conditional forwarder for {remote_domain_name}"
                    )
                else:
                    logger.info("DRY RUN: Would delete conditional forwarder")
                    result.affected_resources = [f"{directory_id}/{remote_domain_name}"]
            else:
                raise ConfigurationError(
                    "Directory Service conditional forwarder was not found"
                )

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting conditional forwarder: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback Directory Service experiments"""
        try:
            if hasattr(self, "forwarder_details") and hasattr(self, "directory_id"):
                # Re-create conditional forwarder
                request = {
                    "DirectoryId": self.directory_id,
                    "RemoteDomainName": self.remote_domain_name,
                }
                for key in ("DnsIpAddrs", "DnsIpv6Addrs"):
                    if self.forwarder_details.get(key):
                        request[key] = list(self.forwarder_details[key])
                self.ds.create_conditional_forwarder(**request)
                logger.info(
                    f"Re-created conditional forwarder for {self.remote_domain_name}"
                )

        except Exception as e:
            logger.error(f"Error during Directory Service rollback: {e}")
            raise


class AppStreamChaosExperiment(ChaosExperiment):
    """AppStream-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.appstream = self.client("appstream")

    def _fleet_state(self, fleet_name: str) -> str:
        """Return the state of exactly one AppStream fleet."""
        fleets = self.appstream.describe_fleets(Names=[fleet_name]).get("Fleets", [])
        if len(fleets) != 1:
            raise RuntimeError("AppStream did not return the selected fleet")
        return str(fleets[0].get("State"))

    def _wait_for_fleet_state(
        self, fleet_name: str, expected_state: str, interruptible: bool
    ) -> None:
        """Wait cooperatively for an AppStream fleet state."""
        deadline = time.monotonic() + int(
            self.config.get("state_timeout_seconds", 1_800)
        )
        while time.monotonic() < deadline:
            if interruptible:
                self._check_forward_safety()
            if self._fleet_state(fleet_name) == expected_state:
                return
            wait_seconds = min(10.0, max(0.1, deadline - time.monotonic()))
            if interruptible:
                self._wait_forward(wait_seconds)
            else:
                time.sleep(wait_seconds)
        raise TimeoutError(
            f"Timed out waiting for AppStream fleet state {expected_state}"
        )

    def stop_fleet(self, fleet_name: str) -> ExperimentResult:
        """Stop AppStream fleet"""
        experiment_id = _experiment_id("appstream-fleet-stop")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.APPSTREAM_FLEET_STOP,
            start_time=utc_now(),
        )

        try:
            # Get fleet state
            fleet_info = self.appstream.describe_fleets(Names=[fleet_name])
            fleets = fleet_info.get("Fleets", [])
            if len(fleets) != 1:
                raise ConfigurationError(f"AppStream fleet not found: {fleet_name}")
            self.fleet_name = fleet_name
            self.original_state = fleets[0].get("State")
            if self.original_state != "RUNNING":
                raise SafetyViolation("The selected AppStream fleet must be RUNNING")

            if not self.dry_run:
                self.appstream.stop_fleet(Name=fleet_name)
                self._wait_for_fleet_state(fleet_name, "STOPPED", True)
                result.affected_resources = [fleet_name]
                logger.info(f"Stopped fleet: {fleet_name}")
            else:
                logger.info(f"DRY RUN: Would stop fleet: {fleet_name}")
                result.affected_resources = [fleet_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error stopping fleet: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def disassociate_stack(self, fleet_name: str, stack_name: str) -> ExperimentResult:
        """Disassociate fleet from stack"""
        experiment_id = _experiment_id("appstream-stack-disassociate")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.APPSTREAM_STACK_DISASSOCIATE,
            start_time=utc_now(),
        )

        try:
            associated = self.appstream.list_associated_fleets(
                StackName=stack_name
            ).get("Names", [])
            if fleet_name not in associated:
                raise ConfigurationError(
                    "The selected AppStream fleet is not associated with the stack"
                )
            self.fleet_name = fleet_name
            self.stack_name = stack_name

            if not self.dry_run:
                self.appstream.disassociate_fleet(
                    FleetName=fleet_name, StackName=stack_name
                )
                result.affected_resources = [f"{fleet_name}/{stack_name}"]
                logger.info(f"Disassociated fleet {fleet_name} from stack {stack_name}")
            else:
                logger.info("DRY RUN: Would disassociate fleet from stack")
                result.affected_resources = [f"{fleet_name}/{stack_name}"]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error disassociating fleet: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback AppStream experiments"""
        try:
            if hasattr(self, "fleet_name"):
                if hasattr(self, "original_state") and self.original_state == "RUNNING":
                    current_state = self._fleet_state(self.fleet_name)
                    if current_state == "STOPPING":
                        self._wait_for_fleet_state(self.fleet_name, "STOPPED", False)
                        current_state = "STOPPED"
                    if current_state == "STOPPED":
                        self.appstream.start_fleet(Name=self.fleet_name)
                        self._wait_for_fleet_state(self.fleet_name, "RUNNING", False)
                    elif current_state == "STARTING":
                        self._wait_for_fleet_state(self.fleet_name, "RUNNING", False)
                    elif current_state != "RUNNING":
                        raise RuntimeError(
                            "AppStream rollback found an unexpected fleet state"
                        )
                    self.rollback_verified = True
                    logger.info(f"Started fleet: {self.fleet_name}")

                if hasattr(self, "stack_name"):
                    # Re-associate fleet and stack
                    self.appstream.associate_fleet(
                        FleetName=self.fleet_name, StackName=self.stack_name
                    )
                    logger.info(
                        f"Re-associated fleet {self.fleet_name} with stack {self.stack_name}"
                    )

        except Exception as e:
            logger.error(f"Error during AppStream rollback: {e}")
            raise


class ECRChaosExperiment(ChaosExperiment):
    """ECR-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.ecr = self.client("ecr")

    def delete_images(
        self, repository_name: str, image_ids: list[dict[str, str]]
    ) -> ExperimentResult:
        """Delete images from ECR repository"""
        experiment_id = _experiment_id("ecr-image-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ECR_IMAGE_DELETE,
            start_time=utc_now(),
        )

        try:
            image_details = self.ecr.describe_images(
                repositoryName=repository_name,
                imageIds=image_ids,
            ).get("imageDetails", [])
            missing_images = []
            for image_id in image_ids:
                tag = image_id.get("imageTag")
                digest = image_id.get("imageDigest")
                if not any(
                    (tag and tag in detail.get("imageTags", []))
                    or (digest and digest == detail.get("imageDigest"))
                    for detail in image_details
                ):
                    missing_images.append(image_id)
            if missing_images:
                raise ConfigurationError(
                    "ECR did not return every selected image for deletion"
                )
            # Store image details for logging
            self.deleted_images = image_ids
            self.repository_name = repository_name

            if not self.dry_run:
                deletion = self.ecr.batch_delete_image(
                    repositoryName=repository_name, imageIds=image_ids
                )
                if deletion.get("failures"):
                    raise RuntimeError(
                        "ECR reported one or more image deletion failures"
                    )
                result.affected_resources = [
                    f"{repository_name}/{img.get('imageTag', img.get('imageDigest'))}"
                    for img in image_ids
                ]
                logger.info(
                    f"Deleted {len(image_ids)} images from repository {repository_name}"
                )
            else:
                logger.info(
                    f"DRY RUN: Would delete images from repository {repository_name}"
                )
                result.affected_resources = [
                    f"{repository_name}/{img.get('imageTag', img.get('imageDigest'))}"
                    for img in image_ids
                ]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting images: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def restrict_repository_policy(
        self,
        repository_name: str,
        break_glass_principal_arn: str,
    ) -> ExperimentResult:
        """Apply restrictive repository policy"""
        experiment_id = _experiment_id("ecr-policy-restrict")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.ECR_REPOSITORY_POLICY_RESTRICT,
            start_time=utc_now(),
        )

        try:
            # Get current policy
            try:
                response = self.ecr.get_repository_policy(
                    repositoryName=repository_name
                )
                self.original_policy = response["policyText"]
                self.had_policy = True
            except self.ecr.exceptions.RepositoryPolicyNotFoundException:
                self.had_policy = False

            self.repository_name = repository_name

            restrictive_policy = (
                json.loads(self.original_policy)
                if self.had_policy
                else {"Version": "2012-10-17", "Statement": []}
            )
            statements = restrictive_policy.setdefault("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
                restrictive_policy["Statement"] = statements
            if any(item.get("Sid") == "ChaosFrameworkDeny" for item in statements):
                raise ConfigurationError(
                    "Repository policy already contains ChaosFrameworkDeny"
                )
            statements.append(
                {
                    "Sid": "ChaosFrameworkDeny",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": [
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage",
                        "ecr:PutImage",
                    ],
                    "Condition": {
                        "ArnNotEquals": {"aws:PrincipalArn": break_glass_principal_arn}
                    },
                }
            )

            if not self.dry_run:
                self.ecr.set_repository_policy(
                    repositoryName=repository_name,
                    policyText=json.dumps(restrictive_policy),
                )
                result.affected_resources = [repository_name]
                logger.info(
                    f"Applied restrictive policy to repository {repository_name}"
                )
            else:
                logger.info("DRY RUN: Would restrict repository policy")
                result.affected_resources = [repository_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error restricting repository policy: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback ECR experiments"""
        try:
            if hasattr(self, "repository_name") and hasattr(self, "had_policy"):
                if self.had_policy and hasattr(self, "original_policy"):
                    # Restore original policy
                    self.ecr.set_repository_policy(
                        repositoryName=self.repository_name,
                        policyText=self.original_policy,
                    )
                else:
                    # Delete policy
                    self.ecr.delete_repository_policy(
                        repositoryName=self.repository_name
                    )
                logger.info(f"Restored repository policy for {self.repository_name}")

        except Exception as e:
            logger.error(f"Error during ECR rollback: {e}")
            raise


class CodeCommitChaosExperiment(ChaosExperiment):
    """CodeCommit-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.codecommit = self.client("codecommit")

    def delete_trigger(
        self, repository_name: str, trigger_name: str
    ) -> ExperimentResult:
        """Delete repository trigger"""
        experiment_id = _experiment_id("codecommit-trigger-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.CODECOMMIT_TRIGGER_DELETE,
            start_time=utc_now(),
        )

        try:
            # Get current triggers
            response = self.codecommit.get_repository_triggers(
                repositoryName=repository_name
            )
            self.original_triggers = response["triggers"]

            # Find and store the trigger to delete
            for trigger in response["triggers"]:
                if trigger["name"] == trigger_name:
                    self.deleted_trigger = trigger
                    break
            if not hasattr(self, "deleted_trigger"):
                raise ConfigurationError(
                    f"CodeCommit trigger not found: {trigger_name}"
                )

            self.repository_name = repository_name

            if not self.dry_run:
                # Remove the trigger
                remaining_triggers = [
                    t for t in response["triggers"] if t["name"] != trigger_name
                ]
                self.codecommit.put_repository_triggers(
                    repositoryName=repository_name, triggers=remaining_triggers
                )
                result.affected_resources = [f"{repository_name}/{trigger_name}"]
                logger.info(
                    f"Deleted trigger {trigger_name} from repository {repository_name}"
                )
            else:
                logger.info("DRY RUN: Would delete trigger from repository")
                result.affected_resources = [f"{repository_name}/{trigger_name}"]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting trigger: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def protect_branch(
        self, repository_name: str, branch_name: str
    ) -> ExperimentResult:
        """Apply branch protection rules"""
        experiment_id = _experiment_id("codecommit-branch-protect")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.CODECOMMIT_BRANCH_PROTECT,
            start_time=utc_now(),
        )

        try:
            raise ConfigurationError(
                "codecommit_branch_protect is declared but not safely implemented"
            )

        except Exception as e:
            logger.error(f"Error protecting branch: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback CodeCommit experiments"""
        try:
            if hasattr(self, "deleted_trigger") and hasattr(self, "repository_name"):
                # Get current triggers
                response = self.codecommit.get_repository_triggers(
                    repositoryName=self.repository_name
                )
                triggers = response["triggers"]

                # Re-add the deleted trigger
                triggers.append(self.deleted_trigger)
                self.codecommit.put_repository_triggers(
                    repositoryName=self.repository_name, triggers=triggers
                )
                logger.info(f"Restored trigger {self.deleted_trigger['name']}")

        except Exception as e:
            logger.error(f"Error during CodeCommit rollback: {e}")
            raise


class SESChaosExperiment(ChaosExperiment):
    """SES-based chaos experiments"""

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.ses = self.client("ses")

    def delete_configuration_set(self, config_set_name: str) -> ExperimentResult:
        """Delete SES configuration set"""
        experiment_id = _experiment_id("ses-configset-delete")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.SES_CONFIGURATION_SET_DELETE,
            start_time=utc_now(),
        )

        try:
            # Get configuration set details
            response = self.ses.describe_configuration_set(
                ConfigurationSetName=config_set_name
            )
            self.config_set_details = response
            self.config_set_name = config_set_name

            if not self.dry_run:
                self.ses.delete_configuration_set(ConfigurationSetName=config_set_name)
                result.affected_resources = [config_set_name]
                logger.info(f"Deleted configuration set: {config_set_name}")
            else:
                logger.info(
                    f"DRY RUN: Would delete configuration set: {config_set_name}"
                )
                result.affected_resources = [config_set_name]

            result.status = "completed"

        except Exception as e:
            logger.error(f"Error deleting configuration set: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def modify_sending_quota(self, max_send_rate: float = 1.0) -> ExperimentResult:
        """Modify SES sending quota (requires SES sandbox mode)"""
        experiment_id = _experiment_id("ses-quota-limit")
        result = ExperimentResult(
            experiment_id=experiment_id,
            experiment_type=ChaosType.SES_SENDING_QUOTA_LIMIT,
            start_time=utc_now(),
        )

        try:
            raise ConfigurationError(
                "ses_sending_quota_limit is declared but not safely implemented"
            )

        except Exception as e:
            logger.error(f"Error modifying sending quota: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        finally:
            result.end_time = utc_now()

        return result

    def rollback(self):
        """Rollback SES experiments"""
        try:
            if hasattr(self, "config_set_name") and hasattr(self, "config_set_details"):
                # Re-create configuration set
                self.ses.create_configuration_set(
                    ConfigurationSet={"Name": self.config_set_name}
                )
                logger.info(f"Re-created configuration set: {self.config_set_name}")

        except Exception as e:
            logger.error(f"Error during SES rollback: {e}")
            raise


class FISTemplateExperiment(ChaosExperiment):
    """Run and monitor an existing AWS FIS experiment template."""

    TERMINAL_STATES = frozenset({"completed", "stopped", "failed", "cancelled"})
    ACTIVE_STATES = frozenset({"pending", "initiating", "running", "stopping"})

    def __init__(self, config: dict[str, Any], safety_controller: SafetyController):
        super().__init__(config, safety_controller)
        self.fis = self.client("fis")
        self.fis_experiment_id: str | None = None

    def _validate_template(self, template: dict[str, Any]) -> list[str]:
        """Validate target scope, role identity, and stop conditions."""
        violations: list[str] = []
        safety = self.safety_controller.config
        live = not self.dry_run
        stop_conditions = template.get("stopConditions", [])
        has_alarm_stop = False
        for item in stop_conditions:
            arn = str(item.get("value", ""))
            prefix = f"arn:{'aws-us-gov' if self.region in GOVCLOUD_REGIONS else 'aws'}:cloudwatch:{self.region}:{self.config.get('account_id', '')}:alarm:"
            if (
                item.get("source") != "aws:cloudwatch:alarm"
                or not arn.startswith(prefix)
                or not arn[len(prefix) :]
            ):
                continue
            if not live:
                has_alarm_stop = True
                continue
            if arn[len(prefix) :] not in safety.get("safety_alarms", []):
                continue
            alarms = self.client("cloudwatch").describe_alarms(
                AlarmNames=[arn[len(prefix) :]]
            )
            candidates = alarms.get("MetricAlarms", []) + alarms.get(
                "CompositeAlarms", []
            )
            if any(
                alarm.get("AlarmArn") == arn and alarm.get("StateValue") == "OK"
                for alarm in candidates
            ):
                has_alarm_stop = True
        if live:
            actions = template.get("actions", {})
            if not actions:
                violations.append("FIS template contains no reviewed actions")
            for action in actions.values():
                action_id = action.get("actionId")
                parameters = action.get("parameters", {})
                if action_id == "aws:ec2:reboot-instances":
                    continue
                duration = str(parameters.get("startInstancesAfterDuration", ""))
                if action_id == "aws:ec2:stop-instances" and re.fullmatch(
                    r"PT(?:[1-9]|[1-5][0-9])M", duration
                ):
                    continue
                violations.append(
                    f"FIS action {action_id!r} lacks reviewed automatic recovery; live execution is disabled"
                )
        if (
            live
            and not has_alarm_stop
            and not safety.get("_runtime_allow_fis_without_stop_conditions", False)
        ):
            violations.append("FIS template has no CloudWatch alarm stop condition")

        expected_account = str(self.config.get("account_id", ""))
        expected_partition = "aws-us-gov" if self.region in GOVCLOUD_REGIONS else "aws"
        role_arn = str(template.get("roleArn", ""))
        if not role_arn:
            violations.append("FIS template has no execution role")
        else:
            parts = role_arn.split(":", 5)
            if len(parts) < 6 or parts[0] != "arn":
                violations.append("FIS template roleArn is invalid")
            else:
                if parts[1] != expected_partition:
                    violations.append("FIS template role uses the wrong AWS partition")
                if expected_account and parts[4] != expected_account:
                    violations.append(
                        "FIS template role belongs to a different account"
                    )

        max_blast_radius = int(safety.get("max_blast_radius", 1))
        allow_unbounded = bool(
            safety.get("_runtime_allow_fis_unbounded_targets", False)
        )
        required_tags = safety.get("required_target_tags", {"ChaosReady": "true"})
        allowlist = set(str(item) for item in safety.get("target_allowlist", []))
        total_targets = 0
        for target_name, target in template.get("targets", {}).items():
            selection = str(target.get("selectionMode", ""))
            match = re.fullmatch(r"COUNT\(([0-9]+)\)", selection)
            percent_match = re.fullmatch(r"PERCENT\(([0-9]+)\)", selection)
            resource_arns = [str(item) for item in target.get("resourceArns", [])]
            if match:
                total_targets += (
                    min(int(match.group(1)), len(resource_arns))
                    if resource_arns
                    else int(match.group(1))
                )
            elif resource_arns:
                total_targets += len(resource_arns)
            else:
                total_targets += max_blast_radius + 1
            explicitly_bounded = (
                bool(resource_arns) and len(resource_arns) <= max_blast_radius
            )
            if selection == "ALL" or percent_match:
                if percent_match and not 1 <= int(percent_match.group(1)) <= 100:
                    violations.append(
                        f"FIS target {target_name} has invalid selection mode {selection!r}"
                    )
                if live and not allow_unbounded and not explicitly_bounded:
                    violations.append(
                        f"FIS target {target_name} uses unbounded selection mode {selection}"
                    )
            elif match:
                count = int(match.group(1))
                if count < 1 or count > max_blast_radius:
                    violations.append(
                        f"FIS target {target_name} exceeds max_blast_radius={max_blast_radius}"
                    )
            elif not match:
                violations.append(
                    f"FIS target {target_name} has invalid selection mode {selection!r}"
                )

            if live and resource_arns:
                missing = [arn for arn in resource_arns if arn not in allowlist]
                if missing:
                    violations.append(
                        f"FIS target {target_name} contains ARNs not in target_allowlist"
                    )
                prefix = f"arn:{expected_partition}:ec2:{self.region}:{expected_account}:instance/"
                if any(
                    not arn.startswith(prefix)
                    or not re.fullmatch(
                        r"i-[0-9a-f]{8}(?:[0-9a-f]{9})?", arn[len(prefix) :]
                    )
                    for arn in resource_arns
                ):
                    violations.append(
                        "Reviewed FIS actions require exact local EC2 instance ARNs"
                    )
            elif live:
                violations.append(
                    "Live FIS recovery verification requires explicit instance ARNs"
                )

            resource_tags = target.get("resourceTags", {})
            if live and not resource_arns and required_tags:
                missing_tags = {
                    str(k): str(v)
                    for k, v in required_tags.items()
                    if str(resource_tags.get(k)) != str(v)
                }
                if missing_tags:
                    violations.append(
                        f"FIS target {target_name} is missing required target tags"
                    )
        if total_targets > max_blast_radius:
            violations.append("FIS template aggregate targets exceed max_blast_radius")
        return violations

    def run_template(self, experiment_template_id: str) -> ExperimentResult:
        """Plan or execute one existing AWS FIS template."""
        result = ExperimentResult(
            experiment_id=_experiment_id("fis-template"),
            experiment_type=ChaosType.FIS_TEMPLATE,
            start_time=utc_now(),
            provider="fis",
            risk_level=RiskLevel.MEDIUM.value,
        )
        try:
            response = self.fis.get_experiment_template(id=experiment_template_id)
            template = response.get("experimentTemplate")
            if not template:
                raise ConfigurationError(
                    f"FIS experiment template not found: {experiment_template_id}"
                )
            violations = self._validate_template(template)
            result.additional_info = {
                "template_id": experiment_template_id,
                "action_count": len(template.get("actions", {})),
                "target_count": len(template.get("targets", {})),
                "stop_condition_count": len(template.get("stopConditions", [])),
                "guardrail_violations": violations,
            }
            result.affected_resources = [experiment_template_id]
            if violations:
                raise SafetyViolation("; ".join(violations))
            if not self.dry_run:
                raise SafetyViolation(
                    "Live FIS templates are disabled: StartExperiment cannot bind an immutable reviewed template"
                )
            result.status = "planned"

        except Exception as exc:
            logger.error("FIS template experiment failed: %s", exc)
            result.errors.append(str(exc))
            result.status = "failed"
        finally:
            result.end_time = utc_now()
            result.mutation_operations = list(self.mutation_operations)
        return result

    def rollback(self) -> None:
        """Stop an active FIS experiment. FIS manages action recovery."""
        if not self.fis_experiment_id:
            if self.mutation_attempts:
                raise SafetyViolation(
                    "FIS start outcome is unknown; operator reconciliation is required"
                )
            return
        response = self.fis.get_experiment(id=self.fis_experiment_id)
        status = response.get("experiment", {}).get("state", {}).get("status")
        if status in self.ACTIVE_STATES:
            self.fis.stop_experiment(id=self.fis_experiment_id)
            logger.info("Requested stop for FIS experiment %s", self.fis_experiment_id)
            timeout_seconds = int(self.config.get("fis_stop_timeout_seconds", 120))
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                response = self.fis.get_experiment(id=self.fis_experiment_id)
                status = response.get("experiment", {}).get("state", {}).get("status")
                if status in self.TERMINAL_STATES:
                    break
                time.sleep(min(2, max(0.1, deadline - time.monotonic())))
            if status not in self.TERMINAL_STATES:
                raise RuntimeError("Timed out waiting for the FIS experiment to stop")
        if status not in self.TERMINAL_STATES:
            raise RuntimeError(
                f"AWS FIS returned an unknown experiment status: {status}"
            )
        ids = getattr(self, "recovery_instance_ids", [])
        if not ids:
            raise SafetyViolation("FIS resource recovery cannot be verified")
        response = self.client("ec2").describe_instances(InstanceIds=ids)
        states = {
            instance["InstanceId"]: instance.get("State", {}).get("Name")
            for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        }
        if set(states) != set(ids) or any(
            state != "running" for state in states.values()
        ):
            raise SafetyViolation("FIS resource recovery is not yet verified")
        self.rollback_verified = True


def restoration_required(current: Any, original: Any, owned: Any) -> bool:
    """Refuse to overwrite a property changed by another actor."""
    if current == original:
        return False
    if current != owned:
        raise SafetyViolation(
            "Recovery conflicts with a concurrent control-plane change"
        )
    return True


def remove_owned_policy_statement(
    current: str, owned: dict[str, Any]
) -> dict[str, Any]:
    """Remove only the exact framework statement, preserving unrelated policy edits."""
    policy = json.loads(current)
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    matches = [item for item in statements if item.get("Sid") == owned["Sid"]]
    if matches and (len(matches) != 1 or matches[0] != owned):
        raise SafetyViolation(
            "The framework-owned policy statement changed concurrently"
        )
    policy["Statement"] = [
        item for item in statements if item.get("Sid") != owned["Sid"]
    ]
    return policy


class ChaosOrchestrator:
    """Orchestrates chaos experiments"""

    def __init__(
        self,
        config_file: str,
        vpc_id: str | None = None,
        dry_run_flag: bool = False,
        live: bool = False,
        profile: str | None = None,
        role_arn: str | None = None,
        output_dir: str = "chaos-reports",
        confirmation: str | None = None,
        allow_irreversible: bool = False,
        allow_long_term_credentials: bool = False,
        allow_fis_without_stop_condition: bool = False,
        allow_unbounded_fis_targets: bool = False,
        allow_live_without_safety_alarms: bool = False,
        seed: int | None = None,
    ):
        if live and dry_run_flag:
            raise ConfigurationError("--live and --dry-run cannot be used together")
        self.config_file = str(Path(config_file).expanduser().resolve())
        self.config = load_yaml_config(self.config_file)
        validate_config_data(self.config)
        global_config = self.config.setdefault("global", {})
        if not isinstance(global_config, dict):
            raise ConfigurationError("global must be a mapping")
        self.region = str(global_config.get("region", DEFAULT_REGION))
        self.live = bool(live and not dry_run_flag)
        self.dry_run = not self.live
        self.confirmation = confirmation
        self.allow_irreversible = allow_irreversible
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.run_id = _experiment_id("run")
        # Deterministic selection supports reproducible plans; this is not cryptography.
        self.random = random.Random(seed)  # nosec B311
        self.seed = seed

        requested_role = role_arn or global_config.get("role_arn")
        if requested_role:
            # Cover CLI precedence before making any STS request or forwarding
            # the configured ExternalId to a different account or partition.
            effective_config = copy.deepcopy(self.config)
            effective_config["global"]["role_arn"] = requested_role
            validate_config_data(effective_config)
            if not ACCOUNT_ID_PATTERN.fullmatch(
                str(global_config.get("account_id", ""))
            ):
                raise ConfigurationError(
                    "Role assumption requires a configured account ID"
                )
        session = boto3.Session(profile_name=profile, region_name=self.region)
        self.approval_scope = {
            "profile": profile,
            "role_arn": requested_role,
            "vpc_id": vpc_id,
            "seed": seed,
        }
        if requested_role:
            sts = session.client(
                "sts",
                region_name=self.region,
                config=BotocoreConfig(
                    retries={"max_attempts": 3, "mode": "standard"},
                    user_agent_extra=f"aws-chaos-framework/{__version__}",
                ),
            )
            assume_args: dict[str, Any] = {
                "RoleArn": str(requested_role),
                "RoleSessionName": f"aws-chaos-{uuid.uuid4().hex[:12]}",
            }
            external_id = global_config.get("external_id")
            if external_id:
                assume_args["ExternalId"] = str(external_id)
            assumed = sts.assume_role(**assume_args)["Credentials"]
            session = boto3.Session(
                aws_access_key_id=assumed["AccessKeyId"],
                aws_secret_access_key=assumed["SecretAccessKey"],
                aws_session_token=assumed["SessionToken"],
                region_name=self.region,
            )
        self.session = session
        safety_config = self.config.setdefault("safety", {})
        if not isinstance(safety_config, dict):
            raise ConfigurationError("safety must be a mapping")
        safety_config["_runtime_allow_fis_without_stop_conditions"] = bool(
            allow_fis_without_stop_condition
            and safety_config.get("allow_fis_without_stop_conditions", False)
        )
        safety_config["_runtime_allow_fis_unbounded_targets"] = bool(
            allow_unbounded_fis_targets
            and safety_config.get("allow_fis_unbounded_targets", False)
        )
        safety_config["_runtime_allow_live_without_safety_alarms"] = bool(
            allow_live_without_safety_alarms
            and safety_config.get("allow_live_without_safety_alarms", False)
        )
        self.safety_controller = SafetyController(
            safety_config,
            self.session,
            self.region,
            self.live,
        )

        self.expected_account = str(global_config.get("account_id", ""))
        self.actual_account: str | None = None
        self.caller_arn: str | None = None
        self.active_access_key_id: str | None = None
        try:
            identity = self.safety_controller.client("sts").get_caller_identity()
            self.actual_account = str(identity["Account"])
            self.caller_arn = str(identity["Arn"])
        except Exception as exc:
            if self.live:
                raise SafetyViolation(
                    f"Could not verify the active AWS identity: {exc}"
                ) from exc
            logger.warning("Could not verify AWS identity during dry run: %s", exc)

        if self.live:
            if not ACCOUNT_ID_PATTERN.fullmatch(self.expected_account):
                raise SafetyViolation(
                    "A valid global.account_id is mandatory for live runs"
                )
            if self.actual_account != self.expected_account:
                raise SafetyViolation(
                    "Configured account does not match the active AWS identity"
                )
            expected_partition = (
                "aws-us-gov" if self.region in GOVCLOUD_REGIONS else "aws"
            )
            if not self.caller_arn or not self.caller_arn.startswith(
                f"arn:{expected_partition}:"
            ):
                raise SafetyViolation(
                    "The active AWS identity partition does not match the configured region"
                )
            credentials = self.session.get_credentials()
            frozen = credentials.get_frozen_credentials() if credentials else None
            self.active_access_key_id = frozen.access_key if frozen else None
            long_term_approved = bool(
                allow_long_term_credentials
                and safety_config.get("allow_long_term_credentials", False)
            )
            if not long_term_approved and (frozen is None or not frozen.token):
                raise SafetyViolation(
                    "Live runs require temporary credentials. Long-term credentials need "
                    "both CLI and configuration approval."
                )
        elif (
            self.actual_account
            and self.expected_account
            and (self.actual_account != self.expected_account)
        ):
            logger.warning("Dry-run account does not match the active AWS identity")

        self.results: list[ExperimentResult] = []
        self.operator_principal_arn = (
            str(requested_role)
            if requested_role
            else canonical_caller_principal(self.caller_arn)
        )
        self._active_experiments_lock = threading.Lock()
        self.active_experiments: list[ChaosExperiment] = []
        self.vpc_id = vpc_id
        self.discovered_resources: dict[str, list[str]] = {}
        self._discovered_target_values: set[str] = set()
        self._report_sensitive_values: set[str] = set()
        self._sensitive_values_lock = threading.Lock()
        configured_sensitive_values = {
            str(item)
            for item in (
                list(safety_config.get("safety_alarms", []))
                + list(safety_config.get("target_allowlist", []))
            )
            if item
        }
        self._report_sensitive_values.update(configured_sensitive_values)
        self._log_sensitive_values = configured_sensitive_values | {
            value
            for value in (
                self.expected_account,
                self.actual_account,
                self.caller_arn,
                self.vpc_id,
            )
            if value
        }
        self._failed_future_count = 0
        self.suite_name: str | None = None
        self.report_path: Path | None = None
        self._cleanup_done = False
        self._cleanup_lock = threading.Lock()

        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        atexit.register(self._cleanup)

    def expected_confirmation(self, suite_name: str, irreversible: bool) -> str:
        """Bind approval to the complete reviewed configuration and runtime identity."""
        reviewed = copy.deepcopy(self.config)
        reviewed["global"]["account_id"] = self.expected_account
        reviewed["global"]["region"] = self.region
        return confirmation_token(reviewed, suite_name, self.approval_scope)

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Request cooperative shutdown and rollback."""
        logger.warning("Shutdown signal %s received", signum)
        self.safety_controller.emergency_stop_all()

    def _cleanup(self) -> None:
        """Wait for live execution to finish before fallback recovery."""
        with _LIVE_EXPERIMENT_LOCK:
            self._cleanup_locked()

    def _cleanup_locked(self) -> None:
        """Clean up and rollback all active experiments"""
        with self._cleanup_lock:
            if self._cleanup_done:
                return
            logger.info("Performing cleanup")
            with self._active_experiments_lock:
                experiments_snapshot = list(self.active_experiments)
            for experiment in experiments_snapshot:
                if (
                    not self.live
                    or not experiment.mutation_attempts
                    or experiment.rollback_mode not in {"automatic", "managed"}
                ):
                    continue
                try:
                    experiment.run_rollback()
                    if not experiment.rollback_verified or experiment.rollback_errors:
                        _LIVE_RECOVERY_BLOCKED.set()
                        self.safety_controller.emergency_stop_all()
                except Exception as exc:
                    _LIVE_RECOVERY_BLOCKED.set()
                    self.safety_controller.emergency_stop_all()
                    logger.error("Error during cleanup rollback: %s", exc)
            self._cleanup_done = True

    def _discover_resources(self):
        """Discover explicitly tagged resources within the specified VPC."""
        if not self.vpc_id:
            return
        if not VPC_ID_PATTERN.fullmatch(self.vpc_id):
            raise ConfigurationError(f"Invalid VPC ID: {self.vpc_id}")

        logger.info("Starting resource discovery for VPC %s", self.vpc_id)
        ec2 = self.safety_controller.client("ec2")
        required_tags = self.config.get("safety", {}).get(
            "required_target_tags", {"ChaosReady": "true"}
        )
        vpc_response = ec2.describe_vpcs(VpcIds=[self.vpc_id])
        if len(vpc_response.get("Vpcs", [])) != 1:
            raise SafetyViolation("The selected VPC was not found")
        vpc_tags = {
            str(item.get("Key")): str(item.get("Value"))
            for item in vpc_response["Vpcs"][0].get("Tags", [])
        }
        if any(
            vpc_tags.get(str(key)) != str(value) for key, value in required_tags.items()
        ):
            raise SafetyViolation("The selected VPC is missing required safety tags")

        def filters(*base_filters: dict[str, Any]) -> list[dict[str, Any]]:
            result = list(base_filters)
            for key, value in required_tags.items():
                result.append({"Name": f"tag:{key}", "Values": [str(value)]})
            return result

        def paginated(
            operation: str, result_key: str, **kwargs: Any
        ) -> list[dict[str, Any]]:
            paginator = ec2.get_paginator(operation)
            return [
                item
                for page in paginator.paginate(**kwargs)
                for item in page[result_key]
            ]

        self.discovered_resources = {
            "instances": [],
            "subnets": [],
            "security_groups": [],
            "nacls": [],
            "route_tables": [],
            "vpc_endpoints": [],
            "peering_connections": [],
        }

        try:
            reservations = paginated(
                "describe_instances",
                "Reservations",
                Filters=filters(
                    {"Name": "vpc-id", "Values": [self.vpc_id]},
                    {"Name": "instance-state-name", "Values": ["running"]},
                ),
            )
            self.discovered_resources["instances"] = [
                instance["InstanceId"]
                for reservation in reservations
                for instance in reservation.get("Instances", [])
            ]
            self.discovered_resources["subnets"] = [
                item["SubnetId"]
                for item in paginated(
                    "describe_subnets",
                    "Subnets",
                    Filters=filters({"Name": "vpc-id", "Values": [self.vpc_id]}),
                )
            ]
            self.discovered_resources["security_groups"] = [
                item["GroupId"]
                for item in paginated(
                    "describe_security_groups",
                    "SecurityGroups",
                    Filters=filters({"Name": "vpc-id", "Values": [self.vpc_id]}),
                )
            ]
            self.discovered_resources["nacls"] = [
                item["NetworkAclId"]
                for item in paginated(
                    "describe_network_acls",
                    "NetworkAcls",
                    Filters=filters({"Name": "vpc-id", "Values": [self.vpc_id]}),
                )
            ]
            self.discovered_resources["route_tables"] = [
                item["RouteTableId"]
                for item in paginated(
                    "describe_route_tables",
                    "RouteTables",
                    Filters=filters({"Name": "vpc-id", "Values": [self.vpc_id]}),
                )
            ]
            self.discovered_resources["vpc_endpoints"] = [
                item["VpcEndpointId"]
                for item in paginated(
                    "describe_vpc_endpoints",
                    "VpcEndpoints",
                    Filters=filters({"Name": "vpc-id", "Values": [self.vpc_id]}),
                )
            ]
            peerings: dict[str, dict[str, Any]] = {}
            for filter_name in (
                "requester-vpc-info.vpc-id",
                "accepter-vpc-info.vpc-id",
            ):
                for item in paginated(
                    "describe_vpc_peering_connections",
                    "VpcPeeringConnections",
                    Filters=filters(
                        {"Name": filter_name, "Values": [self.vpc_id]},
                        {"Name": "status-code", "Values": ["active"]},
                    ),
                ):
                    peerings[item["VpcPeeringConnectionId"]] = item
            self.discovered_resources["peering_connections"] = sorted(peerings)
            self._discovered_target_values = {
                value
                for values in self.discovered_resources.values()
                for value in values
            }
            for resource_type, values in self.discovered_resources.items():
                logger.info("Discovered %d tagged %s", len(values), resource_type)
        except Exception as exc:
            logger.error("Failed during resource discovery: %s", exc)
            raise

    def run_experiment_suite(self, suite_name: str) -> bool:
        """Run a suite with its own console privacy registry."""
        with sensitive_log_scope(getattr(self, "_log_sensitive_values", ())):
            return self._run_experiment_suite(suite_name)

    def _run_experiment_suite(self, suite_name: str) -> bool:
        """Run a suite of experiments. Returns True if all experiments succeeded."""
        self.suite_name = suite_name
        suites = self.config.get("experiment_suites", {})
        if suite_name not in suites:
            raise ConfigurationError(f"Suite {suite_name} not found in configuration")
        suite = suites[suite_name]
        experiment_types = [
            ChaosType(experiment["type"]) for experiment in suite["experiments"]
        ]
        unsupported = [
            item.value
            for item in experiment_types
            if not experiment_metadata(item).live_supported
            and (
                self.live
                or item
                not in CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS | {ChaosType.FIS_TEMPLATE}
            )
        ]
        if unsupported:
            raise ConfigurationError(
                "Suite contains declared but unsupported experiments: "
                + ", ".join(sorted(unsupported))
            )
        contains_irreversible = any(
            experiment_metadata(item).risk == RiskLevel.IRREVERSIBLE
            for item in experiment_types
        )
        if self.live:
            for item in suite["experiments"]:
                if any(
                    value in {"@discovered", "@random_discovered"}
                    for value in item.values()
                    if isinstance(value, str)
                ):
                    raise SafetyViolation(
                        "Live approval requires concrete targets. Materialize discovered "
                        "IDs into the reviewed configuration and exact target allowlist."
                    )
            contains_extension = any(
                item != ChaosType.FIS_TEMPLATE for item in experiment_types
            )
            safety = self.config.get("safety", {})
            if (
                contains_extension
                and not safety.get("safety_alarms")
                and not safety.get("_runtime_allow_live_without_safety_alarms", False)
            ):
                raise SafetyViolation(
                    "Live extension experiments require at least one CloudWatch safety alarm. "
                    "Bypass requires both CLI and configuration approval."
                )
            if contains_irreversible and not (
                self.allow_irreversible
                and self.config.get("safety", {}).get("allow_irreversible", False)
            ):
                raise SafetyViolation(
                    "Irreversible experiments require both --allow-irreversible and "
                    "safety.allow_irreversible=true"
                )
            expected = self.expected_confirmation(suite_name, contains_irreversible)
            if self.confirmation != expected:
                raise SafetyViolation(
                    f"Live confirmation mismatch. Required token: {expected}"
                )

        if self.vpc_id:
            self._discover_resources()

        logger.info("Starting experiment suite %s", suite_name)

        if self.live:
            require_runtime_safety(
                self.safety_controller, "Suite preflight safety", SafetyViolation
            )
        else:
            _safe, violations = self.safety_controller.check_safety_conditions()
            if violations:
                logger.warning("Dry-run safety observations: %s", "; ".join(violations))

        suite_concurrency = int(suite.get("max_concurrent", 1))
        global_concurrency = int(
            self.config.get("safety", {}).get("max_concurrent_experiments", 1)
        )
        workers = min(suite_concurrency, global_concurrency)
        if self.live:
            workers = 1
        scheduled = 0
        experiment_configs = [item.copy() for item in suite["experiments"]]
        next_index = 0
        stop_on_failure = suite.get("failure_policy", "stop") == "stop"
        delay = int(suite.get("delay_between_experiments", 0))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            active: set[Any] = set()
            while active or next_index < len(experiment_configs):
                while (
                    len(active) < workers
                    and next_index < len(experiment_configs)
                    and not self.safety_controller.emergency_stop.is_set()
                ):
                    active.add(
                        executor.submit(
                            self._run_with_failure_policy,
                            experiment_configs[next_index],
                            stop_on_failure,
                        )
                    )
                    next_index += 1
                    scheduled += 1
                    if (
                        delay
                        and not self.live
                        and next_index < len(experiment_configs)
                        and self.safety_controller.emergency_stop.wait(delay)
                    ):
                        break

                if not active:
                    break
                done, active = wait(active, return_when=FIRST_COMPLETED)
                for future in done:
                    failed = False
                    try:
                        result = future.result()
                        self.results.append(result)
                        failed = result.status in {"failed", "aborted"}
                    except Exception as exc:
                        self._failed_future_count += 1
                        failed = True
                        logger.error("Experiment worker failed: %s", exc)
                    if failed and stop_on_failure:
                        logger.error("Suite failure policy requested an emergency stop")
                        self.safety_controller.emergency_stop_all()
                if (
                    self.live
                    and delay
                    and next_index < len(experiment_configs)
                    and not self.safety_controller.emergency_stop.is_set()
                ):
                    self.safety_controller.emergency_stop.wait(delay)

        self.results.sort(key=lambda item: (item.start_time, item.experiment_id))

        self._generate_report()
        success_states = {"completed"} if self.live else {"planned", "completed"}
        return (
            scheduled == len(suite["experiments"])
            and self._failed_future_count == 0
            and len(self.results) == scheduled
            and all(result.status in success_states for result in self.results)
            and all(result.rollback_successful is not False for result in self.results)
        )

    # Explicit mapping from config keys to discovered resource types
    _DISCOVERY_KEY_MAP = {
        "instance_ids": "instances",
        "instance_id": "instances",
        "subnet_id": "subnets",
        "subnet_ids": "subnets",
        "group_id": "security_groups",
        "security_group_id": "security_groups",
        "nacl_id": "nacls",
        "nacl_ids": "nacls",
        "route_table_id": "route_tables",
        "endpoint_id": "vpc_endpoints",
        "peering_connection_id": "peering_connections",
    }

    def _prepare_experiment_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """Replace discovery keywords in config with actual resource IDs."""
        for key, value in config.items():
            if not isinstance(value, str) or not value.startswith("@"):
                continue
            if value not in {"@random_discovered", "@discovered"}:
                continue
            if self.live:
                raise SafetyViolation(
                    "Live execution requires reviewed concrete target IDs"
                )
            if not self.vpc_id:
                raise ConfigurationError(
                    f"{value} for {key} requires --vpc-id resource discovery"
                )
            resource_type = self._DISCOVERY_KEY_MAP.get(key)
            if resource_type is None:
                raise ConfigurationError(
                    f"Discovery keyword is not supported for parameter {key}"
                )
            available = self.discovered_resources.get(resource_type, [])
            if not available:
                raise ConfigurationError(
                    f"No tagged discovered resources of type {resource_type} for {key}"
                )
            if value == "@random_discovered":
                chosen_resource = self.random.choice(available)
                config[key] = (
                    [chosen_resource] if key.endswith("s") else chosen_resource
                )
                logger.info("Selected one tagged discovered resource for %s", key)
            else:
                if not key.endswith("s"):
                    raise ConfigurationError(
                        f"@discovered is only valid for plural parameter names, not {key}"
                    )
                config[key] = list(available)
                logger.info(
                    "Selected %d tagged discovered resources for %s",
                    len(available),
                    key,
                )
        return config

    @staticmethod
    def _target_values(config: dict[str, Any]) -> set[str]:
        """Extract explicit target identifiers without exposing config values."""
        targets: set[str] = (
            derived_target_scope(ChaosType(config["type"]), config)
            if "type" in config
            else set()
        )
        selector_fields = {
            ChaosType.VPC_SECURITY_GROUP_MODIFY.value: ("remove_rule",),
            ChaosType.RDS_PARAMETER_GROUP_MODIFY.value: ("parameters",),
            ChaosType.LAMBDA_ENVIRONMENT_CORRUPT.value: ("corrupt_vars",),
            ChaosType.ELB_REMOVE_TARGETS.value: ("target_descriptors",),
        }
        selector = {
            key: config[key]
            for key in selector_fields.get(config.get("type"), ())
            if key in config
        }
        if config.get("type") == ChaosType.VPC_NACL_BLOCK_TRAFFIC.value:
            selector = {
                "rule_number": config.get("rule_number", 100),
                "protocol": config.get("protocol", "-1"),
                "cidr_block": config.get("cidr_block", "0.0.0.0/0"),
                "egress": False,
                "action": "deny",
            }
        if selector:
            digest = hashlib.sha256(
                json.dumps(
                    selector, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode("utf-8")
            ).hexdigest()
            targets.add(f"selector:{config['type']}:{digest}")
        for key, value in config.items():
            if key not in TARGET_PARAMETER_KEYS:
                continue
            if isinstance(value, str) and value:
                targets.add(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item:
                        targets.add(item)
                    elif isinstance(item, dict):
                        for child_key, child_value in item.items():
                            if child_key not in {
                                "Key",
                                "VersionId",
                                "imageTag",
                                "imageDigest",
                            }:
                                raise SafetyViolation(
                                    "Unsupported nested target selector"
                                )
                            if not isinstance(child_value, str) or not child_value:
                                raise SafetyViolation("Invalid nested target selector")
                            targets.add(child_value)
                    else:
                        raise SafetyViolation("Invalid target selector")
        return targets

    @staticmethod
    def _blast_radius(experiment_type: ChaosType, config: dict[str, Any]) -> int:
        """Count materially affected primary and explicitly approved child resources."""
        if experiment_type == ChaosType.EC2_TERMINATE:
            return len(
                set(config["instance_ids"])
                | derived_target_scope(experiment_type, config)
            )
        if experiment_type == ChaosType.EBS_DETACH_VOLUME:
            derived_target_scope(experiment_type, config)
            return 2
        primary_keys = PRIMARY_TARGET_KEYS.get(experiment_type)
        if primary_keys is None:
            primary_keys = tuple(
                key
                for key in REQUIRED_PARAMETERS.get(experiment_type, ())
                if key in TARGET_PARAMETER_KEYS
            )[:1]
        counts = []
        for key in primary_keys:
            value = config.get(key)
            if isinstance(value, list):
                counts.append(len(value))
            elif value is not None:
                counts.append(1)
        return max(counts, default=0)

    def _validate_target_scope(
        self,
        experiment_type: ChaosType,
        config: dict[str, Any],
    ) -> None:
        """Enforce exact target allowlisting and blast-radius limits for live extensions."""
        if not self.live or experiment_type == ChaosType.FIS_TEMPLATE:
            return
        safety = self.config.get("safety", {})
        break_glass = config.get("break_glass_principal_arn")
        if break_glass and str(break_glass) != str(self.operator_principal_arn):
            raise SafetyViolation(
                "The active operator must be the configured break-glass principal for "
                "resource-policy experiments"
            )
        targets = self._target_values(config)
        max_blast_radius = int(safety.get("max_blast_radius", 1))
        blast_radius = self._blast_radius(experiment_type, config)
        if blast_radius > max_blast_radius:
            raise SafetyViolation(
                f"Experiment blast radius {blast_radius} exceeds "
                f"max_blast_radius={max_blast_radius}"
            )
        if (
            experiment_type == ChaosType.S3_OBJECT_DELETE
            and int(config.get("max_objects", 10)) > max_blast_radius
        ):
            raise SafetyViolation(
                "S3 max_objects exceeds the configured max_blast_radius"
            )
        allowlist = {str(item) for item in safety.get("target_allowlist", [])}
        allowed = allowlist if self.live else allowlist | self._discovered_target_values
        unapproved = targets - allowed
        if unapproved:
            raise SafetyViolation(
                f"Experiment has {len(unapproved)} target(s) not in the exact target allowlist"
            )
        for pattern in safety.get(
            "denied_target_patterns",
            [r"(?i)(?:^|[-_/])prod(?:uction)?(?:$|[-_/])"],
        ):
            compiled = re.compile(str(pattern))
            if any(compiled.search(target) for target in targets):
                raise SafetyViolation("A target matches a denied target pattern")

    def _wait_with_runtime_checks(self, duration_seconds: int) -> None:
        """Wait cooperatively while rechecking configured steady-state guards."""
        if duration_seconds <= 0:
            return
        interval = max(
            5,
            int(self.config.get("safety", {}).get("monitor_interval_seconds", 15)),
        )
        deadline = time.monotonic() + duration_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            if self.safety_controller.emergency_stop.wait(min(interval, remaining)):
                raise EmergencyStop("Emergency stop requested")
            require_runtime_safety(self.safety_controller, "Runtime safety")

    @staticmethod
    def _rollback_outcome(
        metadata: ExperimentMetadata,
        experiment: ChaosExperiment,
    ) -> bool:
        """Return an honest rollback outcome, including ambiguous write failures."""
        if experiment.rollback_errors:
            return False
        return metadata.rollback not in {"automatic", "managed"} or bool(
            experiment.rollback_verified
        )

    def _run_with_failure_policy(self, config: dict[str, Any], stop_on_failure: bool):
        """Signal failure from the worker before the scheduler can submit more work."""
        try:
            result = self._run_single_experiment(
                {**config, "_runtime_stop_on_failure": stop_on_failure}
            )
        except Exception:
            if stop_on_failure:
                self.safety_controller.emergency_stop_all()
            raise
        if self.live and result.rollback_successful is False:
            _LIVE_RECOVERY_BLOCKED.set()
            self.safety_controller.emergency_stop_all()
        elif stop_on_failure and result.status in {"failed", "aborted"}:
            self.safety_controller.emergency_stop_all()
        return result

    def _run_single_experiment(
        self, experiment_config: dict[str, Any]
    ) -> ExperimentResult:
        """Serialize live capture, mutation, verification and recovery as one unit."""
        with sensitive_log_scope(getattr(self, "_log_sensitive_values", ())):
            if self.live:
                with _LIVE_EXPERIMENT_LOCK:
                    if _PROCESS_EMERGENCY_STOP.is_set():
                        raise EmergencyStop(
                            "Process-wide emergency stop prevents new live experiments"
                        )
                    if _LIVE_RECOVERY_BLOCKED.is_set():
                        raise SafetyViolation(
                            "Live execution is blocked after unverified recovery; "
                            "reconcile the resource and start a new process"
                        )
                    result = self._run_single_experiment_locked(experiment_config)
                    metadata = experiment_metadata(result.experiment_type)
                    if metadata.rollback in {"automatic", "managed"} and (
                        result.rollback_successful is False
                        or (
                            result.mutation_attempts
                            and result.rollback_successful is not True
                        )
                    ):
                        _LIVE_RECOVERY_BLOCKED.set()
                        self.safety_controller.emergency_stop_all()
                        result.rollback_successful = False
                        result.status = "failed"
                        result.errors.append(
                            "Unverified recovery blocks all later live experiments "
                            "in this process"
                        )
                    return result
            return self._run_single_experiment_locked(experiment_config)

    def _run_single_experiment_locked(
        self, experiment_config: dict[str, Any]
    ) -> ExperimentResult:
        """Run a single experiment"""
        runtime_config = dict(self.config.get("global", {}))
        runtime_config.update(experiment_config)
        runtime_config["region"] = self.region
        runtime_config["account_id"] = getattr(
            self,
            "expected_account",
            self.config.get("global", {}).get("account_id", ""),
        )
        runtime_config["dry_run"] = self.dry_run
        runtime_config["operator_principal_arn"] = self.operator_principal_arn
        runtime_config["active_access_key_id"] = self.active_access_key_id
        experiment_config = runtime_config
        experiment_config = self._prepare_experiment_config(experiment_config)
        target_values = self._target_values(experiment_config)
        register_sensitive_log_values(target_values)
        with self._sensitive_values_lock:
            self._report_sensitive_values.update(target_values)
        experiment_type = ChaosType(experiment_config["type"])
        metadata = experiment_metadata(experiment_type)
        if (
            self.live
            and metadata.rollback == "automatic"
            and not experiment_config.get("auto_rollback", True)
        ):
            raise SafetyViolation("Live automatic recovery cannot be disabled")
        self._validate_target_scope(experiment_type, experiment_config)
        if self.live:
            require_runtime_safety(
                self.safety_controller, "Pre-experiment safety", SafetyViolation
            )

        logger.info(
            "Running experiment type=%s provider=%s risk=%s target_count=%d",
            experiment_type.value,
            metadata.provider,
            metadata.risk.value,
            self._blast_radius(experiment_type, experiment_config),
        )
        experiment = self._create_experiment(experiment_type, experiment_config)
        experiment.rollback_mode = metadata.rollback
        with self._active_experiments_lock:
            self.active_experiments.append(experiment)
        self.safety_controller.experiment_started()

        result: ExperimentResult | None = None
        try:
            result = self._execute_experiment(
                experiment, experiment_type, experiment_config
            )
            if (
                self.live
                and result.status == "completed"
                and (not experiment.mutation_attempts or not result.affected_resources)
            ):
                result.status = "failed"
                result.errors.append(
                    "Live completion requires a mutation attempt and explicit affected-resource evidence"
                )
            result.provider = metadata.provider
            result.risk_level = metadata.risk.value
            if self.dry_run and result.status == "completed":
                result.status = "planned"
            if experiment_config.get("_runtime_stop_on_failure") and result.status in {
                "failed",
                "aborted",
            }:
                self.safety_controller.emergency_stop_all()

            duration = int(experiment_config.get("duration_seconds", 0))
            if (
                self.live
                and duration
                and result.status == "completed"
                and metadata.rollback == "automatic"
            ):
                logger.info("Experiment active for %d seconds", duration)
                self._wait_with_runtime_checks(duration)

            should_rollback = (
                self.live
                and bool(experiment.mutation_attempts)
                and (
                    (
                        metadata.rollback == "automatic"
                        and experiment_config.get("auto_rollback", True)
                    )
                    or (
                        metadata.rollback == "managed"
                        and result.status in {"completed", "failed", "aborted"}
                    )
                )
            )
            if should_rollback:
                logger.info("Performing automatic rollback")
                try:
                    experiment.run_rollback()
                    result.rollback_successful = self._rollback_outcome(
                        metadata, experiment
                    )
                    if not result.rollback_successful:
                        result.errors.append(
                            "Rollback produced no verifiable recovery operation"
                        )
                        result.status = "failed"
                except Exception as exc:
                    result.rollback_successful = False
                    result.rollback_errors.append(str(exc))
                    result.errors.append(f"Rollback failed: {exc}")
                    result.status = "failed"
        except EmergencyStop as exc:
            self.safety_controller.emergency_stop_all()
            if result is None:
                result = ExperimentResult(
                    experiment_id=_experiment_id("aborted"),
                    experiment_type=experiment_type,
                    start_time=utc_now(),
                )
            result.status = "aborted"
            result.errors.append(str(exc))
            if (
                self.live
                and experiment.mutation_attempts
                and metadata.rollback in {"automatic", "managed"}
            ):
                try:
                    experiment.run_rollback()
                    result.rollback_successful = self._rollback_outcome(
                        metadata, experiment
                    )
                except Exception as rollback_exc:
                    result.rollback_successful = False
                    result.rollback_errors.append(str(rollback_exc))
        except Exception as exc:
            if experiment_config.get("_runtime_stop_on_failure"):
                self.safety_controller.emergency_stop_all()
            if result is None:
                result = ExperimentResult(
                    experiment_id=_experiment_id("failed"),
                    experiment_type=experiment_type,
                    start_time=utc_now(),
                )
            result.status = "failed"
            result.errors.append(str(exc))
            logger.error("Experiment %s failed: %s", experiment_type.value, exc)

        finally:
            if result is not None:
                result.provider = metadata.provider
                result.risk_level = metadata.risk.value
                result.mutation_operations = list(experiment.mutation_operations)
                result.mutation_attempts = list(experiment.mutation_attempts)
                result.rollback_operations = list(experiment.rollback_operations)
                result.rollback_attempts = list(experiment.rollback_attempts)
                result.rollback_errors.extend(
                    error
                    for error in experiment.rollback_errors
                    if error not in result.rollback_errors
                )
                if result.end_time is None:
                    result.end_time = utc_now()
            with self._active_experiments_lock:
                if experiment in self.active_experiments:
                    self.active_experiments.remove(experiment)
            self.safety_controller.experiment_finished()

        if result is None:
            raise RuntimeError("Experiment worker exited without a result")
        return result

    def _execute_experiment(
        self, experiment, experiment_type: ChaosType, config: dict[str, Any]
    ) -> ExperimentResult:
        """Execute specific experiment based on type"""
        metadata = experiment_metadata(experiment_type)
        if not metadata.live_supported and (
            not experiment.dry_run
            or experiment_type
            not in CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS | {ChaosType.FIS_TEMPLATE}
        ):
            raise ConfigurationError(
                f"Experiment type is not safely executable: {experiment_type.value}"
            )
        if experiment_type == ChaosType.FIS_TEMPLATE:
            return experiment.run_template(config["experiment_template_id"])

        # EC2 experiments
        elif experiment_type == ChaosType.EC2_TERMINATE:
            return experiment.terminate_instances(config["instance_ids"])
        elif experiment_type == ChaosType.EC2_STOP:
            return experiment.stop_instances(config["instance_ids"])
        elif experiment_type == ChaosType.EC2_REBOOT:
            return experiment.reboot_instances(config["instance_ids"])
        elif experiment_type == ChaosType.EC2_NETWORK_LATENCY:
            return experiment.inject_network_latency(
                config["instance_ids"], config.get("latency_ms", 100)
            )
        elif experiment_type == ChaosType.EC2_NETWORK_PACKET_LOSS:
            return experiment.inject_packet_loss(
                config["instance_ids"], config.get("loss_percent", 10)
            )
        elif experiment_type == ChaosType.EC2_CPU_STRESS:
            return experiment.inject_cpu_stress(
                config["instance_ids"],
                config.get("cpu_percent", 80),
                config.get("duration_seconds", 300),
            )
        elif experiment_type == ChaosType.EC2_MEMORY_STRESS:
            return experiment.inject_memory_stress(
                config["instance_ids"],
                config.get("memory_percent", 80),
                config.get("duration_seconds", 300),
            )
        elif experiment_type == ChaosType.EC2_DISK_STRESS:
            return experiment.inject_disk_stress(
                config["instance_ids"],
                config.get("io_percent", 80),
                config.get("duration_seconds", 300),
            )
        elif experiment_type == ChaosType.EC2_DISK_FILL:
            return experiment.fill_disk(
                config["instance_ids"], config.get("fill_percent", 90)
            )

        # EBS experiments
        elif experiment_type == ChaosType.EBS_DETACH_VOLUME:
            return experiment.detach_volume(config["volume_id"])
        elif experiment_type == ChaosType.EBS_THROTTLE_IOPS:
            return experiment.throttle_iops(
                config["volume_id"], config.get("iops", 3_000)
            )

        # EFS experiments
        elif experiment_type == ChaosType.EFS_MOUNT_TARGET_DELETE:
            return experiment.delete_mount_target(config["mount_target_id"])
        elif experiment_type == ChaosType.EFS_THROTTLE_THROUGHPUT:
            return experiment.throttle_throughput(
                config["file_system_id"],
                config.get("throughput_mode", "provisioned"),
                config.get("provisioned_throughput", 1.0),
            )

        # VPC experiments
        elif experiment_type == ChaosType.VPC_SUBNET_ACL_MODIFY:
            return experiment.modify_subnet_acl(config["subnet_id"], config["nacl_id"])
        elif experiment_type == ChaosType.VPC_ROUTE_TABLE_MODIFY:
            return experiment.modify_route_table(
                config["route_table_id"],
                config["destination_cidr"],
                config.get("blackhole", True),
            )
        elif experiment_type == ChaosType.VPC_SECURITY_GROUP_MODIFY:
            return experiment.modify_security_group(
                config["group_id"], config["remove_rule"]
            )
        elif experiment_type == ChaosType.VPC_NACL_BLOCK_TRAFFIC:
            return experiment.block_traffic_nacl(
                config["nacl_id"],
                config.get("rule_number", 100),
                config.get("protocol", "-1"),
                config.get("cidr_block", "0.0.0.0/0"),
            )
        elif experiment_type == ChaosType.VPC_PEERING_DELETE:
            return experiment.delete_vpc_peering(config["peering_connection_id"])
        elif experiment_type == ChaosType.VPC_ENDPOINT_DELETE:
            return experiment.delete_vpc_endpoint(config["endpoint_id"])

        # RDS experiments
        elif experiment_type == ChaosType.RDS_FAILOVER:
            return experiment.failover_db_cluster(config["cluster_identifier"])
        elif experiment_type == ChaosType.RDS_REBOOT:
            return experiment.reboot_db_instance(
                config["db_instance_identifier"], config.get("force_failover", False)
            )
        elif experiment_type == ChaosType.RDS_BACKUP_RETENTION_MODIFY:
            return experiment.modify_backup_retention(
                config["db_identifier"], config.get("retention_period", 0)
            )
        elif experiment_type == ChaosType.RDS_PARAMETER_GROUP_MODIFY:
            return experiment.modify_parameter_group(
                config["parameter_group_name"], config["parameters"]
            )

        # Lambda experiments
        elif experiment_type == ChaosType.LAMBDA_THROTTLE:
            return experiment.throttle_function(
                config["function_name"], config.get("reserved_concurrent_executions", 0)
            )
        elif experiment_type == ChaosType.LAMBDA_ERROR_INJECTION:
            return experiment.inject_error(
                config["function_name"], config.get("error_rate", 0.5)
            )
        elif experiment_type == ChaosType.LAMBDA_TIMEOUT_MODIFY:
            return experiment.modify_timeout(
                config["function_name"], config.get("timeout_seconds", 1)
            )
        elif experiment_type == ChaosType.LAMBDA_MEMORY_LIMIT:
            return experiment.modify_memory_limit(
                config["function_name"], config.get("memory_mb", 128)
            )
        elif experiment_type == ChaosType.LAMBDA_ENVIRONMENT_CORRUPT:
            return experiment.corrupt_environment(
                config["function_name"], config["corrupt_vars"]
            )

        # S3 experiments
        elif experiment_type == ChaosType.S3_BUCKET_POLICY_DENY:
            return experiment.deny_bucket_policy(
                config["bucket_name"],
                config["break_glass_principal_arn"],
            )
        elif experiment_type == ChaosType.S3_BUCKET_VERSIONING_SUSPEND:
            return experiment.suspend_versioning(config["bucket_name"])
        elif experiment_type == ChaosType.S3_BUCKET_ENCRYPTION_DISABLE:
            return experiment.disable_encryption(config["bucket_name"])
        elif experiment_type == ChaosType.S3_OBJECT_DELETE:
            return experiment.delete_objects(
                config["bucket_name"],
                config.get("prefix", ""),
                config.get("max_objects", 10),
            )
        elif experiment_type == ChaosType.S3_LIFECYCLE_MODIFY:
            return experiment.modify_lifecycle(
                config["bucket_name"], config.get("expire_days", 1)
            )

        # SQS experiments
        elif experiment_type == ChaosType.SQS_QUEUE_PURGE:
            return experiment.purge_queue(config["queue_url"])
        elif experiment_type == ChaosType.SQS_QUEUE_POLICY_RESTRICT:
            return experiment.restrict_queue_policy(
                config["queue_url"],
                config["break_glass_principal_arn"],
            )
        elif experiment_type == ChaosType.SQS_MESSAGE_DELAY:
            return experiment.modify_message_delay(
                config["queue_url"], config.get("delay_seconds", 900)
            )
        elif experiment_type == ChaosType.SQS_VISIBILITY_TIMEOUT:
            return experiment.modify_visibility_timeout(
                config["queue_url"], config.get("timeout_seconds", 43200)
            )

        # SNS experiments
        elif experiment_type == ChaosType.SNS_SUBSCRIPTION_DELETE:
            return experiment.delete_subscription(config["subscription_arn"])
        elif experiment_type == ChaosType.SNS_TOPIC_POLICY_RESTRICT:
            return experiment.restrict_topic_policy(
                config["topic_arn"],
                config["break_glass_principal_arn"],
            )

        # ELB experiments
        elif experiment_type == ChaosType.ELB_REMOVE_TARGETS:
            return experiment.remove_targets(
                config["target_group_arn"],
                config["target_ids"],
                config.get("target_descriptors"),
            )
        elif experiment_type == ChaosType.ELB_MODIFY_ATTRIBUTES:
            return experiment.modify_attributes(
                config["target_group_arn"], config.get("deregistration_delay", 3600)
            )
        elif experiment_type == ChaosType.ELB_HEALTH_CHECK_MODIFY:
            return experiment.modify_health_check(
                config["target_group_arn"],
                config.get("interval", 300),
                config.get("timeout", 120),
            )
        elif experiment_type == ChaosType.ELB_LISTENER_RULE_MODIFY:
            return experiment.modify_listener_rule(
                config["rule_arn"],
                config.get("action_type", "fixed-response"),
                config.get("status_code", "503"),
            )

        # ECS experiments
        elif experiment_type == ChaosType.ECS_TASK_STOP:
            return experiment.stop_tasks(
                config["cluster"],
                config["task_arns"],
                config.get("reason", "Chaos experiment"),
            )
        elif experiment_type == ChaosType.ECS_SERVICE_UPDATE:
            return experiment.update_service(
                config["cluster"], config["service"], config.get("desired_count", 0)
            )
        elif experiment_type == ChaosType.ECS_CONTAINER_INSTANCE_DRAIN:
            return experiment.drain_container_instance(
                config["cluster"], config["container_instance_arn"]
            )
        elif experiment_type == ChaosType.ECS_TASK_DEFINITION_MODIFY:
            return experiment.modify_task_definition(
                config["task_definition"],
                config.get("cpu", "256"),
                config.get("memory", "512"),
            )

        # Kinesis experiments
        elif experiment_type == ChaosType.KINESIS_SHARD_SPLIT:
            return experiment.split_shard(
                config["stream_name"],
                config["shard_to_split"],
                config["new_starting_hash_key"],
            )
        elif experiment_type == ChaosType.KINESIS_SHARD_MERGE:
            return experiment.merge_shards(
                config["stream_name"],
                config["shard_to_merge"],
                config["adjacent_shard"],
            )
        elif experiment_type == ChaosType.KINESIS_RETENTION_MODIFY:
            return experiment.modify_retention(
                config["stream_name"], config.get("retention_hours", 168)
            )
        elif experiment_type == ChaosType.KINESIS_THROUGHPUT_LIMIT:
            return experiment.limit_throughput(
                config["stream_name"], config.get("shard_count", 1)
            )

        # OpenSearch experiments
        elif experiment_type == ChaosType.OPENSEARCH_NODE_RESTART:
            return experiment.restart_node(config["domain_name"], config["instance_id"])
        elif experiment_type == ChaosType.OPENSEARCH_CLUSTER_CONFIG_MODIFY:
            return experiment.modify_cluster_config(
                config["domain_name"], config.get("instance_count", 1)
            )
        elif experiment_type == ChaosType.OPENSEARCH_INDEX_DELETE:
            return experiment.delete_index(
                config["domain_endpoint"], config["index_name"]
            )

        # CloudFront experiments
        elif experiment_type == ChaosType.CLOUDFRONT_BEHAVIOR_MODIFY:
            return experiment.modify_behavior(
                config["distribution_id"],
                config.get("path_pattern", "/*"),
                config.get("error_code", 503),
            )
        elif experiment_type == ChaosType.CLOUDFRONT_ORIGIN_FAILOVER:
            return experiment.trigger_origin_failover(config["distribution_id"])
        elif experiment_type == ChaosType.CLOUDFRONT_CACHE_INVALIDATE:
            return experiment.invalidate_cache(
                config["distribution_id"], config.get("paths", ["/*"])
            )

        # WAF experiments
        elif experiment_type == ChaosType.WAF_RULE_MODIFY:
            return experiment.modify_rule(
                config["web_acl_id"],
                config["web_acl_name"],
                config["rule_name"],
                config.get("action", "BLOCK"),
                config.get("scope", "REGIONAL"),
            )
        elif experiment_type == ChaosType.WAF_RATE_LIMIT_MODIFY:
            return experiment.modify_rate_limit(
                config["web_acl_id"],
                config["web_acl_name"],
                config["rule_name"],
                config.get("limit", 100),
                config.get("scope", "REGIONAL"),
            )
        elif experiment_type == ChaosType.WAF_IP_SET_MODIFY:
            return experiment.modify_ip_set(
                config["ip_set_id"],
                config["ip_set_name"],
                config["addresses_to_add"],
                config.get("scope", "REGIONAL"),
            )

        # KMS experiments
        elif experiment_type == ChaosType.KMS_KEY_DISABLE:
            return experiment.disable_key(config["key_id"])
        elif experiment_type == ChaosType.KMS_KEY_POLICY_RESTRICT:
            return experiment.restrict_key_policy(
                config["key_id"],
                config["break_glass_principal_arn"],
            )
        elif experiment_type == ChaosType.KMS_GRANT_REVOKE:
            return experiment.revoke_grant(config["key_id"], config["grant_id"])

        # IAM experiments
        elif experiment_type == ChaosType.IAM_POLICY_DETACH:
            return experiment.detach_policy(config["role_name"], config["policy_arn"])
        elif experiment_type == ChaosType.IAM_ROLE_MODIFY:
            return experiment.modify_role(
                config["role_name"], config.get("max_session_duration", 3600)
            )
        elif experiment_type == ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE:
            return experiment.deactivate_access_key(
                config["user_name"], config["access_key_id"]
            )

        # Directory Service experiments
        elif experiment_type == ChaosType.DS_TRUST_DELETE:
            return experiment.delete_trust(config["trust_id"])
        elif experiment_type == ChaosType.DS_CONDITIONAL_FORWARDER_DELETE:
            return experiment.delete_conditional_forwarder(
                config["directory_id"], config["remote_domain_name"]
            )

        # AppStream experiments
        elif experiment_type == ChaosType.APPSTREAM_FLEET_STOP:
            return experiment.stop_fleet(config["fleet_name"])
        elif experiment_type == ChaosType.APPSTREAM_STACK_DISASSOCIATE:
            return experiment.disassociate_stack(
                config["fleet_name"], config["stack_name"]
            )

        # ECR experiments
        elif experiment_type == ChaosType.ECR_IMAGE_DELETE:
            return experiment.delete_images(
                config["repository_name"], config["image_ids"]
            )
        elif experiment_type == ChaosType.ECR_REPOSITORY_POLICY_RESTRICT:
            return experiment.restrict_repository_policy(
                config["repository_name"],
                config["break_glass_principal_arn"],
            )

        # CodeCommit experiments
        elif experiment_type == ChaosType.CODECOMMIT_TRIGGER_DELETE:
            return experiment.delete_trigger(
                config["repository_name"], config["trigger_name"]
            )
        elif experiment_type == ChaosType.CODECOMMIT_BRANCH_PROTECT:
            return experiment.protect_branch(
                config["repository_name"], config["branch_name"]
            )

        # SES experiments
        elif experiment_type == ChaosType.SES_CONFIGURATION_SET_DELETE:
            return experiment.delete_configuration_set(config["config_set_name"])
        elif experiment_type == ChaosType.SES_SENDING_QUOTA_LIMIT:
            return experiment.modify_sending_quota(config.get("max_send_rate", 1.0))

        else:
            raise ValueError(f"Unsupported experiment type: {experiment_type}")

    def _create_experiment(
        self, experiment_type: ChaosType, config: dict[str, Any]
    ) -> ChaosExperiment:
        """Create experiment instance based on type"""
        if (
            not experiment_metadata(experiment_type).live_supported
            and experiment_type
            not in CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS | {ChaosType.FIS_TEMPLATE}
        ):
            raise ConfigurationError(
                f"Experiment type is not safely executable: {experiment_type.value}"
            )
        experiment_config = {**self.config.get("global", {}), **config}

        if experiment_type == ChaosType.FIS_TEMPLATE:
            return FISTemplateExperiment(experiment_config, self.safety_controller)

        # EC2 experiments
        elif experiment_type in [
            ChaosType.EC2_TERMINATE,
            ChaosType.EC2_STOP,
            ChaosType.EC2_REBOOT,
            ChaosType.EC2_NETWORK_LATENCY,
            ChaosType.EC2_NETWORK_PACKET_LOSS,
            ChaosType.EC2_CPU_STRESS,
            ChaosType.EC2_MEMORY_STRESS,
            ChaosType.EC2_DISK_STRESS,
            ChaosType.EC2_DISK_FILL,
        ]:
            return EC2ChaosExperiment(experiment_config, self.safety_controller)

        # EBS experiments
        elif experiment_type in [
            ChaosType.EBS_DETACH_VOLUME,
            ChaosType.EBS_THROTTLE_IOPS,
        ]:
            return EBSChaosExperiment(experiment_config, self.safety_controller)

        # EFS experiments
        elif experiment_type in [
            ChaosType.EFS_MOUNT_TARGET_DELETE,
            ChaosType.EFS_THROTTLE_THROUGHPUT,
        ]:
            return EFSChaosExperiment(experiment_config, self.safety_controller)

        # VPC experiments
        elif experiment_type in [
            ChaosType.VPC_SUBNET_ACL_MODIFY,
            ChaosType.VPC_ROUTE_TABLE_MODIFY,
            ChaosType.VPC_SECURITY_GROUP_MODIFY,
            ChaosType.VPC_NACL_BLOCK_TRAFFIC,
            ChaosType.VPC_PEERING_DELETE,
            ChaosType.VPC_ENDPOINT_DELETE,
        ]:
            return VPCChaosExperiment(experiment_config, self.safety_controller)

        # RDS experiments
        elif experiment_type in [
            ChaosType.RDS_FAILOVER,
            ChaosType.RDS_REBOOT,
            ChaosType.RDS_BACKUP_RETENTION_MODIFY,
            ChaosType.RDS_PARAMETER_GROUP_MODIFY,
        ]:
            return RDSChaosExperiment(experiment_config, self.safety_controller)

        # Lambda experiments
        elif experiment_type in [
            ChaosType.LAMBDA_THROTTLE,
            ChaosType.LAMBDA_ERROR_INJECTION,
            ChaosType.LAMBDA_TIMEOUT_MODIFY,
            ChaosType.LAMBDA_MEMORY_LIMIT,
            ChaosType.LAMBDA_ENVIRONMENT_CORRUPT,
        ]:
            return LambdaChaosExperiment(experiment_config, self.safety_controller)

        # S3 experiments
        elif experiment_type in [
            ChaosType.S3_BUCKET_POLICY_DENY,
            ChaosType.S3_BUCKET_VERSIONING_SUSPEND,
            ChaosType.S3_BUCKET_ENCRYPTION_DISABLE,
            ChaosType.S3_OBJECT_DELETE,
            ChaosType.S3_LIFECYCLE_MODIFY,
        ]:
            return S3ChaosExperiment(experiment_config, self.safety_controller)

        # SQS experiments
        elif experiment_type in [
            ChaosType.SQS_QUEUE_PURGE,
            ChaosType.SQS_QUEUE_POLICY_RESTRICT,
            ChaosType.SQS_MESSAGE_DELAY,
            ChaosType.SQS_VISIBILITY_TIMEOUT,
        ]:
            return SQSChaosExperiment(experiment_config, self.safety_controller)

        # SNS experiments
        elif experiment_type in [
            ChaosType.SNS_SUBSCRIPTION_DELETE,
            ChaosType.SNS_TOPIC_POLICY_RESTRICT,
        ]:
            return SNSChaosExperiment(experiment_config, self.safety_controller)

        # ELB experiments
        elif experiment_type in [
            ChaosType.ELB_REMOVE_TARGETS,
            ChaosType.ELB_MODIFY_ATTRIBUTES,
            ChaosType.ELB_HEALTH_CHECK_MODIFY,
            ChaosType.ELB_LISTENER_RULE_MODIFY,
        ]:
            return ELBChaosExperiment(experiment_config, self.safety_controller)

        # ECS experiments
        elif experiment_type in [
            ChaosType.ECS_TASK_STOP,
            ChaosType.ECS_SERVICE_UPDATE,
            ChaosType.ECS_CONTAINER_INSTANCE_DRAIN,
            ChaosType.ECS_TASK_DEFINITION_MODIFY,
        ]:
            return ECSChaosExperiment(experiment_config, self.safety_controller)

        # Kinesis experiments
        elif experiment_type in [
            ChaosType.KINESIS_SHARD_SPLIT,
            ChaosType.KINESIS_SHARD_MERGE,
            ChaosType.KINESIS_RETENTION_MODIFY,
            ChaosType.KINESIS_THROUGHPUT_LIMIT,
        ]:
            return KinesisChaosExperiment(experiment_config, self.safety_controller)

        # OpenSearch experiments
        elif experiment_type in [
            ChaosType.OPENSEARCH_NODE_RESTART,
            ChaosType.OPENSEARCH_CLUSTER_CONFIG_MODIFY,
            ChaosType.OPENSEARCH_INDEX_DELETE,
        ]:
            return OpenSearchChaosExperiment(experiment_config, self.safety_controller)

        # CloudFront experiments
        elif experiment_type in [
            ChaosType.CLOUDFRONT_BEHAVIOR_MODIFY,
            ChaosType.CLOUDFRONT_ORIGIN_FAILOVER,
            ChaosType.CLOUDFRONT_CACHE_INVALIDATE,
        ]:
            return CloudFrontChaosExperiment(experiment_config, self.safety_controller)

        # WAF experiments
        elif experiment_type in [
            ChaosType.WAF_RULE_MODIFY,
            ChaosType.WAF_RATE_LIMIT_MODIFY,
            ChaosType.WAF_IP_SET_MODIFY,
        ]:
            return WAFChaosExperiment(experiment_config, self.safety_controller)

        # KMS experiments
        elif experiment_type in [
            ChaosType.KMS_KEY_DISABLE,
            ChaosType.KMS_KEY_POLICY_RESTRICT,
            ChaosType.KMS_GRANT_REVOKE,
        ]:
            return KMSChaosExperiment(experiment_config, self.safety_controller)

        # IAM experiments
        elif experiment_type in [
            ChaosType.IAM_POLICY_DETACH,
            ChaosType.IAM_ROLE_MODIFY,
            ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE,
        ]:
            return IAMChaosExperiment(experiment_config, self.safety_controller)

        # Directory Service experiments
        elif experiment_type in [
            ChaosType.DS_TRUST_DELETE,
            ChaosType.DS_CONDITIONAL_FORWARDER_DELETE,
        ]:
            return DirectoryServiceChaosExperiment(
                experiment_config, self.safety_controller
            )

        # AppStream experiments
        elif experiment_type in [
            ChaosType.APPSTREAM_FLEET_STOP,
            ChaosType.APPSTREAM_STACK_DISASSOCIATE,
        ]:
            return AppStreamChaosExperiment(experiment_config, self.safety_controller)

        # ECR experiments
        elif experiment_type in [
            ChaosType.ECR_IMAGE_DELETE,
            ChaosType.ECR_REPOSITORY_POLICY_RESTRICT,
        ]:
            return ECRChaosExperiment(experiment_config, self.safety_controller)

        # CodeCommit experiments
        elif experiment_type in [
            ChaosType.CODECOMMIT_TRIGGER_DELETE,
            ChaosType.CODECOMMIT_BRANCH_PROTECT,
        ]:
            return CodeCommitChaosExperiment(experiment_config, self.safety_controller)

        # SES experiments
        elif experiment_type in [
            ChaosType.SES_CONFIGURATION_SET_DELETE,
            ChaosType.SES_SENDING_QUOTA_LIMIT,
        ]:
            return SESChaosExperiment(experiment_config, self.safety_controller)

        else:
            raise ValueError(f"Unsupported experiment type: {experiment_type}")

    def _generate_report(self) -> Path:
        """Write a privacy-conscious, atomic evidence report for the run."""
        reporting = self.config.get("reporting", {})
        include_resource_ids = bool(reporting.get("include_resource_ids", False))
        include_diagnostics = bool(reporting.get("include_diagnostics", False))
        include_identity = bool(reporting.get("include_identity", False))

        protected_values = {
            value
            for result in self.results
            for value in result.affected_resources
            if value
        }
        protected_values.update(
            value
            for value in (self.actual_account, self.caller_arn, self.vpc_id)
            if value
        )
        with self._sensitive_values_lock:
            protected_values.update(self._report_sensitive_values)

        def collect_derived(value: Any, sensitive: bool = False) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    collect_derived(
                        child,
                        sensitive
                        or bool(
                            re.search(
                                r"(?i)(?:id|identifier|arn|endpoint|member|snapshot|domain)",
                                str(key),
                            )
                        ),
                    )
            elif isinstance(value, (list, tuple)):
                for child in value:
                    collect_derived(child, sensitive)
            elif sensitive and isinstance(value, str) and value:
                protected_values.add(value)

        for result in self.results:
            collect_derived(result.additional_info)
            collect_derived(result.metrics_before)
            collect_derived(result.metrics_after)

        def redact(value: Any) -> Any:
            """Redact credentials and known target identifiers from report details."""
            sanitized = sanitize_for_log(value)
            if isinstance(sanitized, dict):
                redacted_mapping = {}
                for index, (key, item) in enumerate(sanitized.items()):
                    safe_key = redact(str(key))
                    if safe_key in redacted_mapping:
                        safe_key = f"{safe_key}_{index}"
                    redacted_mapping[safe_key] = redact(item)
                return redacted_mapping
            if isinstance(sanitized, list):
                return [redact(item) for item in sanitized]
            if isinstance(sanitized, tuple):
                return [redact(item) for item in sanitized]
            if isinstance(sanitized, str):
                redacted = sanitized
                # Disclosure flags apply only to the typed fields below. Free
                # text and diagnostics retain identity and target filtering.
                return redact_runtime_text(redacted, protected_values)
            return sanitized

        status_counts = {
            status: sum(result.status == status for result in self.results)
            for status in ("planned", "completed", "failed", "aborted")
        }
        report: dict[str, Any] = {
            "schema_version": 1,
            "framework": {
                "name": TOOL_NAME,
                "version": __version__,
                "python_version": sys.version.split()[0],
            },
            "run": {
                "id": self.run_id,
                "generated_at": utc_now().isoformat(),
                "suite": redact(getattr(self, "suite_name", None)),
                "mode": "live" if self.live else "plan",
                "region": self.region,
                "seed": self.seed,
                "account_verified": bool(
                    self.actual_account
                    and self.expected_account
                    and self.actual_account == self.expected_account
                ),
                "worker_failures": self._failed_future_count,
            },
            "scope": {
                "vpc_scoped": bool(self.vpc_id),
                "discovered_resource_counts": {
                    key: len(values)
                    for key, values in sorted(self.discovered_resources.items())
                },
            },
            "summary": {
                "total": len(self.results),
                **status_counts,
                "rollback_failures": sum(
                    result.rollback_successful is False for result in self.results
                ),
            },
            "experiments": [],
        }
        if include_identity:
            report["run"]["account_id"] = self.actual_account
            report["run"]["caller_arn"] = self.caller_arn
        if include_resource_ids and self.vpc_id:
            report["scope"]["vpc_id"] = self.vpc_id

        for result in self.results:
            duration = None
            if result.end_time is not None:
                duration = max(
                    0.0, (result.end_time - result.start_time).total_seconds()
                )
            experiment_report: dict[str, Any] = {
                "id": result.experiment_id,
                "type": result.experiment_type.value,
                "provider": result.provider,
                "risk": result.risk_level,
                "status": result.status,
                "started_at": result.start_time.isoformat(),
                "ended_at": result.end_time.isoformat() if result.end_time else None,
                "duration_seconds": duration,
                "affected_resource_count": len(result.affected_resources),
                "errors": redact(result.errors),
                "rollback_successful": result.rollback_successful,
                "rollback_errors": redact(result.rollback_errors),
                "mutation_operations": sorted(set(result.mutation_operations)),
                "mutation_attempts": sorted(set(result.mutation_attempts)),
                "rollback_operations": sorted(set(result.rollback_operations)),
                "rollback_attempts": sorted(set(result.rollback_attempts)),
            }
            if include_resource_ids:
                experiment_report["affected_resources"] = [
                    value if include_identity else redact_runtime_text(value, ())
                    for value in result.affected_resources
                ]
            if include_diagnostics:
                experiment_report["metrics_before"] = redact(result.metrics_before)
                experiment_report["metrics_after"] = redact(result.metrics_after)
                experiment_report["additional_info"] = redact(result.additional_info)
            report["experiments"].append(experiment_report)

        report_file = self.output_dir / f"chaos-report-{self.run_id}.json"
        atomic_write_json(report_file, report)
        self.report_path = report_file
        logger.info("Evidence report saved to %s", report_file)

        print("\nCHAOS EXPERIMENT SUMMARY")
        print(f"Mode: {report['run']['mode']}")
        print(f"Suite: {safe_display(report['run']['suite'])}")
        print(f"Total: {report['summary']['total']}")
        print(f"Completed: {report['summary']['completed']}")
        print(f"Planned: {report['summary']['planned']}")
        print(f"Failed: {report['summary']['failed']}")
        print(f"Aborted: {report['summary']['aborted']}")
        print(f"Report: {safe_display(report_file)}")
        return report_file


SAMPLE_CONFIG = """# AWS Chaos Engineering Framework configuration
# Replace every placeholder before live use. Live mode is enabled only by --live.
schema_version: 1

global:
  region: us-gov-west-1
  account_id: "000000000000"
  # role_arn: arn:aws-us-gov:iam::000000000000:role/ChaosExperimentOperator

safety:
  fail_closed: true
  allowed_hours:
    start: 13
    end: 22
  allowed_days: [MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY]
  safety_alarms: []
  block_on_insufficient_data: true
  guardduty_check: false
  security_hub_check: false
  max_concurrent_experiments: 1
  max_experiments_per_run: 25
  max_blast_radius: 1
  monitor_interval_seconds: 15
  require_temporary_credentials: true
  allow_long_term_credentials: false
  allow_live_without_safety_alarms: false
  required_target_tags:
    ChaosReady: "true"
  target_allowlist: []
  denied_target_patterns:
    - '(?i)(?:^|[-_/])prod(?:uction)?(?:$|[-_/])'
  allow_irreversible: false
  allow_fis_without_stop_conditions: false
  allow_fis_unbounded_targets: false

reporting:
  include_identity: false
  include_resource_ids: false
  include_diagnostics: false

experiment_suites:
  tagged_ec2_recovery:
    description: Stop one tagged test instance, observe recovery, then restart it.
    max_concurrent: 1
    delay_between_experiments: 0
    failure_policy: stop
    experiments:
      - type: ec2_stop
        instance_ids: "@random_discovered"
        duration_seconds: 60
        auto_rollback: true

  managed_fis_template:
    description: Inspect an existing AWS FIS template; live starts are disabled.
    max_concurrent: 1
    failure_policy: stop
    experiments:
      - type: fis_template
        experiment_template_id: EXTxxxxxxxxxxxxxxxxxx
"""


def create_sample_config(output_file: str = "chaos-config.example.yaml") -> Path:
    """Create a safe example configuration without overwriting an existing file."""
    path = Path(output_file).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(SAMPLE_CONFIG)
    except FileExistsError as exc:
        raise ConfigurationError(
            f"Refusing to overwrite existing file: {path}"
        ) from exc
    print(f"Sample configuration created: {safe_display(path)}")
    print(
        "Live execution remains disabled until --live and the exact token are supplied."
    )
    return path


def _mapping(value: Any, location: str) -> dict[str, Any]:
    """Require a mapping at a configuration location."""
    if not isinstance(value, dict):
        raise ConfigurationError(f"{location} must be a mapping")
    return value


def _integer_in_range(
    value: Any,
    location: str,
    minimum: int,
    maximum: int,
) -> int:
    """Require an integer in an inclusive range."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{location} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{location} must be between {minimum} and {maximum}")
    return value


def _nonempty(value: Any) -> bool:
    """Return True for a configuration value that is meaningfully populated."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)
    return True


def validate_config_data(config: dict[str, Any]) -> None:
    """Validate configuration structure, bounds, and public safety contracts."""
    if config.get("schema_version", 1) != 1:
        raise ConfigurationError("schema_version must be 1")
    for section in ("global", "safety", "experiment_suites"):
        if section not in config:
            raise ConfigurationError(f"Missing required section: {section}")

    global_config = _mapping(config["global"], "global")
    safety = _mapping(config["safety"], "safety")
    suites = _mapping(config["experiment_suites"], "experiment_suites")
    reporting = _mapping(config.get("reporting", {}), "reporting")

    region = str(global_config.get("region", DEFAULT_REGION))
    if "dry_run" in global_config:
        raise ConfigurationError(
            "global.dry_run is obsolete. Plan mode is default and live mode is CLI-only."
        )
    forbidden_credential_keys = {
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "secret_access_key",
        "session_token",
        "password",
    }
    embedded_credentials = forbidden_credential_keys & set(global_config)
    if embedded_credentials:
        raise ConfigurationError(
            "Configuration must not contain embedded AWS credentials or passwords"
        )
    if not REGION_PATTERN.fullmatch(region):
        raise ConfigurationError(f"global.region is invalid: {region}")
    account_id = str(global_config.get("account_id", ""))
    if account_id and not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise ConfigurationError("global.account_id must be a 12-digit AWS account ID")
    role_arn = global_config.get("role_arn")
    if role_arn:
        expected_partition = "aws-us-gov" if region in GOVCLOUD_REGIONS else "aws"
        match = re.fullmatch(
            r"arn:(aws|aws-us-gov):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+",
            str(role_arn),
        )
        if (
            not match
            or match.group(1) != expected_partition
            or (account_id and match.group(2) != account_id)
        ):
            raise ConfigurationError(
                "global.role_arn must match the configured partition and account"
            )
    if (
        "external_id" in global_config
        and not 2 <= len(str(global_config["external_id"])) <= 1_224
    ):
        raise ConfigurationError("global.external_id has an invalid length")
    for key, minimum, maximum in (
        ("state_timeout_seconds", 10, 7_200),
        ("snapshot_timeout_seconds", 60, 86_400),
        ("fis_poll_seconds", 2, 300),
        ("fis_stop_timeout_seconds", 10, 3_600),
    ):
        if key in global_config:
            _integer_in_range(global_config[key], f"global.{key}", minimum, maximum)

    if safety.get("fail_closed", True) is not True:
        raise ConfigurationError("safety.fail_closed must remain true")
    if safety.get("require_temporary_credentials", True) is not True:
        raise ConfigurationError(
            "safety.require_temporary_credentials must remain true; use the dual override"
        )
    allowed_hours = safety.get("allowed_hours")
    if allowed_hours is not None:
        allowed = _mapping(allowed_hours, "safety.allowed_hours")
        _integer_in_range(allowed.get("start"), "safety.allowed_hours.start", 0, 23)
        _integer_in_range(allowed.get("end"), "safety.allowed_hours.end", 0, 23)
    allowed_days = safety.get("allowed_days")
    valid_days = {
        "MONDAY",
        "TUESDAY",
        "WEDNESDAY",
        "THURSDAY",
        "FRIDAY",
        "SATURDAY",
        "SUNDAY",
    }
    if allowed_days is not None and (
        not isinstance(allowed_days, list)
        or not allowed_days
        or any(day not in valid_days for day in allowed_days)
    ):
        raise ConfigurationError(
            "safety.allowed_days must be a non-empty list of uppercase UTC day names"
        )
    _integer_in_range(
        safety.get("max_concurrent_experiments", 1),
        "safety.max_concurrent_experiments",
        1,
        50,
    )
    _integer_in_range(
        safety.get("max_blast_radius", 1),
        "safety.max_blast_radius",
        1,
        100,
    )
    max_experiments_per_run = _integer_in_range(
        safety.get("max_experiments_per_run", 25),
        "safety.max_experiments_per_run",
        1,
        1_000,
    )
    _integer_in_range(
        safety.get("monitor_interval_seconds", 15),
        "safety.monitor_interval_seconds",
        5,
        3600,
    )

    alarms = safety.get("safety_alarms", [])
    if not isinstance(alarms, list) or not all(
        isinstance(item, str) and item.strip() for item in alarms
    ):
        raise ConfigurationError("safety.safety_alarms must be a list of names")
    allowlist = safety.get("target_allowlist", [])
    if not isinstance(allowlist, list) or not all(
        isinstance(item, str) and item.strip() for item in allowlist
    ):
        raise ConfigurationError(
            "safety.target_allowlist must be a list of identifiers"
        )
    required_tags = _mapping(
        safety.get("required_target_tags", {"ChaosReady": "true"}),
        "safety.required_target_tags",
    )
    if not required_tags or not all(
        isinstance(key, str)
        and key.strip()
        and isinstance(value, (str, int, float, bool))
        and str(value).strip()
        for key, value in required_tags.items()
    ):
        raise ConfigurationError(
            "safety.required_target_tags must contain at least one exact tag"
        )
    denied_patterns = safety.get(
        "denied_target_patterns",
        [r"(?i)(?:^|[-_/])prod(?:uction)?(?:$|[-_/])"],
    )
    if not isinstance(denied_patterns, list) or not denied_patterns:
        raise ConfigurationError(
            "safety.denied_target_patterns must be a non-empty list"
        )
    for index, pattern in enumerate(denied_patterns):
        try:
            re.compile(str(pattern))
        except re.error as exc:
            raise ConfigurationError(
                f"safety.denied_target_patterns[{index}] is invalid: {exc}"
            ) from exc

    for key in (
        "block_on_insufficient_data",
        "guardduty_check",
        "security_hub_check",
        "require_temporary_credentials",
        "allow_long_term_credentials",
        "allow_live_without_safety_alarms",
        "allow_irreversible",
        "allow_fis_without_stop_conditions",
        "allow_fis_unbounded_targets",
    ):
        if key in safety and not isinstance(safety[key], bool):
            raise ConfigurationError(f"safety.{key} must be true or false")
    for key in ("include_identity", "include_resource_ids", "include_diagnostics"):
        if key in reporting and not isinstance(reporting[key], bool):
            raise ConfigurationError(f"reporting.{key} must be true or false")

    if not suites:
        raise ConfigurationError("experiment_suites must contain at least one suite")
    valid_type_names = {item.value for item in ChaosType}
    numeric_bounds: dict[str, tuple[float, float]] = {
        "latency_ms": (1, 60_000),
        "loss_percent": (0, 100),
        "cpu_percent": (1, 100),
        "memory_percent": (1, 100),
        "io_percent": (1, 100),
        "fill_percent": (1, 95),
        "error_rate": (0, 1),
        "memory_mb": (128, 10_240),
        "reserved_concurrent_executions": (0, 100_000),
        "retention_period": (0, 35),
        "delay_seconds": (0, 900),
        "rule_number": (1, 32_766),
        "limit": (10, 2_000_000_000),
        "max_session_duration": (3_600, 43_200),
        "max_objects": (1, 1_000),
        "expire_days": (1, 36_500),
        "iops": (100, 256_000),
        "provisioned_throughput": (1, 3_414),
        "deregistration_delay": (0, 3_600),
        "desired_count": (0, 1_000_000),
        "retention_hours": (24, 8_760),
        "instance_count": (1, 1_000),
        "state_timeout_seconds": (10, 7_200),
        "snapshot_timeout_seconds": (60, 86_400),
        "fis_poll_seconds": (2, 300),
        "fis_stop_timeout_seconds": (10, 3_600),
    }

    for suite_name, suite_value in suites.items():
        if not isinstance(suite_name, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", suite_name
        ):
            raise ConfigurationError(f"Invalid suite name: {suite_name!r}")
        suite = _mapping(suite_value, f"experiment_suites.{suite_name}")
        experiments = suite.get("experiments")
        if not isinstance(experiments, list) or not experiments:
            raise ConfigurationError(
                f"experiment_suites.{suite_name}.experiments must be a non-empty list"
            )
        if len(experiments) > max_experiments_per_run:
            raise ConfigurationError(
                f"experiment_suites.{suite_name} exceeds safety.max_experiments_per_run"
            )
        _integer_in_range(
            suite.get("max_concurrent", 1),
            f"experiment_suites.{suite_name}.max_concurrent",
            1,
            50,
        )
        _integer_in_range(
            suite.get("delay_between_experiments", 0),
            f"experiment_suites.{suite_name}.delay_between_experiments",
            0,
            86_400,
        )
        if suite.get("failure_policy", "stop") not in {"stop", "continue"}:
            raise ConfigurationError(
                f"experiment_suites.{suite_name}.failure_policy must be stop or continue"
            )

        for index, experiment_value in enumerate(experiments):
            location = f"experiment_suites.{suite_name}.experiments[{index}]"
            experiment = _mapping(experiment_value, location)
            if {"account_id", "region", "role_arn", "external_id"} & experiment.keys():
                raise ConfigurationError(
                    f"{location} cannot override global execution identity"
                )
            type_name = experiment.get("type")
            if type_name not in valid_type_names:
                raise ConfigurationError(f"{location}.type is invalid: {type_name!r}")
            experiment_type = ChaosType(type_name)
            derived_target_scope(experiment_type, experiment)
            metadata = experiment_metadata(experiment_type)
            if (
                not metadata.live_supported
                and experiment_type
                not in CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS | {ChaosType.FIS_TEMPLATE}
            ):
                if metadata.provider == "fis-template":
                    raise ConfigurationError(
                        f"{location}.type must be expressed in an AWS FIS template and "
                        "run with type: fis_template"
                    )
                raise ConfigurationError(
                    f"{location}.type is declared but not safely implemented: {type_name}"
                )
            required = REQUIRED_PARAMETERS.get(experiment_type, ())
            missing = [key for key in required if not _nonempty(experiment.get(key))]
            if missing:
                raise ConfigurationError(
                    f"{location} is missing required parameter(s): {', '.join(missing)}"
                )
            for key in ("instance_ids", "target_ids", "task_arns", "paths"):
                if key not in experiment:
                    continue
                value = experiment[key]
                discovery_value = isinstance(value, str) and value in {
                    "@random_discovered",
                    "@discovered",
                }
                if not discovery_value and (
                    not isinstance(value, list)
                    or not value
                    or not all(isinstance(item, str) and item for item in value)
                ):
                    raise ConfigurationError(
                        f"{location}.{key} must be a non-empty list of strings"
                    )
            if "image_ids" in experiment:
                image_ids = experiment["image_ids"]
                if not isinstance(image_ids, list) or not image_ids:
                    raise ConfigurationError(
                        f"{location}.image_ids must be a non-empty list"
                    )
                for image_id in image_ids:
                    if (
                        not isinstance(image_id, dict)
                        or len(set(image_id) & {"imageDigest", "imageTag"}) != 1
                        or set(image_id) - {"imageDigest", "imageTag"}
                    ):
                        raise ConfigurationError(
                            f"{location}.image_ids entries need exactly imageTag or imageDigest"
                        )
            if "parameters" in experiment:
                parameters = experiment["parameters"]
                if not isinstance(parameters, list) or not parameters:
                    raise ConfigurationError(
                        f"{location}.parameters must be a non-empty list"
                    )
                for parameter in parameters:
                    if not isinstance(parameter, dict) or not {
                        "ParameterName",
                        "ParameterValue",
                        "ApplyMethod",
                    } <= set(parameter):
                        raise ConfigurationError(
                            f"{location}.parameters entries need ParameterName, "
                            "ParameterValue, and ApplyMethod"
                        )
                    if parameter["ApplyMethod"] not in {"immediate", "pending-reboot"}:
                        raise ConfigurationError(
                            f"{location}.parameters has an invalid ApplyMethod"
                        )
                    if (
                        experiment_type == ChaosType.RDS_PARAMETER_GROUP_MODIFY
                        and parameter["ApplyMethod"] != "immediate"
                    ):
                        raise ConfigurationError(
                            f"{location}.parameters must use ApplyMethod=immediate"
                        )
            if "remove_rule" in experiment and not isinstance(
                experiment["remove_rule"], dict
            ):
                raise ConfigurationError(f"{location}.remove_rule must be a mapping")
            if "auto_rollback" in experiment and not isinstance(
                experiment["auto_rollback"], bool
            ):
                raise ConfigurationError(
                    f"{location}.auto_rollback must be true or false"
                )
            for key in ("blackhole", "force_failover", "instrumented"):
                if key in experiment and not isinstance(experiment[key], bool):
                    raise ConfigurationError(f"{location}.{key} must be true or false")
            if metadata.risk == RiskLevel.IRREVERSIBLE and experiment.get(
                "auto_rollback", False
            ):
                raise ConfigurationError(
                    f"{location} is irreversible and cannot claim automatic rollback"
                )
            _integer_in_range(
                experiment.get("duration_seconds", 0),
                f"{location}.duration_seconds",
                0,
                86_400,
            )
            for key, (minimum, maximum) in numeric_bounds.items():
                if key not in experiment:
                    continue
                value = experiment[key]
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ConfigurationError(f"{location}.{key} must be numeric")
                if not minimum <= value <= maximum:
                    raise ConfigurationError(
                        f"{location}.{key} must be between {minimum} and {maximum}"
                    )
            if "timeout_seconds" in experiment:
                timeout_maximum = (
                    43_200
                    if experiment_type == ChaosType.SQS_VISIBILITY_TIMEOUT
                    else 900
                )
                _integer_in_range(
                    experiment["timeout_seconds"],
                    f"{location}.timeout_seconds",
                    0 if experiment_type == ChaosType.SQS_VISIBILITY_TIMEOUT else 1,
                    timeout_maximum,
                )
            if "interval" in experiment:
                interval = _integer_in_range(
                    experiment["interval"], f"{location}.interval", 5, 300
                )
                health_timeout = _integer_in_range(
                    experiment.get("timeout", 120),
                    f"{location}.timeout",
                    2,
                    120,
                )
                if health_timeout >= interval:
                    raise ConfigurationError(
                        f"{location}.timeout must be less than interval"
                    )
            for key in ("destination_cidr", "cidr_block"):
                if key in experiment:
                    try:
                        ipaddress.ip_network(str(experiment[key]), strict=False)
                    except ValueError as exc:
                        raise ConfigurationError(
                            f"{location}.{key} is invalid"
                        ) from exc
            if "addresses_to_add" in experiment:
                addresses = experiment["addresses_to_add"]
                if not isinstance(addresses, list) or not addresses:
                    raise ConfigurationError(
                        f"{location}.addresses_to_add must be a non-empty list"
                    )
                try:
                    for address in addresses:
                        ipaddress.ip_network(str(address), strict=True)
                except ValueError as exc:
                    raise ConfigurationError(
                        f"{location}.addresses_to_add contains an invalid CIDR"
                    ) from exc
            if experiment_type == ChaosType.EFS_THROTTLE_THROUGHPUT and experiment.get(
                "throughput_mode", "provisioned"
            ) not in {"bursting", "provisioned", "elastic"}:
                raise ConfigurationError(f"{location}.throughput_mode is invalid")
            if experiment_type in {
                ChaosType.WAF_RULE_MODIFY,
                ChaosType.WAF_RATE_LIMIT_MODIFY,
                ChaosType.WAF_IP_SET_MODIFY,
            } and experiment.get("scope", "REGIONAL") not in {
                "REGIONAL",
                "CLOUDFRONT",
            }:
                raise ConfigurationError(
                    f"{location}.scope must be REGIONAL or CLOUDFRONT"
                )
            if (
                experiment_type == ChaosType.WAF_RULE_MODIFY
                and str(experiment.get("action", "BLOCK")).upper()
                not in WAFChaosExperiment.ACTIONS
            ):
                raise ConfigurationError(f"{location}.action is invalid")
            if (
                experiment_type == ChaosType.LAMBDA_ERROR_INJECTION
                and experiment.get("instrumented") is not True
            ):
                raise ConfigurationError(
                    f"{location}.instrumented must be true because the Lambda function "
                    "must honor CHAOS_ERROR_RATE"
                )
            if "corrupt_vars" in experiment:
                corrupt_vars = experiment["corrupt_vars"]
                if not isinstance(corrupt_vars, dict) or not corrupt_vars:
                    raise ConfigurationError(
                        f"{location}.corrupt_vars must be a non-empty mapping"
                    )
                if not all(
                    isinstance(key, str)
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,127}", key)
                    and not key.startswith("AWS_")
                    and isinstance(value, str)
                    for key, value in corrupt_vars.items()
                ):
                    raise ConfigurationError(
                        f"{location}.corrupt_vars contains an invalid or reserved variable"
                    )
            for key, value in experiment.items():
                if (
                    isinstance(value, str)
                    and value == "@discovered"
                    and not key.endswith("s")
                ):
                    raise ConfigurationError(
                        f"{location}.{key} cannot use @discovered because it is singular"
                    )

            if region in GOVCLOUD_REGIONS and experiment_type in {
                ChaosType.CLOUDFRONT_BEHAVIOR_MODIFY,
                ChaosType.CLOUDFRONT_CACHE_INVALIDATE,
            }:
                raise ConfigurationError(
                    f"{location} uses CloudFront, which is not an AWS GovCloud service"
                )

            break_glass = experiment.get("break_glass_principal_arn")
            if break_glass:
                expected_partition = (
                    "aws-us-gov" if region in GOVCLOUD_REGIONS else "aws"
                )
                match = re.fullmatch(
                    r"arn:(aws|aws-us-gov):iam::([0-9]{12}):(role|user)/.+",
                    str(break_glass),
                )
                if not match or match.group(1) != expected_partition:
                    raise ConfigurationError(
                        f"{location}.break_glass_principal_arn has the wrong format or partition"
                    )
                if (
                    account_id
                    and account_id != "000000000000"
                    and match.group(2) != account_id
                ):
                    raise ConfigurationError(
                        f"{location}.break_glass_principal_arn belongs to a different account"
                    )
            if (
                experiment_type == ChaosType.IAM_USER_ACCESS_KEY_DEACTIVATE
                and not re.fullmatch(
                    r"(?:AKIA|ASIA)[A-Z0-9]{16}", str(experiment["access_key_id"])
                )
            ):
                raise ConfigurationError(f"{location}.access_key_id is invalid")


def validate_config(config_file: str, quiet: bool = False) -> bool:
    """Validate a configuration file and return a process-friendly result."""
    try:
        config = load_yaml_config(config_file)
        validate_config_data(config)
    except (ConfigurationError, OSError) as exc:
        if not quiet:
            print(
                f"Configuration validation failed: {redact_runtime_text(exc)}",
                file=sys.stderr,
            )
        return False
    if not quiet:
        print(
            f"Configuration is valid: {safe_display(Path(config_file).expanduser().resolve())}"
        )
    return True


def list_experiment_types() -> None:
    """List experiment support, provider, risk, and rollback behavior."""
    headers = ("TYPE", "PROVIDER", "RISK", "ROLLBACK", "LIVE")
    rows = []
    for chaos_type in ChaosType:
        metadata = experiment_metadata(chaos_type)
        rows.append(
            (
                chaos_type.value,
                metadata.provider,
                metadata.risk.value,
                metadata.rollback,
                "yes" if metadata.live_supported else "no",
            )
        )
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]
    print("  ".join(value.ljust(widths[index]) for index, value in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def validate_queue_identity(
    config: dict[str, Any], queue_url: str, queue_arn: str
) -> None:
    """Bind an opaque SQS URL to an explicit local partition, region and account."""
    region = str(config.get("region", DEFAULT_REGION))
    account = str(config.get("account_id", ""))
    partition = "aws-us-gov" if region in GOVCLOUD_REGIONS else "aws"
    match = re.fullmatch(
        r"arn:(aws|aws-us-gov):sqs:([^:]+):([0-9]{12}):([A-Za-z0-9_-]{1,80}(?:\.fifo)?)",
        queue_arn,
    )
    if not match or match.group(1, 2, 3) != (partition, region, account):
        raise ConfigurationError(
            "SQS QueueArn must match the reviewed partition, region and account"
        )
    parsed = urlsplit(queue_url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != f"sqs.{region}.amazonaws.com"
        or parsed.path != f"/{account}/{match.group(4)}"
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError(
            "SQS QueueUrl must exactly match the reviewed QueueArn"
        )


def confirmation_token(
    config: dict[str, Any],
    suite_name: str,
    execution_scope: dict[str, Any] | None = None,
) -> str:
    """Build the exact live confirmation token without contacting AWS."""
    validate_config_data(config)
    suites = config["experiment_suites"]
    if suite_name not in suites:
        raise ConfigurationError(f"Suite {suite_name} not found in configuration")
    if any(
        value in {"@discovered", "@random_discovered"}
        for item in suites[suite_name]["experiments"]
        for value in item.values()
        if isinstance(value, str)
    ):
        raise ConfigurationError(
            "Materialize concrete targets before generating live approval"
        )
    experiment_types = [
        ChaosType(item["type"]) for item in suites[suite_name]["experiments"]
    ]
    for item in suites[suite_name]["experiments"]:
        if item["type"] == ChaosType.SQS_QUEUE_PURGE.value:
            values = {**config["global"], **item}
            validate_queue_identity(
                config["global"], values["queue_url"], values["queue_arn"]
            )
    if ChaosType.FIS_TEMPLATE in experiment_types:
        raise ConfigurationError(
            "Live FIS approval is disabled until immutable template authorization can be verified"
        )
    if any(item in CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS for item in experiment_types):
        raise ConfigurationError(
            "Live approval is unavailable for experiments without conditional recovery ownership proof"
        )
    irreversible = any(
        experiment_metadata(item).risk == RiskLevel.IRREVERSIBLE
        for item in experiment_types
    )
    prefix = "LIVE-IRREVERSIBLE" if irreversible else "LIVE"
    global_config = config["global"]
    account_id = str(global_config.get("account_id", ""))
    region = str(global_config.get("region", DEFAULT_REGION))
    if not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise ConfigurationError(
            "A valid global.account_id is required to generate a live token"
        )
    reviewed = copy.deepcopy(config)
    effective_role = (execution_scope or {}).get("role_arn") or global_config.get(
        "role_arn"
    )
    if effective_role:
        reviewed["global"]["role_arn"] = effective_role
        validate_config_data(reviewed)
    reviewed["safety"] = {
        key: value
        for key, value in reviewed.get("safety", {}).items()
        if not key.startswith("_runtime_")
    }
    reviewed["execution_scope"] = execution_scope or {
        "profile": None,
        "role_arn": global_config.get("role_arn"),
        "vpc_id": None,
        "seed": None,
    }
    digest = hashlib.sha256(
        json.dumps(
            reviewed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    return f"{prefix}:{account_id}:{region}:{suite_name}:{digest}"


def configure_logging(level: str) -> None:
    """Configure concise console logging without exposing experiment config values."""
    handler = logging.StreamHandler()
    handler.setFormatter(
        PrivacyFormatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%SZ")
    )
    formatter = handler.formatter
    if formatter is not None:
        formatter.converter = time.gmtime
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper()))
    logger.propagate = False


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line interface."""
    parser = argparse.ArgumentParser(
        description=(
            "Guarded AWS chaos orchestration using AWS FIS plus one-file service extensions"
        )
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {__version__}"
    )
    parser.add_argument("--config", "-c", help="YAML configuration file")
    parser.add_argument("--suite", "-s", help="Experiment suite to plan or run")
    parser.add_argument(
        "--vpc-id", help="Discover only exactly tagged resources in this VPC"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan and perform read-only validation. This is the default mode.",
    )
    mode.add_argument(
        "--live",
        action="store_true",
        help="Enable live AWS mutations after all safety checks pass",
    )
    parser.add_argument(
        "--confirm", help="Exact account, region, and suite confirmation token"
    )
    parser.add_argument(
        "--allow-irreversible",
        action="store_true",
        help="Second approval required for irreversible experiments",
    )
    parser.add_argument(
        "--allow-long-term-credentials",
        action="store_true",
        help="Second approval to permit long-term credentials for a live run",
    )
    parser.add_argument(
        "--allow-live-without-safety-alarms",
        action="store_true",
        help="Second approval for live extensions without CloudWatch safety alarms",
    )
    parser.add_argument(
        "--allow-fis-without-stop-condition",
        action="store_true",
        help="Second approval for a FIS template without an alarm stop condition",
    )
    parser.add_argument(
        "--allow-unbounded-fis-targets",
        action="store_true",
        help="Second approval for FIS ALL or PERCENT target selection",
    )
    parser.add_argument("--profile", help="AWS shared configuration profile")
    parser.add_argument("--role-arn", help="AWS IAM role to assume for the run")
    parser.add_argument(
        "--output-dir",
        default="chaos-reports",
        help="Directory for local JSON evidence reports",
    )
    parser.add_argument(
        "--seed", type=int, help="Deterministic resource-selection seed"
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
    )
    utilities = parser.add_mutually_exclusive_group()
    utilities.add_argument(
        "--create-sample-config",
        nargs="?",
        const="chaos-config.example.yaml",
        metavar="PATH",
        help="Create a safe sample configuration, optionally at PATH",
    )
    utilities.add_argument(
        "--validate-config", metavar="PATH", help="Validate YAML and exit"
    )
    utilities.add_argument(
        "--list-experiments",
        action="store_true",
        help="List support, provider, risk, and rollback metadata",
    )
    utilities.add_argument(
        "--show-live-token",
        action="store_true",
        help="Print the exact token required for the selected suite",
    )
    utilities.add_argument(
        "--show-target-selectors",
        action="store_true",
        help="Print exact child-selector approval digests without contacting AWS",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    try:
        if args.create_sample_config:
            create_sample_config(args.create_sample_config)
            return 0
        if args.validate_config:
            return 0 if validate_config(args.validate_config) else 2
        if args.list_experiments:
            list_experiment_types()
            return 0
        if not args.config or not args.suite:
            parser.error(
                "--config and --suite are required unless a utility option is used"
            )

        config = load_yaml_config(args.config)
        validate_config_data(config)
        if args.show_live_token:
            print(
                safe_display(
                    confirmation_token(
                        config,
                        args.suite,
                        {
                            "profile": args.profile,
                            "role_arn": args.role_arn
                            or config["global"].get("role_arn"),
                            "vpc_id": args.vpc_id,
                            "seed": args.seed,
                        },
                    )
                )
            )
            return 0
        if args.show_target_selectors:
            if args.suite not in config["experiment_suites"]:
                raise ConfigurationError("The selected suite does not exist")
            selectors = set()
            for item in config["experiment_suites"][args.suite]["experiments"]:
                values = {**config.get("global", {}), **item}
                selectors.update(
                    value
                    for value in ChaosOrchestrator._target_values(values)
                    if value.startswith("selector:")
                )
            print(json.dumps(sorted(selectors), indent=2))
            return 0

        mode = "LIVE" if args.live else "PLAN"
        print(f"{TOOL_NAME} {__version__}")
        print(f"Mode: {mode}")
        print(f"Suite: {safe_display(args.suite)}")
        if args.vpc_id:
            print("Scope: one VPC with exact tag filtering")
        if args.live:
            print(
                "Live mode can modify AWS resources. Press Ctrl+C for emergency stop."
            )
        else:
            print("Plan mode is read-only and is the default.")

        orchestrator = ChaosOrchestrator(
            args.config,
            vpc_id=args.vpc_id,
            dry_run_flag=args.dry_run,
            live=args.live,
            profile=args.profile,
            role_arn=args.role_arn,
            output_dir=args.output_dir,
            confirmation=args.confirm,
            allow_irreversible=args.allow_irreversible,
            allow_long_term_credentials=args.allow_long_term_credentials,
            allow_live_without_safety_alarms=args.allow_live_without_safety_alarms,
            allow_fis_without_stop_condition=args.allow_fis_without_stop_condition,
            allow_unbounded_fis_targets=args.allow_unbounded_fis_targets,
            seed=args.seed,
        )
        return 0 if orchestrator.run_experiment_suite(args.suite) else 1
    except KeyboardInterrupt:
        logger.error("Interrupted. Emergency rollback was requested.")
        return 130
    except (ConfigurationError, SafetyViolation) as exc:
        logger.error("%s", exc)
        return 2
    except Exception as exc:
        logger.error("Unexpected failure: %s", exc)
        logger.debug("Unexpected failure details", exc_info=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
