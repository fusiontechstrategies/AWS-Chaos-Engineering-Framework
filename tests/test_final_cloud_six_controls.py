"""Ordinary sequential models for final Cloud source controls; no AWS calls."""

from __future__ import annotations

import copy
import itertools
from typing import Any
from urllib.parse import urlsplit

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    INSTANCE_ID,
    REGION,
    VOLUME_ID,
    FakeAWS,
    FakeClient,
    FakeClientError,
    action_configs,
    make_experiment,
    make_orchestrator,
)

import aws_chaos_framework as framework

FUNCTION = "chaos-test-function"
FUNCTION_ARN = f"arn:aws-us-gov:lambda:{REGION}:{ACCOUNT_ID}:function:{FUNCTION}"
INVALID_FUNCTIONS = (
    f"{ACCOUNT_ID}:function:{FUNCTION}",
    f"999900001111:function:{FUNCTION}",
    f"arn:aws-us-gov:lambda:{REGION}:999900001111:function:{FUNCTION}",
    f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{FUNCTION}",
    f"arn:aws-us-gov:lambda:us-gov-east-1:{ACCOUNT_ID}:function:{FUNCTION}",
    f"{FUNCTION}:alias",
    f"{FUNCTION_ARN}:1",
    "function:name",
    "name*",
    " name",
    "n" * 65,
)


class SequentialClock:
    """A bounded deterministic clock, with no worker or concurrent state changes."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    value = SequentialClock()
    monkeypatch.setattr(framework.time, "monotonic", value.monotonic)
    monkeypatch.setattr(framework.time, "sleep", value.sleep)
    return value


def lambda_plan(aws):
    kind = framework.ChaosType.LAMBDA_TIMEOUT_MODIFY
    return make_experiment(kind, action_configs()[kind], aws)


@pytest.mark.parametrize("identifier", INVALID_FUNCTIONS)
def test_lambda_invalid_identity_refuses_plan_handler_and_sdk_without_calls(identifier):
    aws = FakeAWS()
    experiment = lambda_plan(aws)
    aws.calls.clear()
    with pytest.raises(framework.SafetyViolation):
        framework.validate_experiment_arns(
            {"type": "lambda_timeout_modify", "function_name": identifier},
            ACCOUNT_ID,
            REGION,
        )
    with pytest.raises(framework.SafetyViolation):
        experiment.modify_timeout(identifier, 1)
    with pytest.raises(framework.SafetyViolation):
        experiment.lambda_client.get_function_configuration(FunctionName=identifier)
    assert aws.calls == []
    assert experiment.mutation_attempts == []


@pytest.mark.parametrize("identifier", (FUNCTION, FUNCTION_ARN))
def test_lambda_accepted_identifiers_bind_exact_canonical_response(identifier):
    framework.validate_lambda_function_identifier(identifier, ACCOUNT_ID, REGION)
    framework.validate_lambda_function_response(
        identifier, {"FunctionArn": FUNCTION_ARN}, ACCOUNT_ID, REGION
    )
    for response in (
        {},
        {"FunctionArn": FUNCTION},
        {"FunctionArn": FUNCTION_ARN + "-other"},
    ):
        with pytest.raises(framework.SafetyViolation):
            framework.validate_lambda_function_response(
                identifier, response, ACCOUNT_ID, REGION
            )


def test_lambda_separate_qualifier_and_wrong_endpoint_refuse_before_sdk():
    aws = FakeAWS()
    experiment = lambda_plan(aws)
    aws.calls.clear()
    with pytest.raises(framework.SafetyViolation, match="Qualified"):
        experiment.lambda_client.get_function_configuration(
            FunctionName=FUNCTION, Qualifier="alias"
        )
    aws.client("lambda").meta.region_name = "us-gov-east-1"
    with pytest.raises(framework.SafetyViolation, match="endpoint"):
        experiment.lambda_client.get_function_concurrency(FunctionName=FUNCTION)
    assert aws.calls == []
    assert experiment.mutation_attempts == []


def route_model(aws):
    kind = framework.ChaosType.VPC_ROUTE_TABLE_MODIFY
    experiment = make_experiment(kind, action_configs()[kind], aws)
    experiment.route_table_id = "rtb-0123456789abcdef0"
    experiment.destination_cidr = "10.20.0.0/16"
    experiment.original_route_target = {"GatewayId": "igw-0123456789abcdef0"}
    experiment.config["state_timeout_seconds"] = 2
    return experiment


def route_response(state="active", **changes):
    route = {
        "DestinationCidrBlock": "10.20.0.0/16",
        "GatewayId": "igw-0123456789abcdef0",
        "State": state,
    }
    route.update(changes)
    return {
        "RouteTables": [{"RouteTableId": "rtb-0123456789abcdef0", "Routes": [route]}]
    }


def test_route_waits_for_exact_active_state_and_independent_predicate(clock):
    aws = FakeAWS()
    experiment = route_model(aws)
    pending = route_response("pending")
    active = route_response()
    aws.read_overrides[("ec2", "describe_route_tables")] = [pending, active]
    experiment.config["state_timeout_seconds"] = 10
    assert not experiment._route_is_restored(pending["RouteTables"][0]["Routes"])
    experiment._wait_for_active_route()
    assert clock.sleeps == [5.0]
    assert experiment._route_is_restored(experiment._current_selected_routes())
    assert experiment.mutation_attempts == []


@pytest.mark.parametrize(
    "case", ("blackhole", "wrong-target", "duplicate", "wrong-table")
)
def test_route_invalid_recovery_state_refuses_without_writes(case, clock):
    aws = FakeAWS()
    experiment = route_model(aws)
    response = route_response("blackhole" if case == "blackhole" else "active")
    table = response["RouteTables"][0]
    if case == "wrong-target":
        table["Routes"][0]["GatewayId"] = "igw-0123456789abcdef1"
    elif case == "duplicate":
        table["Routes"].append(copy.deepcopy(table["Routes"][0]))
    elif case == "wrong-table":
        table["RouteTableId"] = "rtb-0123456789abcdef1"
    aws.read_overrides[("ec2", "describe_route_tables")] = [response]
    with pytest.raises(framework.SafetyViolation):
        experiment._wait_for_active_route()
    assert clock.sleeps == []
    assert experiment.mutation_attempts == []
    assert not experiment.rollback_verified


def test_route_unknown_state_cannot_claim_recovery_at_deadline(clock):
    aws = FakeAWS()
    experiment = route_model(aws)
    aws.read_overrides[("ec2", "describe_route_tables")] = [route_response(None)]
    with pytest.raises(TimeoutError):
        experiment._wait_for_active_route()
    assert clock.sleeps == [2.0]
    assert not experiment.rollback_verified


def attachment_model(aws):
    kind = framework.ChaosType.EBS_DETACH_VOLUME
    experiment = make_experiment(kind, action_configs()[kind], aws)
    experiment.volume_id = VOLUME_ID
    experiment.original_instance = INSTANCE_ID
    experiment.original_device = "/dev/xvdf"
    experiment.config["state_timeout_seconds"] = 2
    return experiment


def volume_response(attachment_state="attached", **changes: Any):
    volume = {
        "VolumeId": VOLUME_ID,
        "State": "in-use",
        "MultiAttachEnabled": False,
        "Attachments": [
            {
                "InstanceId": INSTANCE_ID,
                "Device": "/dev/xvdf",
                "State": attachment_state,
            }
        ],
    }
    volume.update(changes)
    return {"Volumes": [volume]}


def test_ebs_aggregate_in_use_waits_until_exact_tuple_attached(clock):
    aws = FakeAWS()
    experiment = attachment_model(aws)
    aws.read_overrides[("ec2", "describe_volumes")] = [
        volume_response("attaching"),
        volume_response(),
    ]
    experiment.config["state_timeout_seconds"] = 10
    experiment._wait_for_exact_attachment()
    assert clock.sleeps == [5.0]
    assert experiment.mutation_attempts == []


@pytest.mark.parametrize(
    "case",
    (
        "extra",
        "wrong-instance",
        "wrong-device",
        "detaching",
        "multi",
        "unknown-capability",
        "wrong-volume",
    ),
)
def test_ebs_unexpected_attachment_or_capability_refuses(case, clock):
    aws = FakeAWS()
    experiment = attachment_model(aws)
    response = volume_response()
    volume = response["Volumes"][0]
    if case == "extra":
        volume["Attachments"].append(copy.deepcopy(volume["Attachments"][0]))
    elif case == "wrong-instance":
        volume["Attachments"][0]["InstanceId"] = "i-0123456789abcdef1"
    elif case == "wrong-device":
        volume["Attachments"][0]["Device"] = "/dev/xvdg"
    elif case == "detaching":
        volume["Attachments"][0]["State"] = "detaching"
    elif case == "multi":
        volume["MultiAttachEnabled"] = True
    elif case == "unknown-capability":
        del volume["MultiAttachEnabled"]
    elif case == "wrong-volume":
        volume["VolumeId"] = "vol-0123456789abcdef1"
    aws.read_overrides[("ec2", "describe_volumes")] = [response]
    with pytest.raises(framework.SafetyViolation):
        experiment._wait_for_exact_attachment()
    assert clock.sleeps == []
    assert experiment.mutation_attempts == []
    assert not experiment.rollback_verified


def test_ebs_attaching_tuple_is_not_verified_at_deadline(clock):
    aws = FakeAWS()
    experiment = attachment_model(aws)
    aws.read_overrides[("ec2", "describe_volumes")] = [volume_response("attaching")]
    with pytest.raises(TimeoutError):
        experiment._wait_for_exact_attachment()
    assert clock.sleeps == [2.0]
    assert not experiment.rollback_verified


# Selected --vpc-id inventory and S3 region admission.

VPC = "vpc-0123456789abcdef0"
OTHER_VPC = "vpc-0123456789abcdef1"
UNTAGGED_INSTANCE = "i-0123456789abcdef1"
OUTSIDE_INSTANCE = "i-0123456789abcdef2"
SUBNET = "subnet-0123456789abcdef0"
UNTAGGED_SUBNET = "subnet-0123456789abcdef1"
OUTSIDE_SUBNET = "subnet-0123456789abcdef2"
ORIGINAL_NACL = "acl-0123456789abcdef0"
NACL = "acl-0fedcba9876543210"
UNTAGGED_NACL = "acl-0fedcba9876543211"
OUTSIDE_NACL = "acl-0fedcba9876543212"
ENDPOINT = "vpce-0123456789abcdef0"
UNTAGGED_ENDPOINT = "vpce-0123456789abcdef1"
OUTSIDE_ENDPOINT = "vpce-0123456789abcdef2"
PEERING = "pcx-0123456789abcdef0"
MOUNT_TARGET = "fsmt-0123456789abcdef0"
TAGS = [{"Key": "ChaosReady", "Value": "true"}]
MUTATIONS = {
    "reboot_instances",
    "replace_network_acl_association",
    "delete_vpc_endpoints",
    "delete_vpc_peering_connection",
    "delete_mount_target",
    "put_bucket_lifecycle_configuration",
}


def item(id_key: str, value: str, vpc: str, tagged: bool) -> dict[str, Any]:
    return {id_key: value, "VpcId": vpc, **({"Tags": TAGS} if tagged else {})}


# Every in-VPC resource appears both with and without the required safety tag.
INVENTORY = {
    "describe_instances": [
        {**item("InstanceId", INSTANCE_ID, VPC, True), "State": {"Name": "running"}},
        {
            **item("InstanceId", UNTAGGED_INSTANCE, VPC, False),
            "State": {"Name": "running"},
        },
        {
            **item("InstanceId", OUTSIDE_INSTANCE, OTHER_VPC, True),
            "State": {"Name": "running"},
        },
    ],
    "describe_subnets": [
        item("SubnetId", SUBNET, VPC, True),
        item("SubnetId", UNTAGGED_SUBNET, VPC, False),
        item("SubnetId", OUTSIDE_SUBNET, OTHER_VPC, True),
    ],
    "describe_security_groups": [],
    "describe_network_acls": [
        item("NetworkAclId", ORIGINAL_NACL, VPC, True),
        item("NetworkAclId", NACL, VPC, True),
        item("NetworkAclId", UNTAGGED_NACL, VPC, False),
        item("NetworkAclId", OUTSIDE_NACL, OTHER_VPC, True),
    ],
    "describe_route_tables": [],
    "describe_vpc_endpoints": [
        item("VpcEndpointId", ENDPOINT, VPC, True),
        item("VpcEndpointId", UNTAGGED_ENDPOINT, VPC, False),
        item("VpcEndpointId", OUTSIDE_ENDPOINT, OTHER_VPC, True),
    ],
    "describe_vpc_peering_connections": [
        {
            "VpcPeeringConnectionId": PEERING,
            "RequesterVpcInfo": {"VpcId": VPC},
            "AccepterVpcInfo": {"VpcId": OTHER_VPC},
            "Status": {"Code": "active"},
            "Tags": TAGS,
        }
    ],
}
RESULT_KEYS = {
    "describe_instances": "Reservations",
    "describe_subnets": "Subnets",
    "describe_security_groups": "SecurityGroups",
    "describe_network_acls": "NetworkAcls",
    "describe_route_tables": "RouteTables",
    "describe_vpc_endpoints": "VpcEndpoints",
    "describe_vpc_peering_connections": "VpcPeeringConnections",
}


def matches(resource: dict[str, Any], filters: list[dict[str, Any]]) -> bool:
    """Apply the EC2 filter names used by the discovery pass."""
    tags = {tag["Key"]: tag["Value"] for tag in resource.get("Tags", [])}
    for entry in filters:
        name = entry["Name"]
        if name.startswith("tag:"):
            actual = tags.get(name[4:])
        elif name == "vpc-id":
            actual = resource.get("VpcId")
        elif name in {"requester-vpc-info.vpc-id", "accepter-vpc-info.vpc-id"}:
            field = name.split("-vpc-info")[0].capitalize() + "VpcInfo"
            actual = resource.get(field, {}).get("VpcId")
        elif name == "instance-state-name":
            actual = resource.get("State", {}).get("Name")
        elif name == "status-code":
            actual = resource.get("Status", {}).get("Code")
        else:
            raise AssertionError(f"Unmodeled filter {name}")
        if actual not in entry["Values"]:
            return False
    return True


class ModeledPaginator:
    def __init__(self, operation: str) -> None:
        self.operation = operation

    def paginate(self, Filters: list[dict[str, Any]]) -> list[dict[str, Any]]:
        found = [
            copy.deepcopy(resource)
            for resource in INVENTORY[self.operation]
            if matches(resource, Filters)
        ]
        if self.operation == "describe_instances":
            found = [{"Instances": found}] if found else []
        return [{RESULT_KEYS[self.operation]: found}]


class ModeledEC2(FakeClient):
    """Discovery reads honor VPC and tag filters; other reads use FakeAWS."""

    def describe_vpcs(self, VpcIds: list[str]) -> dict[str, Any]:
        assert VpcIds == [VPC]
        return {"Vpcs": [{"VpcId": VPC, "Tags": TAGS}]}

    def get_paginator(self, operation: str) -> ModeledPaginator:
        return ModeledPaginator(operation)


def scoped(kind, values=None, aws=None):
    """A confirmed live orchestrator whose approval and discovery bind one VPC."""
    aws = aws or FakeAWS(reject_writes=False)
    aws.clients.setdefault("ec2", ModeledEC2(aws, "ec2"))
    values = action_configs()[kind] if values is None else values
    orchestrator = make_orchestrator(kind, values, aws, dry_run=False)
    orchestrator.vpc_id = VPC
    orchestrator.approval_scope["vpc_id"] = VPC
    orchestrator.confirmation = orchestrator.expected_confirmation("ordinary", True)
    orchestrator._discover_resources()
    aws.calls.clear()
    return orchestrator, aws, values


def mutation_calls(aws) -> list[str]:
    return [operation for _, operation, _ in aws.calls if operation in MUTATIONS]


def fast_poll(experiment, monkeypatch) -> None:
    ticks = itertools.count()
    monkeypatch.setattr(framework.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(experiment, "_wait_forward", lambda seconds: None)


def test_discovery_inventory_contains_only_tagged_resources_in_the_vpc():
    orchestrator, _aws, _values = scoped(framework.ChaosType.EC2_REBOOT)
    assert orchestrator.discovered_resources["instances"] == [INSTANCE_ID]
    assert orchestrator.discovered_resources["subnets"] == [SUBNET]
    assert orchestrator.discovered_resources["nacls"] == [ORIGINAL_NACL, NACL]
    assert orchestrator.discovered_resources["vpc_endpoints"] == [ENDPOINT]
    assert orchestrator.discovered_resources["peering_connections"] == [PEERING]


PEERING_VALUES = action_configs()[framework.ChaosType.VPC_PEERING_DELETE]
SWAPPED_PEERING = {
    **PEERING_VALUES,
    "peering_endpoints": {
        "requester": PEERING_VALUES["peering_endpoints"]["accepter"],
        "accepter": PEERING_VALUES["peering_endpoints"]["requester"],
    },
}
OUT_OF_SCOPE = [
    (framework.ChaosType.EC2_REBOOT, {"instance_ids": [OUTSIDE_INSTANCE]}),
    (framework.ChaosType.EC2_REBOOT, {"instance_ids": [UNTAGGED_INSTANCE]}),
    (
        framework.ChaosType.EC2_REBOOT,
        {"instance_ids": [INSTANCE_ID, OUTSIDE_INSTANCE]},
    ),
    (
        framework.ChaosType.VPC_SUBNET_ACL_MODIFY,
        {
            "subnet_id": OUTSIDE_SUBNET,
            "nacl_id": NACL,
            "original_nacl_id": ORIGINAL_NACL,
        },
    ),
    (
        framework.ChaosType.VPC_SUBNET_ACL_MODIFY,
        {
            "subnet_id": UNTAGGED_SUBNET,
            "nacl_id": NACL,
            "original_nacl_id": ORIGINAL_NACL,
        },
    ),
    (
        framework.ChaosType.VPC_SUBNET_ACL_MODIFY,
        {
            "subnet_id": SUBNET,
            "nacl_id": OUTSIDE_NACL,
            "original_nacl_id": ORIGINAL_NACL,
        },
    ),
    (
        framework.ChaosType.VPC_SUBNET_ACL_MODIFY,
        {
            "subnet_id": SUBNET,
            "nacl_id": UNTAGGED_NACL,
            "original_nacl_id": ORIGINAL_NACL,
        },
    ),
    (framework.ChaosType.VPC_PEERING_DELETE, PEERING_VALUES),
    (framework.ChaosType.VPC_PEERING_DELETE, SWAPPED_PEERING),
]


@pytest.mark.parametrize(("kind", "values"), OUT_OF_SCOPE)
def test_allowlisted_target_outside_vpc_or_tags_is_a_configuration_error(kind, values):
    orchestrator, aws, values = scoped(kind, values)
    # The literal allowlist admits every target; only VPC scope refuses it.
    allowlist = set(orchestrator.config["safety"]["target_allowlist"])
    assert orchestrator._target_values({"type": kind.value, **values}) <= allowlist
    with pytest.raises(framework.ConfigurationError):
        orchestrator._create_experiment(kind, copy.deepcopy(values))
    assert aws.calls == []

    started = []
    orchestrator._run_single_experiment = started.append
    with pytest.raises(framework.ConfigurationError):
        orchestrator.run_experiment_suite("ordinary")
    assert started == []
    assert mutation_calls(aws) == []


# RDS reboot is planning only, so live admission refuses it before any VPC
# check; a live-supported Lambda type covers the unverifiable-membership case.
@pytest.mark.parametrize(
    "kind",
    [
        framework.ChaosType.LAMBDA_MEMORY_LIMIT,
        framework.ChaosType.LAMBDA_TIMEOUT_MODIFY,
        framework.ChaosType.ECS_TASK_STOP,
        framework.ChaosType.DS_TRUST_DELETE,
    ],
)
def test_vpc_scope_refuses_types_whose_membership_is_unverified(kind):
    values = action_configs()[kind]
    orchestrator, aws, values = scoped(kind, values)
    with pytest.raises(framework.ConfigurationError, match="cannot prove"):
        orchestrator._create_experiment(kind, copy.deepcopy(values))
    assert aws.calls == []
    # Without --vpc-id, admission is unchanged.
    unscoped = make_orchestrator(
        kind, values, FakeAWS(reject_writes=False), dry_run=False
    )
    assert unscoped._create_experiment(kind, copy.deepcopy(values)).dry_run is False


def test_vpc_scope_leaves_vpc_independent_types_admitted():
    # S3 lifecycle and Kinesis retention are now planning only; KMS grant
    # revocation is a live-supported VPC-independent type.
    kind = framework.ChaosType.KMS_GRANT_REVOKE
    orchestrator, _aws, values = scoped(kind)
    experiment = orchestrator._create_experiment(kind, copy.deepcopy(values))
    assert experiment._execution_grant.vpc_id == VPC


def instances_in(vpc: str | None) -> dict[str, Any]:
    return {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": INSTANCE_ID,
                        "VpcId": vpc,
                        "State": {"Name": "running"},
                    }
                ]
            }
        ]
    }


def nacls_in(vpc: str, original: str = ORIGINAL_NACL) -> dict[str, Any]:
    return {
        "NetworkAcls": [
            {
                "NetworkAclId": original,
                "VpcId": vpc,
                "Associations": [
                    {
                        "NetworkAclAssociationId": "aclassoc-0123456789abcdef0",
                        "SubnetId": SUBNET,
                    }
                ],
            }
        ]
    }


def endpoints_in(vpc: str) -> dict[str, Any]:
    return {"VpcEndpoints": [{"VpcEndpointId": ENDPOINT, "VpcId": vpc}]}


def mount_target(**changes: Any) -> dict[str, Any]:
    target = {
        "MountTargetId": MOUNT_TARGET,
        "FileSystemId": "fs-0123456789abcdef0",
        "SubnetId": SUBNET,
        "VpcId": VPC,
    }
    target.update(changes)
    return {"MountTargets": [{k: v for k, v in target.items() if v is not None}]}


def scoped_experiment(kind, values=None):
    orchestrator, aws, values = scoped(kind, values)
    experiment = orchestrator._create_experiment(kind, copy.deepcopy(values))
    assert experiment._execution_grant.vpc_id == VPC
    return experiment, aws


def run_handler(kind, experiment):
    values = copy.deepcopy(action_configs()[kind])
    handler, parameters = framework.AUTHORIZED_HANDLER_CALLS[kind]
    arguments = [values[key] for key, _optional, _default in parameters]
    return getattr(experiment, handler)(*arguments)


@pytest.mark.parametrize(
    ("kind", "operation", "response"),
    [
        (framework.ChaosType.EC2_REBOOT, "describe_instances", instances_in(OTHER_VPC)),
        (framework.ChaosType.EC2_REBOOT, "describe_instances", instances_in(None)),
        (
            framework.ChaosType.VPC_SUBNET_ACL_MODIFY,
            "describe_network_acls",
            nacls_in(OTHER_VPC),
        ),
        (
            # The original NACL is the recovery target, so it must be tagged too.
            framework.ChaosType.VPC_SUBNET_ACL_MODIFY,
            "describe_network_acls",
            nacls_in(VPC, original=UNTAGGED_NACL),
        ),
        (
            framework.ChaosType.EFS_MOUNT_TARGET_DELETE,
            "describe_mount_targets",
            mount_target(VpcId=OTHER_VPC),
        ),
        (
            framework.ChaosType.EFS_MOUNT_TARGET_DELETE,
            "describe_mount_targets",
            mount_target(VpcId=None),
        ),
        (
            framework.ChaosType.EFS_MOUNT_TARGET_DELETE,
            "describe_mount_targets",
            mount_target(SubnetId=UNTAGGED_SUBNET),
        ),
        (
            framework.ChaosType.EFS_MOUNT_TARGET_DELETE,
            "describe_mount_targets",
            mount_target(SubnetId=OUTSIDE_SUBNET, VpcId=OTHER_VPC),
        ),
        (
            framework.ChaosType.EFS_MOUNT_TARGET_DELETE,
            "describe_mount_targets",
            mount_target(MountTargetId="fsmt-0123456789abcdef1"),
        ),
    ],
)
def test_pre_mutation_response_outside_scope_refuses_before_mutation(
    kind, operation, response
):
    experiment, aws = scoped_experiment(kind)
    service = "efs" if kind == framework.ChaosType.EFS_MOUNT_TARGET_DELETE else "ec2"
    aws.read_overrides[(service, operation)] = [response]
    result = run_handler(kind, experiment)
    assert result.status == "failed"
    assert "selected VPC" in " ".join(result.errors)
    assert not result.affected_resources
    assert experiment.mutation_attempts == []
    assert mutation_calls(aws) == []


def test_in_scope_ec2_reboot_is_admitted():
    kind = framework.ChaosType.EC2_REBOOT
    experiment, aws = scoped_experiment(kind)
    aws.read_overrides[("ec2", "describe_instances")] = [instances_in(VPC)]
    result = run_handler(kind, experiment)
    assert result.status == "completed", result.errors
    assert mutation_calls(aws) == ["reboot_instances"]


def test_in_scope_subnet_nacl_replacement_is_admitted():
    kind = framework.ChaosType.VPC_SUBNET_ACL_MODIFY
    experiment, aws = scoped_experiment(kind)
    aws.read_overrides[("ec2", "describe_network_acls")] = [nacls_in(VPC)]
    original = aws.respond

    def respond(service, operation, request):
        response = original(service, operation, request)
        if operation == "replace_network_acl_association":
            return {"NewAssociationId": "aclassoc-0fedcba9876543210"}
        return response

    aws.respond = respond
    result = run_handler(kind, experiment)
    assert result.status == "completed", result.errors
    assert mutation_calls(aws) == ["replace_network_acl_association"]


# VPC endpoint deletion is planning only: DeleteVpcEndpoints also removes the
# endpoint's network interfaces and gateway routes and accepts no condition over
# that association set. Under --vpc-id, an in-scope, untagged or outside
# endpoint is refused before discovery, the handler's pre-read or any write.
@pytest.mark.parametrize("endpoint", [ENDPOINT, UNTAGGED_ENDPOINT, OUTSIDE_ENDPOINT])
def test_vpc_scoped_endpoint_deletion_cannot_obtain_live_approval(endpoint):
    kind = framework.ChaosType.VPC_ENDPOINT_DELETE
    aws = FakeAWS(reject_writes=False)
    aws.clients.setdefault("ec2", ModeledEC2(aws, "ec2"))
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_orchestrator(kind, {"endpoint_id": endpoint}, aws, dry_run=False)
    assert mutation_calls(aws) == []
    assert all(operation != "describe_vpc_endpoints" for _, operation, _ in aws.calls)


def test_efs_mount_target_admitted_only_when_its_subnet_resolves_to_the_vpc():
    kind = framework.ChaosType.EFS_MOUNT_TARGET_DELETE
    experiment, aws = scoped_experiment(kind)
    aws.read_overrides[("efs", "describe_mount_targets")] = [mount_target()]
    result = run_handler(kind, experiment)
    assert result.status == "completed", result.errors
    assert mutation_calls(aws) == ["delete_mount_target"]


def test_peering_rule_requires_both_endpoints_in_the_selected_vpc():
    endpoints, _targets = framework.peering_endpoint_scope(PEERING_VALUES)
    assert {endpoint["vpc_id"] for endpoint in endpoints.values()} == {VPC, OTHER_VPC}
    for values in (PEERING_VALUES, SWAPPED_PEERING):
        with pytest.raises(framework.ConfigurationError, match="both endpoints"):
            framework.validate_vpc_target_scope(
                framework.ChaosType.VPC_PEERING_DELETE,
                values,
                VPC,
                {"peering_connections": [PEERING]},
            )


# S3 lifecycle region binding. Live lifecycle replacement is planning only: it
# has no conditional revision, so the owner-bound location read is never reached
# by a live lifecycle write. The botocore signing-region guard remains in force.

LIFECYCLE = framework.ChaosType.S3_LIFECYCLE_MODIFY
BUCKET = action_configs()[LIFECYCLE]["bucket_name"]


def lifecycle_values(region=REGION, aws=None):
    aws = aws or FakeAWS(reject_writes=False)
    values = dict(action_configs()[LIFECYCLE])
    if region != REGION:
        values["region"] = region
        aws.client("s3").meta.region_name = region
    return values, aws


def s3_calls(aws) -> list[tuple[str, dict[str, Any]]]:
    return [
        (operation, request)
        for service, operation, request in aws.calls
        if service == "s3"
    ]


@pytest.mark.parametrize(
    ("location", "expected"),
    [(None, "us-east-1"), ("", "us-east-1"), ("EU", "eu-west-1"), (REGION, REGION)],
)
def test_bucket_location_normalizes_legacy_constraints(location, expected):
    assert framework.normalize_s3_bucket_region(location) == expected


@pytest.mark.parametrize("location", ["us-gov-east-1", "us-east-1", "EU", None, ""])
def test_s3_lifecycle_in_another_region_is_refused_before_write(location):
    values, aws = lifecycle_values()
    aws.read_overrides[("s3", "get_bucket_location")] = [
        {"LocationConstraint": location}
    ]
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_experiment(LIFECYCLE, values, aws, dry_run=False)
    # Refused before any bucket read, location read or write.
    assert s3_calls(aws) == []
    assert mutation_calls(aws) == []


def owner_bound_s3_in_forward_dispatch(aws):
    """An admitted live owner inside its forward dispatch, with an owned S3 proxy."""
    owner = make_experiment(
        framework.ChaosType.EC2_REBOOT,
        action_configs()[framework.ChaosType.EC2_REBOOT],
        aws,
        dry_run=False,
    )
    owner._sdk_request_authority.execution = owner._execution_grant
    owner._sdk_request_authority.phase = "forward"
    aws.calls.clear()
    return owner, owner.client("s3")


@pytest.mark.parametrize(
    "response",
    [
        FakeClientError("AccessDenied"),
        {"LocationConstraint": "not-a-region"},
        [],
        {"LocationConstraint": "us-gov-east-1"},
        {"LocationConstraint": None},
    ],
)
def test_s3_lifecycle_location_errors_fail_closed(response, monkeypatch):
    # The owner-bound location read still guards every S3 write that is
    # admitted. Every owner-bound S3 write is now also denied at the proxy, so
    # this test-only path lifts that one denial to reach the location guard;
    # test_s3_encryption_delete_is_denied_before_the_location_read covers the
    # production deny list.
    monkeypatch.setattr(
        framework,
        "CONCURRENCY_UNSAFE_MUTATIONS",
        framework.CONCURRENCY_UNSAFE_MUTATIONS - {"s3.delete_bucket_encryption"},
    )
    aws = FakeAWS(reject_writes=False)
    owner, s3 = owner_bound_s3_in_forward_dispatch(aws)
    original = aws.respond

    def respond(service, operation, request):
        if operation == "get_bucket_location":
            aws.calls.append((service, operation, request))
            if isinstance(response, Exception):
                raise response
            return response
        return original(service, operation, request)

    aws.respond = respond
    with pytest.raises((framework.SafetyViolation, FakeClientError)):
        s3.delete_bucket_encryption(Bucket=BUCKET)
    assert s3_calls(aws) == [
        ("get_bucket_location", {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT_ID})
    ]
    assert owner.mutation_attempts == []
    assert mutation_calls(aws) == []


def test_s3_encryption_delete_is_denied_before_the_location_read():
    assert "s3.delete_bucket_encryption" in framework.CONCURRENCY_UNSAFE_MUTATIONS
    aws = FakeAWS(reject_writes=False)
    owner, s3 = owner_bound_s3_in_forward_dispatch(aws)
    with pytest.raises(framework.SafetyViolation, match="conditional ownership"):
        s3.delete_bucket_encryption(Bucket=BUCKET)
    assert s3_calls(aws) == []
    assert owner.mutation_attempts == []
    assert mutation_calls(aws) == []


@pytest.mark.parametrize(
    ("region", "location"),
    [(REGION, REGION), ("us-east-1", None), ("us-east-1", ""), ("eu-west-1", "EU")],
)
def test_matching_region_and_owner_plan_the_lifecycle_without_writes(region, location):
    values, aws = lifecycle_values(region, FakeAWS(reject_writes=True))
    aws.read_overrides[("s3", "get_bucket_location")] = [
        {"LocationConstraint": location}
    ]
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_experiment(LIFECYCLE, values, aws, dry_run=False)
    experiment = make_experiment(LIFECYCLE, values, aws, dry_run=True)
    aws.calls.clear()
    result = experiment.modify_lifecycle(BUCKET, 1, values["prefix"])
    assert result.status == "completed", result.errors
    owner = {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT_ID}
    assert s3_calls(aws) == [("get_bucket_lifecycle_configuration", owner)]
    assert experiment.mutation_attempts == []
    assert experiment.mutation_operations == []


class OfflineBody:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def stream(self, **_kwargs: Any):
        yield self.body


REDIRECT_XML = (
    b"<Error><Code>PermanentRedirect</Code><Message>redirect</Message></Error>"
)


@pytest.mark.parametrize("redirect", [True, False])
def test_botocore_region_redirect_of_lifecycle_write_is_refused(monkeypatch, redirect):
    """A real botocore client, answered locally before any network send."""
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    session = boto3.Session(
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
        aws_session_token="offline",
        region_name=REGION,
    )
    controller = framework.SafetyController(
        {}, session, REGION, True, expected_account=ACCOUNT_ID
    )
    # The signing guard is installed on the cached SDK client itself, so it
    # also binds S3 writes that do not pass through an experiment owner.
    raw = controller.client("s3")._client
    sent: list[tuple[str, str]] = []

    def offline(request, **_kwargs):
        url = urlsplit(request.url)
        sent.append((request.method, url.netloc))
        if request.method == "PUT" and url.query == "lifecycle":
            if redirect:
                headers = {"x-amz-bucket-region": "us-gov-east-1"}
                return AWSResponse(request.url, 301, headers, OfflineBody(REDIRECT_XML))
            return AWSResponse(request.url, 200, {}, OfflineBody(b""))
        raise AssertionError(f"Unexpected offline request {request.method} {url}")

    raw.meta.events.register("before-send.s3", offline)
    request = {
        "Bucket": BUCKET,
        "ExpectedBucketOwner": ACCOUNT_ID,
        "LifecycleConfiguration": {
            "Rules": [
                {
                    "ID": framework.S3_LIFECYCLE_RULE_ID,
                    "Status": "Enabled",
                    "Filter": {"Prefix": "chaos-test/"},
                    "Expiration": {"Days": 1},
                }
            ]
        },
    }
    if redirect:
        with pytest.raises(framework.SafetyViolation, match="redirected"):
            raw.put_bucket_lifecycle_configuration(**request)
    else:
        raw.put_bucket_lifecycle_configuration(**request)
    puts = [host for method, host in sent if method == "PUT"]
    assert all("us-gov-east-1" not in host for _method, host in sent)
    assert len(puts) == 1
