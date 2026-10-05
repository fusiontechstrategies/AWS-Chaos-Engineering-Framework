"""Ordinary sequential admission controls for withdrawn route/EBS live APIs."""

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    REGION,
    FakeAWS,
    FakeSafetyController,
    action_configs,
    make_experiment,
)

import aws_chaos_framework as framework

CASES = (
    (
        framework.ChaosType.VPC_ROUTE_TABLE_MODIFY,
        framework.VPCChaosExperiment,
        "modify_route_table",
    ),
    (
        framework.ChaosType.EBS_DETACH_VOLUME,
        framework.EBSChaosExperiment,
        "detach_volume",
    ),
)


@pytest.mark.parametrize("kind,cls,method", CASES)
def test_route_and_ebs_live_admission_refuses_before_effects(kind, cls, method):
    aws = FakeAWS()
    values = action_configs()[kind]
    assert not framework.experiment_metadata(kind).live_supported
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_experiment(kind, values, aws, dry_run=False)
    assert aws.calls == []
    plan = make_experiment(kind, values, aws, dry_run=True)
    result = getattr(plan, method)(**values)
    assert result.status == "completed"
    assert plan.dry_run and not plan.mutation_attempts and not plan.rollback_attempts
    assert all(
        operation in framework.READ_ONLY_OPERATIONS.get(service, ())
        for service, operation, _ in aws.calls
    )
    before = list(aws.calls)
    plan.run_rollback()
    assert aws.calls == before and not plan.rollback_verified
    assert all(
        operation in framework.READ_ONLY_OPERATIONS.get(service, ())
        for service, operation, _ in aws.calls[len(before) :]
    )
    assert not plan.mutation_attempts and not plan.rollback_attempts


@pytest.mark.parametrize("kind,cls,method", CASES)
def test_route_and_ebs_standalone_and_historical_recovery_have_no_authority(
    kind, cls, method
):
    aws = FakeAWS()
    values = action_configs()[kind]
    config = {**values, "account_id": ACCOUNT_ID, "region": REGION, "dry_run": False}
    if kind == framework.ChaosType.VPC_ROUTE_TABLE_MODIFY:
        config["original_route_target"] = {"GatewayId": "igw-0123456789abcdef0"}
    else:
        config["original_instance"] = values["attachment"]["instance_id"]
        config["original_device"] = values["attachment"]["device"]
    with pytest.raises(
        framework.SafetyViolation, match="Direct experiment construction is plan-only"
    ):
        cls(config, FakeSafetyController(aws, live=True))
    assert not aws.calls


@pytest.mark.parametrize(
    "kind,operation,sdk_request",
    (
        (
            framework.ChaosType.VPC_ROUTE_TABLE_MODIFY,
            "delete_route",
            {
                "RouteTableId": "rtb-0123456789abcdef0",
                "DestinationCidrBlock": "10.20.0.0/16",
            },
        ),
        (
            framework.ChaosType.VPC_ROUTE_TABLE_MODIFY,
            "create_route",
            {
                "RouteTableId": "rtb-0123456789abcdef0",
                "DestinationCidrBlock": "10.20.0.0/16",
                "GatewayId": "igw-0123456789abcdef0",
            },
        ),
        (
            framework.ChaosType.EBS_DETACH_VOLUME,
            "detach_volume",
            {
                "VolumeId": "vol-0123456789abcdef0",
                "InstanceId": "i-0123456789abcdef0",
                "Device": "/dev/xvdf",
            },
        ),
        (
            framework.ChaosType.EBS_DETACH_VOLUME,
            "attach_volume",
            {
                "VolumeId": "vol-0123456789abcdef0",
                "InstanceId": "i-0123456789abcdef0",
                "Device": "/dev/xvdf",
            },
        ),
    ),
)
def test_route_and_ebs_sdk_forward_and_restore_operations_are_retired(
    kind, operation, sdk_request
):
    aws = FakeAWS()
    plan = make_experiment(kind, action_configs()[kind], aws, dry_run=True)
    before = list(aws.calls)
    assert "ec2." + operation in framework.CONCURRENCY_UNSAFE_MUTATIONS
    with pytest.raises(framework.SafetyViolation):
        getattr(plan.ec2, operation)(**sdk_request)
    assert aws.calls == before
    assert not plan.mutation_attempts and not plan.rollback_attempts
