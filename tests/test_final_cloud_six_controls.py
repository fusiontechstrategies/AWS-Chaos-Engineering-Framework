"""Ordinary sequential models for final Cloud source controls; no AWS calls."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    INSTANCE_ID,
    REGION,
    VOLUME_ID,
    FakeAWS,
    action_configs,
    make_experiment,
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
