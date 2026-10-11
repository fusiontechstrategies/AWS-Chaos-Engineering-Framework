"""Offline regressions for the provider-deleted EFS network interface."""

from __future__ import annotations

import copy

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    REGION,
    FakeAWS,
    FakeSafetyController,
    action_configs,
    make_experiment,
    make_orchestrator,
)
from test_final_cloud_six_controls import (
    MOUNT_TARGET,
    mount_target,
    mutation_calls,
    run_handler,
    scoped_experiment,
)

import aws_chaos_framework as framework

KIND = framework.ChaosType.EFS_MOUNT_TARGET_DELETE
INTERFACE = "eni-0123456789abcdef0"
OTHER_INTERFACE = "eni-0fedcba9876543210"


def test_missing_or_invalid_reviewed_interface_refuses_live_before_sdk():
    for value in (None, "", "eni-wrong", OTHER_INTERFACE.upper()):
        aws = FakeAWS(reject_writes=False)
        config = copy.deepcopy(action_configs()[KIND])
        if value is None:
            del config["network_interface_id"]
        else:
            config["network_interface_id"] = value
        with pytest.raises(framework.ConfigurationError, match="network_interface_id"):
            make_orchestrator(KIND, config, aws, dry_run=False)
        assert mutation_calls(aws) == []


def test_child_is_confirmation_target_and_consumes_second_radius_slot():
    config = {"type": KIND.value, **action_configs()[KIND]}
    assert framework.ChaosOrchestrator._target_values(config) == {
        MOUNT_TARGET,
        INTERFACE,
    }
    assert framework.ChaosOrchestrator._blast_radius(KIND, config) == 2
    for field, value, phrase in (
        ("target_allowlist", [MOUNT_TARGET], "allowlist"),
        ("max_blast_radius", 1, "blast radius"),
    ):
        aws = FakeAWS(reject_writes=False)
        orchestrator = make_orchestrator(
            KIND, action_configs()[KIND], aws, dry_run=False
        )
        orchestrator.config["safety"][field] = value
        with pytest.raises(framework.SafetyViolation, match=phrase):
            orchestrator._validate_target_scope(KIND, config)
        assert mutation_calls(aws) == []


@pytest.mark.parametrize(
    "response",
    [
        mount_target(NetworkInterfaceId=None),
        mount_target(NetworkInterfaceId=OTHER_INTERFACE),
        {"MountTargets": [mount_target()["MountTargets"][0]] * 2},
        mount_target(MountTargetId="fsmt-0fedcba9876543210"),
    ],
)
def test_current_child_or_parent_mismatch_refuses_before_delete(response):
    experiment, aws = scoped_experiment(KIND)
    aws.read_overrides[("efs", "describe_mount_targets")] = [response]
    result = run_handler(KIND, experiment)
    assert result.status == "failed"
    assert "reviewed scope" in " ".join(result.errors)
    assert result.affected_resources == []
    assert mutation_calls(aws) == []


def test_handler_arguments_must_match_reviewed_configuration_before_read():
    experiment, aws = scoped_experiment(KIND)
    result = experiment.delete_mount_target(MOUNT_TARGET, OTHER_INTERFACE)
    assert result.status == "failed"
    assert "immutable approved request" in " ".join(result.errors)
    assert aws.calls == []


def test_live_and_planning_report_both_materially_affected_identifiers():
    live, aws = scoped_experiment(KIND)
    aws.read_overrides[("efs", "describe_mount_targets")] = [mount_target()]
    result = run_handler(KIND, live)
    assert result.status == "completed", result.errors
    assert result.affected_resources == [MOUNT_TARGET, INTERFACE]
    assert mutation_calls(aws) == ["delete_mount_target"]

    plan_aws = FakeAWS(reject_writes=True)
    plan_aws.read_overrides[("efs", "describe_mount_targets")] = [mount_target()]
    plan = make_experiment(KIND, action_configs()[KIND], plan_aws, dry_run=True)
    planned = plan.delete_mount_target(MOUNT_TARGET, INTERFACE)
    assert planned.status == "completed", planned.errors
    assert planned.affected_resources == [MOUNT_TARGET, INTERFACE]
    assert mutation_calls(plan_aws) == []


@pytest.mark.parametrize("configured", [None, "", "eni-wrong"])
def test_direct_planning_rejects_unreviewed_child_before_inventory(configured):
    aws = FakeAWS(reject_writes=True)
    config = {
        "dry_run": True,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "mount_target_id": MOUNT_TARGET,
    }
    if configured is not None:
        config["network_interface_id"] = configured
    plan = framework.EFSChaosExperiment(config, FakeSafetyController(aws))
    result = plan.delete_mount_target(MOUNT_TARGET, configured)
    assert result.status == "failed"
    assert "network_interface_id" in " ".join(result.errors)
    assert aws.calls == []
    assert result.affected_resources == []


@pytest.mark.parametrize("response_child", [None, ""])
def test_direct_planning_rejects_missing_response_child(response_child):
    aws = FakeAWS(reject_writes=True)
    config = {
        "dry_run": True,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "mount_target_id": MOUNT_TARGET,
        "network_interface_id": INTERFACE,
    }
    plan = framework.EFSChaosExperiment(config, FakeSafetyController(aws))
    aws.read_overrides[("efs", "describe_mount_targets")] = [
        mount_target(NetworkInterfaceId=response_child)
    ]
    result = plan.delete_mount_target(MOUNT_TARGET, INTERFACE)
    assert result.status == "failed"
    assert "reviewed scope" in " ".join(result.errors)
    assert mutation_calls(aws) == []
    assert result.affected_resources == []
