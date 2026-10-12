"""Offline adversarial regressions for the fb87be0 runtime scan findings."""

import copy
import os
import subprocess
import sys
import time
import tracemalloc
from contextlib import contextmanager, suppress
from pathlib import Path
from unittest.mock import patch

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    INSTANCE_ID,
    REGION,
    VOLUME_ID,
    FakeAWS,
    FakeSafetyController,
    action_configs,
    make_experiment,
    planning_only_experiment,
    prepare_lambda_memory,
)
from test_final_scan_regressions import worker

import aws_chaos_framework as framework

ROOT = Path(__file__).resolve().parents[1]
OTHER_INSTANCE = "i-0fedcba9876543210"
OTHER_VOLUME = "vol-0fedcba9876543210"


def writes(aws):
    return [
        call
        for call in aws.calls
        if call[1] not in framework.READ_ONLY_OPERATIONS.get(call[0], ())
    ]


def termination(aws, expected=None, *, dry_run=False):
    config = {
        "dry_run": dry_run,
        "instance_ids": [INSTANCE_ID],
        "delete_on_termination_volumes": expected or {INSTANCE_ID: [VOLUME_ID]},
    }
    safety = FakeSafetyController(aws, live=not dry_run)
    safety.config["target_allowlist"] = [INSTANCE_ID, VOLUME_ID]
    safety.config["max_blast_radius"] = 2
    return framework.EC2ChaosExperiment(config, safety)


def termination_response(aws):
    response = aws.respond("ec2", "describe_instances", {})
    response["Reservations"][0]["Instances"][0]["BlockDeviceMappings"][0]["Ebs"][
        "DeleteOnTermination"
    ] = True
    return response


@pytest.mark.parametrize(
    "attack",
    [
        "child_allowlist",
        "radius",
        "relationship",
        "missing_relationship",
        "incomplete_flag",
        "extra_instance",
        "duplicate_instance",
    ],
)
def test_termination_refuses_unapproved_or_incomplete_derived_scope(attack):
    aws = FakeAWS(reject_writes=False)
    response = termination_response(aws)
    if attack in {"child_allowlist", "radius"}:
        with pytest.raises(
            framework.SafetyViolation, match="Direct experiment construction"
        ):
            termination(aws, dry_run=False)
        assert not writes(aws)
        return
    item = termination(aws, dry_run=True)
    instance = response["Reservations"][0]["Instances"][0]
    if attack == "child_allowlist":
        item.safety_controller.config["target_allowlist"] = [INSTANCE_ID]
    elif attack == "radius":
        item.safety_controller.config["max_blast_radius"] = 1
    elif attack == "relationship":
        instance["BlockDeviceMappings"][0]["Ebs"]["VolumeId"] = OTHER_VOLUME
    elif attack == "missing_relationship":
        del instance["BlockDeviceMappings"]
    elif attack == "incomplete_flag":
        del instance["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"]
    elif attack in {"extra_instance", "duplicate_instance"}:
        duplicate = copy.deepcopy(instance)
        if attack == "extra_instance":
            duplicate["InstanceId"] = OTHER_INSTANCE
        response["Reservations"][0]["Instances"].append(duplicate)
    aws.read_overrides[("ec2", "describe_instances")] = [
        copy.deepcopy(response),
        response,
    ]
    result = item.terminate_instances([INSTANCE_ID])
    assert result.status == "failed"
    assert not writes(aws)
    assert not item.mutation_attempts


def test_termination_plan_binds_deleted_volumes_in_evidence():
    aws = FakeAWS(reject_writes=False)
    response = termination_response(aws)
    aws.read_overrides[("ec2", "describe_instances")] = [
        copy.deepcopy(response),
        response,
    ]
    item = termination(aws, dry_run=True)
    result = item.terminate_instances([INSTANCE_ID])
    assert result.status == "completed"
    assert set(result.affected_resources) == {INSTANCE_ID, VOLUME_ID}
    assert result.additional_info["delete_on_termination_volumes"] == {
        INSTANCE_ID: [VOLUME_ID]
    }
    assert writes(aws) == []


def test_termination_rechecks_relationship_after_other_baseline_reads():
    aws = FakeAWS(reject_writes=False)
    baseline = termination_response(aws)
    changed = copy.deepcopy(baseline)
    changed["Reservations"][0]["Instances"][0]["BlockDeviceMappings"][0]["Ebs"][
        "VolumeId"
    ] = OTHER_VOLUME
    aws.read_overrides[("ec2", "describe_instances")] = [baseline, changed]
    assert (
        termination(aws, dry_run=True).terminate_instances([INSTANCE_ID]).status
        == "failed"
    )
    assert not writes(aws)


@pytest.mark.parametrize(
    "attack",
    [
        "instance",
        "device",
        "multiple",
        "wrong_volume",
        "allowlist",
        "tuple_allowlist",
        "radius",
        "changed_before_write",
    ],
)
def test_detach_refuses_unapproved_or_changed_attachment(attack):
    aws = FakeAWS(reject_writes=True)
    kind = framework.ChaosType.EBS_DETACH_VOLUME
    config = action_configs()[kind]
    item = planning_only_experiment(kind, config, aws)
    volume = aws.respond("ec2", "describe_volumes", {})
    attachment = volume["Volumes"][0]["Attachments"][0]
    changed = None
    scope = framework.ChaosOrchestrator._target_values({"type": kind.value, **config})
    tuple_target = f"attachment:{INSTANCE_ID}:/dev/xvdf"
    assert scope == {VOLUME_ID, INSTANCE_ID, tuple_target}
    assert framework.ChaosOrchestrator._blast_radius(kind, config) == 2
    if attack == "instance":
        attachment["InstanceId"] = OTHER_INSTANCE
    elif attack == "device":
        attachment["Device"] = "/dev/xvdz"
    elif attack == "multiple":
        volume["Volumes"][0]["Attachments"].append(copy.deepcopy(attachment))
    elif attack == "wrong_volume":
        volume["Volumes"][0]["VolumeId"] = OTHER_VOLUME
    elif attack == "allowlist":
        item.safety_controller.config["target_allowlist"].remove(INSTANCE_ID)
        assert INSTANCE_ID in scope - set(
            item.safety_controller.config["target_allowlist"]
        )
    elif attack == "tuple_allowlist":
        item.safety_controller.config["target_allowlist"].remove(tuple_target)
        assert tuple_target in scope - set(
            item.safety_controller.config["target_allowlist"]
        )
    elif attack == "radius":
        item.safety_controller.config["max_blast_radius"] = 1
        assert (
            framework.ChaosOrchestrator._blast_radius(kind, config)
            > item.safety_controller.config["max_blast_radius"]
        )
    elif attack == "changed_before_write":
        changed = copy.deepcopy(volume)
        changed["Volumes"][0]["Attachments"][0]["InstanceId"] = OTHER_INSTANCE
        changed["Volumes"][0]["MultiAttachEnabled"] = True
    aws.read_overrides[("ec2", "describe_volumes")] = [volume]
    result = item.detach_volume(**config)
    if attack in {"instance", "device", "multiple", "wrong_volume"}:
        assert result.status == "failed" and result.errors
    else:
        # Planning computes scope; it does not grant or reject live authorization.
        assert result.status == "completed"
        assert {item.volume_id, item.original_instance} == {VOLUME_ID, INSTANCE_ID}
        assert item.original_device == "/dev/xvdf"
    if changed is not None:
        aws.read_overrides[("ec2", "describe_volumes")] = [changed]
        later = item.ec2.describe_volumes(VolumeIds=[VOLUME_ID])
        assert later["Volumes"][0]["Attachments"][0]["InstanceId"] == OTHER_INSTANCE
        assert later["Volumes"][0]["MultiAttachEnabled"] is True
        # This is later read-only evidence, not the old live guarded-write interval.
    approval = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    approval["global"].update(account_id=ACCOUNT_ID, region=REGION)
    approval["safety"] = copy.deepcopy(item.safety_controller.config)
    approval["experiment_suites"] = {
        "ordinary": {"experiments": [{"type": kind.value, **config}]}
    }
    framework.validate_config_data(approval)
    before = list(aws.calls)
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        framework.confirmation_token(approval, "ordinary")
    with pytest.raises(
        framework.SafetyViolation, match="Direct experiment construction is plan-only"
    ):
        framework.EBSChaosExperiment(
            {**item.config, "dry_run": False}, item.safety_controller
        )
    for operation in ("detach_volume", "attach_volume"):
        with pytest.raises(framework.SafetyViolation):
            getattr(item.ec2, operation)(
                VolumeId=VOLUME_ID, InstanceId=INSTANCE_ID, Device="/dev/xvdf"
            )
    assert aws.calls == before
    assert not writes(aws)
    assert not item.mutation_attempts and not item.rollback_attempts


def test_detach_write_contains_exact_reviewed_attachment_tuple():
    aws = FakeAWS(reject_writes=True)
    kind = framework.ChaosType.EBS_DETACH_VOLUME
    config = action_configs()[kind]
    item = planning_only_experiment(kind, config, aws)
    result = item.detach_volume(**config)
    assert result.status == "completed"
    assert set(result.affected_resources) == {VOLUME_ID, INSTANCE_ID}
    captured = {
        "VolumeId": item.volume_id,
        "InstanceId": item.original_instance,
        "Device": item.original_device,
    }
    assert captured == {
        "VolumeId": VOLUME_ID,
        "InstanceId": INSTANCE_ID,
        "Device": "/dev/xvdf",
    }
    assert item.config["attachment"] == {
        "instance_id": INSTANCE_ID,
        "device": "/dev/xvdf",
    }
    assert framework.ChaosOrchestrator._blast_radius(kind, config) == 2
    assert writes(aws) == []
    assert not item.mutation_attempts and not item.rollback_attempts


@pytest.mark.parametrize(
    "kind", [framework.ChaosType.EC2_TERMINATE, framework.ChaosType.EBS_DETACH_VOLUME]
)
def test_child_relationship_scope_and_live_token_restrictions(kind):
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    suite = next(iter(config["experiment_suites"]))
    action = {"type": kind.value, **action_configs()[kind]}
    config["experiment_suites"][suite]["experiments"] = [action]
    framework.validate_config_data(config)
    if kind == framework.ChaosType.EC2_TERMINATE:
        original_scope = framework.ChaosOrchestrator._target_values(action)
        with pytest.raises(framework.ConfigurationError):
            framework.confirmation_token(config, suite)
        action["delete_on_termination_volumes"][INSTANCE_ID] = [VOLUME_ID]
        assert framework.ChaosOrchestrator._target_values(action) != original_scope
        with pytest.raises(framework.ConfigurationError):
            framework.confirmation_token(config, suite)
        field = "delete_on_termination_volumes"
    else:
        original_scope = framework.ChaosOrchestrator._target_values(action)
        with pytest.raises(
            framework.ConfigurationError, match="Live approval is unavailable"
        ):
            framework.confirmation_token(config, suite)
        action["attachment"]["device"] = "/dev/xvdz"
        field = "attachment"
        assert framework.ChaosOrchestrator._target_values(action) != original_scope
        assert (
            "attachment:" + INSTANCE_ID + ":/dev/xvdz"
            in framework.ChaosOrchestrator._target_values(action)
        )
        framework.validate_config_data(config)
        with pytest.raises(
            framework.ConfigurationError, match="Live approval is unavailable"
        ):
            framework.confirmation_token(config, suite)
    del action[field]
    with pytest.raises(framework.ConfigurationError, match=field):
        framework.validate_config_data(config)
    with pytest.raises(framework.ConfigurationError):
        framework.confirmation_token(config, suite)


WAIT_CASES = [
    (
        framework.EC2ChaosExperiment,
        "_wait_for_instance_state",
        [[INSTANCE_ID], "stopped"],
        "ec2",
        "describe_instances",
        "Reservations",
        "State",
    ),
    (
        framework.EBSChaosExperiment,
        "_wait_for_volume_state",
        [VOLUME_ID, "available"],
        "ec2",
        "describe_volumes",
        "Volumes",
        "State",
    ),
    (
        framework.EBSChaosExperiment,
        "_wait_for_iops",
        [VOLUME_ID, 100],
        "ec2",
        "describe_volumes",
        "Volumes",
        "Iops",
    ),
    (
        framework.EFSChaosExperiment,
        "_wait_for_throughput",
        ["fs-test", "provisioned", 1.0],
        "efs",
        "describe_file_systems",
        "FileSystems",
        "ProvisionedThroughputInMibps",
    ),
    (
        framework.RDSChaosExperiment,
        "_wait_for_parameters",
        ["group", [{"ParameterName": "max_connections", "ParameterValue": "200"}]],
        "rds",
        "describe_db_parameters",
        "Parameters",
        "ParameterValue",
    ),
    (
        framework.RDSChaosExperiment,
        "_wait_for_cluster_available",
        ["cluster"],
        "rds",
        "describe_db_clusters",
        "DBClusters",
        "Status",
    ),
    (
        framework.RDSChaosExperiment,
        "_wait_for_db_instance_available",
        ["db"],
        "rds",
        "describe_db_instances",
        "DBInstances",
        "DBInstanceStatus",
    ),
    (
        framework.LambdaChaosExperiment,
        "_wait_for_configuration",
        ["fn"],
        "lambda",
        "get_function_configuration",
        None,
        "LastUpdateStatus",
    ),
    (
        framework.ECSChaosExperiment,
        "_wait_for_service_count",
        ["cluster", "service", 0],
        "ecs",
        "describe_services",
        "services",
        "desiredCount",
    ),
    (
        framework.ECSChaosExperiment,
        "_wait_for_container_status",
        ["cluster", "arn", "DRAINING"],
        "ecs",
        "describe_container_instances",
        "containerInstances",
        "status",
    ),
    (
        framework.KinesisChaosExperiment,
        "_wait_for_retention",
        ["stream", 24],
        "kinesis",
        "describe_stream",
        "StreamDescription",
        "RetentionPeriodHours",
    ),
    (
        framework.OpenSearchChaosExperiment,
        "_wait_for_domain_idle",
        ["domain"],
        "opensearch",
        "describe_domain",
        "DomainStatus",
        "Processing",
    ),
    (
        framework.AppStreamChaosExperiment,
        "_wait_for_fleet_state",
        ["fleet", "STOPPED"],
        "appstream",
        "describe_fleets",
        "Fleets",
        "State",
    ),
]


def transition_states(aws, case):
    cls, method, args, service, operation, collection, field = case
    baseline = aws.respond(service, operation, {})
    pending = copy.deepcopy(baseline)
    ready = copy.deepcopy(baseline)

    def leaf(response):
        if collection == "Reservations":
            return response[collection][0]["Instances"][0]
        if collection in {None, "StreamDescription", "DomainStatus"}:
            return response if collection is None else response[collection]
        return response[collection][0]

    desired = {
        "_wait_for_instance_state": "stopped",
        "_wait_for_volume_state": "available",
        "_wait_for_iops": 100,
        "_wait_for_throughput": 1.0,
        "_wait_for_parameters": "200",
        "_wait_for_cluster_available": "available",
        "_wait_for_db_instance_available": "available",
        "_wait_for_configuration": "Successful",
        "_wait_for_service_count": 0,
        "_wait_for_container_status": "DRAINING",
        "_wait_for_retention": 24,
        "_wait_for_domain_idle": False,
        "_wait_for_fleet_state": "STOPPED",
    }[method]
    if method in {"_wait_for_cluster_available", "_wait_for_db_instance_available"}:
        identity_key = (
            "DBClusterIdentifier"
            if method == "_wait_for_cluster_available"
            else "DBInstanceIdentifier"
        )
        leaf(pending)[identity_key] = args[0]
        leaf(ready)[identity_key] = args[0]
        leaf(pending)[field] = "modifying"
    elif method == "_wait_for_configuration":
        leaf(pending)[field] = "InProgress"
        for response in (pending, ready):
            response["FunctionName"] = args[0]
            response["FunctionArn"] = (
                f"arn:aws-us-gov:lambda:{REGION}:{ACCOUNT_ID}:function:{args[0]}"
            )
    elif method == "_wait_for_domain_idle":
        leaf(pending)[field] = True
    if method == "_wait_for_instance_state":
        leaf(ready)[field] = {"Name": desired}
    else:
        leaf(ready)[field] = desired
    if method == "_wait_for_service_count":
        ready["services"][0]["serviceName"] = args[1]
        ready["services"][0].update(
            {
                "runningCount": desired,
                "pendingCount": 0,
                "deployments": [{"rolloutState": "COMPLETED"}],
            }
        )
    return pending, ready


def transition_owner(cls, aws, timeout, *, dry_run=False):
    kinds = {
        framework.EC2ChaosExperiment: framework.ChaosType.EC2_STOP,
        framework.EBSChaosExperiment: framework.ChaosType.EBS_DETACH_VOLUME,
        framework.EFSChaosExperiment: framework.ChaosType.EFS_THROTTLE_THROUGHPUT,
        framework.RDSChaosExperiment: framework.ChaosType.RDS_PARAMETER_GROUP_MODIFY,
        framework.LambdaChaosExperiment: framework.ChaosType.LAMBDA_MEMORY_LIMIT,
        framework.ECSChaosExperiment: framework.ChaosType.ECS_SERVICE_UPDATE,
        framework.KinesisChaosExperiment: framework.ChaosType.KINESIS_RETENTION_MODIFY,
        framework.OpenSearchChaosExperiment: framework.ChaosType.OPENSEARCH_CLUSTER_CONFIG_MODIFY,
        framework.AppStreamChaosExperiment: framework.ChaosType.APPSTREAM_FLEET_STOP,
    }
    kind = kinds[cls]
    return make_experiment(
        kind,
        {**action_configs()[kind], "state_timeout_seconds": timeout},
        aws,
        dry_run=dry_run,
    )


@pytest.mark.parametrize("case", WAIT_CASES, ids=lambda case: case[1])
def test_every_forward_transition_polls_alarm_changes_and_stops_promptly(
    case, monkeypatch
):
    cls, method, args, service, operation, _collection, _field = case
    aws = FakeAWS()
    pending, _ready = transition_states(aws, case)
    withdrawn = cls in {
        framework.EC2ChaosExperiment,
        framework.EBSChaosExperiment,
        framework.EFSChaosExperiment,
        framework.RDSChaosExperiment,
        framework.ECSChaosExperiment,
        framework.AppStreamChaosExperiment,
        framework.OpenSearchChaosExperiment,
        framework.KinesisChaosExperiment,
    }
    if withdrawn:
        # Original service data/args still exercise its read-only planning waiter.
        item = transition_owner(cls, aws, 10, dry_run=True)
        aws.read_overrides[(service, operation)] = [
            copy.deepcopy(pending) for _ in range(3)
        ]
        plan_clock = [0.0]
        plan_waits = []

        def plan_sleep(seconds):
            plan_waits.append(seconds)
            plan_clock[0] += seconds

        with (
            patch.object(framework.time, "monotonic", lambda: plan_clock[0]),
            patch.object(framework.time, "sleep", plan_sleep),
            pytest.raises(TimeoutError),
        ):
            getattr(item, method)(*args, False)
        assert plan_waits and all(0 < seconds <= 10 for seconds in plan_waits)
        assert sum(plan_waits) == plan_clock[0] == 10
        assert (
            item.dry_run and not item.mutation_attempts and not item.rollback_attempts
        )
        assert not writes(aws)
        # Shared forward safety is separately exercised by a supported public
        # conditional Lambda configuration owner, not the withdrawn service.
        live_aws = FakeAWS()
        kind = framework.ChaosType.LAMBDA_MEMORY_LIMIT
        values = action_configs()[kind]
        item = make_experiment(
            kind, {**values, "state_timeout_seconds": 60}, live_aws, dry_run=False
        )
        pending_memory = live_aws.respond("lambda", "get_function_configuration", {})
        pending_memory["LastUpdateStatus"] = "InProgress"
        live_aws.read_overrides[("lambda", "get_function_configuration")] = [
            pending_memory
        ]
        monitor_method, monitor_args = (
            "_wait_for_configuration",
            [values["function_name"]],
        )
    else:
        live_aws = aws
        aws.read_overrides[(service, operation)] = [pending]
        item = transition_owner(cls, aws, 60)
        monitor_method, monitor_args = method, args
    safety = item.safety_controller
    safety.config["monitor_interval_seconds"] = 5
    clock = [0.0]
    alarm = [False]
    polls = []
    waits = []
    monkeypatch.setattr(framework.time, "monotonic", lambda: clock[0])

    def wait(seconds):
        waits.append(seconds)
        clock[0] += seconds
        alarm[0] = True
        return False

    safety.emergency_stop.wait = wait
    safety.check_safety_conditions = lambda: (
        polls.append(alarm[0])
        or (not alarm[0], ["Synthetic alarm entered ALARM"] if alarm[0] else [])
    )
    with pytest.raises(framework.EmergencyStop, match="Runtime safety"):
        getattr(item, monitor_method)(*monitor_args, True)
    assert polls[-1] is True and False in polls
    assert waits and max(waits) <= 5
    assert safety.emergency_stop.is_set()
    assert not writes(aws)
    assert not writes(live_aws)


@pytest.mark.parametrize("case", WAIT_CASES, ids=lambda case: case[1])
def test_every_recovery_transition_ignores_stop_event_and_safety_alarm(case):
    cls, method, args, service, operation, _collection, _field = case
    aws = FakeAWS()
    _pending, ready = transition_states(aws, case)
    withdrawn = cls in {
        framework.EC2ChaosExperiment,
        framework.EBSChaosExperiment,
        framework.EFSChaosExperiment,
        framework.RDSChaosExperiment,
        framework.ECSChaosExperiment,
        framework.AppStreamChaosExperiment,
        framework.OpenSearchChaosExperiment,
        framework.KinesisChaosExperiment,
    }
    item = transition_owner(cls, aws, 10, dry_run=withdrawn)
    if withdrawn:
        # Real owned conditional recovery retains the shared stop exemption.
        live_aws = FakeAWS(reject_writes=False)
        values = prepare_lambda_memory(live_aws)
        memory = make_experiment(
            framework.ChaosType.LAMBDA_MEMORY_LIMIT, values, live_aws, dry_run=False
        )
        assert memory.modify_memory_limit(**values).status == "completed"
        memory.safety_controller.emergency_stop.set()
        memory.safety_controller.check_safety_conditions = lambda: (
            _ for _ in ()
        ).throw(AssertionError("Recovery must not poll forward guards"))
        memory.run_rollback()
        assert memory.rollback_verified
        requests = [
            request
            for _, op, request in live_aws.calls
            if op == "update_function_configuration"
        ]
        assert [request["RevisionId"] for request in requests] == [
            "memory-original-revision",
            "memory-owned-revision",
        ]
        assert memory.mutation_attempts == ["lambda.update_function_configuration"]
        assert memory.rollback_attempts == ["lambda.update_function_configuration"]
        assert (
            item.dry_run and not item.mutation_attempts and not item.rollback_attempts
        )
    aws.read_overrides[(service, operation)] = [ready]
    safety = item.safety_controller
    safety.emergency_stop.set()
    safety.check_safety_conditions = lambda: (_ for _ in ()).throw(
        AssertionError("Recovery must not poll forward guards")
    )
    getattr(item, method)(*args, False)
    assert not writes(aws)


@pytest.mark.parametrize(
    "kind,operation,key",
    [
        (
            framework.ChaosType.VPC_SUBNET_ACL_MODIFY,
            "describe_network_acls",
            "NetworkAcls",
        ),
        (
            framework.ChaosType.ELB_HEALTH_CHECK_MODIFY,
            "describe_target_groups",
            "TargetGroups",
        ),
        (framework.ChaosType.ELB_LISTENER_RULE_MODIFY, "describe_rules", "Rules"),
    ],
)
@pytest.mark.parametrize("attack", ["empty", "duplicate", "wrong", "missing_child"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_absent_duplicate_wrong_or_incomplete_targets_never_complete(
    kind, operation, key, attack, dry_run
):
    aws = FakeAWS(reject_writes=dry_run)
    service = "ec2" if kind == framework.ChaosType.VPC_SUBNET_ACL_MODIFY else "elbv2"
    response = aws.respond(service, operation, {})
    entry = response[key][0]
    if attack == "empty":
        response[key] = []
    elif attack == "duplicate":
        response[key].append(copy.deepcopy(entry))
    elif kind == framework.ChaosType.VPC_SUBNET_ACL_MODIFY:
        if attack == "wrong":
            entry["Associations"][0]["SubnetId"] = "subnet-other"
        else:
            entry["Associations"] = []
    elif kind == framework.ChaosType.ELB_LISTENER_RULE_MODIFY:
        if attack == "wrong":
            entry["RuleArn"] = "wrong"
        else:
            entry["Actions"] = []
    elif attack == "wrong":
        entry["TargetGroupArn"] = "wrong"
    else:
        del entry["TargetGroupArn"]
    aws.read_overrides[(service, operation)] = [response]
    config = action_configs()[kind]
    if kind in {
        framework.ChaosType.ELB_LISTENER_RULE_MODIFY,
        framework.ChaosType.ELB_HEALTH_CHECK_MODIFY,
    }:
        item = planning_only_experiment(kind, config, aws)
    else:
        item = make_experiment(kind, config, aws, dry_run=dry_run)
    result = object.__new__(framework.ChaosOrchestrator)._execute_experiment(
        item, kind, config
    )
    assert result.status == "failed"
    assert not writes(aws)
    assert not item.mutation_attempts


def test_orchestrator_refuses_live_no_write_completion():
    aws = FakeAWS()
    values = prepare_lambda_memory(aws)
    item = worker(aws, framework.ChaosType.LAMBDA_MEMORY_LIMIT, values)
    item._execute_experiment = lambda *_: framework.ExperimentResult(
        "synthetic",
        framework.ChaosType.LAMBDA_MEMORY_LIMIT,
        framework.utc_now(),
        status="completed",
        affected_resources=[values["function_name"]],
    )
    result = item._run_single_experiment({"type": "lambda_memory_limit", **values})
    assert result.status == "failed"
    assert "mutation attempt" in result.errors[0]
    assert not writes(aws)


@pytest.mark.parametrize("dry_run", [True, False])
def test_subnet_no_change_cannot_produce_a_fault_completion(dry_run):
    aws = FakeAWS(reject_writes=dry_run)
    config = {
        "subnet_id": "subnet-0123456789abcdef0",
        "nacl_id": "acl-0123456789abcdef0",
        "original_nacl_id": "acl-0123456789abcdef0",
    }
    item = make_experiment(
        framework.ChaosType.VPC_SUBNET_ACL_MODIFY, config, aws, dry_run=dry_run
    )
    assert item.modify_subnet_acl(**config).status == "failed"
    assert not writes(aws)


@pytest.mark.parametrize(
    "text",
    [
        "safety: {}\nsafety: {}\n",
        "experiment_suites: {}\nexperiment_suites: {}\n",
        "safety:\n  target_allowlist: [benign]\n  target_allowlist: [other]\n",
        "experiment:\n  instance_ids: [benign]\n  instance_ids: [other]\n",
        "safety:\n  allow_irreversible: false\n  allow_irreversible: true\n",
        "x: &anchor {target: benign}\ny: {<<: *anchor, target: other}\n",
        "x: {<<: {target: benign}, target: other}\n",
        "x: &anchor [benign]\ny: *anchor\n",
    ],
)
def test_yaml_duplicate_nested_merge_and_alias_inputs_are_rejected_before_mapping_use(
    text, tmp_path
):
    config = tmp_path / "synthetic.yaml"
    config.write_text(text, encoding="utf-8")
    with pytest.raises(
        framework.ConfigurationError, match="Invalid YAML configuration at line"
    ):
        framework.load_yaml_config(str(config))


@pytest.mark.parametrize(
    "key", ["password", "token", "external_id", "aws_secret_access_key"]
)
def test_yaml_secret_parser_lines_never_reach_exception_or_cli_diagnostics(
    key, tmp_path
):
    secret = "SYNTHETIC_PRIVATE_VALUE_0123456789"
    config = tmp_path / "invalid.yaml"
    config.write_text(f"{key}: [{secret}\n", encoding="utf-8")
    with pytest.raises(framework.ConfigurationError) as error:
        framework.load_yaml_config(str(config))
    assert secret not in str(error.value)
    assert error.value.__suppress_context__
    process = subprocess.run(
        [
            sys.executable,
            str(ROOT / "aws_chaos_framework.py"),
            "--validate-config",
            str(config),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert process.returncode != 0
    assert secret not in process.stdout + process.stderr
    assert "line 2" in process.stderr


@pytest.mark.parametrize(
    "kind",
    sorted(framework.CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS, key=lambda kind: kind.value),
)
def test_concurrency_unsafe_types_plan_but_cannot_obtain_live_approval_or_mutate(kind):
    config = action_configs()[kind]
    planned_aws = FakeAWS()
    planned = make_experiment(kind, config, planned_aws)
    dispatch = object.__new__(framework.ChaosOrchestrator)
    assert dispatch._execute_experiment(planned, kind, config).status == "completed"
    assert not writes(planned_aws)
    live_aws = FakeAWS(reject_writes=False)
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_experiment(kind, config, live_aws, dry_run=False)
    assert not writes(live_aws)
    suite_config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    suite_config["global"]["account_id"] = ACCOUNT_ID
    suite = next(iter(suite_config["experiment_suites"]))
    suite_config["experiment_suites"][suite]["experiments"] = [
        {"type": kind.value, **config}
    ]
    with pytest.raises(framework.ConfigurationError, match="ownership proof"):
        framework.confirmation_token(suite_config, suite)
    assert not framework.experiment_metadata(kind).live_supported


@pytest.mark.parametrize("operation", sorted(framework.CONCURRENCY_UNSAFE_MUTATIONS))
@pytest.mark.parametrize("rollback", [False, True])
def test_direct_forward_or_legacy_cleanup_cannot_clobber_concurrent_state(
    operation, rollback
):
    aws = FakeAWS(reject_writes=False)
    owner = make_experiment(
        framework.ChaosType.EC2_REBOOT,
        action_configs()[framework.ChaosType.EC2_REBOOT],
        aws,
        dry_run=False,
    )
    owner.expected_account = ACCOUNT_ID
    owner._in_rollback = rollback
    service, method = operation.split(".")
    current = {"concurrent_principal": "must remain unchanged"}
    original = copy.deepcopy(current)
    proxy = owner.client(service)
    with pytest.raises(framework.SafetyViolation, match="active approved handler"):
        request = (
            {"Bucket": "owned-test-bucket"}
            if service == "s3"
            else {"SyntheticState": current}
        )
        if service == "lambda":
            request["FunctionName"] = "chaos-test-function"
        getattr(proxy, method)(**request)
    assert current == original
    assert not aws.calls
    assert not owner.mutation_attempts and not owner.rollback_attempts


@pytest.mark.parametrize(
    "response",
    [
        [],
        [{"InstanceId": INSTANCE_ID, "State": {"Name": "running"}}],
        [{"InstanceId": OTHER_INSTANCE, "State": {"Name": "running"}}],
    ],
)
def test_incomplete_ec2_recovery_blocks_later_live_work(response):
    # EC2 stop/start is planning-only. Retain exact two-instance collection
    # verification independently from the supported conditional recovery latch.
    targets = [INSTANCE_ID, OTHER_INSTANCE]
    aws = FakeAWS(reject_writes=True)
    values = {"instance_ids": targets}
    before = list(aws.calls)
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_experiment(framework.ChaosType.EC2_STOP, values, aws, dry_run=False)
    assert aws.calls == before
    item = make_experiment(framework.ChaosType.EC2_STOP, values, aws, dry_run=True)
    assert item.dry_run
    selected = {"InstanceId": INSTANCE_ID, "State": {"Name": "running"}}
    invalid_collections = [
        response,
        [selected, copy.deepcopy(selected)],
        [selected, {"InstanceId": "i-01112223334445556", "State": {"Name": "running"}}],
        [selected],
    ]
    for instances in invalid_collections:
        aws.read_overrides[("ec2", "describe_instances")] = [
            {"Reservations": [{"Instances": copy.deepcopy(instances)}]},
            {"Reservations": [{"Instances": copy.deepcopy(instances)}]},
        ]
        with pytest.raises(
            framework.SafetyViolation, match="exact selected instance set"
        ):
            item._instance_states(targets)
        with pytest.raises(
            framework.SafetyViolation, match="exact selected instance set"
        ):
            item._wait_for_instance_state(targets, "running", False)
        assert not writes(aws)
        assert not item.mutation_attempts and not item.rollback_attempts
        assert not item.rollback_verified

    pending = [{"InstanceId": value, "State": {"Name": "pending"}} for value in targets]
    aws.read_overrides[("ec2", "describe_instances")] = [
        {"Reservations": [{"Instances": copy.deepcopy(pending)}]},
        {"Reservations": [{"Instances": copy.deepcopy(pending)}]},
    ]
    assert item._instance_states(targets) == dict.fromkeys(targets, "pending")
    with (
        patch.object(framework.time, "monotonic", side_effect=[0.0, 1.0, 2.0, 601.0]),
        patch.object(framework.time, "sleep") as sleep,
        pytest.raises(TimeoutError, match="Timed out waiting for EC2 state running"),
    ):
        item._wait_for_instance_state(targets, "running", False)
    sleep.assert_called_once_with(5.0)
    assert all(
        request["InstanceIds"] == targets
        for _, op, request in aws.calls
        if op == "describe_instances"
    )
    assert not writes(aws)
    assert not item.mutation_attempts and not item.rollback_attempts
    assert not item.rollback_verified

    # A genuine public Lambda memory lifecycle supplies both conditional writes;
    # an ordinary unsuccessful recovery response must latch later live work.
    aws = FakeAWS(reject_writes=False)
    values = {**prepare_lambda_memory(aws), "auto_rollback": True}
    snapshots = aws.read_overrides[("lambda", "get_function_configuration")]
    snapshots[3] = {**snapshots[3], "LastUpdateStatus": "Failed"}
    orchestrator = worker(aws, framework.ChaosType.LAMBDA_MEMORY_LIMIT, values)
    result = orchestrator._run_single_experiment(
        {"type": "lambda_memory_limit", **values}
    )
    assert result.status == "failed" and result.rollback_successful is False
    assert result.rollback_errors == ["Lambda configuration update failed"]
    assert result.mutation_attempts == ["lambda.update_function_configuration"]
    assert result.rollback_attempts == ["lambda.update_function_configuration"]
    requests = [
        request for _, op, request in aws.calls if op == "update_function_configuration"
    ]
    assert requests == [
        {
            "FunctionName": values["function_name"],
            "MemorySize": 128,
            "RevisionId": "memory-original-revision",
        },
        {
            "FunctionName": values["function_name"],
            "MemorySize": 256,
            "RevisionId": "memory-owned-revision",
        },
    ]
    assert framework._LIVE_RECOVERY_BLOCKED.is_set()
    assert orchestrator.safety_controller.emergency_stop.is_set()
    before = list(aws.calls)
    with pytest.raises(framework.EmergencyStop, match="Process-wide emergency stop"):
        worker(
            aws, framework.ChaosType.LAMBDA_MEMORY_LIMIT, values
        )._run_single_experiment({"type": "lambda_memory_limit", **values})
    assert aws.calls == before


@pytest.mark.parametrize("attack", ["changed_association", "unconfirmed_forward"])
def test_nacl_conditional_association_recovery_never_reverses_external_change(attack):
    aws = FakeAWS(reject_writes=False)
    config = action_configs()[framework.ChaosType.VPC_SUBNET_ACL_MODIFY]
    item = make_experiment(
        framework.ChaosType.VPC_SUBNET_ACL_MODIFY, config, aws, dry_run=False
    )
    item.original_association_id = "aclassoc-original"
    item.original_nacl_id = "acl-original"
    item.subnet_id = config["subnet_id"]
    item.applied_nacl_id = config["nacl_id"]
    if attack == "changed_association":
        item.current_association_id = "aclassoc-owned"
    before = list(aws.calls)
    with pytest.raises(framework.SafetyViolation):
        item.run_rollback()
    assert not writes(aws)
    if attack == "unconfirmed_forward":
        assert aws.calls == before


def test_yaml_composition_rejects_deep_and_high_node_inputs_before_construction(
    tmp_path,
):
    path = tmp_path / "bounded.yaml"
    deep = "\n".join("  " * depth + "child:" for depth in range(70)) + "\n"
    broad = "root:\n" + "  - [" + ", ".join(["x"] * 100) + "]\n"
    path.write_text(deep, encoding="utf-8")
    assert path.stat().st_size < framework.MAX_CONFIG_BYTES
    with pytest.raises(framework.ConfigurationError, match="nesting exceeds"):
        framework.load_yaml_config(str(path))
    path.write_text("root:\n" + broad.split("\n", 1)[1] * 101, encoding="utf-8")
    assert path.stat().st_size < framework.MAX_CONFIG_BYTES
    tracemalloc.start()
    started = time.perf_counter()
    try:
        with pytest.raises(framework.ConfigurationError, match="node count exceeds"):
            framework.load_yaml_config(str(path))
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert elapsed < 20
    assert peak < 128 * 1024 * 1024


def test_yaml_composition_accepts_documented_width_and_rejects_scalar_budgets(tmp_path):
    path = tmp_path / "bounded.yaml"
    items = ["x"] * framework.MAX_CONFIG_COLLECTION_WIDTH
    path.write_text("root: [" + ", ".join(items) + "]\n", encoding="utf-8")
    assert framework.load_yaml_config(str(path))["root"] == items
    for scalar, message in (
        ("x" * (framework.MAX_CONFIG_SCALAR_CHARS + 1), "scalar exceeds"),
        ("9" * (framework.MAX_CONFIG_NUMERIC_CHARS + 1), "number exceeds"),
        ("! " + "9" * (framework.MAX_CONFIG_NUMERIC_CHARS + 1), "number exceeds"),
        ("!!int " + "9" * (framework.MAX_CONFIG_NUMERIC_CHARS + 1), "number exceeds"),
    ):
        path.write_text("root: " + scalar + "\n", encoding="utf-8")
        with pytest.raises(framework.ConfigurationError, match=message):
            framework.load_yaml_config(str(path))


def test_yaml_composition_accepts_maximum_node_count_and_supported_depth(tmp_path):
    path = tmp_path / "bounded.yaml"
    groups = ["  - [" + ", ".join(["x"] * 100) + "]\n"] * 98
    groups.append("  - [" + ", ".join(["x"] * 98) + "]\n")
    path.write_text("root:\n" + "".join(groups), encoding="utf-8")
    assert path.stat().st_size < framework.MAX_CONFIG_BYTES
    assert (
        sum(len(group) for group in framework.load_yaml_config(str(path))["root"])
        == 9898
    )
    nested = "\n".join("  " * depth + f"key{depth}:" for depth in range(62))
    path.write_text(nested + "\n" + "  " * 62 + "leaf: 1\n", encoding="utf-8")
    assert isinstance(framework.load_yaml_config(str(path)), dict)


def test_yaml_composition_accepts_mapping_scalar_and_numeric_maxima(tmp_path):
    path = tmp_path / "bounded.yaml"
    entries = [
        f"key{index}: x" for index in range(framework.MAX_CONFIG_COLLECTION_WIDTH)
    ]
    path.write_text("\n".join(entries) + "\n", encoding="utf-8")
    assert len(framework.load_yaml_config(str(path))) == len(entries)
    scalar = "x" * framework.MAX_CONFIG_SCALAR_CHARS
    path.write_text("root: " + scalar + "\n", encoding="utf-8")
    assert framework.load_yaml_config(str(path))["root"] == scalar
    number = "9" * framework.MAX_CONFIG_NUMERIC_CHARS
    path.write_text("root: " + number + "\n", encoding="utf-8")
    assert framework.load_yaml_config(str(path))["root"] == int(number)


@pytest.mark.parametrize("scalar", ("!!int _", "!!int __", "!!float _"))
def test_yaml_malformed_numeric_constructor_is_source_free(tmp_path, scalar):
    path = tmp_path / "bounded.yaml"
    path.write_text("root: " + scalar + "\n", encoding="utf-8")
    with pytest.raises(framework.ConfigurationError) as captured:
        framework.load_yaml_config(str(path))
    assert "Invalid YAML configuration" in str(captured.value)
    assert "root:" not in str(captured.value)
    assert captured.value.__cause__ is None


def test_config_bounded_reader_uses_only_retained_descriptor(tmp_path):
    original = tmp_path / "original.yaml"
    selected = tmp_path / "selected.yaml"
    original.write_bytes(b"root: original\n")
    selected.write_bytes(b"root: replacement\n")

    @contextmanager
    def original_descriptor(_path):
        descriptor = os.open(original, os.O_RDONLY)
        try:
            yield descriptor
        finally:
            os.close(descriptor)

    with patch.object(framework, "_config_descriptor", original_descriptor):
        assert framework._read_config_bytes(selected) == b"root: original\n"


def test_config_path_replacement_after_open_reads_original_or_fails_closed(tmp_path):
    selected = tmp_path / "selected.yaml"
    replacement = tmp_path / "replacement.yaml"
    selected.write_text("root: original\n", encoding="utf-8")
    replacement.write_text("root: replacement\n", encoding="utf-8")
    real_fstat = framework.os.fstat
    attempted = False

    def switch_after_open(descriptor):
        nonlocal attempted
        if not attempted:
            attempted = True
            with suppress(PermissionError):
                os.replace(replacement, selected)
        return real_fstat(descriptor)

    with patch.object(framework.os, "fstat", switch_after_open):
        result = framework.load_yaml_config(str(selected))
    assert attempted
    assert result == {"root": "original"}


def test_config_bounded_reader_refuses_growth_after_admission(tmp_path):
    path = tmp_path / "growing.yaml"
    path.write_bytes(b"root: ok\n")
    original_read = framework.os.read
    calls = 0

    def growing_read(descriptor, size):
        nonlocal calls
        calls += 1
        if calls == 1:
            with path.open("ab") as output:
                output.write(b"x" * framework.MAX_CONFIG_BYTES)
        return original_read(descriptor, size)

    with (
        patch.object(framework.os, "read", growing_read),
        pytest.raises(framework.ConfigurationError, match="byte budget"),
    ):
        framework.load_yaml_config(str(path))
    assert calls > 1


def test_config_path_symlink_is_rejected_when_supported(tmp_path):
    target = tmp_path / "target.yaml"
    link = tmp_path / "link.yaml"
    target.write_text(framework.SAMPLE_CONFIG, encoding="utf-8")
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this host")
    with pytest.raises(framework.ConfigurationError):
        framework.load_yaml_config(str(link))
    with (
        patch.object(
            framework.boto3, "Session", side_effect=AssertionError("admission bypassed")
        ),
        pytest.raises(framework.ConfigurationError),
    ):
        framework.ChaosOrchestrator(str(link))
    assert framework.main(["--validate-config", str(link)]) == 2


def test_config_directory_reparse_or_symlink_is_rejected_when_supported(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "config.yaml").write_text(framework.SAMPLE_CONFIG, encoding="utf-8")
    link = tmp_path / "directory-link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory link creation is unavailable on this host")
    with pytest.raises(framework.ConfigurationError):
        framework.load_yaml_config(str(link / "config.yaml"))
    assert framework.main(["--validate-config", str(link / "config.yaml")]) == 2


def test_config_ancestor_rebinding_during_acquisition_reads_pinned_tree(tmp_path):
    selected = tmp_path / "selected"
    moved = tmp_path / "moved"
    attacker = tmp_path / "attacker"
    selected.mkdir()
    attacker.mkdir()
    (selected / "config.yaml").write_text("root: original\n", encoding="utf-8")
    (attacker / "config.yaml").write_text("root: replacement\n", encoding="utf-8")
    attempted = False
    if os.name == "posix":
        real_open = framework.os.open

        def switch_before_file_open(name, flags, *args, **kwargs):
            nonlocal attempted
            if name == "config.yaml" and kwargs.get("dir_fd") is not None:
                attempted = True
                selected.rename(moved)
                selected.symlink_to(attacker, target_is_directory=True)
            return real_open(name, flags, *args, **kwargs)

        with patch.object(framework.os, "open", switch_before_file_open):
            config = framework.load_yaml_config(str(selected / "config.yaml"))
    else:
        real_fstat = framework.os.fstat

        def switch_after_file_open(descriptor):
            nonlocal attempted
            if not attempted:
                attempted = True
                with suppress(PermissionError):
                    selected.rename(moved)
                    selected.symlink_to(attacker, target_is_directory=True)
            return real_fstat(descriptor)

        with patch.object(framework.os, "fstat", switch_after_file_open):
            config = framework.load_yaml_config(str(selected / "config.yaml"))
    assert attempted
    assert config == {"root": "original"}


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative traversal")
def test_config_path_component_budget_is_enforced_before_any_open(tmp_path):
    budget = framework.MAX_CONFIG_PATH_COMPONENTS
    base_components = len(tmp_path.parts) - 1
    within = tmp_path.joinpath(*["d"] * (budget - base_components))
    within.mkdir(parents=True)
    config = within / "config.yaml"
    config.write_text("root: within\n", encoding="utf-8")
    assert len(config.parts[1:-1]) == budget
    assert framework.load_yaml_config(str(config)) == {"root": "within"}

    beyond = within / "d"
    beyond.mkdir()
    deep = beyond / "config.yaml"
    deep.write_text("root: beyond\n", encoding="utf-8")
    real_open = framework.os.open
    opened = []

    def recording_open(*args, **kwargs):
        opened.append(args[0])
        return real_open(*args, **kwargs)

    with (
        patch.object(framework.os, "open", recording_open),
        pytest.raises(framework.ConfigurationError, match="could not be read"),
    ):
        framework.load_yaml_config(str(deep))
    assert opened == []
