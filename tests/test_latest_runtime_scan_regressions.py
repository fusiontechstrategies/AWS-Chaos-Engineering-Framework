"""Offline adversarial regressions for the fb87be0 runtime scan findings."""

import copy
import subprocess
import sys
from pathlib import Path

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    INSTANCE_ID,
    VOLUME_ID,
    FakeAWS,
    FakeSafetyController,
    action_configs,
    make_experiment,
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
    item = termination(aws, dry_run=attack not in {"child_allowlist", "radius"})
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
    assert termination(aws).terminate_instances([INSTANCE_ID]).status == "failed"
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
    aws = FakeAWS(reject_writes=False)
    config = action_configs()[framework.ChaosType.EBS_DETACH_VOLUME]
    item = make_experiment(
        framework.ChaosType.EBS_DETACH_VOLUME, config, aws, dry_run=False
    )
    volume = aws.respond("ec2", "describe_volumes", {})
    attachment = volume["Volumes"][0]["Attachments"][0]
    changed = None
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
    elif attack == "tuple_allowlist":
        item.safety_controller.config["target_allowlist"].remove(
            f"attachment:{INSTANCE_ID}:/dev/xvdf"
        )
    elif attack == "radius":
        item.safety_controller.config["max_blast_radius"] = 1
    elif attack == "changed_before_write":
        changed = copy.deepcopy(volume)
        changed["Volumes"][0]["Attachments"][0]["InstanceId"] = OTHER_INSTANCE
    aws.read_overrides[("ec2", "describe_volumes")] = [volume] + (
        [changed] if changed else []
    )
    assert item.detach_volume(**config).status == "failed"
    assert not writes(aws)
    assert not item.mutation_attempts


def test_detach_write_contains_exact_reviewed_attachment_tuple():
    aws = FakeAWS(reject_writes=False)
    config = action_configs()[framework.ChaosType.EBS_DETACH_VOLUME]
    item = make_experiment(
        framework.ChaosType.EBS_DETACH_VOLUME, config, aws, dry_run=False
    )
    initial = aws.respond("ec2", "describe_volumes", {})
    available = copy.deepcopy(initial)
    available["Volumes"][0]["State"] = "available"
    available["Volumes"][0]["Attachments"] = []
    aws.read_overrides[("ec2", "describe_volumes")] = [
        initial,
        copy.deepcopy(initial),
        available,
    ]
    result = item.detach_volume(**config)
    assert result.status == "completed"
    assert set(result.affected_resources) == {VOLUME_ID, INSTANCE_ID}
    assert writes(aws) == [
        (
            "ec2",
            "detach_volume",
            {"VolumeId": VOLUME_ID, "InstanceId": INSTANCE_ID, "Device": "/dev/xvdf"},
        )
    ]


@pytest.mark.parametrize(
    "kind", [framework.ChaosType.EC2_TERMINATE, framework.ChaosType.EBS_DETACH_VOLUME]
)
def test_child_relationship_scope_and_live_token_restrictions(kind):
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    suite = next(iter(config["experiment_suites"]))
    action = {"type": kind.value, **action_configs()[kind]}
    config["experiment_suites"][suite]["experiments"] = [action]
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
        original = framework.confirmation_token(config, suite)
        action["attachment"]["device"] = "/dev/xvdz"
        field = "attachment"
        assert original != framework.confirmation_token(config, suite)
    del action[field]
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


@pytest.mark.parametrize("case", WAIT_CASES, ids=lambda case: case[1])
def test_every_forward_transition_polls_alarm_changes_and_stops_promptly(
    case, monkeypatch
):
    cls, method, args, service, operation, _collection, _field = case
    aws = FakeAWS()
    pending, _ready = transition_states(aws, case)
    aws.read_overrides[(service, operation)] = [pending]
    safety = FakeSafetyController(aws, live=True)
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
    item = cls({"dry_run": False, "state_timeout_seconds": 60}, safety)
    with pytest.raises(framework.EmergencyStop, match="Runtime safety"):
        getattr(item, method)(*args, True)
    assert polls[-1] is True and False in polls
    assert waits and max(waits) <= 5
    assert safety.emergency_stop.is_set()
    assert not writes(aws)


@pytest.mark.parametrize("case", WAIT_CASES, ids=lambda case: case[1])
def test_every_recovery_transition_ignores_stop_event_and_safety_alarm(case):
    cls, method, args, service, operation, _collection, _field = case
    aws = FakeAWS()
    _pending, ready = transition_states(aws, case)
    aws.read_overrides[(service, operation)] = [ready]
    safety = FakeSafetyController(aws, live=True)
    safety.emergency_stop.set()
    safety.check_safety_conditions = lambda: (_ for _ in ()).throw(
        AssertionError("Recovery must not poll forward guards")
    )
    item = cls({"dry_run": False, "state_timeout_seconds": 10}, safety)
    item._in_rollback = True
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
    item = make_experiment(kind, config, aws, dry_run=dry_run)
    result = object.__new__(framework.ChaosOrchestrator)._execute_experiment(
        item, kind, config
    )
    assert result.status == "failed"
    assert not writes(aws)
    assert not item.mutation_attempts


def test_orchestrator_refuses_live_no_write_completion():
    aws = FakeAWS()
    item = worker(aws)
    item._execute_experiment = lambda *_: framework.ExperimentResult(
        "synthetic",
        framework.ChaosType.EC2_STOP,
        framework.utc_now(),
        status="completed",
        affected_resources=[INSTANCE_ID],
    )
    result = item._run_single_experiment(
        {"type": "ec2_stop", "instance_ids": [INSTANCE_ID]}
    )
    assert result.status == "failed"
    assert "mutation attempt" in result.errors[0]
    assert not writes(aws)


@pytest.mark.parametrize("dry_run", [True, False])
def test_subnet_no_change_cannot_produce_a_fault_completion(dry_run):
    aws = FakeAWS(reject_writes=dry_run)
    config = {
        "subnet_id": "subnet-0123456789abcdef0",
        "nacl_id": "acl-0123456789abcdef0",
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
    live = make_experiment(kind, config, live_aws, dry_run=False)
    with pytest.raises(framework.ConfigurationError, match="not safely executable"):
        dispatch._execute_experiment(live, kind, config)
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
    safety = FakeSafetyController(aws, live=True)
    owner = framework.ChaosExperiment({"dry_run": False}, safety)
    owner._in_rollback = rollback
    service, method = operation.split(".")
    current = {"concurrent_principal": "must remain unchanged"}
    original = copy.deepcopy(current)
    proxy = owner.client(service)
    with pytest.raises(framework.SafetyViolation, match="conditional ownership proof"):
        getattr(proxy, method)(SyntheticState=current)
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
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("ec2", "describe_instances")] = [
        {"Reservations": [{"Instances": response}]}
    ]
    orchestrator = worker(aws)
    experiment = framework.EC2ChaosExperiment(
        {"dry_run": False}, orchestrator.safety_controller
    )
    experiment.stopped_instances = [INSTANCE_ID, OTHER_INSTANCE]
    experiment.mutation_attempts = ["ec2.stop_instances"]
    orchestrator._create_experiment = lambda *_: experiment
    orchestrator._execute_experiment = lambda *_: framework.ExperimentResult(
        "synthetic",
        framework.ChaosType.EC2_STOP,
        framework.utc_now(),
        status="completed",
        affected_resources=[INSTANCE_ID, OTHER_INSTANCE],
    )
    result = orchestrator._run_single_experiment(
        {"type": "ec2_stop", "instance_ids": [INSTANCE_ID, OTHER_INSTANCE]}
    )
    assert result.status == "failed" and result.rollback_successful is False
    assert not experiment.rollback_verified
    assert framework._LIVE_RECOVERY_BLOCKED.is_set()
    before = list(aws.calls)
    with pytest.raises(framework.SafetyViolation, match="blocked after unverified"):
        worker(aws)._run_single_experiment(
            {"type": "ec2_stop", "instance_ids": [INSTANCE_ID]}
        )
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
