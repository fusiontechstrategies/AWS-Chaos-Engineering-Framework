"""Offline adversarial closure for the four validated 27f6421 findings."""

import copy
import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import boto3
import botocore.session
import pytest
from botocore.stub import Stubber
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    BREAK_GLASS_ARN,
    INSTANCE_ID,
    REGION,
    FakeAWS,
    make_experiment,
    make_orchestrator,
    planning_only_experiment,
    prepare_lambda_memory,
)

import aws_chaos_framework as f
from scripts import normalize_sdist
from scripts import verify_distribution as verifier

ROOT = Path(__file__).resolve().parents[1]
BUCKET = ACCOUNT_ID + "private-bucket"
PREFIX = "chaos-test/"


def native_controller(aws=None):
    aws = aws or FakeAWS(reject_writes=False)
    session = SimpleNamespace(client=lambda service, **_kwargs: aws.client(service))
    controller = f.SafetyController(
        {}, session, REGION, True, expected_account=ACCOUNT_ID
    )
    controller.check_safety_conditions = lambda: (True, [])
    return controller, aws


def live_ec2(kind=f.ChaosType.EC2_REBOOT):
    aws = FakeAWS(reject_writes=False)
    owner = make_experiment(kind, {"instance_ids": [INSTANCE_ID]}, aws, dry_run=False)
    return owner, owner.safety_controller, aws


def conditional_lambda_stop_fixture(*, accepted_write=True):
    """Genuine public conditional action with ordinary sequential state data."""
    aws = FakeAWS(reject_writes=False)
    values = prepare_lambda_memory(aws, forward_failure=True)
    if not accepted_write:
        original = copy.deepcopy(
            aws.read_overrides[("lambda", "get_function_configuration")][0]
        )
        aws.read_overrides[("lambda", "get_function_configuration")] = [
            original,
            copy.deepcopy(original),
        ]
    owner = make_experiment(f.ChaosType.LAMBDA_MEMORY_LIMIT, values, aws, dry_run=False)
    return owner, owner.safety_controller, aws, values


def instance_response(state="running"):
    return {
        "Reservations": [
            {"Instances": [{"InstanceId": INSTANCE_ID, "State": {"Name": state}}]}
        ]
    }


def assert_confirmed_ec2_sdk_dispatch_is_tracked():
    """Preserve admitted SDK tracking through a supported public handler."""
    owner, controller, aws = live_ec2()
    raw = boto3.client(
        "ec2",
        region_name=REGION,
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
    )
    owner.ec2 = f.AwsClientProxy("ec2", raw, owner)
    with Stubber(raw) as stub:
        stub.add_response(
            "describe_instances", instance_response(), {"InstanceIds": [INSTANCE_ID]}
        )
        stub.add_response("reboot_instances", {}, {"InstanceIds": [INSTANCE_ID]})
        result = owner.reboot_instances([INSTANCE_ID])
        assert result.status == "completed", result.errors
        stub.assert_no_pending_responses()
    assert owner.mutation_attempts == ["ec2.reboot_instances"]
    assert owner.mutation_operations == ["ec2.reboot_instances"]
    assert not owner.rollback_attempts and not owner.rollback_operations
    assert not controller.emergency_stop.is_set()
    assert not aws.calls


def stopped_ec2_fixture():
    """Supply exact mocked state transitions for supported owned recovery."""
    owner, controller, aws = live_ec2(f.ChaosType.EC2_STOP)
    aws.read_overrides[("ec2", "describe_instances")] = [
        instance_response("running"),
        instance_response("stopped"),
        instance_response("stopped"),
        instance_response("running"),
    ]
    return owner, controller, aws


@pytest.mark.parametrize("account", [None, "", ACCOUNT_ID])
@pytest.mark.parametrize("operation", sorted(f.S3_OWNER_BOUND_OPERATIONS))
def test_ownerless_controller_s3_bucket_reads_and_writes_refuse(account, operation):
    controller, aws = native_controller()
    controller.expected_account = account
    with pytest.raises(f.SafetyViolation, match="require an experiment owner"):
        getattr(controller.client("s3"), operation)(Bucket=BUCKET)
    assert not aws.calls


@pytest.mark.parametrize("stopped", [False, True])
def test_ownerless_controller_mutation_refuses_before_and_after_latch(stopped):
    controller, aws = native_controller()
    if stopped:
        controller.emergency_stop_all()
        assert controller.emergency_stop.is_set()
    with pytest.raises(f.SafetyViolation, match="require an experiment owner"):
        controller.client("ec2").reboot_instances(InstanceIds=[INSTANCE_ID])
    assert not aws.calls


def test_ownerless_controller_safety_identity_reads_remain_usable_after_stop():
    controller, aws = native_controller()
    aws.read_overrides[("sts", "get_caller_identity")] = [{"Account": ACCOUNT_ID}]
    aws.read_overrides[("guardduty", "list_detectors")] = [{"DetectorIds": ["offline"]}]
    aws.read_overrides[("securityhub", "get_findings")] = [{"Findings": []}]
    controller.emergency_stop_all()
    assert controller.client("sts").get_caller_identity()["Account"] == ACCOUNT_ID
    assert controller.client("cloudwatch").describe_alarms()["MetricAlarms"]
    assert controller.client("guardduty").list_detectors()["DetectorIds"]
    assert controller.client("securityhub").get_findings()["Findings"] == []
    assert [(service, name) for service, name, _ in aws.calls] == [
        ("sts", "get_caller_identity"),
        ("cloudwatch", "describe_alarms"),
        ("guardduty", "list_detectors"),
        ("securityhub", "get_findings"),
    ]


@pytest.mark.parametrize(
    "service,operation", [("ec2", "reboot_instances"), ("s3", "delete_objects")]
)
@pytest.mark.parametrize("rollback", [False, True])
def test_plan_owner_cannot_dispatch_direct_mutation_even_as_recovery(
    service, operation, rollback
):
    controller, aws = native_controller()
    owner = f.ChaosExperiment({"dry_run": True}, controller)
    owner._in_rollback = rollback
    request = {"Bucket": BUCKET} if service == "s3" else {"InstanceIds": [INSTANCE_ID]}
    with pytest.raises(f.SafetyViolation, match="Plan mode refuses"):
        getattr(controller.client(service, owner), operation)(**request)
    assert not aws.calls
    assert not owner.mutation_attempts


@pytest.mark.parametrize("owned", [False, True])
@pytest.mark.parametrize(
    "operation,arguments",
    [
        ("get_paginator", ["list_objects_v2"]),
        ("get_waiter", ["bucket_exists"]),
        ("generate_presigned_url", ["get_object"]),
        ("generate_presigned_post", [BUCKET, "key"]),
        ("head_bucket", []),
        ("get_object", []),
        ("list_objects", []),
    ],
)
def test_raw_s3_delegates_and_unreviewed_bucket_methods_refuse(
    owned, operation, arguments
):
    raw = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
    )
    controller = f.SafetyController(
        {},
        SimpleNamespace(client=lambda *args, **kwargs: raw),
        REGION,
        True,
        expected_account=ACCOUNT_ID,
    )
    owner = live_ec2()[0] if owned else None
    with Stubber(raw) as stub:
        # No response is authorized. Any leaked delegate/call must fail this guard
        # before it can obtain an unwrapped operation or reach the SDK endpoint.
        with pytest.raises(f.SafetyViolation, match="only reviewed owner-bound"):
            getattr(controller.client("s3", owner), operation)(*arguments)
        stub.assert_no_pending_responses()


def test_ec2_readonly_approval_inventory_paginator_remains_supported():
    raw = boto3.client(
        "ec2",
        region_name=REGION,
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
    )
    controller = f.SafetyController(
        {},
        SimpleNamespace(client=lambda *args, **kwargs: raw),
        REGION,
        True,
        expected_account=ACCOUNT_ID,
    )
    with Stubber(raw) as stub:
        stub.add_response("describe_instances", {"Reservations": []}, {})
        assert list(
            controller.client("ec2").get_paginator("describe_instances").paginate()
        ) == [{"Reservations": []}]
        stub.assert_no_pending_responses()


# These raw effectful requests must refuse through real Botocore clients. The
# admitted SDK tracking counterpart uses a supported confirmed EC2 handler.
EFFECTFUL_READLIKE_CASES = [
    (
        "stepfunctions",
        "test_state",
        {
            "definition": json.dumps(
                {
                    "Type": "Task",
                    "Resource": "arn:aws-us-gov:states:::lambda:invoke",
                    "Parameters": {
                        "FunctionName": "arn:aws-us-gov:lambda:"
                        + REGION
                        + ":"
                        + ACCOUNT_ID
                        + ":function:offline"
                    },
                    "End": True,
                }
            ),
            "roleArn": "arn:aws-us-gov:iam::" + ACCOUNT_ID + ":role/offline",
        },
        {"status": "SUCCEEDED", "output": "{}"},
    ),
    (
        "elasticache",
        "test_failover",
        {"ReplicationGroupId": "offline", "NodeGroupId": "0001"},
        {},
    ),
    (
        "codecommit",
        "test_repository_triggers",
        {
            "repositoryName": "offline",
            "triggers": [
                {
                    "name": "offline",
                    "destinationArn": "arn:aws-us-gov:sns:"
                    + REGION
                    + ":"
                    + ACCOUNT_ID
                    + ":offline",
                    "events": ["all"],
                }
            ],
        },
        {"successfulExecutions": ["offline"], "failedExecutions": []},
    ),
    ("sts", "get_session_token", {}, {}),
]


def stub_controller(service):
    raw = boto3.client(
        service,
        region_name=REGION,
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
    )
    controller = f.SafetyController(
        {},
        SimpleNamespace(client=lambda *args, **kwargs: raw),
        REGION,
        True,
        expected_account=ACCOUNT_ID,
    )
    controller.check_safety_conditions = lambda: (True, [])
    return controller, raw


@pytest.mark.parametrize(
    "service,operation,call_request,response", EFFECTFUL_READLIKE_CASES
)
@pytest.mark.parametrize(
    "mode",
    [
        "ownerless",
        "ownerless_stopped",
        "plan",
        "plan_recovery",
        "plan_stopped",
        "live_stopped",
    ],
)
def test_effectful_readlike_sdk_calls_do_not_bypass_admission(
    service, operation, call_request, response, mode
):
    controller, raw = stub_controller(service)
    owner = (
        None
        if mode.startswith("ownerless")
        else (
            f.ChaosExperiment({"dry_run": True}, controller)
            if mode.startswith("plan")
            else live_ec2()[0]
        )
    )
    if mode == "live_stopped":
        controller = owner.safety_controller
    if mode == "plan_recovery":
        owner._in_rollback = True
    if mode.endswith("stopped"):
        controller.emergency_stop_all()
        assert controller.emergency_stop.is_set()
    # No stub response exists; leaking dispatch would raise Botocore's
    # UnStubbedResponseError instead of the requested refusal.
    with Stubber(raw), pytest.raises(f.SafetyViolation):
        getattr(f.AwsClientProxy(service, raw, owner), operation)(**call_request)
    if owner is not None:
        assert not owner.mutation_attempts
        assert not owner.mutation_operations


@pytest.mark.parametrize(
    "service,operation,call_request,response", EFFECTFUL_READLIKE_CASES
)
def test_effectful_readlike_actual_sdk_dispatch_is_tracked_when_admitted(
    service, operation, call_request, response
):
    controller, raw = stub_controller(service)
    with pytest.raises(f.SafetyViolation, match="plan-only"):
        f.ChaosExperiment({"dry_run": False}, controller)
    owner, _, _ = live_ec2()
    # Arbitrary effectful SDK calls have no public confirmed handler. Preserve
    # their refusal independently of the supported admitted EC2 counterpart.
    with (
        Stubber(raw),
        pytest.raises(f.SafetyViolation, match="active approved handler"),
    ):
        getattr(f.AwsClientProxy(service, raw, owner), operation)(**call_request)
    assert not owner.mutation_attempts and not owner.mutation_operations
    assert_confirmed_ec2_sdk_dispatch_is_tracked()


@pytest.mark.parametrize("owned", [False, True])
@pytest.mark.parametrize(
    "service,operation,arguments",
    [
        ("ec2", "get_paginator", ["describe_regions"]),
        ("ec2", "get_paginator", ["reboot_instances"]),
        ("ec2", "get_waiter", ["instance_running"]),
        ("ec2", "generate_presigned_url", ["describe_instances"]),
        ("efs", "get_paginator", ["describe_file_systems"]),
    ],
)
def test_non_s3_delegates_cannot_return_an_unreviewed_raw_operation(
    owned, service, operation, arguments
):
    controller, raw = stub_controller(service)
    owner = live_ec2()[0] if owned else None
    with Stubber(raw), pytest.raises(f.SafetyViolation):
        getattr(controller.client(service, owner), operation)(*arguments)


@pytest.mark.parametrize(
    "call_request",
    [
        ([], {}),
        (["describe_instances", "extra"], {}),
        ([], {"operation_name": "describe_instances", "extra": True}),
        ([[]], {}),
    ],
)
def test_reviewed_ec2_paginator_rejects_ambiguous_request_shape(call_request):
    controller, raw = stub_controller("ec2")
    args, kwargs = call_request
    with Stubber(raw), pytest.raises(f.SafetyViolation):
        controller.client("ec2").get_paginator(*args, **kwargs)


@pytest.mark.parametrize(
    "service,operation,call_request,response",
    [
        (
            "sts",
            "get_caller_identity",
            {},
            {
                "Account": ACCOUNT_ID,
                "Arn": "arn:aws-us-gov:iam::" + ACCOUNT_ID + ":user/offline",
                "UserId": "offline",
            },
        ),
        ("cloudwatch", "describe_alarms", {}, {"MetricAlarms": []}),
        ("guardduty", "list_findings", {"DetectorId": "offline"}, {"FindingIds": []}),
        ("securityhub", "get_findings", {}, {"Findings": []}),
        (
            "codecommit",
            "get_repository_triggers",
            {"repositoryName": "offline"},
            {"configurationId": "offline", "triggers": []},
        ),
    ],
)
def test_actual_reviewed_safety_identity_and_baseline_reads_work_after_stop(
    service, operation, call_request, response
):
    controller, raw = stub_controller(service)
    controller.emergency_stop_all()
    assert controller.emergency_stop.is_set()
    with Stubber(raw) as stub:
        stub.add_response(operation, response, call_request)
        assert (
            getattr(controller.client(service), operation)(**call_request) == response
        )
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "mode", ["ownerless", "live", "plan", "live_stopped", "plan_recovery_stopped"]
)
@pytest.mark.parametrize(
    "service,operation,args,kwargs",
    [
        ("s3", "get_paginator", ["list_objects_v2"], {}),
        ("s3", "get_waiter", ["bucket_exists"], {}),
        (
            "s3",
            "generate_presigned_url",
            ["get_object"],
            {"Params": {"Bucket": BUCKET, "Key": "offline"}},
        ),
        ("s3", "generate_presigned_post", [BUCKET, "offline"], {}),
        ("s3", "get_object", [], {"Bucket": BUCKET, "Key": "offline"}),
        ("ec2", "get_waiter", ["instance_running"], {}),
        ("ec2", "generate_presigned_url", ["describe_instances"], {}),
        ("efs", "get_paginator", ["describe_file_systems"], {}),
    ],
)
def test_real_sdk_unsupported_lookup_preserves_protocol_but_call_refuses(
    mode, service, operation, args, kwargs
):
    controller, raw = stub_controller(service)
    owner = (
        None
        if mode == "ownerless"
        else (
            f.ChaosExperiment({"dry_run": True}, controller)
            if mode.startswith("plan")
            else live_ec2()[0]
        )
    )
    if mode.startswith("live"):
        controller = owner.safety_controller
    if "recovery" in mode:
        owner._in_rollback = True
    if mode.endswith("stopped"):
        controller.emergency_stop_all()
        assert controller.emergency_stop.is_set()
    proxy = f.AwsClientProxy(service, raw, owner)
    sentinel = object()
    with Stubber(raw):
        assert hasattr(proxy, operation)
        refused = getattr(proxy, operation, sentinel)
        assert refused is not sentinel and callable(refused)
        # Supported introspection does not return the SDK method/delegate.
        with pytest.raises(f.SafetyViolation):
            refused(*args, **kwargs)
    assert controller.emergency_stop.is_set() == mode.endswith("stopped")
    if owner is not None:
        assert not owner.mutation_attempts and not owner.mutation_operations
        assert not owner.rollback_attempts and not owner.rollback_operations


@pytest.mark.parametrize("service", ["ec2", "s3"])
@pytest.mark.parametrize("owned", [False, True])
@pytest.mark.parametrize("stopped", [False, True])
def test_real_sdk_unknown_attributes_obey_attributeerror_and_default_protocol(
    service, owned, stopped
):
    controller, raw = stub_controller(service)
    owner = live_ec2()[0] if owned else None
    if stopped:
        controller.emergency_stop_all()
    proxy = controller.client(service, owner)
    sentinel = object()
    unknown = "offline_nonexistent_sdk_operation"
    with Stubber(raw):
        assert not hasattr(proxy, unknown)
        assert getattr(proxy, unknown, sentinel) is sentinel
        with pytest.raises(AttributeError):
            getattr(proxy, unknown)
        with pytest.raises(AttributeError):
            _ = proxy.offline_nonexistent_sdk_operation
        assert proxy.meta is raw.meta
    assert controller.emergency_stop.is_set() == stopped
    if owner is not None:
        assert not owner.mutation_attempts and not owner.mutation_operations


@pytest.mark.parametrize("owned", [False, True])
def test_real_sdk_reviewed_paginator_lookup_and_calls_remain_readonly_after_stop(owned):
    controller, raw = stub_controller("ec2")
    owner = f.ChaosExperiment({"dry_run": True}, controller) if owned else None
    controller.emergency_stop_all()
    proxy = controller.client("ec2", owner)
    with Stubber(raw) as stub:
        stub.add_response("describe_instances", {"Reservations": []}, {})
        assert hasattr(proxy, "get_paginator")
        paginator_factory = getattr(proxy, "get_paginator", None)
        assert callable(paginator_factory)
        assert list(
            paginator_factory(operation_name="describe_instances").paginate()
        ) == [{"Reservations": []}]
        stub.assert_no_pending_responses()
    assert controller.emergency_stop.is_set()
    if owner is not None:
        assert not owner.mutation_attempts and not owner.mutation_operations


def test_real_sdk_mutation_lookup_still_tracks_admission_and_refuses_after_latch():
    operation = "reboot_instances"
    _, raw = stub_controller("ec2")
    owner, controller, _ = live_ec2()
    later, _, later_aws = live_ec2()
    owner.ec2 = proxy = f.AwsClientProxy("ec2", raw, owner)
    with Stubber(raw) as stub:
        stub.add_response(
            "describe_instances", instance_response(), {"InstanceIds": [INSTANCE_ID]}
        )
        stub.add_response("reboot_instances", {}, {"InstanceIds": [INSTANCE_ID]})
        assert hasattr(proxy, operation)
        call = getattr(proxy, operation, None)
        assert callable(call)
        with pytest.raises(f.SafetyViolation, match="active approved handler"):
            call(InstanceIds=[INSTANCE_ID])
        result = owner.reboot_instances([INSTANCE_ID])
        assert result.status == "completed", result.errors
        stub.assert_no_pending_responses()
        controller.emergency_stop_all()
        assert controller.emergency_stop.is_set()
        with pytest.raises(f.SafetyViolation, match="active approved handler"):
            getattr(proxy, operation)(InstanceIds=[INSTANCE_ID])
    refused = later.reboot_instances([INSTANCE_ID])
    assert refused.status == "failed"
    assert any("Emergency stop" in error for error in refused.errors)
    assert owner.mutation_attempts == ["ec2.reboot_instances"]
    assert owner.mutation_operations == ["ec2.reboot_instances"]
    assert not later.mutation_attempts and not later.mutation_operations
    assert not any(name == "reboot_instances" for _, name, _ in later_aws.calls)


def test_stop_requested_after_admission_blocks_dispatch_and_latches_on_exit():
    owner, controller, aws = live_ec2()
    record = owner._record_mutation_attempt

    def stop_during_record(operation):
        record(operation)
        controller.emergency_stop_all()
        assert controller.emergency_stop.wait(0)
        # The request is immediate; stop activation waits for this admitted call.
        assert not controller.emergency_stop.is_set()

    owner._record_mutation_attempt = stop_during_record
    result = owner.reboot_instances([INSTANCE_ID])
    assert result.status == "failed"
    assert any("admitted SDK dispatch" in error for error in result.errors)
    assert controller.emergency_stop.is_set()
    assert not any(name == "reboot_instances" for _, name, _ in aws.calls)
    assert owner.mutation_attempts == ["ec2.reboot_instances"]
    assert not owner.mutation_operations


def test_same_thread_signal_request_is_deferred_without_dispatch_or_deadlock():
    aws = FakeAWS(reject_writes=False)
    config = {"instance_ids": [INSTANCE_ID]}
    orchestrator = make_orchestrator(f.ChaosType.EC2_REBOOT, config, aws, dry_run=False)
    owner = orchestrator._create_experiment(f.ChaosType.EC2_REBOOT, config)
    controller = orchestrator.safety_controller
    record = owner._record_mutation_attempt

    def signal_during_record(operation):
        record(operation)
        # Ordinary callback simulation only; no operating-system signal is sent.
        orchestrator._signal_handler(f.signal.SIGTERM, None)
        assert controller.emergency_stop.stop_requested()
        assert not controller.emergency_stop.is_set()

    owner._record_mutation_attempt = signal_during_record
    result = owner.reboot_instances([INSTANCE_ID])
    assert result.status == "failed"
    assert any("admitted SDK dispatch" in error for error in result.errors)
    assert controller.emergency_stop.is_set()
    assert not any(name == "reboot_instances" for _, name, _ in aws.calls)
    assert owner.mutation_attempts == ["ec2.reboot_instances"]
    assert not owner.mutation_operations


def test_stop_waits_for_accepted_sdk_call_and_blocks_later_calls_but_not_recovery():
    owner, controller, aws, values = conditional_lambda_stop_fixture()
    later, _, later_aws = live_ec2()
    # The stop request in the SDK callback prevents the forward state wait.
    starts = []
    recovery_starts = []
    respond = aws.respond

    def admitted_call(service, operation, request):
        if (
            operation == "update_function_configuration"
            and request.get("MemorySize") == 128
        ):
            starts.append(controller.emergency_stop.is_set())
            controller.emergency_stop_all()
            assert controller.emergency_stop.wait(0)
            assert not controller.emergency_stop.is_set()
        elif (
            operation == "update_function_configuration"
            and request.get("MemorySize") == 256
        ):
            recovery_starts.append(controller.emergency_stop.is_set())
        return respond(service, operation, request)

    aws.respond = admitted_call
    result = owner.modify_memory_limit(**values)
    assert result.status == "failed"
    assert any("Emergency stop" in error for error in result.errors)
    assert starts == [False]
    assert controller.emergency_stop.is_set()
    refused = later.reboot_instances([INSTANCE_ID])
    assert refused.status == "failed"
    assert any("Emergency stop" in error for error in refused.errors)
    assert not later.mutation_attempts and not later.mutation_operations
    assert not any(name == "reboot_instances" for _, name, _ in later_aws.calls)
    owner._in_rollback = True
    try:
        with pytest.raises(f.SafetyViolation, match="active approved handler"):
            owner.lambda_client.update_function_configuration(
                FunctionName=values["function_name"],
                MemorySize=256,
                RevisionId="memory-owned-revision",
            )
    finally:
        owner._in_rollback = False
    assert not owner.rollback_attempts and not owner.rollback_operations
    owner.run_rollback()
    assert owner.mutation_attempts == ["lambda.update_function_configuration"]
    assert owner.mutation_operations == ["lambda.update_function_configuration"]
    assert recovery_starts == [True]
    assert owner.rollback_attempts == ["lambda.update_function_configuration"]
    assert owner.rollback_operations == ["lambda.update_function_configuration"]
    assert owner.rollback_verified and not owner.rollback_errors
    requests = [
        request
        for _, operation, request in aws.calls
        if operation == "update_function_configuration"
    ]
    assert [request["RevisionId"] for request in requests] == [
        "memory-original-revision",
        "memory-owned-revision",
    ]


def test_reentrant_stop_inside_already_started_sdk_call_latches_after_return():
    owner, controller, aws = live_ec2()
    later, _, _ = live_ec2()
    states = []
    respond = aws.respond

    def admitted_call(service, operation, request):
        if operation == "reboot_instances":
            states.append(controller.emergency_stop.is_set())
            controller.emergency_stop_all()
            states.append(controller.emergency_stop.is_set())
        return respond(service, operation, request)

    aws.respond = admitted_call
    result = owner.reboot_instances([INSTANCE_ID])
    assert result.status == "completed", result.errors
    assert states == [False, False]
    assert controller.emergency_stop.is_set()
    assert owner.mutation_operations == ["ec2.reboot_instances"]
    assert owner.mutation_attempts == ["ec2.reboot_instances"]
    with pytest.raises(f.SafetyViolation, match="active approved handler"):
        owner.ec2.reboot_instances(InstanceIds=[INSTANCE_ID])
    refused = later.reboot_instances([INSTANCE_ID])
    assert refused.status == "failed"
    assert any("Emergency stop" in error for error in refused.errors)
    assert not later.mutation_attempts and not later.mutation_operations


@pytest.mark.parametrize("stop_at", ["before_handler", "admission", "sdk_return"])
def test_stop_dispatch_stress_has_no_sdk_start_after_latch(monkeypatch, stop_at):
    """Deterministic lifecycle control retaining the historical test's invariant."""
    owner, controller, aws, values = conditional_lambda_stop_fixture(
        accepted_write=stop_at == "sdk_return"
    )
    later, _, later_aws = live_ec2()
    states = []
    recovery_states = []
    record = owner._record_mutation_attempt
    respond = aws.respond

    def record_admission(operation):
        record(operation)
        if stop_at == "admission":
            controller.emergency_stop_all()
            assert controller.emergency_stop.stop_requested()
            assert not controller.emergency_stop.is_set()

    def raw_call(service, operation, request):
        if (
            operation == "update_function_configuration"
            and request.get("MemorySize") == 128
        ):
            states.append(controller.emergency_stop.is_set())
            if stop_at == "sdk_return":
                controller.emergency_stop_all()
                assert controller.emergency_stop.stop_requested()
                assert not controller.emergency_stop.is_set()
        elif (
            operation == "update_function_configuration"
            and request.get("MemorySize") == 256
        ):
            recovery_states.append(controller.emergency_stop.is_set())
        return respond(service, operation, request)

    monkeypatch.setattr(owner, "_record_mutation_attempt", record_admission)
    monkeypatch.setattr(aws, "respond", raw_call)
    if stop_at == "before_handler":
        controller.emergency_stop_all()
    result = owner.modify_memory_limit(**values)
    assert result.status == "failed"
    assert any("Emergency stop" in error for error in result.errors)
    assert states == ([False] if stop_at == "sdk_return" else [])
    assert not any(states)
    assert controller.emergency_stop.is_set()
    assert owner.mutation_attempts == (
        [] if stop_at == "before_handler" else ["lambda.update_function_configuration"]
    )
    assert owner.mutation_operations == (
        ["lambda.update_function_configuration"] if stop_at == "sdk_return" else []
    )
    refused = later.reboot_instances([INSTANCE_ID])
    assert refused.status == "failed"
    assert any("Emergency stop" in error for error in refused.errors)
    assert not later.mutation_attempts and not later.mutation_operations
    assert not any(name == "reboot_instances" for _, name, _ in later_aws.calls)
    if owner.mutation_attempts:
        owner.run_rollback()
        assert owner.rollback_verified and not owner.rollback_errors
    assert recovery_states == ([True] if stop_at == "sdk_return" else [])
    assert owner.rollback_attempts == (
        ["lambda.update_function_configuration"] if stop_at == "sdk_return" else []
    )
    assert owner.rollback_operations == owner.rollback_attempts
    requests = [
        request
        for _, operation, request in aws.calls
        if operation == "update_function_configuration"
    ]
    assert [request["RevisionId"] for request in requests] == (
        ["memory-original-revision", "memory-owned-revision"]
        if stop_at == "sdk_return"
        else []
    )


@pytest.mark.parametrize("operation", sorted(f.S3_OWNER_BOUND_OPERATIONS))
def test_all_s3_bucket_reads_writes_and_verifications_bind_captured_owner(operation):
    calls = []
    client = SimpleNamespace(
        meta=SimpleNamespace(region_name=REGION),
        **{operation: lambda **kwargs: calls.append(kwargs) or {}},
    )
    controller, _ = native_controller()
    owner = f.ChaosExperiment({"account_id": ACCOUNT_ID, "dry_run": True}, controller)
    # An unrelated later mapping edit cannot replace the authenticated account.
    owner.config["account_id"] = "999999999999"
    proxy = f.AwsClientProxy("s3", client, owner)
    if operation not in f.READ_ONLY_OPERATIONS["s3"]:
        with pytest.raises(f.SafetyViolation, match="Plan mode refuses"):
            getattr(proxy, operation)(Bucket=BUCKET)
        assert not calls
        assert not owner.mutation_attempts and not owner.mutation_operations
        if "s3." + operation in f.CONCURRENCY_UNSAFE_MUTATIONS:
            with pytest.raises(
                f.ConfigurationError, match="Live approval is unavailable"
            ):
                make_experiment(
                    f.ChaosType.S3_BUCKET_POLICY_DENY,
                    {
                        "bucket_name": BUCKET,
                        "break_glass_principal_arn": BREAK_GLASS_ARN,
                    },
                    FakeAWS(reject_writes=False),
                    dry_run=False,
                )
        else:
            assert_confirmed_ec2_sdk_dispatch_is_tracked()
    else:
        getattr(proxy, operation)(Bucket=BUCKET)
        assert calls == [{"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT_ID}]
    model = botocore.session.get_session().get_service_model("s3")
    api = next(
        name for name in model.operation_names if botocore.xform_name(name) == operation
    )
    assert "ExpectedBucketOwner" in model.operation_model(api).input_shape.members


@pytest.mark.parametrize("owner_value", [None, "", "123", 123456789012])
def test_s3_without_valid_reviewed_owner_fails_before_read(owner_value):
    calls = []
    controller, _ = native_controller()
    controller.expected_account = owner_value
    owner = f.ChaosExperiment({"dry_run": True}, controller)
    proxy = f.AwsClientProxy(
        "s3",
        SimpleNamespace(list_objects_v2=lambda **kwargs: calls.append(kwargs)),
        owner,
    )
    with pytest.raises(f.SafetyViolation, match="reviewed twelve-digit"):
        proxy.list_objects_v2(Bucket=BUCKET)
    assert not calls


def test_s3_caller_cannot_override_captured_expected_owner():
    calls = []
    controller, _ = native_controller()
    owner = f.ChaosExperiment({"dry_run": True}, controller)
    proxy = f.AwsClientProxy(
        "s3",
        SimpleNamespace(list_objects_v2=lambda **kwargs: calls.append(kwargs)),
        owner,
    )
    with pytest.raises(f.SafetyViolation, match="differs from the reviewed"):
        proxy.list_objects_v2(Bucket=BUCKET, ExpectedBucketOwner="999999999999")
    assert not calls
    proxy.list_objects_v2(Bucket=BUCKET, ExpectedBucketOwner=ACCOUNT_ID)
    assert calls == [{"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT_ID}]


def test_experiment_account_override_is_refused_and_owner_changes_confirmation():
    controller, _ = native_controller()
    orchestrator = object.__new__(f.ChaosOrchestrator)
    orchestrator.config = {"global": {"account_id": ACCOUNT_ID, "region": REGION}}
    orchestrator.expected_account = ACCOUNT_ID
    orchestrator.safety_controller = controller
    with pytest.raises(f.SafetyViolation, match="cannot override"):
        orchestrator._create_experiment(
            f.ChaosType.LAMBDA_MEMORY_LIMIT, {"account_id": "999999999999"}
        )
    with pytest.raises(f.SafetyViolation, match="cannot override"):
        orchestrator._run_single_experiment_locked(
            {"type": "lambda_memory_limit", "account_id": "999999999999"}
        )
    config = {
        "schema_version": 1,
        "global": {"account_id": ACCOUNT_ID, "region": REGION},
        "safety": {"target_allowlist": [], "fail_closed": True},
        "experiment_suites": {
            "test": {
                "experiments": [
                    {
                        "type": "lambda_memory_limit",
                        "function_name": "chaos-test-function",
                        "memory_mb": 128,
                    }
                ]
            }
        },
    }
    other = copy.deepcopy(config)
    other["global"]["account_id"] = "999999999999"
    assert f.confirmation_token(config, "test") != f.confirmation_token(other, "test")


@pytest.mark.parametrize("failure", [None, "list", "delete"])
def test_real_botocore_owner_mismatch_refuses_delete_and_valid_owner_succeeds(failure):
    client = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
    )
    controller = f.SafetyController(
        {},
        SimpleNamespace(client=lambda *args, **kwargs: client),
        REGION,
        True,
        expected_account=ACCOUNT_ID,
    )
    controller.check_safety_conditions = lambda: (True, [])
    with pytest.raises(f.SafetyViolation, match="plan-only"):
        f.S3ChaosExperiment({"dry_run": False}, controller)
    aws = FakeAWS(reject_writes=False)
    owner = planning_only_experiment(
        f.ChaosType.S3_OBJECT_DELETE,
        {"bucket_name": BUCKET, "prefix": PREFIX, "max_objects": 1},
        aws,
    )
    owner.s3 = f.AwsClientProxy("s3", client, owner)
    read = {
        "Bucket": BUCKET,
        "Prefix": PREFIX,
        "MaxKeys": 1,
        "ExpectedBucketOwner": ACCOUNT_ID,
    }
    with Stubber(client) as stub:
        if failure == "list":
            stub.add_client_error(
                "list_objects_v2",
                service_error_code="AccessDenied",
                service_message="Owner mismatch",
                http_status_code=403,
                expected_params=read,
            )
        else:
            stub.add_response(
                "list_objects_v2", {"Contents": [{"Key": PREFIX + "object"}]}, read
            )
        result = owner.delete_objects(BUCKET, PREFIX, 1)
        assert result.status == ("failed" if failure == "list" else "completed")
        request = {
            "Bucket": BUCKET,
            "Delete": {"Objects": [{"Key": PREFIX + "object"}]},
            "ExpectedBucketOwner": "999999999999"
            if failure == "delete"
            else ACCOUNT_ID,
        }
        with pytest.raises(
            f.SafetyViolation,
            match="owner differs" if failure == "delete" else "Plan mode",
        ):
            owner.s3.delete_objects(**request)
        stub.assert_no_pending_responses()
    assert owner.mutation_attempts == []
    assert owner.mutation_operations == []
    assert owner.rollback_attempts == []


@pytest.mark.parametrize(
    "value",
    [
        BUCKET,
        "AKIA" + "A" * 16 + "-private-target",
        "arn:aws-us-gov:s3:::" + BUCKET,
        "[RESOURCE]",
        "key",
        "123456789012",
    ],
)
def test_registered_complete_targets_win_over_shorter_generic_prefixes(value):
    with f.sensitive_log_scope([value]):
        assert f.redact_runtime_text(value) == "[RESOURCE]"
        assert (
            f.redact_runtime_text("target=" + value + "; done")
            == "target=[RESOURCE]; done"
        )


def test_longest_target_and_longer_generic_arn_both_mask_complete_values():
    value = ACCOUNT_ID + "private-bucket"
    assert f.redact_runtime_text(value, [ACCOUNT_ID, value]) == "[RESOURCE]"
    parent = "arn:aws-us-gov:s3:::" + value
    # Giving exact values precedence must not expose a longer unregistered ARN.
    assert f.redact_runtime_text(parent + "/private-object", [parent]) == "[ARN]"
    assert f.redact_runtime_text(ACCOUNT_ID, []) == "[ACCOUNT]"
    assert f.redact_runtime_text("AKIA" + "A" * 16, []) == "[ACCESS_KEY]"
    assert f.redact_runtime_text(parent, []) == "[ARN]"


@pytest.fixture(scope="module")
def approved_sdist(tmp_path_factory):
    output = tmp_path_factory.mktemp("approved-main-four-distribution")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )  # noqa: S603
    sdist = next(output.glob("*.tar.gz"))
    normalize_sdist.normalize_sdist(sdist, 315532800)
    verifier._verify_sdist(sdist, ROOT)
    return sdist


def rewrite_sdist(
    original,
    destination,
    replacements=None,
    additions=None,
    deleted=None,
    metadata=None,
):
    replacements, additions, deleted = (
        replacements or {},
        additions or {},
        deleted or set(),
    )
    with (
        tarfile.open(original, "r:gz") as source,
        tarfile.open(destination, "w:gz") as target,
    ):
        root = source.getmembers()[0].name
        for member in source.getmembers():
            relative = member.name.removeprefix(root + "/")
            if relative in deleted:
                continue
            changed = copy.copy(member)
            data = source.extractfile(member).read() if member.isfile() else None
            if relative in replacements:
                data = replacements[relative]
                changed.size = len(data)
            if metadata and relative == metadata[0]:
                changed.mode = metadata[1]
            target.addfile(changed, io.BytesIO(data) if data is not None else None)
        for name, data in additions.items():
            member = tarfile.TarInfo(root + "/" + name)
            member.mode = 0o644
            member.size = len(data)
            target.addfile(member, io.BytesIO(data))


@pytest.mark.parametrize(
    "attack",
    [
        "backend",
        "backend_path",
        "build_requirement",
        "cmdclass",
        "dynamic",
        "setup_py",
        "manifest_helper",
    ],
)
def test_tag_controlled_backend_and_matching_hook_bytes_are_rejected(
    approved_sdist, tmp_path, attack
):
    source = tmp_path / "selected-source"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git", "build", "dist", "__pycache__", "*.egg-info"
        ),
    )
    project = (source / "pyproject.toml").read_text(encoding="utf-8")
    replacements, additions = {}, {}
    if attack == "backend":
        project = project.replace(
            'build-backend = "setuptools.build_meta"',
            'build-backend = "scripts.custom_backend"',
        )
    elif attack == "backend_path":
        project = project.replace(
            "[build-system]", '[build-system]\nbackend-path = ["."]'
        )
    elif attack == "build_requirement":
        project = project.replace('"setuptools==84.0.0"', '"unreviewed-backend==1.0.0"')
    elif attack == "cmdclass":
        project += (
            '\n[tool.setuptools.cmdclass]\nbuild_py = "scripts.custom_backend.Build"\n'
        )
    elif attack == "dynamic":
        project = project.replace('version = "2.0.4"', 'dynamic = ["version"]')
        project += '\n[tool.setuptools.dynamic]\nversion = {attr = "scripts.custom_backend.version"}\n'
    elif attack == "setup_py":
        additions["setup.py"] = (
            b"raise AssertionError('legacy hook must never execute')\n"
        )
        (source / "setup.py").write_bytes(additions["setup.py"])
    elif attack == "manifest_helper":
        manifest = (
            source / "MANIFEST.in"
        ).read_bytes() + b"\ninclude scripts/custom_backend.py\n"
        (source / "MANIFEST.in").write_bytes(manifest)
        replacements["MANIFEST.in"] = manifest
    if attack in {"backend", "backend_path", "cmdclass", "dynamic", "manifest_helper"}:
        additions["scripts/custom_backend.py"] = (
            b"raise AssertionError('custom backend must never execute')\n"
        )
        (source / "scripts/custom_backend.py").write_bytes(
            additions["scripts/custom_backend.py"]
        )
    (source / "pyproject.toml").write_text(project, encoding="utf-8")
    replacements["pyproject.toml"] = (source / "pyproject.toml").read_bytes()
    altered = tmp_path / approved_sdist.name
    rewrite_sdist(approved_sdist, altered, replacements, additions)
    with pytest.raises(ValueError, match="unreviewed|trusted packaging policy"):
        verifier._verify_sdist(altered, source)


def test_recursive_manifest_cannot_authorize_new_matching_python_helper(
    approved_sdist, tmp_path
):
    source = tmp_path / "selected-source"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git", "build", "dist", "__pycache__", "*.egg-info"
        ),
    )
    payload = b"raise AssertionError('not a trusted executable source member')\n"
    (source / "scripts/custom_backend.py").write_bytes(payload)
    altered = tmp_path / approved_sdist.name
    rewrite_sdist(
        approved_sdist, altered, additions={"scripts/custom_backend.py": payload}
    )
    with pytest.raises(ValueError, match="unreviewed file"):
        verifier._verify_sdist(altered, source)


@pytest.mark.parametrize(
    "attack",
    [
        "sources",
        "requires",
        "pkg_info",
        "entry_points",
        "setup_cfg",
        "missing",
        "executable_mode",
    ],
)
def test_generated_sdist_metadata_never_authorizes_new_members_or_hooks(
    approved_sdist, tmp_path, attack
):
    altered = tmp_path / approved_sdist.name
    replacements, deleted, metadata = {}, None, None
    egg = verifier.EGG_INFO
    if attack == "sources":
        replacements[egg + "SOURCES.txt"] = b"scripts/custom_backend.py\n"
    elif attack == "requires":
        replacements[egg + "requires.txt"] = b"unreviewed-backend==1.0.0\n"
    elif attack == "pkg_info":
        with tarfile.open(approved_sdist) as archive:
            member = next(
                item for item in archive if item.name.endswith(egg + "PKG-INFO")
            )
            value = archive.extractfile(member).read()
        replacements[egg + "PKG-INFO"] = value.replace(
            b"Requires-Dist: boto3==1.43.102",
            b"Requires-Dist: unreviewed-backend==1.0.0",
        )
    elif attack == "entry_points":
        replacements[egg + "entry_points.txt"] = (
            b"[console_scripts]\nextra = scripts.custom_backend:main\n"
        )
    elif attack == "setup_cfg":
        replacements["setup.cfg"] = (
            b"[egg_info]\ntag_build = \ntag_date = 0\n[build_py]\nforce = 1\n"
        )
    elif attack == "missing":
        deleted = {egg + "requires.txt"}
    else:
        metadata = (
            f.MODULE_NAME if hasattr(f, "MODULE_NAME") else "aws_chaos_framework.py",
            0o755,
        )
    rewrite_sdist(
        approved_sdist, altered, replacements, deleted=deleted, metadata=metadata
    )
    with pytest.raises(ValueError, match="metadata|canonical|mode"):
        verifier._verify_sdist(altered, ROOT)


def test_approved_static_sdist_builds_verify_without_importing_selected_helpers(
    approved_sdist,
):
    verifier._verify_sdist(approved_sdist, ROOT)
    assert verifier._approved_project(ROOT)["version"] == "2.0.4"
