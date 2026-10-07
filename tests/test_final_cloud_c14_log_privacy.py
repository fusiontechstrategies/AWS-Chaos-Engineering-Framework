"""Exact-value log redaction survives exception unwinding and direct library use.

1. Suite and worker scopes reset while an exception unwinds, but the CLI and
   the suite loop log that exception afterwards. Each scope now attaches an
   immutable snapshot of its protected values to the escaping exception, and
   terminal logging (including debug tracebacks and chained causes) runs under
   that snapshot.
2. Direct, imported handler calls install a scope from every bound target, and
   a logger filter redacts framework records before any host handler, so a
   basic StreamHandler never receives raw identifiers.

Ordinary sequential fakes only; no AWS calls and no credentials.
"""

from __future__ import annotations

import io
import logging
import threading

import pytest
from botocore.exceptions import ClientError
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    INSTANCE_ID,
    OTHER_ACCESS_KEY,
    REGION,
    FakeAWS,
    FakeSafetyController,
    action_configs,
    make_orchestrator,
)

import aws_chaos_framework as framework

ALARM = "orchestrator-only-alarm"
SUITE_ONLY = "orchestrator-only-target"
MOUNT_TARGET = "fsmt-0fedcba9876543210"
REBOOT = framework.ChaosType.EC2_REBOOT


@pytest.fixture(autouse=True)
def empty_registry():
    """Start from the import-time default: no registry, as an embedding host has."""
    token = framework._SENSITIVE_LOG_VALUES.set(frozenset())
    try:
        yield
    finally:
        framework._SENSITIVE_LOG_VALUES.reset(token)


@pytest.fixture
def host_log():
    """Attach only a basic host handler, as an embedding application would."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    saved = (
        list(framework.logger.handlers),
        framework.logger.level,
        framework.logger.propagate,
    )
    framework.logger.handlers = [handler]
    framework.logger.setLevel(logging.DEBUG)
    framework.logger.propagate = False
    try:
        yield stream
    finally:
        framework.logger.handlers, level, framework.logger.propagate = saved
        framework.logger.setLevel(level)


@pytest.fixture
def restore_logger():
    saved = (
        list(framework.logger.handlers),
        framework.logger.level,
        framework.logger.propagate,
    )
    try:
        yield
    finally:
        framework.logger.handlers, level, framework.logger.propagate = saved
        framework.logger.setLevel(level)


def config_file(tmp_path):
    """A valid reviewed configuration that never names the scope-only values."""
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    config["global"]["region"] = REGION
    config["safety"]["safety_alarms"] = ["synthetic-alarm"]
    values = {"type": REBOOT.value, **action_configs()[REBOOT]}
    config["safety"]["target_allowlist"] = sorted(
        framework.ChaosOrchestrator._target_values(values)
    )
    config["experiment_suites"] = {"ordinary": {"experiments": [values]}}
    path = tmp_path / "config.yaml"
    path.write_text(framework.yaml.safe_dump(config), encoding="utf-8")
    return path


def serve(monkeypatch, orchestrator):
    """Make main() use one prepared orchestrator without changing static helpers."""

    class Prepared(framework.ChaosOrchestrator):
        def __new__(cls, *_args, **_kwargs):
            return orchestrator

    monkeypatch.setattr(framework, "ChaosOrchestrator", Prepared)


def aws_error(value):
    return ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": f"User is not authorized to act on {value}",
            }
        },
        "DescribeInstances",
    )


@pytest.mark.parametrize("level", ["INFO", "DEBUG"])
def test_missing_alarm_violation_is_redacted_after_suite_scope_unwinds(
    level, tmp_path, monkeypatch, capsys, restore_logger
):
    aws = FakeAWS(reject_writes=False)
    orchestrator = make_orchestrator(
        REBOOT, action_configs()[REBOOT], aws, dry_run=False
    )
    orchestrator.config["safety"]["safety_alarms"] = [ALARM]
    orchestrator.safety_controller.config["safety_alarms"] = [ALARM]
    # Only the orchestrator's own suite scope knows this exact alarm name.
    orchestrator._log_sensitive_values = {ALARM, ACCOUNT_ID}
    orchestrator.confirmation = orchestrator.expected_confirmation("ordinary", True)
    del orchestrator.safety_controller.check_safety_conditions
    raised = []
    run = orchestrator.run_experiment_suite

    def observed(suite):
        try:
            return run(suite)
        except framework.SafetyViolation as error:
            raised.append(error)
            raise

    orchestrator.run_experiment_suite = observed
    serve(monkeypatch, orchestrator)
    code = framework.main(
        [
            "--config",
            str(config_file(tmp_path)),
            "--suite",
            "ordinary",
            "--live",
            "--log-level",
            level,
        ]
    )
    assert code == 2
    # The violation really carried the exact alarm name past the scope reset.
    assert raised and ALARM in str(raised[0])
    assert ALARM in framework.exception_log_values(raised[0])
    captured = capsys.readouterr()
    assert ALARM not in captured.err + captured.out
    assert "CloudWatch alarm not found: [RESOURCE]" in captured.err
    assert framework._SENSITIVE_LOG_VALUES.get() == frozenset()


def test_aws_error_and_chained_cause_are_redacted_in_debug_traceback(
    tmp_path, monkeypatch, capsys, restore_logger
):
    aws = FakeAWS(reject_writes=False)
    orchestrator = make_orchestrator(REBOOT, action_configs()[REBOOT], aws)
    orchestrator._log_sensitive_values = {SUITE_ONLY}

    def failing_report():
        try:
            raise aws_error(SUITE_ONLY)
        except ClientError as error:
            raise RuntimeError(f"Report for {SUITE_ONLY} failed") from error

    orchestrator._generate_report = failing_report
    serve(monkeypatch, orchestrator)
    code = framework.main(
        [
            "--config",
            str(config_file(tmp_path)),
            "--suite",
            "ordinary",
            "--log-level",
            "DEBUG",
        ]
    )
    assert code == 1
    err = capsys.readouterr().err
    assert SUITE_ONLY not in err
    assert "Unexpected failure: Report for [RESOURCE] failed" in err
    # The traceback and its chained AWS cause were rendered, then redacted.
    assert "Unexpected failure details" in err
    assert "direct cause" in err and "not authorized to act on [RESOURCE]" in err


def test_worker_aws_error_is_redacted_when_the_suite_logs_it(host_log):
    aws = FakeAWS(reject_writes=False)
    orchestrator = make_orchestrator(REBOOT, action_configs()[REBOOT], aws)
    # The suite scope does not know the target; only the worker scope does.
    orchestrator._log_sensitive_values = set()

    def refuse(_kind, config):
        raise aws_error(config["instance_ids"][0])

    orchestrator._validate_target_scope = refuse
    assert orchestrator.run_experiment_suite("ordinary") is False
    text = host_log.getvalue()
    assert "Experiment worker failed" in text
    assert INSTANCE_ID not in text
    assert "not authorized to act on [RESOURCE]" in text


def _raise_rewrapped_suite_error():
    try:
        with framework.sensitive_log_scope([SUITE_ONLY]):
            raise ValueError(SUITE_ONLY)
    except ValueError as error:
        raise RuntimeError("outer") from error


def _raise_in_bound_target_scope():
    with framework.bound_target_log_scope({"instance_ids": [INSTANCE_ID]}):
        raise ValueError(INSTANCE_ID)


def test_scope_retains_snapshot_through_nested_rewrapping():
    with pytest.raises(RuntimeError) as caught:
        _raise_rewrapped_suite_error()
    assert framework._SENSITIVE_LOG_VALUES.get() == frozenset()
    assert framework.exception_log_values(caught.value) == {SUITE_ONLY}
    with framework.exception_log_scope(caught.value):
        assert framework.redact_runtime_text(repr(caught.value.__cause__)) == (
            "ValueError('[RESOURCE]')"
        )
    # A handler scope retains its bound targets the same way.
    with pytest.raises(ValueError) as bound:
        _raise_in_bound_target_scope()
    assert framework.exception_log_values(bound.value) == {INSTANCE_ID}
    # A cyclic chain is bounded and still terminates.
    first, second = ValueError("a"), ValueError("b")
    first.__context__, second.__context__ = second, first
    assert framework.exception_log_values(first) == frozenset()


def test_generic_masking_and_control_escaping_still_apply(host_log, capsys):
    arn = f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/Operator"
    framework.logger.error(
        "key %s arn %s account %s\x1b[31m\nforged line",
        OTHER_ACCESS_KEY,
        arn,
        ACCOUNT_ID,
    )
    text = host_log.getvalue()
    for value in (OTHER_ACCESS_KEY, arn, ACCOUNT_ID, "\x1b", "\nforged"):
        assert value not in text
    assert "[ACCESS_KEY]" in text and "[ARN]" in text and "[ACCOUNT]" in text
    assert "\\u001b[31m\\nforged line" in text
    # The CLI formatter keeps the same results on an already filtered record.
    framework.configure_logging("INFO")
    framework.logger.error("key %s\x1b", OTHER_ACCESS_KEY)
    err = capsys.readouterr().err
    assert OTHER_ACCESS_KEY not in err and "\x1b" not in err
    assert "[ACCESS_KEY]\\u001b" in err


def direct(cls, aws, **config):
    return cls(
        {"dry_run": True, "account_id": ACCOUNT_ID, "region": REGION, **config},
        FakeSafetyController(aws),
    )


def test_direct_ec2_plan_handler_redacts_bound_targets_at_info(host_log):
    aws = FakeAWS(reject_writes=True)
    item = direct(framework.EC2ChaosExperiment, aws)
    assert framework._SENSITIVE_LOG_VALUES.get() == frozenset()
    result = item.stop_instances([INSTANCE_ID])
    assert result.status == "completed", result.errors
    text = host_log.getvalue()
    assert "DRY RUN: Would stop instances" in text
    assert INSTANCE_ID not in text and "[RESOURCE]" in text
    assert framework._SENSITIVE_LOG_VALUES.get() == frozenset()
    # Direct calls remain plan-only: only reads, no mutation accounting.
    assert all(
        operation in framework.READ_ONLY_OPERATIONS.get(service, ())
        for service, operation, _ in aws.calls
    )
    assert item.mutation_attempts == []


def test_direct_efs_plan_handler_redacts_bound_target_at_error(host_log):
    aws = FakeAWS(reject_writes=True)
    aws.read_overrides[("efs", "describe_mount_targets")] = [{"MountTargets": []}]
    item = direct(framework.EFSChaosExperiment, aws)
    result = item.delete_mount_target(MOUNT_TARGET)
    assert result.status == "failed"
    text = host_log.getvalue()
    assert "ERROR Error deleting mount target" in text
    assert MOUNT_TARGET not in text and "[RESOURCE]" in text
    assert item.mutation_attempts == []


def test_direct_handler_redacts_configured_targets_without_cli_main(host_log):
    aws = FakeAWS(reject_writes=True)
    item = direct(
        framework.EC2ChaosExperiment, aws, instance_ids=["i-0aaaaaaaaaaaaaaa0"]
    )
    item.reboot_instances([INSTANCE_ID])
    framework.logger.info("after the call %s", INSTANCE_ID)
    text = host_log.getvalue()
    # During the call the bound value is protected; afterwards the scope ended.
    assert "DRY RUN" in text
    assert text.count(INSTANCE_ID) == 1
    assert text.rstrip().endswith(f"after the call {INSTANCE_ID}")
    assert not any(
        isinstance(handler.formatter, framework.PrivacyFormatter)
        for handler in framework.logger.handlers
    )


def test_direct_live_construction_remains_refused():
    aws = FakeAWS(reject_writes=False)
    with pytest.raises(
        framework.SafetyViolation, match="Direct experiment construction is plan-only"
    ):
        framework.EFSChaosExperiment(
            {"dry_run": False, "account_id": ACCOUNT_ID, "region": REGION},
            FakeSafetyController(aws, live=True),
        )
    assert aws.calls == []


def test_bound_target_values_cover_nested_identifiers_only():
    values = framework.bound_target_log_values(
        {
            "instance_ids": [INSTANCE_ID],
            "attachment": {"instance_id": "i-0bbbbbbbbbbbbbbb0", "device": "/dev/sdf"},
            "duration_seconds": 300,
            "description": "not an identifier",
        },
        {"mount_target_id": MOUNT_TARGET},
    )
    assert values == {INSTANCE_ID, "i-0bbbbbbbbbbbbbbb0", "/dev/sdf", MOUNT_TARGET}


def test_filter_redacts_tracebacks_and_stack_info_for_host_handlers(host_log):
    # The stack names this test function, so protect that exact name too.
    caller = "test_filter_redacts_tracebacks_and_stack_info_for_host_handlers"
    with framework.sensitive_log_scope([SUITE_ONLY, caller]):
        try:
            raise RuntimeError(f"cause names {SUITE_ONLY}")
        except RuntimeError:
            framework.logger.error("failed", exc_info=True, stack_info=True)
    text = host_log.getvalue()
    assert SUITE_ONLY not in text and caller not in text
    assert "cause names [RESOURCE]" in text and "Stack (most recent call last)" in text
    assert "in [RESOURCE]" in text


def test_cli_redacts_configured_values_outside_inner_scopes(
    tmp_path, monkeypatch, capsys, restore_logger
):
    """Construction-time logs and errors are protected by the loaded config."""

    class Refused(framework.ChaosOrchestrator):
        def __new__(cls, *_args, **_kwargs):
            framework.logger.error("Discovery failed near synthetic-alarm")
            raise framework.SafetyViolation(f"Target {INSTANCE_ID} is unavailable")

    monkeypatch.setattr(framework, "ChaosOrchestrator", Refused)
    code = framework.main(
        ["--config", str(config_file(tmp_path)), "--suite", "ordinary"]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "synthetic-alarm" not in err and INSTANCE_ID not in err
    assert "Discovery failed near [RESOURCE]" in err
    assert "Target [RESOURCE] is unavailable" in err


def test_direct_recovery_logs_under_the_bound_target_scope(host_log):
    aws = FakeAWS(reject_writes=True)
    item = direct(framework.EC2ChaosExperiment, aws, instance_ids=[INSTANCE_ID])
    item.rollback = lambda: framework.logger.info("restoring %s", INSTANCE_ID)
    item.run_rollback()
    assert host_log.getvalue() == "INFO restoring [RESOURCE]\n"
    assert aws.calls == []


FILE_SYSTEM = "fs-0123456789abcdef0"


def argument_only_efs_plan(aws):
    """A direct EFS plan whose file system is named only by handler arguments."""
    item = direct(framework.EFSChaosExperiment, aws)
    assert "file_system_id" not in item.config
    result = item.throttle_throughput(FILE_SYSTEM, "provisioned", 1.0)
    assert result.status == "completed", result.errors
    assert item.file_system_id == FILE_SYSTEM
    assert FILE_SYSTEM in item._log_protected_values
    return item


def fail_reads_naming(aws, service, operation, value):
    respond = aws.respond

    def failing(called_service, called_operation, request):
        if (called_service, called_operation) == (service, operation):
            framework.logger.info("Recovery read for %s", value)
            raise aws_error(value)
        return respond(called_service, called_operation, request)

    aws.respond = failing


def test_direct_efs_recovery_keeps_argument_only_targets_at_info_and_error(
    host_log,
):
    aws = FakeAWS(reject_writes=True)
    item = argument_only_efs_plan(aws)
    host_log.truncate(0)
    host_log.seek(0)
    fail_reads_naming(aws, "efs", "describe_file_systems", FILE_SYSTEM)
    with pytest.raises(ClientError) as recovery:
        item.run_rollback()
    with pytest.raises(ClientError):
        item.rollback()
    text = host_log.getvalue()
    assert FILE_SYSTEM not in text
    assert text.count("INFO Recovery read for [RESOURCE]") == 2
    assert text.count("ERROR Error during EFS rollback") == 2
    assert "not authorized to act on [RESOURCE]" in text
    assert FILE_SYSTEM in framework.exception_log_values(recovery.value)
    assert framework._SENSITIVE_LOG_VALUES.get() == frozenset()
    assert all(
        operation in framework.READ_ONLY_OPERATIONS.get(service, ())
        for service, operation, _ in aws.calls
    )


def test_direct_ec2_recovery_keeps_argument_only_targets_at_info_and_error(
    host_log,
):
    aws = FakeAWS(reject_writes=True)
    item = direct(framework.EC2ChaosExperiment, aws)
    assert item.stop_instances([INSTANCE_ID]).status == "completed"
    assert INSTANCE_ID in item._log_protected_values
    # The forward lifecycle records its selected instances for recovery.
    item.stopped_instances = [INSTANCE_ID]
    host_log.truncate(0)
    host_log.seek(0)
    fail_reads_naming(aws, "ec2", "describe_instances", INSTANCE_ID)
    with pytest.raises(ClientError):
        item.run_rollback()
    text = host_log.getvalue()
    assert INSTANCE_ID not in text
    assert "INFO Recovery read for [RESOURCE]" in text
    assert "ERROR Error during EC2 rollback" in text and "[RESOURCE]" in text
    assert item.mutation_attempts == [] and item.rollback_attempts == []


def test_protected_values_are_instance_scoped_and_append_only(host_log):
    aws = FakeAWS(reject_writes=True)
    first = argument_only_efs_plan(aws)
    retained = first._log_protected_values
    assert isinstance(retained, frozenset)
    other = direct(framework.EFSChaosExperiment, FakeAWS(reject_writes=True))
    assert other._log_protected_values == frozenset()
    assert framework.ChaosExperiment.__dict__.get("_log_protected_values") is None
    # A later handler call only adds to the first instance's set.
    first.delete_mount_target("fsmt-0123456789abcdef0")
    assert retained < first._log_protected_values
    assert other._log_protected_values == frozenset()
    host_log.truncate(0)
    host_log.seek(0)
    other.rollback = framework._scope_public_method(
        lambda self: framework.logger.info("unrelated %s", FILE_SYSTEM)
    ).__get__(other)
    other.rollback()
    assert host_log.getvalue() == f"INFO unrelated {FILE_SYSTEM}\n"


def test_run_rollback_scope_itself_keeps_argument_only_targets(host_log):
    aws = FakeAWS(reject_writes=True)
    item = argument_only_efs_plan(aws)
    host_log.truncate(0)
    host_log.seek(0)
    # An instance-level recovery bypasses the class wrapper, so only the
    # run_rollback scope (which also covers recovery verification) applies.
    item.rollback = lambda: framework.logger.error("verify %s", FILE_SYSTEM)
    item.run_rollback()
    assert host_log.getvalue() == "ERROR verify [RESOURCE]\n"


MOUNT_TARGET_B = "fsmt-0aaaaaaaaaaaaaaa1"


class InterleavingSet(frozenset):
    """Hold each union until a second caller arrives (or a short timeout).

    Without the instance lock both concurrent calls read this same base set
    before either commits, so one accepted target would be lost. With the lock
    the second caller cannot enter, the first times out and commits, and the
    second then builds on that committed set.
    """

    def __new__(cls, arrivals, both):
        value = super().__new__(cls)
        value.arrivals, value.both = arrivals, both
        return value

    def __or__(self, other):
        self.arrivals.append(threading.current_thread().name)
        if len(self.arrivals) >= 2:
            self.both.set()
        self.both.wait(0.5)
        return frozenset(self) | other


def test_concurrent_calls_on_one_instance_retain_every_target(host_log):
    aws = FakeAWS(reject_writes=True)
    item = direct(framework.EFSChaosExperiment, aws)
    arrivals: list[str] = []
    item._log_protected_values = InterleavingSet(arrivals, threading.Event())
    calls = [
        threading.Thread(
            target=item.throttle_throughput,
            args=(FILE_SYSTEM, "provisioned", 1.0),
            name="throttle",
        ),
        threading.Thread(
            target=item.delete_mount_target, args=(MOUNT_TARGET_B,), name="mount"
        ),
    ]
    for call in calls:
        call.start()
    for call in calls:
        call.join(5)
        assert not call.is_alive()
    # Only the first caller ever saw the uncommitted base set.
    assert len(arrivals) == 1
    assert {FILE_SYSTEM, MOUNT_TARGET_B} <= item._log_protected_values
    assert type(item._log_protected_values) is frozenset
    host_log.truncate(0)
    host_log.seek(0)
    fail_reads_naming(aws, "efs", "describe_file_systems", FILE_SYSTEM)
    with pytest.raises(ClientError):
        item.run_rollback()
    text = host_log.getvalue()
    assert FILE_SYSTEM not in text and "ERROR Error during EFS rollback" in text


def test_over_budget_call_is_rejected_without_changing_retained_targets(
    host_log, monkeypatch
):
    aws = FakeAWS(reject_writes=True)
    item = direct(
        framework.EFSChaosExperiment, aws, mount_target_id="fsmt-0bbbbbbbbbbbbbbb2"
    )
    assert item.throttle_throughput(FILE_SYSTEM, "provisioned", 1.0).status == (
        "completed"
    )
    retained = item._log_protected_values
    # Exactly at capacity: configured target plus the retained file system.
    monkeypatch.setattr(framework, "MAX_SENSITIVE_LOG_VALUES", 2)
    calls_before = list(aws.calls)
    # Retained plus new arguments alone fit; with the configured target the
    # complete union exceeds the budget, so nothing may be committed.
    with pytest.raises(framework.ConfigurationError, match="Too many"):
        item.delete_mount_target(MOUNT_TARGET_B)
    assert item._log_protected_values is retained
    assert aws.calls == calls_before
    host_log.truncate(0)
    host_log.seek(0)
    fail_reads_naming(aws, "efs", "describe_file_systems", FILE_SYSTEM)
    with pytest.raises(ClientError):
        item.run_rollback()
    with pytest.raises(ClientError):
        item.rollback()
    text = host_log.getvalue()
    assert FILE_SYSTEM not in text
    assert text.count("ERROR Error during EFS rollback") == 2


FILE_SYSTEM_B = "fs-0bbbbbbbbbbbbbbb1"


class RecoveryGate:
    """Pause the recovery thread inside its privacy scope, before its target read.

    `self.efs.describe_file_systems` is looked up before the recovery call
    evaluates `self.file_system_id`, so a concurrent change made while the
    gate is closed would be the identifier recovery actually requests.
    """

    def __init__(self, proxy, entered, release):
        self._proxy, self._entered, self._release = proxy, entered, release

    def __getattr__(self, name):
        if name == "describe_file_systems" and (
            threading.current_thread().name == "recovery"
        ):
            self._entered.set()
            assert self._release.wait(5)
        return getattr(self._proxy, name)


def test_plan_call_waits_for_active_recovery_on_the_same_instance(host_log):
    aws = FakeAWS(reject_writes=True)
    item = argument_only_efs_plan(aws)
    respond = aws.respond

    def recovery_fails(service, operation, request):
        if threading.current_thread().name == "recovery" and (
            operation == "describe_file_systems"
        ):
            aws.calls.append((service, operation, request))
            raise aws_error(request["FileSystemId"])
        return respond(service, operation, request)

    aws.respond = recovery_fails
    entered, release = threading.Event(), threading.Event()
    item.efs = RecoveryGate(item.efs, entered, release)
    errors = []

    def recover():
        try:
            item.run_rollback()
        except ClientError as error:
            errors.append(error)

    host_log.truncate(0)
    host_log.seek(0)
    recovery = threading.Thread(target=recover, name="recovery")
    plan = threading.Thread(
        target=item.throttle_throughput,
        args=(FILE_SYSTEM_B, "provisioned", 1.0),
        name="plan",
    )
    recovery.start()
    assert entered.wait(5)
    plan.start()
    plan.join(0.3)
    # The plan call cannot replace recovery state while recovery is active.
    assert plan.is_alive()
    assert item.file_system_id == FILE_SYSTEM
    assert FILE_SYSTEM_B not in item._log_protected_values
    release.set()
    recovery.join(5)
    plan.join(5)
    assert not recovery.is_alive() and not plan.is_alive()
    # Recovery used only the target captured in its own snapshot.
    assert len(errors) == 1
    assert FILE_SYSTEM in str(errors[0]) and FILE_SYSTEM_B not in str(errors[0])
    assert framework.exception_log_values(errors[0]) >= {FILE_SYSTEM}
    text = host_log.getvalue()
    assert FILE_SYSTEM not in text and FILE_SYSTEM_B not in text
    assert "ERROR Error during EFS rollback" in text
    # The plan then ran to completion under its own protected snapshot.
    assert item.file_system_id == FILE_SYSTEM_B
    assert FILE_SYSTEM_B in item._log_protected_values
