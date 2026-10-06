"""SQS purge and RDS failover, reboot and backup retention are planning only.

PurgeQueue cannot be conditioned on an exact, immutable message set, so no
approved blast radius bounds the messages it destroys. RDS offers no
conditional generation or exclusive lease, so a reboot, failover or
ApplyImmediately retention write can activate changes queued after admission,
and failover can restart members outside the approved target count. Every live
gate refuses these four types; plans keep working.

Ordinary sequential fakes only; no AWS calls and no credentials.
"""

from __future__ import annotations

import dataclasses
import json
from unittest.mock import MagicMock

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    REGION,
    FakeAWS,
    FakeSafetyController,
    action_configs,
    make_experiment,
    make_orchestrator,
    planning_only_experiment,
)

import aws_chaos_framework as framework

PURGE = framework.ChaosType.SQS_QUEUE_PURGE
FAILOVER = framework.ChaosType.RDS_FAILOVER
REBOOT = framework.ChaosType.RDS_REBOOT
RETENTION = framework.ChaosType.RDS_BACKUP_RETENTION_MODIFY

# kind -> (experiment class, plan handler, service, mutating SDK operation, request)
WITHDRAWN = {
    PURGE: (
        framework.SQSChaosExperiment,
        "purge_queue",
        "sqs",
        "purge_queue",
        {"QueueUrl": action_configs()[PURGE]["queue_url"]},
    ),
    FAILOVER: (
        framework.RDSChaosExperiment,
        "failover_db_cluster",
        "rds",
        "failover_db_cluster",
        {"DBClusterIdentifier": "chaos-test-cluster"},
    ),
    REBOOT: (
        framework.RDSChaosExperiment,
        "reboot_db_instance",
        "rds",
        "reboot_db_instance",
        {"DBInstanceIdentifier": "chaos-test-db", "ForceFailover": False},
    ),
    RETENTION: (
        framework.RDSChaosExperiment,
        "modify_backup_retention",
        "rds",
        "modify_db_instance",
        {
            "DBInstanceIdentifier": "chaos-test-db",
            "BackupRetentionPeriod": 0,
            "ApplyImmediately": True,
        },
    ),
}
KINDS = sorted(WITHDRAWN, key=lambda kind: kind.value)


def kinds(function):
    return pytest.mark.parametrize("kind", KINDS, ids=lambda kind: kind.value)(function)


def run_plan_handler(kind, item):
    values = action_configs()[kind]
    _cls, handler, *_rest = WITHDRAWN[kind]
    method, parameters = framework.AUTHORIZED_HANDLER_CALLS[kind]
    assert method == handler
    arguments = [
        values.get(key, default) if optional else values[key]
        for key, optional, default in parameters
    ]
    return getattr(item, handler)(*arguments)


def suite_config(kind, **safety) -> dict:
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    config["global"]["region"] = REGION
    values = {"type": kind.value, **action_configs()[kind]}
    config["safety"]["safety_alarms"] = ["synthetic-alarm"]
    config["safety"]["allow_irreversible"] = True
    config["safety"]["target_allowlist"] = sorted(
        framework.ChaosOrchestrator._target_values(values)
    )
    config["safety"]["max_blast_radius"] = 50
    config["safety"].update(safety)
    config["experiment_suites"] = {"ordinary": {"experiments": [values]}}
    return config


def admitted_owner(aws):
    """A confirmed live EC2 reboot inside its active forward dispatch."""
    owner = make_experiment(
        framework.ChaosType.EC2_REBOOT,
        action_configs()[framework.ChaosType.EC2_REBOOT],
        aws,
        dry_run=False,
    )
    owner._sdk_request_authority.execution = owner._execution_grant
    owner._sdk_request_authority.phase = "forward"
    aws.calls.clear()
    return owner


@kinds
def test_metadata_and_every_capability_set_mark_the_kind_planning_only(kind):
    metadata = framework.experiment_metadata(kind)
    assert metadata.live_supported is False
    assert metadata.rollback == "none"
    assert kind in framework.CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS
    service, operation = WITHDRAWN[kind][2:4]
    assert f"{service}.{operation}" in framework.CONCURRENCY_UNSAFE_MUTATIONS
    # Plan validation still accepts the reviewed configuration.
    framework.validate_config_data(suite_config(kind))


@kinds
def test_list_experiments_reports_no_live_support(kind, capsys):
    assert framework.main(["--list-experiments"]) == 0
    rows = [line.split() for line in capsys.readouterr().out.splitlines()]
    row = next(row for row in rows if row and row[0] == kind.value)
    assert row[-1] == "no"


@kinds
@pytest.mark.parametrize("radius", [1, 50])
def test_live_token_is_refused_whatever_the_radius_or_approvals(kind, radius):
    config = suite_config(kind, max_blast_radius=radius)
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        framework.confirmation_token(config, "ordinary")


@kinds
def test_cli_show_live_token_prints_no_token(kind, tmp_path, capsys):
    path = tmp_path / "config.yaml"
    path.write_text(framework.yaml.safe_dump(suite_config(kind)), encoding="utf-8")
    code = framework.main(
        ["--config", str(path), "--suite", "ordinary", "--show-live-token"]
    )
    assert code == 2
    assert "LIVE" not in capsys.readouterr().out


@kinds
def test_live_orchestrator_admission_is_refused_without_aws_calls(kind):
    aws = FakeAWS(reject_writes=False)
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_orchestrator(kind, action_configs()[kind], aws, dry_run=False)
    assert aws.calls == []


@kinds
def test_live_suite_refuses_before_any_experiment_starts(kind):
    aws = FakeAWS(reject_writes=False)
    orchestrator = make_orchestrator(
        framework.ChaosType.EC2_REBOOT,
        action_configs()[framework.ChaosType.EC2_REBOOT],
        aws,
        dry_run=False,
    )
    orchestrator.config["experiment_suites"]["ordinary"]["experiments"] = [
        {"type": kind.value, **action_configs()[kind]}
    ]
    started = []
    orchestrator._run_single_experiment = started.append
    aws.calls.clear()
    with pytest.raises(framework.ConfigurationError, match="unsupported"):
        orchestrator._run_experiment_suite("ordinary")
    assert started == []
    assert aws.calls == []


@kinds
def test_direct_live_construction_has_no_authority(kind):
    cls = WITHDRAWN[kind][0]
    aws = FakeAWS(reject_writes=False)
    config = {
        **action_configs()[kind],
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "dry_run": False,
    }
    with pytest.raises(
        framework.SafetyViolation, match="Direct experiment construction is plan-only"
    ):
        cls(config, FakeSafetyController(aws, live=True))
    assert aws.calls == []


@kinds
def test_execution_grant_and_recovery_refuse_the_kind(kind):
    aws = FakeAWS(reject_writes=False)
    owner = admitted_owner(aws)
    owner._require_execution_grant(dispatch=True)
    owner._execution_grant = dataclasses.replace(owner._execution_grant, kind=kind)
    with pytest.raises(framework.SafetyViolation, match="conditional ownership"):
        owner._require_execution_grant(dispatch=True)
    # Recovery of a historical execution of this kind has no authority either.
    owner._execution_used = owner._forward_finished = True
    owner.mutation_attempts = [f"{WITHDRAWN[kind][2]}.{WITHDRAWN[kind][3]}"]
    del owner._sdk_request_authority.phase
    del owner._sdk_request_authority.execution
    with pytest.raises(framework.SafetyViolation, match="conditional ownership"):
        owner.run_rollback()
    assert aws.calls == []
    assert owner.rollback_attempts == []


@kinds
def test_mutating_sdk_call_never_reaches_the_client_inside_admitted_dispatch(kind):
    aws = FakeAWS(reject_writes=False)
    service, operation, request = WITHDRAWN[kind][2:]
    client = MagicMock(name=f"{service}-client")
    client.meta.region_name = REGION
    aws.clients[service] = client
    owner = admitted_owner(aws)
    proxy = owner.client(service)
    with pytest.raises(framework.SafetyViolation, match="conditional ownership"):
        getattr(proxy, operation)(**request)
    getattr(client, operation).assert_not_called()
    assert client.method_calls == []
    assert owner.mutation_attempts == []


@kinds
def test_flipped_plan_cannot_dispatch_through_the_orchestrator(kind):
    aws = FakeAWS(reject_writes=False)
    item = planning_only_experiment(kind, action_configs()[kind], aws)
    item.dry_run = False
    with pytest.raises(framework.ConfigurationError, match="not safely executable"):
        framework.ChaosOrchestrator._execute_experiment(
            object.__new__(framework.ChaosOrchestrator),
            item,
            kind,
            action_configs()[kind],
        )
    # Even a direct handler call on a forged non-plan object has no grant.
    result = run_plan_handler(kind, item)
    assert result.status == "failed"
    assert "execution authority" in result.errors[0]
    operation = WITHDRAWN[kind][3]
    assert not any(name == operation for _, name, _ in aws.calls)
    assert item.mutation_attempts == []


@kinds
def test_plan_still_produces_a_read_only_result(kind):
    aws = FakeAWS(reject_writes=True)
    item = planning_only_experiment(kind, action_configs()[kind], aws)
    result = run_plan_handler(kind, item)
    assert result.status == "completed", result.errors
    assert result.affected_resources
    assert all(
        operation in framework.READ_ONLY_OPERATIONS.get(service, ())
        for service, operation, _ in aws.calls
    )
    assert item.mutation_attempts == [] and item.rollback_attempts == []


@kinds
def test_plan_mode_suite_runs_and_reports_without_writes(kind):
    aws = FakeAWS(reject_writes=True)
    orchestrator = make_orchestrator(kind, action_configs()[kind], aws)
    assert orchestrator.run_experiment_suite("ordinary") is True
    report = json.loads(orchestrator.report_path.read_text(encoding="utf-8"))
    assert [item["status"] for item in report["experiments"]] == ["planned"]
    assert all(
        operation in framework.READ_ONLY_OPERATIONS.get(service, ())
        for service, operation, _ in aws.calls
    )


def test_retention_plan_rollback_never_claims_recovery():
    aws = FakeAWS(reject_writes=True)
    values = action_configs()[RETENTION]
    item = planning_only_experiment(RETENTION, values, aws)
    assert item.modify_backup_retention(**values).status == "completed"
    with pytest.raises(framework.SafetyViolation, match="irreversible"):
        item.run_rollback()
    assert not item.rollback_verified and item.rollback_attempts == []
