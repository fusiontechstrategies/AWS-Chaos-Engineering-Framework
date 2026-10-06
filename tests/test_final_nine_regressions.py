"""Adversarial, network-free regressions for the 37449ad final nine findings."""

import copy
import itertools
from types import SimpleNamespace

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    INSTANCE_ID,
    REGION,
    FakeAWS,
    action_configs,
    make_experiment,
    make_orchestrator,
    prepare_lambda_memory,
)

import aws_chaos_framework as f
from scripts.verify_distribution import validate_entry_points
from scripts.verify_publish_trust import verify_controls

QUEUE_URL = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT_ID}/chaos-test-queue"
QUEUE_ARN = f"arn:aws-us-gov:sqs:{REGION}:{ACCOUNT_ID}:chaos-test-queue"


def config_for(kind, **values):
    return {
        "schema_version": 1,
        "global": {"account_id": ACCOUNT_ID, "region": REGION},
        "safety": {"target_allowlist": [], "fail_closed": True},
        "experiment_suites": {
            "test": {"experiments": [{"type": kind.value, **values}]}
        },
    }


def test_later_orchestrator_signal_stops_earlier_controller_and_keeps_rollback(
    tmp_path, monkeypatch
):
    handlers = {}
    monkeypatch.setattr(
        f.signal, "signal", lambda signum, handler: handlers.update({signum: handler})
    )
    monkeypatch.setattr(f.atexit, "register", lambda *args: None)
    aws = FakeAWS(reject_writes=False)
    session = SimpleNamespace(client=lambda service, **kwargs: aws.client(service))
    monkeypatch.setattr(f.boto3, "Session", lambda **kwargs: session)
    cfg = config_for(f.ChaosType.EC2_REBOOT, instance_ids=[INSTANCE_ID])
    path = tmp_path / "config.yaml"
    path.write_text(f.yaml.safe_dump(cfg), encoding="utf-8")
    values = prepare_lambda_memory(aws)
    first = make_orchestrator(
        f.ChaosType.LAMBDA_MEMORY_LIMIT, values, aws, dry_run=False
    )
    earlier = first._create_experiment(f.ChaosType.LAMBDA_MEMORY_LIMIT, values)
    assert earlier.modify_memory_limit(**values).status == "completed"
    second = f.ChaosOrchestrator(str(path), output_dir=str(tmp_path / "second"))
    handlers[f.signal.SIGTERM](f.signal.SIGTERM, None)
    assert (
        first.safety_controller.emergency_stop
        is second.safety_controller.emergency_stop
    )
    assert first.safety_controller.emergency_stop.is_set()
    with pytest.raises(f.SafetyViolation, match="active approved handler"):
        earlier.lambda_client.update_function_configuration(
            FunctionName=values["function_name"],
            MemorySize=128,
            RevisionId="memory-owned-revision",
        )
    assert (
        len([call for call in aws.calls if call[1] == "update_function_configuration"])
        == 1
    )
    with pytest.raises(f.EmergencyStop):
        earlier._wait_forward(100)
    earlier.run_rollback()
    assert earlier.rollback_operations == ["lambda.update_function_configuration"]
    writes = [r for _, op, r in aws.calls if op == "update_function_configuration"]
    assert [r["RevisionId"] for r in writes] == [
        "memory-original-revision",
        "memory-owned-revision",
    ]
    third = f.SafetyController({}, session, REGION, True)
    assert third.emergency_stop.is_set()


def live_experiment(kind, aws, **extra):
    return make_experiment(
        kind,
        {
            **action_configs()[kind],
            "region": REGION,
            "account_id": ACCOUNT_ID,
            "dry_run": False,
            "state_timeout_seconds": 12,
            **extra,
        },
        aws,
        dry_run=False,
    )


def fast_poll(item, monkeypatch):
    ticks = itertools.count()
    monkeypatch.setattr(f.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(item, "_wait_forward", lambda seconds: None)


@pytest.mark.parametrize(
    "peering,response",
    [
        (True, {"Return": False}),
        (True, {}),
        (
            False,
            {
                "Unsuccessful": [
                    {
                        "ResourceId": "vpce-0123456789abcdef0",
                        "Error": {"Code": "Denied"},
                    }
                ]
            },
        ),
        (False, {}),
    ],
)
def test_vpc_explicit_or_ambiguous_delete_failure_is_not_completed(peering, response):
    kind = (
        f.ChaosType.VPC_PEERING_DELETE if peering else f.ChaosType.VPC_ENDPOINT_DELETE
    )
    aws = FakeAWS(reject_writes=False)
    original = aws.respond
    operation = "delete_vpc_peering_connection" if peering else "delete_vpc_endpoints"
    aws.respond = lambda service, name, request: (
        response if name == operation else original(service, name, request)
    )
    item = live_experiment(kind, aws)
    result = (
        item.delete_vpc_peering("pcx-0123456789abcdef0")
        if peering
        else item.delete_vpc_endpoint("vpce-0123456789abcdef0")
    )
    assert result.status == "failed"
    assert not result.affected_resources


@pytest.mark.parametrize("peering", [True, False])
@pytest.mark.parametrize("absent", [True, False])
def test_vpc_post_delete_requires_bounded_exact_target_readback(
    peering, absent, monkeypatch
):
    kind = (
        f.ChaosType.VPC_PEERING_DELETE if peering else f.ChaosType.VPC_ENDPOINT_DELETE
    )
    aws = FakeAWS(reject_writes=False)
    item = live_experiment(kind, aws)
    name = "describe_vpc_peering_connections" if peering else "describe_vpc_endpoints"
    key = "VpcPeeringConnections" if peering else "VpcEndpoints"
    target = "pcx-0123456789abcdef0" if peering else "vpce-0123456789abcdef0"
    before = aws.respond("ec2", name, {})
    states = [copy.deepcopy(before), copy.deepcopy(before)]
    if absent:
        states.append({key: []})
    else:
        states += [copy.deepcopy(before)] * 8
    aws.read_overrides[("ec2", name)] = states
    original = aws.respond
    aws.respond = lambda service, op, request: (
        {"Return": True}
        if op == "delete_vpc_peering_connection"
        else {"Unsuccessful": []}
        if op == "delete_vpc_endpoints"
        else original(service, op, request)
    )
    fast_poll(item, monkeypatch)
    result = (
        item.delete_vpc_peering(target) if peering else item.delete_vpc_endpoint(target)
    )
    assert result.status == ("completed" if absent else "failed")
    expected = (
        f.ChaosOrchestrator._target_values(
            {"type": kind.value, **action_configs()[kind]}
        )
        if peering
        else {target}
    )
    assert set(result.affected_resources) == (expected if absent else set())
    assert sum(call[1] == name for call in aws.calls) >= 3


@pytest.mark.parametrize("override", [False, True])
def test_fis_mutable_template_is_read_only_even_with_asserted_trust(override):
    aws = FakeAWS(reject_writes=False)
    with pytest.raises(f.ConfigurationError, match="Live FIS approval is disabled"):
        live_experiment(f.ChaosType.FIS_TEMPLATE, aws, template_immutable=override)
    assert not aws.calls
    cfg = config_for(
        f.ChaosType.FIS_TEMPLATE, experiment_template_id="EXT1234567890abcdef0"
    )
    with pytest.raises(f.ConfigurationError, match="immutable"):
        f.confirmation_token(cfg, "test")
    assert f.experiment_metadata(f.ChaosType.FIS_TEMPLATE).live_supported is False


@pytest.mark.parametrize(
    "foreign", ["account", "partition", "region", "url", "url_credentials"]
)
def test_sqs_foreign_owner_cannot_receive_token_or_purge(foreign):
    arn, url = QUEUE_ARN, QUEUE_URL
    if foreign == "account":
        arn, url = (
            arn.replace(ACCOUNT_ID, "999988887777"),
            url.replace(ACCOUNT_ID, "999988887777"),
        )
    elif foreign == "partition":
        arn = arn.replace("aws-us-gov", "aws")
    elif foreign == "region":
        arn = arn.replace(REGION, "us-gov-east-1")
    elif foreign == "url":
        url = url.replace("sqs.", "attacker.")
    else:
        url = url.replace("https://", "https://user:password@")
    cfg = config_for(f.ChaosType.SQS_QUEUE_PURGE, queue_url=url, queue_arn=arn)
    with pytest.raises(f.ConfigurationError, match="SQS"):
        f.confirmation_token(cfg, "test")
    aws = FakeAWS(reject_writes=False)
    with pytest.raises(f.ConfigurationError, match="SQS"):
        live_experiment(f.ChaosType.SQS_QUEUE_PURGE, aws, queue_url=url, queue_arn=arn)
    assert not aws.calls


# PurgeQueue cannot be conditioned on an exact message set, so SQS purge is
# planning only. A correctly owned queue still receives no live token or grant.
def test_sqs_owner_bound_purge_receives_no_live_token_or_dispatch():
    cfg = config_for(
        f.ChaosType.SQS_QUEUE_PURGE, queue_url=QUEUE_URL, queue_arn=QUEUE_ARN
    )
    with pytest.raises(f.ConfigurationError, match="Live approval is unavailable"):
        f.confirmation_token(cfg, "test")
    aws = FakeAWS(reject_writes=True)
    with pytest.raises(f.ConfigurationError, match="Live approval is unavailable"):
        live_experiment(f.ChaosType.SQS_QUEUE_PURGE, aws, queue_arn=QUEUE_ARN)
    assert not aws.calls
    values = {**action_configs()[f.ChaosType.SQS_QUEUE_PURGE], "queue_arn": QUEUE_ARN}
    item = make_experiment(f.ChaosType.SQS_QUEUE_PURGE, values, aws, dry_run=True)
    assert item.purge_queue(QUEUE_URL).status == "completed"
    with pytest.raises(f.SafetyViolation):
        item.sqs.purge_queue(QueueUrl=QUEUE_URL)
    assert not any(call[1] == "purge_queue" for call in aws.calls)
    assert item.mutation_attempts == []


def test_guardduty_active_old_finding_in_later_detector_and_page_blocks():
    calls = []

    def detectors(**request):
        calls.append(request)
        return (
            {"DetectorIds": ["first"], "NextToken": "second-page"}
            if not request
            else {"DetectorIds": ["second"]}
        )

    def findings(**request):
        calls.append(request)
        criteria = request["FindingCriteria"]["Criterion"]
        assert criteria == {
            "severity": {"Gte": 7},
            "service.archived": {"Eq": ["false"]},
        }
        if request["DetectorId"] == "first":
            return {"FindingIds": []}
        return (
            {"FindingIds": ["active-old-finding"]}
            if request.get("NextToken")
            else {"FindingIds": [], "NextToken": "later-finding-page"}
        )

    client = SimpleNamespace(list_detectors=detectors, list_findings=findings)
    safety = f.SafetyController(
        {"fail_closed": True},
        SimpleNamespace(client=lambda *args, **kwargs: client),
        REGION,
        True,
    )
    assert safety._check_guardduty_findings()
    assert any(call.get("NextToken") == "later-finding-page" for call in calls)


@pytest.mark.parametrize(
    "status,active,blocked",
    [
        ("NOTIFIED", True, True),
        ("NEW", True, True),
        ("RESOLVED", True, False),
        ("SUPPRESSED", True, False),
        ("NOTIFIED", False, False),
    ],
)
def test_securityhub_notified_blocks_but_resolved_suppressed_archived_do_not(
    status, active, blocked
):
    def findings(**request):
        filters = request["Filters"]
        assert filters["WorkflowStatus"] == [
            {"Value": "NEW", "Comparison": "EQUALS"},
            {"Value": "NOTIFIED", "Comparison": "EQUALS"},
        ]
        if "NextToken" not in request:
            return {"Findings": [], "NextToken": "later"}
        matches = (
            status in {item["Value"] for item in filters["WorkflowStatus"]}
            and active
            and filters["RecordState"][0]["Value"] == "ACTIVE"
        )
        return (
            {"Findings": [{"Workflow": {"Status": status}, "RecordState": "ACTIVE"}]}
            if matches
            else {"Findings": []}
        )

    client = SimpleNamespace(get_findings=findings)
    safety = f.SafetyController(
        {"fail_closed": True},
        SimpleNamespace(client=lambda *args, **kwargs: client),
        REGION,
        True,
    )
    assert bool(safety._check_security_hub()) is blocked


def test_security_pages_cycle_fails_closed():
    client = SimpleNamespace(
        get_findings=lambda **kwargs: {"Findings": [], "NextToken": "cycle"}
    )
    safety = f.SafetyController(
        {"fail_closed": True},
        SimpleNamespace(client=lambda *args, **kwargs: client),
        REGION,
        True,
    )
    assert any("pagination" in error for error in safety._check_security_hub())


@pytest.mark.parametrize(
    "role",
    [
        f"arn:aws:iam::{ACCOUNT_ID}:role/Operator",
        "arn:aws-us-gov:iam::999988887777:role/Operator",
        "not-an-arn",
    ],
)
def test_cli_role_override_fails_before_session_or_sts(tmp_path, monkeypatch, role):
    cfg = config_for(f.ChaosType.EC2_REBOOT, instance_ids=[INSTANCE_ID])
    cfg["global"]["external_id"] = "synthetic-external-id"
    path = tmp_path / "config.yaml"
    path.write_text(f.yaml.safe_dump(cfg), encoding="utf-8")

    def no_session(**kwargs):
        pytest.fail("Invalid CLI role must not construct any AWS session or STS client")

    monkeypatch.setattr(f.boto3, "Session", no_session)
    with pytest.raises(f.ConfigurationError):
        f.ChaosOrchestrator(str(path), role_arn=role)
    with pytest.raises(f.ConfigurationError):
        f.confirmation_token(cfg, "test", {"role_arn": role})


def planned_rds(kind, aws):
    """RDS failover/reboot are planning only: refuse live, return the plan."""
    with pytest.raises(f.ConfigurationError, match="Live approval is unavailable"):
        live_experiment(kind, aws)
    assert not aws.calls
    return make_experiment(
        kind,
        {**action_configs()[kind], "state_timeout_seconds": 12},
        aws,
        dry_run=True,
    )


@pytest.mark.parametrize("changed", [True, False])
def test_rds_failover_requires_writer_change_not_unchanged_available(
    changed, monkeypatch
):
    aws = FakeAWS(reject_writes=True)
    before = aws.respond("rds", "describe_db_clusters", {})
    aws.calls.clear()
    after = copy.deepcopy(before)
    for member in after["DBClusters"][0]["DBClusterMembers"]:
        member["IsClusterWriter"] = not member["IsClusterWriter"]
    aws.read_overrides[("rds", "describe_db_clusters")] = [copy.deepcopy(before)] + (
        [after, after] if changed else [copy.deepcopy(before)] * 10
    )
    item = planned_rds(f.ChaosType.RDS_FAILOVER, aws)
    fast_poll(item, monkeypatch)
    # The retained transition evidence check never accepts an unchanged writer.
    if changed:
        metrics = item._wait_for_cluster_available(
            "chaos-test-cluster", original_writer="chaos-test-db"
        )
        assert metrics["status"] == "available"
    else:
        with pytest.raises(TimeoutError):
            item._wait_for_cluster_available(
                "chaos-test-cluster", original_writer="chaos-test-db"
            )
    assert sum(call[1] == "describe_db_clusters" for call in aws.calls) >= 2
    assert not any(call[1] == "failover_db_cluster" for call in aws.calls)


@pytest.mark.parametrize("transition", [True, False])
def test_rds_reboot_requires_observed_reboot_then_available(transition, monkeypatch):
    aws = FakeAWS(reject_writes=True)
    before = aws.respond("rds", "describe_db_instances", {})
    aws.calls.clear()
    reboot = copy.deepcopy(before)
    reboot["DBInstances"][0]["DBInstanceStatus"] = "rebooting"
    aws.read_overrides[("rds", "describe_db_instances")] = (
        [reboot, before] if transition else [copy.deepcopy(before)] * 10
    )
    item = planned_rds(f.ChaosType.RDS_REBOOT, aws)
    fast_poll(item, monkeypatch)
    # The retained transition evidence check never accepts "available" alone.
    if transition:
        item._wait_for_db_instance_available(
            "chaos-test-db", True, require_transition=True
        )
    else:
        with pytest.raises(TimeoutError):
            item._wait_for_db_instance_available(
                "chaos-test-db", True, require_transition=True
            )
    assert not any(call[1] == "reboot_db_instance" for call in aws.calls)


@pytest.mark.parametrize(
    "attack",
    [
        "extra_command",
        "extra_group",
        "duplicate",
        "continuation",
        "defaults",
        "inline_comment",
    ],
)
def test_wheel_entrypoint_extra_behavior_rejected(attack, tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project.scripts]\naws-chaos-framework = "aws_chaos_framework:main"\n',
        encoding="utf-8",
    )
    valid = "[console_scripts]\naws-chaos-framework = aws_chaos_framework:main\n"
    payloads = {
        "extra_command": valid + "another = aws_chaos_framework:main\n",
        "extra_group": valid + "[plugin]\nfoo = aws_chaos_framework:main\n",
        "duplicate": valid + "aws-chaos-framework = aws_chaos_framework:other\n",
        "continuation": valid + "  extra\n",
        "defaults": "[DEFAULT]\nx = y\n" + valid,
        "inline_comment": valid.rstrip() + " # comment\n",
    }
    with pytest.raises(ValueError):
        validate_entry_points(payloads[attack], tmp_path)
    validate_entry_points(valid, tmp_path)


def publish_fixture():
    env = {
        "name": "pypi",
        "can_admins_bypass": False,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "protection_rules": [
            {
                "type": "required_reviewers",
                "reviewers": [{"type": "User", "reviewer": {"login": "owner"}}],
            }
        ],
    }
    policy = {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
    branch = {
        "name": "main",
        "protected": True,
        "protection": {"required_status_checks": {"contexts": ["Security checks"]}},
    }
    repo = {"default_branch": "main", "owner": {"login": "owner"}}
    commit = {"sha": "a" * 40, "commit": {"verification": {"verified": True}}}
    return [env, policy, branch, repo, commit, "refs/heads/main", "a" * 40]


@pytest.mark.parametrize(
    "attack",
    [
        "branch",
        "tag",
        "wildcard",
        "extra_policy",
        "bypass",
        "reviewer",
        "unsigned",
        "unprotected",
        "extra_reviewer",
        "hidden_policy",
    ],
)
def test_external_publish_controls_reject_untrusted_dispatch_or_policy(attack):
    values = publish_fixture()
    verify_controls(*values)
    if attack in {"branch", "tag"}:
        values[5] = "refs/heads/attacker" if attack == "branch" else "refs/tags/main"
    elif attack == "wildcard":
        values[1]["branch_policies"][0]["name"] = "*"
    elif attack == "extra_policy":
        values[1]["branch_policies"].append({"name": "feature", "type": "branch"})
    elif attack == "bypass":
        values[0]["can_admins_bypass"] = True
    elif attack == "reviewer":
        values[0]["protection_rules"] = []
    elif attack == "unsigned":
        values[4]["commit"]["verification"]["verified"] = False
    elif attack == "extra_reviewer":
        values[0]["protection_rules"][0]["reviewers"].append(
            {"type": "User", "reviewer": {"login": "other"}}
        )
    elif attack == "hidden_policy":
        values[1]["total_count"] = 101
    else:
        values[2]["protected"] = False
    with pytest.raises(ValueError):
        verify_controls(*values)


@pytest.mark.parametrize(
    "identity", ["account_id", "region", "role_arn", "external_id"]
)
def test_experiment_cannot_override_global_execution_scope(identity):
    cfg = config_for(
        f.ChaosType.SQS_QUEUE_PURGE, queue_url=QUEUE_URL, queue_arn=QUEUE_ARN
    )
    cfg["experiment_suites"]["test"]["experiments"][0][identity] = "foreign"
    with pytest.raises(f.ConfigurationError, match="global execution identity"):
        f.confirmation_token(cfg, "test")


@pytest.mark.parametrize("path", ["suite", "worker", "duration"])
@pytest.mark.parametrize("raises", [True, False])
def test_live_preflight_and_duration_failure_latch_every_controller(path, raises):
    from test_final_scan_regressions import worker

    aws = FakeAWS(reject_writes=False)
    values = {"instance_ids": [INSTANCE_ID]}
    item = worker(aws, f.ChaosType.EC2_REBOOT, values)

    def unsafe():
        if raises:
            raise RuntimeError("synthetic safety read failure")
        return False, ["synthetic alarm"]

    item.safety_controller.check_safety_conditions = unsafe
    item.safety_controller.emergency_stop.wait = lambda *args: False
    memory = prepare_lambda_memory(aws)
    earlier = make_experiment(
        f.ChaosType.LAMBDA_MEMORY_LIMIT, memory, aws, dry_run=False
    )
    assert earlier.modify_memory_limit(**memory).status == "completed"
    with pytest.raises((f.SafetyViolation, f.EmergencyStop)):
        if path == "suite":
            item._run_experiment_suite("ordinary")
        elif path == "worker":
            item._run_single_experiment_locked(
                {"type": "ec2_reboot", "instance_ids": [INSTANCE_ID]}
            )
        else:
            item._wait_with_runtime_checks(30)
    assert f._PROCESS_EMERGENCY_STOP.is_set()
    with pytest.raises(f.SafetyViolation, match="active approved handler"):
        earlier.lambda_client.update_function_configuration(
            FunctionName=memory["function_name"],
            MemorySize=128,
            RevisionId="memory-owned-revision",
        )
    earlier.run_rollback()
    assert earlier.rollback_operations == ["lambda.update_function_configuration"]


# Live SQS purge and RDS failover/reboot are planning only, so no forward wait
# for them can be reached live; see test_final_cloud_c11_planning_only.py.
@pytest.mark.parametrize("method", ["vpc", "peering_deleted", "peering_not_found"])
def test_stop_during_terminal_read_cannot_complete_forward_wait(method):
    aws = FakeAWS(reject_writes=False)
    session = SimpleNamespace(client=lambda service, **kwargs: aws.client(service))
    safety = f.SafetyController({}, session, REGION, True)
    safety.check_safety_conditions = lambda: (True, [])
    if method == "vpc":
        item = live_experiment(
            f.ChaosType.VPC_ENDPOINT_DELETE
            if method == "vpc"
            else f.ChaosType.VPC_PEERING_DELETE,
            aws,
        )
        operation = "describe_vpc_endpoints"
        result = {"VpcEndpoints": []}

        def call():
            return item._wait_for_vpc_deletion("vpce-0123456789abcdef0", peering=False)
    else:
        item = live_experiment(
            f.ChaosType.VPC_ENDPOINT_DELETE
            if method == "vpc"
            else f.ChaosType.VPC_PEERING_DELETE,
            aws,
        )
        operation = "describe_vpc_peering_connections"
        result = {
            "VpcPeeringConnections": [
                {
                    "VpcPeeringConnectionId": "pcx-0123456789abcdef0",
                    "Status": {"Code": "deleted"},
                }
            ]
        }

        def call():
            return item._wait_for_vpc_deletion("pcx-0123456789abcdef0", peering=True)

    original = aws.respond

    def respond(service, op, request):
        if op == operation:
            f._PROCESS_EMERGENCY_STOP.set()
            if method == "peering_not_found":
                raise f.ClientError(
                    {"Error": {"Code": "InvalidVpcPeeringConnectionID.NotFound"}},
                    "DescribeVpcPeeringConnections",
                )
            return result
        return original(service, op, request)

    aws.respond = respond
    with pytest.raises(f.EmergencyStop):
        call()
