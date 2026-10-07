"""Ordinary offline controls for the five validated 73b residual findings."""

import ast
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    INSTANCE_ID,
    REGION,
    FakeAWS,
    FakeSafetyController,
    action_configs,
    make_experiment,
    make_orchestrator,
    prepare_lambda_memory,
)

import aws_chaos_framework as f
from scripts import create_verified_draft as draft


@pytest.mark.parametrize("experiment_class", f.ChaosExperiment.__subclasses__())
def test_direct_live_constructor_refuses_before_client_acquisition(experiment_class):
    aws = FakeAWS(reject_writes=True)
    controller = FakeSafetyController(aws, live=True)
    with pytest.raises(
        f.SafetyViolation, match="Direct experiment construction is plan-only"
    ):
        experiment_class(
            {"dry_run": False, "account_id": ACCOUNT_ID, "region": REGION}, controller
        )
    assert not aws.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("confirmation", "ordinary-invalid-token"),
        ("actual_account", "999900001111"),
        ("allow_irreversible", False),
    ],
)
def test_creation_requires_actual_identity_confirmation_and_irreversible_approval(
    field, value
):
    # SQS purge and SES configuration-set deletion are planning only; another
    # irreversible live type carries the creation-time identity, confirmation
    # and irreversible-approval checks.
    kind = f.ChaosType.KMS_GRANT_REVOKE
    aws = FakeAWS(reject_writes=False)
    item = make_orchestrator(kind, action_configs()[kind], aws, dry_run=False)
    setattr(item, field, value)
    with pytest.raises(f.SafetyViolation):
        item._create_experiment(kind, action_configs()[kind])
    assert not aws.calls


def test_confirmed_reboot_dispatches_once_and_raw_proxy_has_no_authority():
    aws = FakeAWS(reject_writes=False)
    kind = f.ChaosType.EC2_REBOOT
    item = make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    with pytest.raises(f.SafetyViolation, match="active approved handler"):
        item.ec2.reboot_instances(InstanceIds=[INSTANCE_ID])
    assert not aws.calls
    assert item.reboot_instances([INSTANCE_ID]).status == "completed"
    assert len([call for call in aws.calls if call[1] == "reboot_instances"]) == 1
    refused = item.reboot_instances([INSTANCE_ID])
    assert refused.status == "failed" and "already been consumed" in refused.errors[0]


def test_handler_rejects_different_target_type_and_changed_configuration():
    aws = FakeAWS(reject_writes=False)
    kind = f.ChaosType.EC2_REBOOT
    item = make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    refused = item.reboot_instances(["i-0123456789abcdef1"])
    assert refused.status == "failed" and "arguments differ" in refused.errors[0]
    refused = item.stop_instances([INSTANCE_ID])
    assert refused.status == "failed" and "experiment type" in refused.errors[0]
    item.config["region"] = "us-gov-east-1"
    refused = item.reboot_instances([INSTANCE_ID])
    assert refused.status == "failed" and "unchanged immutable" in refused.errors[0]
    assert not aws.calls


def test_public_recovery_refuses_before_owned_forward_lifecycle():
    aws = FakeAWS(reject_writes=False)
    kind = f.ChaosType.LAMBDA_MEMORY_LIMIT
    item = make_experiment(
        kind,
        {"function_name": "chaos-test-function", "memory_mb": 128},
        aws,
        dry_run=False,
    )
    with pytest.raises(f.SafetyViolation, match="completed approved handler lifecycle"):
        item.run_rollback()
    assert not aws.calls and not item.rollback_attempts and not item.mutation_attempts


@pytest.mark.parametrize("forward_failure", [False, True])
def test_public_lifecycle_refuses_reentry_and_preserves_owned_phase_accounting(
    forward_failure,
):
    aws = FakeAWS(reject_writes=False)
    values = prepare_lambda_memory(aws, forward_failure=forward_failure)
    item = make_experiment(f.ChaosType.LAMBDA_MEMORY_LIMIT, values, aws, dry_run=False)
    phases = []
    item.safety_controller.check_safety_conditions = MagicMock(
        wraps=item.safety_controller.check_safety_conditions
    )
    respond = aws.respond

    def ordinary_callback(service, operation, request):
        if operation == "update_function_configuration":
            phases.append((operation, item._is_recovery_dispatch()))
            with pytest.raises(
                f.SafetyViolation, match="experiment lifecycle is active"
            ):
                item.run_rollback()
        if (
            operation == "update_function_configuration"
            and request["MemorySize"] == 128
            and forward_failure
        ):
            aws.calls.append((service, operation, request))
            raise RuntimeError("ordinary ambiguous SDK failure")
        return respond(service, operation, request)

    aws.respond = ordinary_callback
    result = item.modify_memory_limit(**values)
    assert result.status == ("failed" if forward_failure else "completed")
    if forward_failure:
        assert "ordinary ambiguous SDK failure" in result.errors[0]
    forward_polls = item.safety_controller.check_safety_conditions.call_count
    assert forward_polls > 0
    item.safety_controller.emergency_stop_all()
    if forward_failure:
        # An ambiguous forward has no confirmed post-write revision to own.
        with pytest.raises(f.SafetyViolation, match="revision was not confirmed"):
            item.run_rollback()
    else:
        item.run_rollback()
    assert item.safety_controller.check_safety_conditions.call_count == forward_polls
    assert phases == [("update_function_configuration", False)] + (
        [] if forward_failure else [("update_function_configuration", True)]
    )
    assert item.mutation_attempts == ["lambda.update_function_configuration"]
    assert item.mutation_operations == (
        [] if forward_failure else ["lambda.update_function_configuration"]
    )
    recovered = [] if forward_failure else ["lambda.update_function_configuration"]
    assert item.rollback_attempts == recovered
    assert item.rollback_operations == recovered
    assert item.rollback_verified is not forward_failure
    assert bool(item.rollback_errors) is forward_failure
    assert not item._is_recovery_dispatch()
    writes = [r for _, op, r in aws.calls if op == "update_function_configuration"]
    assert [r["RevisionId"] for r in writes] == ["memory-original-revision"] + (
        [] if forward_failure else ["memory-owned-revision"]
    )


def test_confirmed_handler_uses_detached_approved_argument_containers():
    aws = FakeAWS(reject_writes=False)
    identifiers = [INSTANCE_ID]
    kind = f.ChaosType.EC2_REBOOT
    item = make_experiment(kind, {"instance_ids": identifiers}, aws, dry_run=False)
    assert item.reboot_instances(identifiers).status == "completed"
    request = next(
        value for _, operation, value in aws.calls if operation == "reboot_instances"
    )
    assert request["InstanceIds"] == identifiers
    assert request["InstanceIds"] is not identifiers
    assert identifiers == [INSTANCE_ID]


def test_mutable_policy_cannot_expand_immutable_approved_scope():
    aws = FakeAWS(reject_writes=False)
    kind = f.ChaosType.EC2_REBOOT
    item = make_experiment(kind, {"instance_ids": [INSTANCE_ID]}, aws, dry_run=False)
    other = "i-0123456789abcdef1"
    item.safety_controller.config["target_allowlist"].append(other)
    with pytest.raises(f.SafetyViolation, match="immutable approved scope"):
        item._require_derived_scope(kind, {"instance_ids": [other]})
    assert not aws.calls and not item.mutation_attempts


@pytest.mark.parametrize("explicit_none", [False, True])
def test_confirmed_cloudfront_default_path_preserves_public_handler_contract(
    explicit_none,
):
    aws = FakeAWS(reject_writes=False)
    original = aws.respond

    def respond(service, operation, request):
        if service == "cloudfront" and operation == "create_invalidation":
            aws.calls.append((service, operation, request))
            return {"Invalidation": {"Id": "ordinary-invalidation"}}
        return original(service, operation, request)

    aws.respond = respond
    kind = f.ChaosType.CLOUDFRONT_CACHE_INVALIDATE
    item = make_experiment(kind, {"distribution_id": "EREVIEWED"}, aws, dry_run=False)
    result = (
        item.invalidate_cache("EREVIEWED", None)
        if explicit_none
        else item.invalidate_cache("EREVIEWED")
    )
    assert result.status == "completed", result.errors
    request = next(
        value for _, operation, value in aws.calls if operation == "create_invalidation"
    )
    assert request["InvalidationBatch"]["Paths"] == {"Quantity": 1, "Items": ["/*"]}
    assert item.mutation_operations == ["cloudfront.create_invalidation"]


@pytest.mark.parametrize(
    "method,values",
    [
        ("inject_network_latency", {"latency_ms": 10}),
        ("inject_packet_loss", {"loss_percent": 5}),
        ("inject_cpu_stress", {"cpu_percent": 10}),
        ("inject_memory_stress", {"memory_percent": 10}),
        ("inject_disk_stress", {"io_percent": 10}),
        ("fill_disk", {"fill_percent": 10}),
    ],
)
def test_legacy_fault_methods_are_disabled_for_ordinary_inputs(method, values):
    aws = FakeAWS(reject_writes=True)
    item = f.EC2ChaosExperiment({"dry_run": True}, FakeSafetyController(aws))
    with pytest.raises(
        f.ConfigurationError, match="Legacy SSM shell faults are disabled"
    ):
        getattr(item, method)([INSTANCE_ID], **values)
    assert not aws.calls


def test_no_legacy_generated_shell_dispatch_remains_in_current_source():
    source = Path(f.__file__).read_text()
    assert "AWS-RunShellScript" not in source
    module = ast.parse(source)
    assert not any(
        isinstance(node, ast.Attribute) and node.attr == "send_command"
        for node in ast.walk(module)
    )


@pytest.mark.parametrize(
    "role,field,value",
    [
        ("requester", "OwnerId", "999900001111"),
        ("accepter", "Region", "us-gov-east-1"),
        ("accepter", "VpcId", "vpc-0123456789abcdef2"),
    ],
)
def test_peering_authoritative_endpoint_mismatch_stops_before_delete(
    role, field, value
):
    kind = f.ChaosType.VPC_PEERING_DELETE
    aws = FakeAWS(reject_writes=False)
    response = aws.respond("ec2", "describe_vpc_peering_connections", {})
    response["VpcPeeringConnections"][0][
        "RequesterVpcInfo" if role == "requester" else "AccepterVpcInfo"
    ][field] = value
    aws.read_overrides[("ec2", "describe_vpc_peering_connections")] = [response]
    aws.calls.clear()
    item = make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    result = item.delete_vpc_peering(action_configs()[kind]["peering_connection_id"])
    assert result.status == "failed"
    assert not any(call[1] == "delete_vpc_peering_connection" for call in aws.calls)


def test_peering_tuple_binds_allowlist_confirmation_and_three_resource_radius():
    kind = f.ChaosType.VPC_PEERING_DELETE
    values = {"type": kind.value, **action_configs()[kind]}
    targets = f.ChaosOrchestrator._target_values(values)
    assert {
        "vpc-0123456789abcdef0",
        "vpc-0123456789abcdef1",
        values["peering_connection_id"],
    } <= targets
    assert any(value.startswith("selector:vpc_peering_delete:") for value in targets)
    assert f.ChaosOrchestrator._blast_radius(kind, values) == 3
    item = make_orchestrator(kind, action_configs()[kind], FakeAWS(), dry_run=False)
    before = item.confirmation
    item.config["experiment_suites"]["ordinary"]["experiments"][0]["peering_endpoints"][
        "accepter"
    ]["vpc_id"] = "vpc-0123456789abcdef2"
    assert item.expected_confirmation("ordinary", True) != before


@pytest.mark.parametrize(
    "pattern",
    ["(ordinary)", "ordinary|test", "[ordinary]", "ordinary+", "ordinary\\test"],
)
def test_regex_grammar_is_rejected_without_evaluation(pattern):
    with pytest.raises(f.ConfigurationError, match="literal text"):
        f.validate_denied_patterns([pattern])


def test_bounded_literal_globs_and_fixed_production_guard():
    assert f.denied_target_matches(["test-*"], {"test-queue"})
    assert f.denied_target_matches(["test-?"], {"test-a"})
    assert not f.denied_target_matches(["test-?"], {"test-aa"})
    assert f.denied_target_matches(["ordinary"], {"stage/production/queue"})
    with pytest.raises(f.SafetyViolation, match="target budget"):
        f.denied_target_matches(["ordinary"], {"a" * (f.MAX_DENIED_TARGET_LENGTH + 1)})


@pytest.mark.parametrize(
    "body",
    ["@ordinary-note", "true", "false", "null", "123", "Ordinary release notes\n"],
)
def test_draft_notes_remain_literal_strings_in_raw_request(tmp_path, monkeypatch, body):
    notes = tmp_path / "notes.md"
    notes.write_text(body)
    calls = []
    verifier = MagicMock()
    monkeypatch.setattr(draft, "load_integrity", lambda: verifier)

    def remote(arguments):
        calls.append(arguments)
        if "POST" in arguments:
            position = arguments.index("body=" + body)
            assert arguments[position - 1] == "-f"
        if arguments[0] == "api":
            return json.dumps(
                {
                    "id": 903,
                    "tag_name": "v2.0.4",
                    "draft": True,
                    "prerelease": False,
                    "body": body,
                    "assets": [{"name": "asset"}],
                }
            )
        return ""

    monkeypatch.setattr(draft, "gh", remote)
    assert (
        draft.create_draft(
            tmp_path,
            notes,
            "owner/repository",
            "v2.0.4",
            "ordinary-commit",
            {"asset": "digest"},
        )
        == 903
    )
    assert not any("DELETE" in call for call in calls)


@pytest.mark.parametrize("phase", ["create", "readback"])
def test_draft_body_mismatch_cleans_only_the_returned_immutable_id(
    tmp_path, monkeypatch, phase
):
    notes = tmp_path / "notes.md"
    notes.write_text("Ordinary body")
    calls = []
    monkeypatch.setattr(draft, "load_integrity", MagicMock)

    def remote(arguments):
        calls.append(arguments)
        if arguments[0] != "api" or "DELETE" in arguments:
            return ""
        body = "Ordinary body"
        if ("POST" in arguments) == (phase == "create"):
            body = "Different body"
        return json.dumps(
            {
                "id": 903,
                "tag_name": "v2.0.4",
                "draft": True,
                "prerelease": False,
                "body": body,
                "assets": [{"name": "asset"}],
            }
        )

    monkeypatch.setattr(draft, "gh", remote)
    with pytest.raises(ValueError):
        draft.create_draft(
            tmp_path,
            notes,
            "owner/repository",
            "v2.0.4",
            "ordinary-commit",
            {"asset": "digest"},
        )
    assert [call for call in calls if "DELETE" in call] == [
        ["api", "repos/owner/repository/releases/903", "--method", "DELETE"]
    ]


def test_legacy_regex_key_always_requires_manual_migration():
    for pattern in ["prod", ".*critical.*", "^test-.*$"]:
        with pytest.raises(
            f.ConfigurationError, match="manually migrate every pattern"
        ):
            f.denied_policy_globs({"denied_target_patterns": [pattern]})
    assert f.denied_policy_globs({"denied_target_globs": ["test-*"]}) == ["test-*"]


def test_bounded_denial_work_refuses_large_ordinary_policy():
    with pytest.raises(f.SafetyViolation, match="aggregate work budget"):
        f.denied_target_matches(["a" * 128] * 32, {"ordinary" * 100})


def test_canonical_waf_children_preserve_host_bit_normalization():
    values = {
        "ip_set_id": "01234567-89ab-cdef-0123-456789abcdef",
        "ip_set_name": "Reviewed",
        "scope": "REGIONAL",
        "addresses_to_add": ["198.51.100.9/24", "198.51.100.0/24"],
    }
    result = f.canonical_child_selectors(f.ChaosType.WAF_IP_SET_MODIFY, values)
    assert result["addresses_to_add"] == ["198.51.100.0/24"]
