"""Generation-bound, single-use WAF/Lambda recovery and WAF no-op refusal.

Ordinary sequential fakes only; no AWS calls and no credentials.
"""

from __future__ import annotations

import copy
import dataclasses
import logging

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    REGION,
    FakeAWS,
    FakeClientError,
    action_configs,
    make_experiment,
    make_orchestrator,
    planning_only_experiment,
    prepare_lambda_memory,
)

import aws_chaos_framework as framework

RULE = framework.ChaosType.WAF_RULE_MODIFY
RATE = framework.ChaosType.WAF_RATE_LIMIT_MODIFY
IP_SET = framework.ChaosType.WAF_IP_SET_MODIFY
MEMORY = framework.ChaosType.LAMBDA_MEMORY_LIMIT
FUNCTION = "chaos-test-function"


def web_acl(token: str, kind=None) -> dict:
    """Return an ordinary Web ACL read at one generation, optionally faulted."""
    response = copy.deepcopy(FakeAWS().respond("wafv2", "get_web_acl", {}))
    response["LockToken"] = token
    rule = response["WebACL"]["Rules"][0]
    if kind == RULE:
        rule["Action"] = {"Count": {}}
    elif kind == RATE:
        rule["Statement"]["RateBasedStatement"]["Limit"] = action_configs()[RATE][
            "limit"
        ]
    return response


def ip_set(token: str, addresses: list[str]) -> dict:
    response = copy.deepcopy(FakeAWS().respond("wafv2", "get_ip_set", {}))
    response["LockToken"] = token
    response["IPSet"]["Addresses"] = list(addresses)
    return response


def writes(aws: FakeAWS, operation: str) -> list[dict]:
    return [request for _, name, request in aws.calls if name == operation]


def forward(item, kind):
    values = action_configs()[kind]
    method = {
        RULE: "modify_rule",
        RATE: "modify_rate_limit",
        IP_SET: "modify_ip_set",
    }[kind]
    return getattr(item, method)(**values)


def assert_recovery_authority_ended(item, aws, operation):
    """A terminal outcome revokes the grant and refuses any later recovery."""
    assert item._execution_grant is None
    before = list(aws.calls)
    with pytest.raises(framework.SafetyViolation, match="already consumed"):
        item.run_rollback()
    assert aws.calls == before
    assert not item._is_recovery_dispatch()
    with pytest.raises(framework.SafetyViolation, match="execution authority"):
        item._require_execution_grant()
    assert len(writes(aws, operation)) == len([c for c in before if c[1] == operation])


# Finding 1: WAF recovery is bound to the confirmed post-forward generation.


@pytest.mark.parametrize("kind", [RULE, RATE])
def test_waf_same_value_in_a_later_generation_is_not_reverted(kind):
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("wafv2", "get_web_acl")] = [
        web_acl("lock-1"),
        web_acl("lock-2", kind),
        # Another principal wrote the identical chaos value in generation 3.
        web_acl("lock-3", kind),
    ]
    aws.write_responses[("wafv2", "update_web_acl")] = [{"NextLockToken": "lock-2"}]
    item = make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    assert forward(item, kind).status == "completed"
    assert item.rule_confirmed_generation[-1] == "lock-2"
    with pytest.raises(framework.SafetyViolation, match="generation advanced"):
        item.run_rollback()
    assert [w["LockToken"] for w in writes(aws, "update_web_acl")] == ["lock-1"]
    assert not item.rollback_attempts and not item.rollback_verified
    assert not item.rule_write_confirmed
    assert_recovery_authority_ended(item, aws, "update_web_acl")


@pytest.mark.parametrize("kind", [RULE, RATE])
def test_waf_confirmed_generation_recovers_once_then_revokes_grant(kind):
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("wafv2", "get_web_acl")] = [
        web_acl("lock-1"),
        web_acl("lock-2", kind),
        web_acl("lock-2", kind),
        web_acl("lock-3"),
    ]
    aws.write_responses[("wafv2", "update_web_acl")] = [{"NextLockToken": "lock-2"}]
    item = make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    assert forward(item, kind).status == "completed"
    item.run_rollback()
    assert item.rollback_verified and not item.rollback_errors
    assert [w["LockToken"] for w in writes(aws, "update_web_acl")] == [
        "lock-1",
        "lock-2",
    ]
    # Owned markers are cleared; original-state evidence remains for read-back.
    assert not item.rule_write_confirmed
    assert item.rule_confirmed_generation is None
    assert item.original_rule_value is not None
    assert_recovery_authority_ended(item, aws, "update_web_acl")
    with pytest.raises(framework.SafetyViolation, match="execution authority"):
        item.wafv2.update_web_acl(
            Scope="REGIONAL",
            Name="chaos-test-acl",
            Id=action_configs()[kind]["web_acl_id"],
            LockToken="lock-3",
        )


@pytest.mark.parametrize("next_token", [None, "lock-other"])
def test_waf_rule_forward_requires_its_own_next_lock_token(next_token):
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("wafv2", "get_web_acl")] = [
        web_acl("lock-1"),
        web_acl("lock-2", RULE),
    ]
    aws.write_responses[("wafv2", "update_web_acl")] = [
        {} if next_token is None else {"NextLockToken": next_token}
    ]
    item = make_experiment(RULE, action_configs()[RULE], aws, dry_run=False)
    result = forward(item, RULE)
    assert result.status == "failed"
    assert "reconcile manually" in result.errors[0]
    assert not item.rule_write_confirmed
    with pytest.raises(framework.SafetyViolation, match="not confirmed"):
        item.run_rollback()
    assert len(writes(aws, "update_web_acl")) == 1
    assert_recovery_authority_ended(item, aws, "update_web_acl")


def test_waf_ip_set_address_readded_in_later_generation_is_preserved():
    aws = FakeAWS(reject_writes=False)
    added = action_configs()[IP_SET]["addresses_to_add"]
    aws.read_overrides[("wafv2", "get_ip_set")] = [
        ip_set("lock-1", ["192.0.2.0/32"]),
        # The experiment address was removed and re-added by another principal.
        ip_set("lock-4", ["192.0.2.0/32", *added]),
    ]
    aws.write_responses[("wafv2", "update_ip_set")] = [{"NextLockToken": "lock-2"}]
    item = make_experiment(IP_SET, action_configs()[IP_SET], aws, dry_run=False)
    assert forward(item, IP_SET).status == "completed"
    assert item.ip_set_confirmed_generation[-1] == "lock-2"
    with pytest.raises(framework.SafetyViolation, match="generation advanced"):
        item.run_rollback()
    assert [w["LockToken"] for w in writes(aws, "update_ip_set")] == ["lock-1"]
    assert not item.rollback_attempts and not item.rollback_verified
    assert item.owned_address_additions == set()
    assert_recovery_authority_ended(item, aws, "update_ip_set")


def test_waf_ip_set_confirmed_generation_recovers_once_without_new_ticket():
    aws = FakeAWS(reject_writes=False)
    added = action_configs()[IP_SET]["addresses_to_add"]
    aws.read_overrides[("wafv2", "get_ip_set")] = [
        ip_set("lock-1", ["192.0.2.0/32"]),
        ip_set("lock-2", ["192.0.2.0/32", *added]),
        ip_set("lock-3", ["192.0.2.0/32"]),
    ]
    aws.write_responses[("wafv2", "update_ip_set")] = [{"NextLockToken": "lock-2"}]
    item = make_experiment(IP_SET, action_configs()[IP_SET], aws, dry_run=False)
    assert forward(item, IP_SET).status == "completed"
    item.run_rollback()
    assert item.rollback_verified and not item.rollback_errors
    recovery = writes(aws, "update_ip_set")[-1]
    assert recovery["LockToken"] == "lock-2"
    assert recovery["Addresses"] == ["192.0.2.0/32"]
    assert not item.ip_set_write_confirmed
    assert_recovery_authority_ended(item, aws, "update_ip_set")


def test_waf_ip_set_forward_without_next_lock_token_has_no_ownership():
    aws = FakeAWS(reject_writes=False)
    aws.write_responses[("wafv2", "update_ip_set")] = [{}]
    item = make_experiment(IP_SET, action_configs()[IP_SET], aws, dry_run=False)
    result = forward(item, IP_SET)
    assert result.status == "failed" and "reconcile manually" in result.errors[0]
    assert item.mutation_operations == ["wafv2.update_ip_set"]
    assert not item.ip_set_write_confirmed
    with pytest.raises(framework.SafetyViolation, match="not confirmed"):
        item.run_rollback()
    assert len(writes(aws, "update_ip_set")) == 1


def test_orchestrated_waf_generation_conflict_reports_failed_recovery():
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("wafv2", "get_web_acl")] = [
        web_acl("lock-1"),
        web_acl("lock-2", RULE),
        web_acl("lock-3", RULE),
    ]
    aws.write_responses[("wafv2", "update_web_acl")] = [{"NextLockToken": "lock-2"}]
    values = action_configs()[RULE]
    orchestrator = make_orchestrator(RULE, values, aws, dry_run=False)
    result = orchestrator._run_single_experiment({"type": RULE.value, **values})
    assert result.rollback_successful is False and result.status == "failed"
    assert not result.rollback_attempts
    assert len(writes(aws, "update_web_acl")) == 1
    assert framework._LIVE_RECOVERY_BLOCKED.is_set()


# Finding 2: Lambda recovery is bound to the confirmed post-forward RevisionId.


def lambda_reads(aws, *later):
    """Original and confirmed-owned snapshots followed by later recovery reads."""
    prepare_lambda_memory(aws)
    reads = aws.read_overrides[("lambda", "get_function_configuration")]
    aws.read_overrides[("lambda", "get_function_configuration")] = [
        *reads[:2],
        *later,
    ]
    return copy.deepcopy(reads[1])


def test_lambda_identical_value_under_later_revision_is_not_reverted():
    aws = FakeAWS(reject_writes=False)
    owned = lambda_reads(aws)
    later = {**owned, "RevisionId": "memory-later-revision"}
    aws.read_overrides[("lambda", "get_function_configuration")].append(later)
    values = {"function_name": FUNCTION, "memory_mb": 128}
    item = make_experiment(MEMORY, values, aws, dry_run=False)
    assert item.modify_memory_limit(**values).status == "completed"
    assert item.lambda_confirmed_revision == "memory-owned-revision"
    with pytest.raises(framework.SafetyViolation, match="revision changed"):
        item.run_rollback()
    assert [w["RevisionId"] for w in writes(aws, "update_function_configuration")] == [
        "memory-original-revision"
    ]
    assert not item.rollback_attempts and not item.rollback_verified
    assert item.lambda_confirmed_revision is None
    assert_recovery_authority_ended(item, aws, "update_function_configuration")


def test_lambda_ambiguous_forward_without_confirmed_revision_cannot_roll_back():
    aws = FakeAWS(reject_writes=False)
    owned = lambda_reads(aws)
    aws.read_overrides[("lambda", "get_function_configuration")] = [
        aws.read_overrides[("lambda", "get_function_configuration")][0],
        owned,
    ]
    respond = aws.respond

    def ambiguous(service, operation, request):
        if operation == "update_function_configuration":
            aws.calls.append((service, operation, request))
            raise TimeoutError("synthetic lost response after the write landed")
        return respond(service, operation, request)

    aws.respond = ambiguous
    values = {"function_name": FUNCTION, "memory_mb": 128}
    item = make_experiment(MEMORY, values, aws, dry_run=False)
    assert item.modify_memory_limit(**values).status == "failed"
    assert item.lambda_confirmed_revision is None
    with pytest.raises(framework.SafetyViolation, match="revision was not confirmed"):
        item.run_rollback()
    assert len(writes(aws, "update_function_configuration")) == 1
    assert not item.rollback_attempts and not item.rollback_verified
    assert_recovery_authority_ended(item, aws, "update_function_configuration")


LAMBDA_HANDLERS = {
    framework.ChaosType.LAMBDA_ERROR_INJECTION: (
        "inject_error",
        {"Environment": {"Variables": {"MODE": "normal", "CHAOS_ERROR_RATE": "0.5"}}},
    ),
    framework.ChaosType.LAMBDA_TIMEOUT_MODIFY: ("modify_timeout", {"Timeout": 1}),
    MEMORY: ("modify_memory_limit", {"MemorySize": 128}),
    framework.ChaosType.LAMBDA_ENVIRONMENT_CORRUPT: (
        "corrupt_environment",
        {"Environment": {"Variables": {"MODE": "chaos"}}},
    ),
}
ORIGINAL_REVISION = "memory-original-revision"


def lambda_handler_case(kind, aws, response, settled_revision, *later):
    """Run one configuration handler whose settled read carries its values."""
    original = copy.deepcopy(
        FakeAWS().respond("lambda", "get_function_configuration", {})
    )
    method, fields = LAMBDA_HANDLERS[kind]
    owned = {**original, **copy.deepcopy(fields), "RevisionId": settled_revision}
    aws.read_overrides[("lambda", "get_function_configuration")] = [
        original,
        owned,
        *[{**owned, **state} for state in later],
    ]
    aws.write_responses[("lambda", "update_function_configuration")] = [response]
    values = action_configs()[kind]
    arguments = {
        name: values[name]
        for name, _, _ in framework.AUTHORIZED_HANDLER_CALLS[kind][1]
        if name in values
    }
    item = make_experiment(kind, values, aws, dry_run=False)
    return item, getattr(item, method)(**arguments), original


@pytest.mark.parametrize("kind", list(LAMBDA_HANDLERS), ids=lambda kind: kind.value)
def test_lambda_settled_revision_differing_from_issued_one_is_never_adopted(kind):
    aws = FakeAWS(reject_writes=False)
    # Another writer's revision carries exactly the requested values.
    item, result, _ = lambda_handler_case(
        kind, aws, {"RevisionId": "rev-forward"}, "rev-other", {}
    )
    assert result.status == "failed"
    assert "settled revision differs" in result.errors[0]
    assert item.lambda_confirmed_revision is None
    assert item.mutation_operations == ["lambda.update_function_configuration"]
    with pytest.raises(framework.SafetyViolation, match="settled revision differs"):
        item.run_rollback()
    assert len(writes(aws, "update_function_configuration")) == 1
    assert not item.rollback_attempts and not item.rollback_verified
    assert_recovery_authority_ended(item, aws, "update_function_configuration")


@pytest.mark.parametrize("kind", list(LAMBDA_HANDLERS), ids=lambda kind: kind.value)
@pytest.mark.parametrize(
    "response",
    [{}, {"RevisionId": ""}, {"RevisionId": ORIGINAL_REVISION}, None],
    ids=["absent", "empty", "prior", "no-body"],
)
def test_lambda_update_without_new_response_revision_establishes_no_ownership(
    kind, response
):
    aws = FakeAWS(reject_writes=False)
    item, result, _ = lambda_handler_case(kind, aws, response, "rev-forward")
    assert result.status == "failed"
    assert "returned no new RevisionId" in result.errors[0]
    assert item.lambda_confirmed_revision is None
    # Even a recovery read at a plausible revision cannot authorize a write.
    with pytest.raises(framework.SafetyViolation, match="returned no new RevisionId"):
        item.run_rollback()
    assert len(writes(aws, "update_function_configuration")) == 1
    assert not item.rollback_attempts
    assert_recovery_authority_ended(item, aws, "update_function_configuration")


@pytest.mark.parametrize("kind", list(LAMBDA_HANDLERS), ids=lambda kind: kind.value)
def test_lambda_settled_issued_revision_owns_one_verified_recovery(kind):
    aws = FakeAWS(reject_writes=False)
    original = FakeAWS().respond("lambda", "get_function_configuration", {})
    restored = {
        name: copy.deepcopy(original[name])
        for name in ("Environment", "Timeout", "MemorySize")
    }
    item, result, _ = lambda_handler_case(
        kind,
        aws,
        {"RevisionId": "rev-forward"},
        "rev-forward",
        {},
        {**restored, "RevisionId": "rev-restored"},
        {**restored, "RevisionId": "rev-restored"},
    )
    assert result.status == "completed", result.errors
    assert item.lambda_confirmed_revision == "rev-forward"
    item.run_rollback()
    assert item.rollback_verified and not item.rollback_errors
    requests = writes(aws, "update_function_configuration")
    assert [request["RevisionId"] for request in requests] == [
        ORIGINAL_REVISION,
        "rev-forward",
    ]
    assert_recovery_authority_ended(item, aws, "update_function_configuration")


def test_lambda_issued_revision_without_requested_values_is_not_confirmed():
    aws = FakeAWS(reject_writes=False)
    original = FakeAWS().respond("lambda", "get_function_configuration", {})
    # The issued revision is observed, but it does not carry the owned value.
    unowned = {**original, "RevisionId": "rev-forward", "MemorySize": 512}
    aws.read_overrides[("lambda", "get_function_configuration")] = [
        original,
        unowned,
        unowned,
    ]
    aws.write_responses[("lambda", "update_function_configuration")] = [
        {"RevisionId": "rev-forward"}
    ]
    values = {"function_name": FUNCTION, "memory_mb": 128}
    item = make_experiment(MEMORY, values, aws, dry_run=False)
    result = item.modify_memory_limit(**values)
    assert result.status == "failed"
    assert "does not carry the requested values" in result.errors[0]
    assert item.lambda_confirmed_revision is None
    with pytest.raises(framework.SafetyViolation, match="not confirmed|conflicts"):
        item.run_rollback()
    assert len(writes(aws, "update_function_configuration")) == 1


def test_lambda_unlanded_environment_forward_verifies_original_without_a_write():
    aws = FakeAWS(reject_writes=False)
    respond = aws.respond

    def lost(service, operation, request):
        if operation == "update_function_configuration":
            aws.calls.append((service, operation, request))
            raise TimeoutError("synthetic failure before the write landed")
        return respond(service, operation, request)

    aws.respond = lost
    kind = framework.ChaosType.LAMBDA_ENVIRONMENT_CORRUPT
    values = action_configs()[kind]
    item = make_experiment(kind, values, aws, dry_run=False)
    assert item.corrupt_environment(**values).status == "failed"
    assert item.lambda_confirmed_revision is None
    # Unowned state already equals the original: no recovery write is minted.
    item.run_rollback()
    assert item.rollback_verified and not item.rollback_attempts
    assert len(writes(aws, "update_function_configuration")) == 1
    assert_recovery_authority_ended(item, aws, "update_function_configuration")


def test_lambda_stop_bound_to_issued_revision_refuses_a_later_one():
    aws = FakeAWS(reject_writes=False)
    owned = lambda_reads(aws)
    original = aws.read_overrides[("lambda", "get_function_configuration")][0]
    later = {**owned, "RevisionId": "memory-later-revision"}
    aws.read_overrides[("lambda", "get_function_configuration")] = [original, later]
    values = {"function_name": FUNCTION, "memory_mb": 128}
    item = make_experiment(MEMORY, values, aws, dry_run=False)
    respond = aws.respond

    def stop_during_write(service, operation, request):
        if operation == "update_function_configuration":
            item.safety_controller.emergency_stop_all()
        return respond(service, operation, request)

    aws.respond = stop_during_write
    result = item.modify_memory_limit(**values)
    assert result.status == "failed"
    # The successful write's own response revision remains the only owner.
    assert item.lambda_confirmed_revision == "memory-owned-revision"
    with pytest.raises(framework.SafetyViolation, match="revision changed"):
        item.run_rollback()
    assert len(writes(aws, "update_function_configuration")) == 1
    assert_recovery_authority_ended(item, aws, "update_function_configuration")


def test_lambda_verified_recovery_is_single_use_and_revokes_grant():
    aws = FakeAWS(reject_writes=False)
    values = prepare_lambda_memory(aws)
    item = make_experiment(MEMORY, values, aws, dry_run=False)
    assert item.modify_memory_limit(**values).status == "completed"
    item.run_rollback()
    assert item.rollback_verified and not item.rollback_errors
    assert item.rollback_operations == ["lambda.update_function_configuration"]
    assert item.lambda_confirmed_revision is None
    assert_recovery_authority_ended(item, aws, "update_function_configuration")
    with pytest.raises(framework.SafetyViolation, match="execution authority"):
        item.lambda_client.update_function_configuration(
            FunctionName=FUNCTION, MemorySize=256, RevisionId="memory-restored-revision"
        )
    refused = item.modify_memory_limit(**values)
    assert refused.status == "failed"
    assert len(writes(aws, "update_function_configuration")) == 2


def test_orchestrated_lambda_later_revision_reports_failed_recovery():
    aws = FakeAWS(reject_writes=False)
    owned = lambda_reads(aws)
    later = {**owned, "RevisionId": "memory-later-revision"}
    aws.read_overrides[("lambda", "get_function_configuration")].append(later)
    values = {"function_name": FUNCTION, "memory_mb": 128}
    orchestrator = make_orchestrator(MEMORY, values, aws, dry_run=False)
    result = orchestrator._run_single_experiment({"type": MEMORY.value, **values})
    assert result.rollback_successful is False and result.status == "failed"
    assert result.mutation_operations == ["lambda.update_function_configuration"]
    assert not result.rollback_attempts
    assert len(writes(aws, "update_function_configuration")) == 1


# Finding 3: a WAF semantic no-op is refused before dispatch and owns nothing.


def no_op_cases():
    base = action_configs()
    custom_block = web_acl("lock-1")
    custom_block["WebACL"]["Rules"][0]["Action"] = {
        "Block": {"CustomResponse": {"ResponseCode": 403}}
    }
    return [
        pytest.param(RULE, {**base[RULE], "action": "BLOCK"}, None, id="rule"),
        pytest.param(
            RULE, {**base[RULE], "action": "block"}, custom_block, id="rule-custom"
        ),
        pytest.param(RATE, {**base[RATE], "limit": 2000}, None, id="rate"),
        pytest.param(
            IP_SET,
            {**base[IP_SET], "addresses_to_add": ["192.0.2.0/32"]},
            None,
            id="ip-existing",
        ),
        pytest.param(
            IP_SET,
            {**base[IP_SET], "addresses_to_add": ["192.0.2.0/24"]},
            ip_set("lock-1", ["192.0.2.7/24"]),
            id="ip-canonical-existing",
        ),
    ]


@pytest.mark.parametrize("kind,values,read", no_op_cases())
@pytest.mark.parametrize("dry_run", [False, True])
def test_waf_semantic_no_op_is_refused_without_ownership(kind, values, read, dry_run):
    aws = FakeAWS(reject_writes=dry_run)
    if read is not None:
        operation = "get_ip_set" if kind == IP_SET else "get_web_acl"
        aws.read_overrides[("wafv2", operation)] = [read]
    item = make_experiment(kind, values, aws, dry_run=dry_run)
    method = {
        RULE: "modify_rule",
        RATE: "modify_rate_limit",
        IP_SET: "modify_ip_set",
    }[kind]
    result = getattr(item, method)(**values)
    assert result.status == "failed"
    assert "no fault would be injected" in result.errors[0]
    assert not item.mutation_attempts and not item.mutation_operations
    assert not any(name.startswith("update_") for _, name, _ in aws.calls)
    for marker in ("changed_rule_name", "original_addresses", "ip_set_id"):
        assert not hasattr(item, marker)


@pytest.mark.parametrize("kind,values,read", no_op_cases())
def test_orchestrated_waf_no_op_is_not_reported_as_chaos_or_recovery(
    kind, values, read
):
    aws = FakeAWS(reject_writes=False)
    if read is not None:
        operation = "get_ip_set" if kind == IP_SET else "get_web_acl"
        aws.read_overrides[("wafv2", operation)] = [read]
    orchestrator = make_orchestrator(kind, values, aws, dry_run=False)
    result = orchestrator._run_single_experiment({"type": kind.value, **values})
    assert result.status == "failed"
    assert any("no fault would be injected" in error for error in result.errors)
    assert result.rollback_successful is None
    assert not result.mutation_attempts and not result.rollback_attempts
    assert not any(name.startswith("update_") for _, name, _ in aws.calls)


def test_waf_ip_set_with_one_new_address_still_dispatches_only_that_ownership():
    aws = FakeAWS(reject_writes=False)
    values = {
        **action_configs()[IP_SET],
        "addresses_to_add": ["192.0.2.0/32", "198.51.100.10/32"],
    }
    orchestrator = make_orchestrator(IP_SET, values, aws, dry_run=False)
    item = orchestrator._create_experiment(IP_SET, values)
    assert item.modify_ip_set(**values).status == "completed"
    assert item.owned_address_additions == {"198.51.100.10/32"}
    assert item.expected_account == ACCOUNT_ID and item.expected_region == REGION


# Prescan c10: queued RDS changes, unreadable Lambda environments, canonical
# WAF ownership, FIS plan parity, unsupported grants and exact DS trust IDs.

RDS_REBOOT = framework.ChaosType.RDS_REBOOT
RDS_FAILOVER = framework.ChaosType.RDS_FAILOVER
RETENTION = framework.ChaosType.RDS_BACKUP_RETENTION_MODIFY
FIS = framework.ChaosType.FIS_TEMPLATE
DS_TRUST = framework.ChaosType.DS_TRUST_DELETE
ENVIRONMENT_HANDLERS = [
    framework.ChaosType.LAMBDA_ERROR_INJECTION,
    framework.ChaosType.LAMBDA_ENVIRONMENT_CORRUPT,
]


def queued_instance(fault: str) -> dict:
    response = copy.deepcopy(FakeAWS().respond("rds", "describe_db_instances", {}))
    instance = response["DBInstances"][0]
    if fault == "pending-modifications":
        instance["PendingModifiedValues"] = {"DBInstanceClass": "db.r6g.large"}
    elif fault == "parameter-pending-reboot":
        instance["DBParameterGroups"][0]["ParameterApplyStatus"] = "pending-reboot"
    elif fault == "parameter-applying":
        instance["DBParameterGroups"].append(
            {"DBParameterGroupName": "other", "ParameterApplyStatus": "applying"}
        )
    elif fault == "parameter-groups-absent":
        del instance["DBParameterGroups"]
    elif fault == "parameter-groups-empty":
        instance["DBParameterGroups"] = []
    elif fault == "option-pending-apply":
        instance["OptionGroupMemberships"][0]["Status"] = "pending-apply"
    return response


QUEUED_FAULTS = [
    "pending-modifications",
    "parameter-pending-reboot",
    "parameter-applying",
    "parameter-groups-absent",
    "parameter-groups-empty",
    "option-pending-apply",
]


@pytest.mark.parametrize("fault", QUEUED_FAULTS)
@pytest.mark.parametrize("kind", [RETENTION, RDS_REBOOT], ids=lambda k: k.value)
def test_rds_apply_immediately_and_reboot_refuse_queued_changes(
    kind, fault, monkeypatch
):
    # Live reboot/retention is planning only; the queued-change checks still
    # apply to the plan as defence in depth.
    aws = FakeAWS(reject_writes=True)
    aws.read_overrides[("rds", "describe_db_instances")] = [queued_instance(fault)]
    # A bounded wait keeps a missing guard a fast failure, never a hang.
    values = {**action_configs()[kind], "state_timeout_seconds": 10}
    item = planning_only_experiment(kind, values, aws)
    monkeypatch.setattr(item, "_wait_forward", lambda seconds: None)
    if kind == RETENTION:
        result = item.modify_backup_retention(
            values["db_identifier"], values["retention_period"]
        )
    else:
        result = item.reboot_db_instance(values["db_instance_identifier"])
    assert result.status == "failed"
    assert "could also apply queued changes" in result.errors[0]
    assert result.additional_info["queued_change_refusal"]
    assert not any(
        name in {"modify_db_instance", "reboot_db_instance"} for _, name, _ in aws.calls
    )
    assert item.mutation_attempts == []
    assert not hasattr(item, "original_retention")


@pytest.mark.parametrize("kind", [RETENTION, RDS_REBOOT], ids=lambda k: k.value)
def test_rds_in_sync_instance_without_pending_changes_is_planned_not_dispatched(
    kind, monkeypatch
):
    aws = FakeAWS(reject_writes=True)
    aws.read_overrides[("rds", "describe_db_instances")] = [queued_instance("none")]
    values = action_configs()[kind]
    item = planning_only_experiment(kind, values, aws)
    monkeypatch.setattr(item, "_wait_forward", lambda seconds: None)
    if kind == RETENTION:
        result = item.modify_backup_retention(**values)
        call = writes(aws, "modify_db_instance")
    else:
        result = item.reboot_db_instance(values["db_instance_identifier"])
        call = writes(aws, "reboot_db_instance")
    assert result.status == "completed", result.errors
    assert "queued_change_refusal" not in result.additional_info
    assert call == [] and item.mutation_attempts == []


@pytest.mark.parametrize("fault", ["cluster-pending", "member-pending-reboot"])
def test_rds_cluster_failover_refuses_queued_changes(fault, monkeypatch):
    aws = FakeAWS(reject_writes=True)
    cluster = copy.deepcopy(FakeAWS().respond("rds", "describe_db_clusters", {}))
    if fault == "cluster-pending":
        cluster["DBClusters"][0]["PendingModifiedValues"] = {"EngineVersion": "8.0.40"}
    else:
        member = cluster["DBClusters"][0]["DBClusterMembers"][1]
        member["DBClusterParameterGroupStatus"] = "pending-reboot"
    aws.read_overrides[("rds", "describe_db_clusters")] = [cluster]
    values = {**action_configs()[RDS_FAILOVER], "state_timeout_seconds": 10}
    item = planning_only_experiment(RDS_FAILOVER, values, aws)
    monkeypatch.setattr(item, "_wait_forward", lambda seconds: None)
    result = item.failover_db_cluster("chaos-test-cluster")
    assert result.status == "failed"
    assert "RDS failover refused" in result.errors[0]
    assert result.additional_info["queued_change_refusal"]
    assert writes(aws, "failover_db_cluster") == []


UNREADABLE_ENVIRONMENTS = {
    "kms-error": {
        "Error": {
            "ErrorCode": "KMSAccessDeniedException",
            "Message": "synthetic-sensitive-decrypt-detail",
        }
    },
    "error-with-variables": {
        "Variables": {"MODE": "normal"},
        "Error": {"ErrorCode": "KMSDisabledException", "Message": "x"},
    },
    "variables-missing": {},
    "not-a-structure": None,
}


def handler_arguments(kind) -> dict:
    values = action_configs()[kind]
    return {
        name: values[name]
        for name, _, _ in framework.AUTHORIZED_HANDLER_CALLS[kind][1]
        if name in values
    }


@pytest.mark.parametrize("dry_run", [False, True], ids=["live", "plan"])
@pytest.mark.parametrize("environment", list(UNREADABLE_ENVIRONMENTS))
@pytest.mark.parametrize("kind", ENVIRONMENT_HANDLERS, ids=lambda k: k.value)
def test_lambda_unreadable_environment_is_never_treated_as_empty(
    kind, environment, dry_run
):
    aws = FakeAWS(reject_writes=dry_run)
    current = copy.deepcopy(
        FakeAWS().respond("lambda", "get_function_configuration", {})
    )
    current["Environment"] = copy.deepcopy(UNREADABLE_ENVIRONMENTS[environment])
    aws.read_overrides[("lambda", "get_function_configuration")] = [current]
    method = LAMBDA_HANDLERS[kind][0]
    item = make_experiment(kind, action_configs()[kind], aws, dry_run=dry_run)
    result = getattr(item, method)(**handler_arguments(kind))
    assert result.status == "failed"
    assert "unreadable" in result.errors[0]
    assert "synthetic-sensitive-decrypt-detail" not in result.errors[0]
    assert writes(aws, "update_function_configuration") == []
    assert not hasattr(item, "original_env")


@pytest.mark.parametrize("kind", ENVIRONMENT_HANDLERS, ids=lambda k: k.value)
def test_lambda_absent_environment_is_genuinely_empty(kind):
    aws = FakeAWS(reject_writes=False)
    original = copy.deepcopy(
        FakeAWS().respond("lambda", "get_function_configuration", {})
    )
    del original["Environment"]
    method = LAMBDA_HANDLERS[kind][0]
    arguments = handler_arguments(kind)
    expected = (
        {"CHAOS_ERROR_RATE": str(arguments["error_rate"])}
        if kind == framework.ChaosType.LAMBDA_ERROR_INJECTION
        else dict(arguments["corrupt_vars"])
    )
    aws.read_overrides[("lambda", "get_function_configuration")] = [
        original,
        {
            **original,
            "RevisionId": "rev-forward",
            "Environment": {"Variables": expected},
        },
    ]
    aws.write_responses[("lambda", "update_function_configuration")] = [
        {"RevisionId": "rev-forward"}
    ]
    item = make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    result = getattr(item, method)(**arguments)
    assert result.status == "completed", result.errors
    assert item.original_env == {}
    assert writes(aws, "update_function_configuration")[0]["Environment"] == {
        "Variables": expected
    }


@pytest.mark.parametrize("environment", list(UNREADABLE_ENVIRONMENTS))
@pytest.mark.parametrize("kind", ENVIRONMENT_HANDLERS, ids=lambda k: k.value)
def test_lambda_recovery_refuses_unreadable_environment(kind, environment):
    aws = FakeAWS(reject_writes=False)
    item, result, _ = lambda_handler_case(
        kind,
        aws,
        {"RevisionId": "rev-forward"},
        "rev-forward",
        {"Environment": copy.deepcopy(UNREADABLE_ENVIRONMENTS[environment])},
    )
    assert result.status == "completed", result.errors
    assert item.lambda_confirmed_revision == "rev-forward"
    with pytest.raises(framework.SafetyViolation, match="unreadable"):
        item.run_rollback()
    # Only the forward write exists; no "restore" of an assumed-empty set.
    assert len(writes(aws, "update_function_configuration")) == 1
    assert not item.rollback_attempts and not item.rollback_verified


@pytest.mark.parametrize("echo_requested", [False, True])
def test_lambda_forward_settling_unreadable_is_not_confirmed(echo_requested):
    kind = framework.ChaosType.LAMBDA_ERROR_INJECTION
    aws = FakeAWS(reject_writes=False)
    original = FakeAWS().respond("lambda", "get_function_configuration", {})
    settled = copy.deepcopy(UNREADABLE_ENVIRONMENTS["kms-error"])
    if echo_requested:
        # Variables that look like the request do not outweigh Environment.Error.
        settled["Variables"] = {"MODE": "normal", "CHAOS_ERROR_RATE": "0.5"}
    aws.read_overrides[("lambda", "get_function_configuration")] = [
        copy.deepcopy(original),
        {
            **copy.deepcopy(original),
            "RevisionId": "rev-forward",
            "Environment": settled,
        },
    ]
    aws.write_responses[("lambda", "update_function_configuration")] = [
        {"RevisionId": "rev-forward"}
    ]
    item = make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    result = item.inject_error(**handler_arguments(kind))
    assert result.status == "failed"
    assert "does not carry the requested values" in result.errors[0]
    assert item.lambda_confirmed_revision is None


IPV6_VALUES = {
    **action_configs()[IP_SET],
    "addresses_to_add": ["2001:db8::/32", "2001:db8:1::/48"],
}


def ipv6_set(token: str, addresses: list[str]) -> dict:
    response = ip_set(token, addresses)
    response["IPSet"]["IPAddressVersion"] = "IPV6"
    return response


def test_waf_equivalent_operator_cidr_is_not_owned_and_survives_recovery():
    aws = FakeAWS(reject_writes=False)
    operator = "2001:DB8::/32"  # The operator's form of an approved address.
    aws.read_overrides[("wafv2", "get_ip_set")] = [
        ipv6_set("lock-1", [operator]),
        # WAF reports the owned addition in a different textual form.
        ipv6_set("lock-2", [operator, "2001:DB8:1::/48"]),
        ipv6_set("lock-3", [operator]),
    ]
    aws.write_responses[("wafv2", "update_ip_set")] = [{"NextLockToken": "lock-2"}]
    item = make_experiment(IP_SET, IPV6_VALUES, aws, dry_run=False)
    assert item.modify_ip_set(**IPV6_VALUES).status == "completed"
    assert item.owned_address_additions == {"2001:db8:1::/48"}
    forward_write = writes(aws, "update_ip_set")[0]
    # No duplicate, unowned equivalent of the operator entry is written.
    assert forward_write["Addresses"] == [operator, "2001:db8:1::/48"]
    item.run_rollback()
    assert item.rollback_verified and not item.rollback_errors
    recovery = writes(aws, "update_ip_set")[-1]
    assert recovery["LockToken"] == "lock-2"
    assert recovery["Addresses"] == [operator]


def test_waf_all_equivalent_cidrs_are_a_refused_no_op():
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("wafv2", "get_ip_set")] = [
        ipv6_set("lock-1", ["2001:DB8::/32", "2001:0db8:0001::/48"])
    ]
    item = make_experiment(IP_SET, IPV6_VALUES, aws, dry_run=False)
    result = item.modify_ip_set(**IPV6_VALUES)
    assert result.status == "failed"
    assert "no fault would be injected" in result.errors[0]
    assert writes(aws, "update_ip_set") == []


def unsafe_fis_template() -> dict:
    instance = f"arn:aws-us-gov:ec2:{REGION}:{ACCOUNT_ID}:instance/i-0123456789abcdef1"
    alarm = f"arn:aws-us-gov:cloudwatch:{REGION}:{ACCOUNT_ID}:alarm:unreviewed"
    return {
        "id": "EXT1234567890abcdef0",
        "roleArn": f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/ChaosFisRole",
        "actions": {"a": {"actionId": "aws:ssm:send-command", "parameters": {}}},
        "targets": {
            "first": {"resourceType": "aws:ec2:instance", "selectionMode": "ALL"},
            "second": {
                "resourceType": "aws:ec2:instance",
                "selectionMode": "COUNT(1)",
                "resourceArns": [instance],
            },
        },
        "stopConditions": [{"source": "aws:cloudwatch:alarm", "value": alarm}],
    }


def test_fis_plan_reports_the_same_structural_violations_as_live():
    aws = FakeAWS()
    plan = make_experiment(FIS, action_configs()[FIS], aws)
    planned = plan._validate_template(unsafe_fis_template())
    plan.dry_run = False
    live = plan._validate_template(unsafe_fis_template())
    assert planned == live
    text = "\n".join(planned)
    for expected in (
        "FIS action 'aws:ssm:send-command' lacks reviewed automatic recovery",
        "FIS template has no CloudWatch alarm stop condition",
        "FIS target #1 uses unbounded selection mode ALL",
        "Live FIS recovery verification requires explicit instance ARNs",
        "FIS target #1 is missing required target tags",
        "FIS target #2 contains ARNs not in target_allowlist",
    ):
        assert expected in text


def test_fis_plan_with_violations_is_not_reported_as_planned():
    aws = FakeAWS()
    aws.read_overrides[("fis", "get_experiment_template")] = [
        {"experimentTemplate": unsafe_fis_template()}
    ]
    plan = make_experiment(FIS, action_configs()[FIS], aws)
    result = plan.run_template(action_configs()[FIS]["experiment_template_id"])
    assert result.status == "failed"
    assert result.additional_info["guardrail_violations"]
    assert "lacks reviewed automatic recovery" in result.errors[0]


def test_fis_plan_skips_only_the_live_alarm_state_read():
    aws = FakeAWS()
    plan = make_experiment(FIS, action_configs()[FIS], aws)
    template = FakeAWS().respond("fis", "get_experiment_template", {})
    assert plan._validate_template(template["experimentTemplate"]) == []
    assert not any(name == "describe_alarms" for _, name, _ in aws.calls)


UNSUPPORTED_LIVE_KINDS = sorted(
    (
        framework.UNSUPPORTED_EXPERIMENTS
        | framework.FIS_TEMPLATE_ONLY_EXPERIMENTS
        | {FIS}
    )
    - framework.CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS,
    key=lambda kind: kind.value,
)


def admitted_owner(aws):
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


@pytest.mark.parametrize("kind", UNSUPPORTED_LIVE_KINDS, ids=lambda k: k.value)
def test_execution_grant_refuses_unsupported_experiment_types(kind):
    aws = FakeAWS(reject_writes=False)
    owner = admitted_owner(aws)
    owner._require_execution_grant(dispatch=True)
    owner._execution_grant = dataclasses.replace(owner._execution_grant, kind=kind)
    with pytest.raises(framework.SafetyViolation, match="reviewed live implementation"):
        owner._require_execution_grant()
    with pytest.raises(framework.SafetyViolation, match="reviewed live implementation"):
        owner.client("kinesis").split_shard(StreamName="chaos-test-stream")
    assert aws.calls == []


@pytest.mark.parametrize(
    "operation",
    [
        "kinesis.split_shard",
        "kinesis.merge_shards",
        "kinesis.update_shard_count",
        "ecs.register_task_definition",
        "cloudfront.update_distribution",
    ],
)
def test_unsupported_only_writes_are_refused_even_inside_admitted_dispatch(
    operation,
):
    aws = FakeAWS(reject_writes=False)
    owner = admitted_owner(aws)
    service, method = operation.split(".")
    proxy = owner.client(service)
    with pytest.raises(framework.SafetyViolation, match="conditional ownership"):
        getattr(proxy, method)(Synthetic="request")
    assert aws.calls == []
    assert owner.mutation_attempts == []


@pytest.mark.parametrize(
    "trusts",
    [
        [{"TrustId": "t-9999999999", "TrustState": "Verified"}],
        [
            {"TrustId": "t-1234567890", "TrustState": "Verified"},
            {"TrustId": "t-9999999999", "TrustState": "Verified"},
        ],
        [{"TrustState": "Verified"}],
    ],
    ids=["other-id", "two-trusts", "missing-id"],
)
@pytest.mark.parametrize("dry_run", [False, True], ids=["live", "plan"])
def test_ds_trust_delete_requires_exactly_the_approved_trust(trusts, dry_run):
    aws = FakeAWS(reject_writes=dry_run)
    aws.read_overrides[("ds", "describe_trusts")] = [{"Trusts": trusts}]
    values = action_configs()[DS_TRUST]
    item = make_experiment(DS_TRUST, values, aws, dry_run=dry_run)
    result = item.delete_trust(values["trust_id"])
    assert result.status == "failed"
    assert "exactly the approved trust" in result.errors[0]
    assert writes(aws, "delete_trust") == []
    assert not hasattr(item, "trust_details")


def test_ds_trust_delete_with_the_exact_approved_trust_proceeds():
    aws = FakeAWS(reject_writes=False)
    values = action_configs()[DS_TRUST]
    item = make_experiment(DS_TRUST, values, aws, dry_run=False)
    result = item.delete_trust(values["trust_id"])
    assert result.status == "completed", result.errors
    assert writes(aws, "delete_trust") == [{"TrustId": values["trust_id"]}]


# Prescan c10 v2: the cluster parameter domain of a clustered-instance reboot,
# instance domains of every failover member, uniform refusal metadata and
# empty-map Lambda recovery verification.

CLUSTER = "chaos-test-cluster"


def rds_instance(identifier: str = "chaos-test-db", **changes) -> dict:
    response = copy.deepcopy(
        FakeAWS().respond(
            "rds", "describe_db_instances", {"DBInstanceIdentifier": identifier}
        )
    )
    response["DBInstances"][0].update(changes)
    return response


def rds_cluster(**changes) -> dict:
    response = copy.deepcopy(FakeAWS().respond("rds", "describe_db_clusters", {}))
    response["DBClusters"][0].update(changes)
    return response


def reboot_member(aws, monkeypatch):
    # Live reboot is planning only; every check below runs against the plan.
    values = {**action_configs()[RDS_REBOOT], "state_timeout_seconds": 10}
    item = planning_only_experiment(RDS_REBOOT, values, aws)
    monkeypatch.setattr(item, "_wait_forward", lambda seconds: None)
    return item, item.reboot_db_instance(values["db_instance_identifier"])


def cluster_member_fault(fault: str):
    cluster = rds_cluster()
    members = cluster["DBClusters"][0]["DBClusterMembers"]
    if fault == "member-cluster-group-pending-reboot":
        members[0]["DBClusterParameterGroupStatus"] = "pending-reboot"
    elif fault == "cluster-pending-modifications":
        cluster["DBClusters"][0]["PendingModifiedValues"] = {"EngineVersion": "8.0"}
    elif fault == "member-missing":
        del members[0]
    elif fault == "member-duplicated":
        members.append(copy.deepcopy(members[0]))
    elif fault == "cluster-not-available":
        cluster["DBClusters"][0]["Status"] = "modifying"
    elif fault == "cluster-not-returned":
        cluster = {"DBClusters": []}
    elif fault == "other-cluster-returned":
        cluster["DBClusters"][0]["DBClusterIdentifier"] = "other-cluster"
    return cluster


CLUSTER_DOMAIN_FAULTS = [
    "member-cluster-group-pending-reboot",
    "cluster-pending-modifications",
    "member-missing",
    "member-duplicated",
    "cluster-not-available",
    "cluster-not-returned",
    "other-cluster-returned",
]


@pytest.mark.parametrize("fault", CLUSTER_DOMAIN_FAULTS)
def test_clustered_reboot_refuses_queued_cluster_parameter_domain(fault, monkeypatch):
    aws = FakeAWS(reject_writes=True)
    # The instance parameter domain itself is clean and available.
    aws.read_overrides[("rds", "describe_db_instances")] = [
        rds_instance(DBClusterIdentifier=CLUSTER)
    ]
    aws.read_overrides[("rds", "describe_db_clusters")] = [cluster_member_fault(fault)]
    item, result = reboot_member(aws, monkeypatch)
    assert result.status == "failed"
    assert "RDS reboot refused" in result.errors[0]
    assert result.additional_info["queued_change_refusal"]
    assert ("rds", "describe_db_clusters", {"DBClusterIdentifier": CLUSTER}) in (
        aws.calls
    )
    assert writes(aws, "reboot_db_instance") == []
    assert item.mutation_attempts == []


def test_clustered_reboot_refuses_when_the_parent_cluster_cannot_be_read(
    monkeypatch,
):
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("rds", "describe_db_instances")] = [
        rds_instance(DBClusterIdentifier=CLUSTER)
    ]
    respond = aws.respond

    def denied(service, operation, request):
        if operation == "describe_db_clusters":
            aws.calls.append((service, operation, request))
            raise FakeClientError("AccessDenied")
        return respond(service, operation, request)

    aws.respond = denied
    item, result = reboot_member(aws, monkeypatch)
    assert result.status == "failed"
    assert (
        result.additional_info["queued_change_refusal"]
        == "the parent DB cluster could not be read"
    )
    assert writes(aws, "reboot_db_instance") == []


@pytest.mark.parametrize("cluster_identifier", ["", None])
def test_clustered_reboot_refuses_unreadable_cluster_identity(
    cluster_identifier, monkeypatch
):
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("rds", "describe_db_instances")] = [
        rds_instance(DBClusterIdentifier=cluster_identifier)
    ]
    item, result = reboot_member(aws, monkeypatch)
    assert result.status == "failed"
    assert "identity is unreadable" in result.additional_info["queued_change_refusal"]
    assert writes(aws, "reboot_db_instance") == []


def test_clean_cluster_member_reboot_is_planned_not_dispatched(monkeypatch):
    aws = FakeAWS(reject_writes=True)
    aws.read_overrides[("rds", "describe_db_instances")] = [
        rds_instance(DBClusterIdentifier=CLUSTER)
    ]
    aws.read_overrides[("rds", "describe_db_clusters")] = [rds_cluster()]
    item, result = reboot_member(aws, monkeypatch)
    assert result.status == "completed", result.errors
    assert "queued_change_refusal" not in result.additional_info
    assert ("rds", "describe_db_clusters", {"DBClusterIdentifier": CLUSTER}) in (
        aws.calls
    )
    assert writes(aws, "reboot_db_instance") == []
    assert item.mutation_attempts == []


def test_unclustered_reboot_reads_no_cluster(monkeypatch):
    aws = FakeAWS(reject_writes=True)
    item, result = reboot_member(aws, monkeypatch)
    assert result.status == "completed", result.errors
    assert not any(name == "describe_db_clusters" for _, name, _ in aws.calls)


def failover(aws, monkeypatch):
    # Live failover is planning only; every check below runs against the plan.
    values = {**action_configs()[RDS_FAILOVER], "state_timeout_seconds": 10}
    item = planning_only_experiment(RDS_FAILOVER, values, aws)
    monkeypatch.setattr(item, "_wait_forward", lambda seconds: None)
    return item, item.failover_db_cluster(CLUSTER)


MEMBER_FAULTS = {
    "member-2-parameter-pending-reboot": (
        "cluster member #2",
        [
            rds_instance("chaos-test-db"),
            rds_instance(
                "chaos-test-reader",
                DBParameterGroups=[
                    {
                        "DBParameterGroupName": "chaos-test-params",
                        "ParameterApplyStatus": "pending-reboot",
                    }
                ],
            ),
        ],
    ),
    "member-1-pending-modifications": (
        "cluster member #1",
        [rds_instance("chaos-test-db", PendingModifiedValues={"Port": 3307})],
    ),
    "member-1-option-group-pending": (
        "cluster member #1",
        [
            rds_instance(
                "chaos-test-db",
                OptionGroupMemberships=[
                    {"OptionGroupName": "o", "Status": "pending-apply"}
                ],
            )
        ],
    ),
    "member-2-other-identity": (
        "cluster member #2",
        [rds_instance("chaos-test-db"), rds_instance("chaos-test-db")],
    ),
    "member-1-not-returned": ("cluster member #1", [{"DBInstances": []}]),
}


@pytest.mark.parametrize("fault", list(MEMBER_FAULTS))
def test_failover_refuses_a_member_with_queued_instance_changes(fault, monkeypatch):
    aws = FakeAWS(reject_writes=True)
    # The cluster-level domain is clean; only a member instance domain is not.
    expected, reads = MEMBER_FAULTS[fault]
    aws.read_overrides[("rds", "describe_db_instances")] = copy.deepcopy(reads)
    item, result = failover(aws, monkeypatch)
    assert result.status == "failed"
    assert "RDS failover refused" in result.errors[0]
    assert result.additional_info["queued_change_refusal"].startswith(expected)
    assert writes(aws, "failover_db_cluster") == []
    assert item.mutation_attempts == []


def test_failover_refuses_when_a_member_cannot_be_read(monkeypatch):
    aws = FakeAWS(reject_writes=False)
    respond = aws.respond

    def denied(service, operation, request):
        if operation == "describe_db_instances":
            aws.calls.append((service, operation, request))
            raise FakeClientError("AccessDenied")
        return respond(service, operation, request)

    aws.respond = denied
    item, result = failover(aws, monkeypatch)
    assert result.status == "failed"
    assert (
        result.additional_info["queued_change_refusal"]
        == "cluster member #1 could not be read"
    )
    assert writes(aws, "failover_db_cluster") == []


def test_failover_member_reads_are_bounded(monkeypatch):
    aws = FakeAWS(reject_writes=False)
    cluster = rds_cluster()
    members = cluster["DBClusters"][0]["DBClusterMembers"]
    members.extend(
        {
            "DBInstanceIdentifier": f"chaos-test-reader-{index}",
            "IsClusterWriter": False,
            "DBClusterParameterGroupStatus": "in-sync",
        }
        for index in range(framework.MAX_RDS_CLUSTER_MEMBERS - 1)
    )
    aws.read_overrides[("rds", "describe_db_clusters")] = [cluster]
    item, result = failover(aws, monkeypatch)
    assert result.status == "failed"
    assert "more members" in result.additional_info["queued_change_refusal"]
    assert not any(name == "describe_db_instances" for _, name, _ in aws.calls)
    assert writes(aws, "failover_db_cluster") == []


def test_clean_failover_reads_every_member_instance_once(monkeypatch):
    aws = FakeAWS(reject_writes=True)
    item, result = failover(aws, monkeypatch)
    assert result.status == "completed", result.errors
    member_reads = [
        request["DBInstanceIdentifier"]
        for _, name, request in aws.calls
        if name == "describe_db_instances"
    ]
    assert member_reads == ["chaos-test-db", "chaos-test-reader"]


@pytest.mark.parametrize(
    ("kind", "reads", "expected"),
    [
        (
            RDS_REBOOT,
            ("describe_db_instances", rds_instance(DBInstanceStatus="rebooting")),
            "the DB instance is not available",
        ),
        (
            RDS_FAILOVER,
            ("describe_db_clusters", rds_cluster(Status="failing-over")),
            "the DB cluster is not available",
        ),
    ],
    ids=["reboot", "failover"],
)
def test_unavailable_targets_record_the_refusal_reason(
    kind, reads, expected, monkeypatch
):
    aws = FakeAWS(reject_writes=False)
    operation, response = reads
    aws.read_overrides[("rds", operation)] = [copy.deepcopy(response)]
    if kind == RDS_REBOOT:
        _item, result = reboot_member(aws, monkeypatch)
    else:
        _item, result = failover(aws, monkeypatch)
    assert result.status == "failed"
    assert result.additional_info["queued_change_refusal"] == expected
    assert not any(
        name in {"reboot_db_instance", "failover_db_cluster"}
        for _, name, _ in aws.calls
    )


def empty_map_recovery(aws, restored_environment):
    """Inject into a function without variables, then restore the empty map."""
    kind = framework.ChaosType.LAMBDA_ERROR_INJECTION
    original = copy.deepcopy(
        FakeAWS().respond("lambda", "get_function_configuration", {})
    )
    del original["Environment"]
    owned = {
        **original,
        "RevisionId": "rev-forward",
        "Environment": {"Variables": {"CHAOS_ERROR_RATE": "0.5"}},
    }
    restored = {**original, "RevisionId": "rev-restored"}
    if restored_environment is not None:
        restored["Environment"] = restored_environment
    aws.read_overrides[("lambda", "get_function_configuration")] = [
        original,
        owned,
        copy.deepcopy(owned),
        copy.deepcopy(restored),
        copy.deepcopy(restored),
    ]
    aws.write_responses[("lambda", "update_function_configuration")] = [
        {"RevisionId": "rev-forward"}
    ]
    item = make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    assert item.inject_error(**handler_arguments(kind)).status == "completed"
    assert item.original_env == {}
    return item


@pytest.mark.parametrize(
    "restored_environment",
    [None, {"Variables": {}}],
    ids=["environment-omitted", "empty-variables"],
)
def test_lambda_restore_to_an_empty_map_verifies(restored_environment):
    aws = FakeAWS(reject_writes=False)
    item = empty_map_recovery(aws, restored_environment)
    item.run_rollback()
    assert item.rollback_verified and not item.rollback_errors
    recovery = writes(aws, "update_function_configuration")[-1]
    assert recovery["Environment"] == {"Variables": {}}


@pytest.mark.parametrize(
    "restored_environment",
    [
        {"Error": {"ErrorCode": "KMSAccessDeniedException", "Message": "x"}},
        {"Variables": {}, "Error": {"ErrorCode": "KMSDisabledException"}},
        {},
    ],
    ids=["error", "error-with-empty-variables", "variables-missing"],
)
def test_lambda_empty_map_restore_never_verifies_unreadable_state(
    restored_environment,
):
    aws = FakeAWS(reject_writes=False)
    item = empty_map_recovery(aws, restored_environment)
    with pytest.raises(framework.SafetyViolation, match="not verified"):
        item.run_rollback()
    assert not item.rollback_verified


def test_waf_log_counts_only_owned_additions():
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("wafv2", "get_ip_set")] = [
        ipv6_set("lock-1", ["2001:DB8::/32"])
    ]
    aws.write_responses[("wafv2", "update_ip_set")] = [{"NextLockToken": "lock-2"}]
    item = make_experiment(IP_SET, IPV6_VALUES, aws, dry_run=False)
    records: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda record: records.append(record.getMessage())
    framework.logger.addHandler(handler)
    level = framework.logger.level
    framework.logger.setLevel(logging.INFO)
    try:
        assert item.modify_ip_set(**IPV6_VALUES).status == "completed"
    finally:
        framework.logger.removeHandler(handler)
        framework.logger.setLevel(level)
    # Two addresses were requested; one is the operator's equivalent entry.
    assert "Added 1 addresses to IP set" in records
