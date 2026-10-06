"""Generation-bound, single-use WAF/Lambda recovery and WAF no-op refusal.

Ordinary sequential fakes only; no AWS calls and no credentials.
"""

from __future__ import annotations

import copy

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    REGION,
    FakeAWS,
    action_configs,
    make_experiment,
    make_orchestrator,
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
