"""Account-free adversarial tests for cloud mutation boundaries."""

import copy

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    REGION,
    FakeAWS,
    action_configs,
    make_experiment,
)

import aws_chaos_framework as framework


def experiment(kind, aws, **config):
    values = {**action_configs()[kind], **config}
    return make_experiment(kind, values, aws, dry_run=False), values


def test_absent_ingress_rule_never_creates_access_on_rollback():
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("ec2", "describe_security_groups")] = [
        {"SecurityGroups": [{"IpPermissions": []}]}
    ]
    item, values = experiment(framework.ChaosType.VPC_SECURITY_GROUP_MODIFY, aws)
    assert item.modify_security_group(**values).status == "failed"
    item.run_rollback()
    assert not any(
        operation.startswith(("authorize_", "revoke_")) for _, operation, _ in aws.calls
    )


def test_lost_revoke_response_restores_only_observed_preexisting_rule():
    aws = FakeAWS(reject_writes=False)
    before = aws.respond("ec2", "describe_security_groups", {})
    aws.read_overrides[("ec2", "describe_security_groups")] = [
        before,
        {"SecurityGroups": [{"IpPermissions": []}]},
    ]
    respond = aws.respond

    def lost(service, operation, request):
        if operation == "revoke_security_group_ingress":
            raise TimeoutError("response lost after write")
        return respond(service, operation, request)

    aws.respond = lost
    item, values = experiment(framework.ChaosType.VPC_SECURITY_GROUP_MODIFY, aws)
    assert item.modify_security_group(**values).status == "failed"
    item.run_rollback()
    restores = [
        request
        for _, operation, request in aws.calls
        if operation == "authorize_security_group_ingress"
    ]
    assert restores[0]["IpPermissions"] == before["SecurityGroups"][0]["IpPermissions"]


def test_emergency_stop_blocks_forward_write_but_allows_recovery():
    aws = FakeAWS(reject_writes=False)
    item, _ = experiment(framework.ChaosType.VPC_SECURITY_GROUP_MODIFY, aws)
    item.safety_controller.emergency_stop.set()
    with pytest.raises(framework.EmergencyStop):
        item.ec2.revoke_security_group_ingress(GroupId="sg-test", IpPermissions=[])
    assert not item.mutation_attempts
    item._in_rollback = True
    item.ec2.authorize_security_group_ingress(GroupId="sg-test", IpPermissions=[])
    assert item.rollback_attempts == ["ec2.authorize_security_group_ingress"]


def test_efs_throttle_cannot_increase_capacity():
    aws = FakeAWS(reject_writes=False)
    item, values = experiment(framework.ChaosType.EFS_THROTTLE_THROUGHPUT, aws)
    values["provisioned_throughput"] = 100000
    assert item.throttle_throughput(**values).status == "failed"
    item.run_rollback()
    assert not any(operation == "update_file_system" for _, operation, _ in aws.calls)


def test_nested_resource_selectors_are_included_in_scope():
    targets = framework.ChaosOrchestrator._target_values(
        {
            "repository_name": "repo",
            "image_ids": [{"imageDigest": "sha256:abc"}],
            "bucket_name": "bucket",
            "objects": [{"Key": "private/file", "VersionId": "v2"}],
            "rule_name": "deny",
        }
    )
    assert {"repo", "sha256:abc", "bucket", "private/file", "v2", "deny"} <= targets


def test_waf_recovery_preserves_concurrent_unrelated_change():
    aws = FakeAWS(reject_writes=False)
    before = aws.respond("wafv2", "get_web_acl", {})
    changed = copy.deepcopy(before)
    changed["WebACL"]["Rules"][0]["Action"] = {"Count": {}}
    changed["WebACL"]["Description"] = "New operator description"
    aws.read_overrides[("wafv2", "get_web_acl")] = [before, changed]
    item, values = experiment(framework.ChaosType.WAF_RULE_MODIFY, aws)
    assert item.modify_rule(**values).status == "completed"
    item.run_rollback()
    writes = [
        request for _, operation, request in aws.calls if operation == "update_web_acl"
    ]
    assert writes[-1]["Description"] == "New operator description"
    assert writes[-1]["Rules"][0]["Action"] == before["WebACL"]["Rules"][0]["Action"]


@pytest.mark.parametrize("attack", ["destructive", "alarm", "aggregate"])
def test_fis_rejects_unreviewed_actions_invalid_alarms_and_aggregate_blast_radius(
    attack,
):
    aws = FakeAWS(reject_writes=False)
    item, values = experiment(
        framework.ChaosType.FIS_TEMPLATE, aws, account_id=ACCOUNT_ID, region=REGION
    )
    template = aws.respond("fis", "get_experiment_template", {})["experimentTemplate"]
    if attack == "destructive":
        template["actions"]["stop"]["actionId"] = "aws:ec2:terminate-instances"
    elif attack == "alarm":
        template["stopConditions"][0]["value"] = "not-an-alarm"
    else:
        template["targets"]["Second"] = copy.deepcopy(template["targets"]["Instances"])
    aws.read_overrides[("fis", "get_experiment_template")] = [
        {"experimentTemplate": template}
    ]
    assert item.run_template(values["experiment_template_id"]).status == "failed"
    assert not any(operation == "start_experiment" for _, operation, _ in aws.calls)


def test_unknown_fis_start_cannot_report_successful_recovery():
    aws = FakeAWS(reject_writes=False)
    item, _ = experiment(framework.ChaosType.FIS_TEMPLATE, aws)
    item.mutation_attempts.append("fis.start_experiment")
    with pytest.raises(framework.SafetyViolation, match="unknown"):
        item.run_rollback()


def test_nacl_recovery_uses_replacement_association_id():
    aws = FakeAWS(reject_writes=False)
    original = aws.respond("ec2", "describe_network_acls", {})
    changed = copy.deepcopy(original)
    changed["NetworkAcls"][0]["NetworkAclId"] = "acl-new"
    changed["NetworkAcls"][0]["Associations"][0]["NetworkAclAssociationId"] = (
        "aclassoc-new"
    )
    aws.read_overrides[("ec2", "describe_network_acls")] = [original, changed, original]
    item, values = experiment(framework.ChaosType.VPC_SUBNET_ACL_MODIFY, aws)
    assert item.modify_subnet_acl(**values).status == "completed"
    item.run_rollback()
    writes = [
        request
        for _, operation, request in aws.calls
        if operation == "replace_network_acl_association"
    ]
    assert writes[-1]["AssociationId"] == "aclassoc-new"
    assert item.rollback_verified


def test_elb_recovery_preserves_port_and_availability_zone():
    aws = FakeAWS(reject_writes=False)
    state = aws.respond("elbv2", "describe_target_health", {})
    target = state["TargetHealthDescriptions"][0]["Target"]
    target["Port"] = 8443
    target["AvailabilityZone"] = "all"
    aws.read_overrides[("elbv2", "describe_target_health")] = [state, state]
    item, values = experiment(
        framework.ChaosType.ELB_REMOVE_TARGETS, aws, target_descriptors=[target]
    )
    assert item.remove_targets(**values).status == "completed"
    item.run_rollback()
    writes = [
        request
        for _, operation, request in aws.calls
        if operation in {"register_targets", "deregister_targets"}
    ]
    assert all(request["Targets"] == [target] for request in writes)


def test_ecs_recovery_does_not_accept_desired_count_without_running_tasks(monkeypatch):
    aws = FakeAWS(reject_writes=False)
    item, _ = experiment(
        framework.ChaosType.ECS_SERVICE_UPDATE, aws, state_timeout_seconds=1
    )
    monkeypatch.setattr(framework.time, "sleep", lambda _: None)
    aws.read_overrides[("ecs", "describe_services")] = [
        {
            "services": [
                {
                    "desiredCount": 1,
                    "runningCount": 0,
                    "pendingCount": 1,
                    "deployments": [{"rolloutState": "IN_PROGRESS"}],
                }
            ]
        }
    ]
    ticks = iter([0, 0, 0.5, 2])
    monkeypatch.setattr(framework.time, "monotonic", lambda: next(ticks, 2))
    with pytest.raises(TimeoutError):
        item._wait_for_service_count("cluster", "service", 1, False)
    assert not item.rollback_verified


def test_confirmation_token_binds_reviewed_plan_and_safety():
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    suite = next(iter(config["experiment_suites"]))
    token = framework.confirmation_token(config, suite)
    changed = copy.deepcopy(config)
    changed["safety"]["max_blast_radius"] += 1
    assert framework.confirmation_token(changed, suite) != token
    changed = copy.deepcopy(config)
    changed["experiment_suites"][suite]["experiments"][0]["duration"] = 301
    assert framework.confirmation_token(changed, suite) != token
    config["safety"]["_runtime_allow_live_without_safety_alarms"] = True
    assert framework.confirmation_token(config, suite) == token


@pytest.mark.parametrize(
    "kind,field",
    [
        (framework.ChaosType.VPC_SECURITY_GROUP_MODIFY, "remove_rule"),
        (framework.ChaosType.RDS_PARAMETER_GROUP_MODIFY, "parameters"),
        (framework.ChaosType.LAMBDA_ENVIRONMENT_CORRUPT, "corrupt_vars"),
        (framework.ChaosType.ELB_REMOVE_TARGETS, "target_descriptors"),
    ],
)
def test_child_selector_requires_exact_allowlist_digest(kind, field):
    config = {"type": kind.value, **action_configs()[kind]}
    config[field] = {"synthetic": "approved"}
    approved = framework.ChaosOrchestrator._target_values(config)
    config[field] = {"synthetic": "different"}
    changed = framework.ChaosOrchestrator._target_values(config)
    assert {value for value in approved if value.startswith("selector:")}
    assert changed - approved


def test_empty_s3_prefix_never_lists_or_deletes_bucket_objects():
    aws = FakeAWS(reject_writes=False)
    item, values = experiment(framework.ChaosType.S3_OBJECT_DELETE, aws, prefix="")
    assert item.delete_objects(**values).status == "failed"
    assert not any(
        op in {"list_objects_v2", "delete_objects"} for _, op, _ in aws.calls
    )


def test_worker_failure_sets_emergency_stop_before_scheduler_reaps():
    import threading
    from types import SimpleNamespace

    orchestrator = object.__new__(framework.ChaosOrchestrator)
    stop = threading.Event()
    orchestrator.safety_controller = SimpleNamespace(emergency_stop_all=stop.set)
    orchestrator._run_single_experiment = lambda _: SimpleNamespace(status="failed")
    result = orchestrator._run_with_failure_policy({}, True)
    assert result.status == "failed"
    assert stop.is_set()


def test_rollback_attempt_is_not_recovery_verification():
    from types import SimpleNamespace

    metadata = SimpleNamespace(rollback="automatic")
    item = SimpleNamespace(
        rollback_errors=[],
        rollback_verified=False,
        rollback_attempts=["s3.put_bucket_policy"],
    )
    assert not framework.ChaosOrchestrator._rollback_outcome(metadata, item)
    item.rollback_verified = True
    assert framework.ChaosOrchestrator._rollback_outcome(metadata, item)


def test_fis_completed_does_not_prove_instances_recovered():
    aws = FakeAWS(reject_writes=False)
    item, _ = experiment(framework.ChaosType.FIS_TEMPLATE, aws)
    item.fis_experiment_id = "synthetic"
    item.recovery_instance_ids = ["i-0123456789abcdef0"]
    aws.read_overrides[("fis", "get_experiment")] = [
        {"experiment": {"state": {"status": "completed"}}}
    ]
    aws.read_overrides[("ec2", "describe_instances")] = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": item.recovery_instance_ids[0],
                            "State": {"Name": "stopped"},
                        }
                    ]
                }
            ]
        }
    ]
    with pytest.raises(framework.SafetyViolation, match="not yet verified"):
        item.run_rollback()
    assert not item.rollback_verified


def test_efs_rollback_refuses_concurrent_operator_throughput():
    aws = FakeAWS(reject_writes=False)
    initial = aws.respond("efs", "describe_file_systems", {})
    owned = copy.deepcopy(initial)
    owned["FileSystems"][0]["ProvisionedThroughputInMibps"] = 1.0
    operator = copy.deepcopy(initial)
    operator["FileSystems"][0]["ProvisionedThroughputInMibps"] = 3.0
    aws.read_overrides[("efs", "describe_file_systems")] = [initial, owned, operator]
    item, values = experiment(framework.ChaosType.EFS_THROTTLE_THROUGHPUT, aws)
    assert item.throttle_throughput(**values).status == "completed"
    with pytest.raises(framework.SafetyViolation, match="concurrent"):
        item.run_rollback()
    assert len([call for call in aws.calls if call[1] == "update_file_system"]) == 1
    assert not item.rollback_verified


def test_lambda_recovery_merges_unrelated_variables_and_uses_revision():
    aws = FakeAWS(reject_writes=False)
    initial = aws.respond("lambda", "get_function_configuration", {})
    initial["RevisionId"] = "rev-original"
    owned = copy.deepcopy(initial)
    owned["Environment"]["Variables"]["MODE"] = "chaos"
    current = copy.deepcopy(owned)
    current["RevisionId"] = "rev-current"
    current["Environment"]["Variables"]["UNRELATED"] = "operator-added"
    restored = copy.deepcopy(current)
    restored["Environment"]["Variables"]["MODE"] = "normal"
    aws.read_overrides[("lambda", "get_function_configuration")] = [
        initial,
        owned,
        current,
        restored,
        restored,
    ]
    item, values = experiment(framework.ChaosType.LAMBDA_ENVIRONMENT_CORRUPT, aws)
    assert item.corrupt_environment(**values).status == "completed"
    item.run_rollback()
    writes = [
        args for _, op, args in aws.calls if op == "update_function_configuration"
    ]
    assert writes[-1]["RevisionId"] == "rev-current"
    assert writes[-1]["Environment"]["Variables"] == {
        "MODE": "normal",
        "UNRELATED": "operator-added",
    }
    assert item.rollback_verified


def test_owned_policy_removal_preserves_concurrent_unrelated_statement():
    import json

    owned = {"Sid": "ChaosFrameworkDeny", "Effect": "Deny"}
    unrelated = {"Sid": "OperatorAdded", "Effect": "Allow"}
    policy = json.dumps({"Version": "2012-10-17", "Statement": [owned, unrelated]})
    assert framework.remove_owned_policy_statement(policy, owned)["Statement"] == [
        unrelated
    ]
    changed = {"Sid": "ChaosFrameworkDeny", "Effect": "Allow"}
    with pytest.raises(framework.SafetyViolation):
        framework.remove_owned_policy_statement(
            json.dumps({"Statement": [changed]}), owned
        )
