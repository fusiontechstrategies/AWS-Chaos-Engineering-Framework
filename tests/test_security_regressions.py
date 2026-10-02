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
    item, values = experiment(framework.ChaosType.ELB_REMOVE_TARGETS, aws)
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
