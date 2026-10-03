"""Account-free adversarial tests for cloud mutation boundaries."""

import copy
from types import SimpleNamespace

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    INSTANCE_ID,
    REGION,
    FakeAWS,
    FakeSafetyController,
    action_configs,
    make_experiment,
)

import aws_chaos_framework as framework


def experiment(kind, aws, **config):
    values = {**action_configs()[kind], **config}
    if not framework.experiment_metadata(kind).live_supported:
        before = list(aws.calls)
        with pytest.raises(
            framework.ConfigurationError,
            match="Live (approval is unavailable|FIS approval is disabled)",
        ):
            make_experiment(kind, values, aws, dry_run=False)
        assert aws.calls == before
        return make_experiment(kind, values, aws, dry_run=True), values
    return make_experiment(kind, values, aws, dry_run=False), values


def raw_owner(config, controller):
    if config.get("dry_run", True):
        return framework.ChaosExperiment(config, controller)
    clients = (
        controller.aws
        if isinstance(controller, FakeSafetyController)
        else SimpleNamespace(
            client=lambda service: controller.session.client(
                service, region_name=config.get("region", REGION)
            )
        )
    )
    return make_experiment(
        framework.ChaosType.EC2_REBOOT,
        {"instance_ids": [INSTANCE_ID], "region": config.get("region", REGION)},
        clients,
        dry_run=False,
    )


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


def test_unsupported_ingress_never_infers_forward_or_restore_ownership():
    aws = FakeAWS(reject_writes=False)
    item, values = experiment(framework.ChaosType.VPC_SECURITY_GROUP_MODIFY, aws)
    assert item.modify_security_group(**values).status == "completed"
    item.run_rollback()
    assert not getattr(item, "ingress_write_confirmed", False)
    assert not hasattr(item, "removed_rule")
    assert not any(
        operation.startswith(("authorize_", "revoke_")) for _, operation, _ in aws.calls
    )


def test_emergency_stop_blocks_forward_write_but_allows_recovery():
    aws = FakeAWS(reject_writes=False)
    running = aws.respond("ec2", "describe_instances", {})
    stopped = copy.deepcopy(running)
    stopped["Reservations"][0]["Instances"][0]["State"]["Name"] = "stopped"
    aws.read_overrides[("ec2", "describe_instances")] = [
        running,
        stopped,
        stopped,
        running,
    ]
    item, values = experiment(framework.ChaosType.EC2_STOP, aws)
    assert item.stop_instances(**values).status == "completed"
    item.safety_controller.emergency_stop.set()
    before = list(aws.calls)
    with pytest.raises(framework.SafetyViolation, match="active approved handler"):
        item.ec2.stop_instances(InstanceIds=[INSTANCE_ID])
    assert aws.calls == before
    assert item.stop_instances(**values).status == "failed"
    assert item.mutation_attempts == ["ec2.stop_instances"]
    item.run_rollback()
    assert item.rollback_attempts == ["ec2.start_instances"]
    assert item.rollback_verified


def test_efs_throttle_cannot_increase_capacity():
    aws = FakeAWS(reject_writes=False)
    item, values = experiment(framework.ChaosType.EFS_THROTTLE_THROUGHPUT, aws)
    values["provisioned_throughput"] = 100000
    refused = item.throttle_throughput(**values)
    assert refused.status == "failed"
    assert "arguments differ" in refused.errors[0]
    with pytest.raises(
        framework.SafetyViolation, match="completed approved handler lifecycle"
    ):
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
    aws.read_overrides[("wafv2", "get_web_acl")] = [before, changed, changed]
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
    values = action_configs()[framework.ChaosType.FIS_TEMPLATE]
    template = aws.respond("fis", "get_experiment_template", {})["experimentTemplate"]
    if attack == "destructive":
        template["actions"]["stop"]["actionId"] = "aws:ec2:terminate-instances"
    elif attack == "alarm":
        template["stopConditions"][0]["value"] = "not-an-alarm"
    else:
        template["targets"]["Second"] = copy.deepcopy(template["targets"]["Instances"])
    before = list(aws.calls)
    with pytest.raises(
        framework.ConfigurationError, match="Live FIS approval is disabled"
    ):
        make_experiment(framework.ChaosType.FIS_TEMPLATE, values, aws, dry_run=False)
    assert aws.calls == before
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
    changed["NetworkAcls"][0]["NetworkAclId"] = action_configs()[
        framework.ChaosType.VPC_SUBNET_ACL_MODIFY
    ]["nacl_id"]
    changed["NetworkAcls"][0]["Associations"][0]["NetworkAclAssociationId"] = (
        "aclassoc-new"
    )
    aws.read_overrides[("ec2", "describe_network_acls")] = [original, changed, original]
    original_respond = aws.respond

    def response(service, operation, request):
        value = original_respond(service, operation, request)
        if operation == "replace_network_acl_association":
            return {"NewAssociationId": "aclassoc-new"}
        return value

    aws.respond = response
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
        framework.ChaosType.ECS_SERVICE_UPDATE, aws, state_timeout_seconds=10
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
    ticks = iter([0, 0, 0.5, 11])
    monkeypatch.setattr(framework.time, "monotonic", lambda: next(ticks, 11))
    with pytest.raises(TimeoutError):
        item._wait_for_service_count("cluster", "service", 1, False)
    assert not item.rollback_verified


def test_confirmation_token_binds_reviewed_plan_and_safety():
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    for suite_config in config["experiment_suites"].values():
        for action in suite_config["experiments"]:
            if action.get("instance_ids") in ("@discovered", "@random_discovered"):
                action["instance_ids"] = ["i-0123456789abcdef0"]
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
    with pytest.raises(framework.ConfigurationError, match="prefix"):
        experiment(framework.ChaosType.S3_OBJECT_DELETE, aws, prefix="")
    assert not aws.calls


def test_worker_failure_sets_emergency_stop_before_scheduler_reaps():
    import threading
    from types import SimpleNamespace

    orchestrator = object.__new__(framework.ChaosOrchestrator)
    orchestrator.live = False
    stop = threading.Event()
    orchestrator.safety_controller = SimpleNamespace(emergency_stop_all=stop.set)
    orchestrator._run_single_experiment = lambda _: SimpleNamespace(
        status="failed", rollback_successful=None
    )
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


def test_rds_retention_cannot_claim_data_recovery_even_without_concurrent_change():
    aws = FakeAWS(reject_writes=False)
    original = aws.respond("rds", "describe_db_instances", {})
    owned = copy.deepcopy(original)
    owned["DBInstances"][0]["BackupRetentionPeriod"] = 0
    operator = copy.deepcopy(original)
    operator["DBInstances"][0]["BackupRetentionPeriod"] = 14
    aws.read_overrides[("rds", "describe_db_instances")] = [original, owned, operator]
    item, values = experiment(framework.ChaosType.RDS_BACKUP_RETENTION_MODIFY, aws)
    assert item.modify_backup_retention(**values).status == "completed"
    with pytest.raises(framework.SafetyViolation, match="irreversible"):
        item.run_rollback()
    assert len([call for call in aws.calls if call[1] == "modify_db_instance"]) == 1
    assert not item.rollback_verified


def test_rds_original_retention_with_pending_change_is_not_verified():
    aws = FakeAWS(reject_writes=False)
    original = aws.respond("rds", "describe_db_instances", {})
    owned = copy.deepcopy(original)
    owned["DBInstances"][0]["BackupRetentionPeriod"] = 0
    current = copy.deepcopy(original)
    current["DBInstances"][0]["PendingModifiedValues"] = {"BackupRetentionPeriod": 0}
    aws.read_overrides[("rds", "describe_db_instances")] = [original, owned, current]
    item, values = experiment(framework.ChaosType.RDS_BACKUP_RETENTION_MODIFY, aws)
    assert item.modify_backup_retention(**values).status == "completed"
    with pytest.raises(framework.SafetyViolation, match="irreversible"):
        item.run_rollback()
    assert item.mutation_attempts == ["rds.modify_db_instance"]
    assert not item.rollback_verified


RECOVERY_ACTIONS = [
    "vpc_route_table_modify",
    "vpc_security_group_modify",
    "vpc_nacl_block_traffic",
    "sqs_queue_policy_restrict",
    "sqs_message_delay",
    "sqs_visibility_timeout",
    "elb_modify_attributes",
    "elb_listener_rule_modify",
    "elb_health_check_modify",
    "ecs_container_instance_drain",
    "waf_rule_modify",
    "waf_rate_limit_modify",
    "waf_ip_set_modify",
    "kms_key_disable",
    "kms_key_policy_restrict",
    "iam_policy_detach",
    "iam_role_modify",
    "iam_user_access_key_deactivate",
    "ds_conditional_forwarder_delete",
    "appstream_stack_disassociate",
    "ecr_repository_policy_restrict",
    "codecommit_trigger_delete",
]


@pytest.mark.parametrize("action", RECOVERY_ACTIONS)
def test_extension_recovery_requires_original_post_state(action):
    kind = framework.ChaosType(action)
    aws = FakeAWS(reject_writes=False)
    if action == "vpc_security_group_modify":
        before = aws.respond("ec2", "describe_security_groups", {})
        aws.read_overrides[("ec2", "describe_security_groups")] = [
            before,
            {"SecurityGroups": [{"IpPermissions": []}]},
        ]
    if action == "ecs_container_instance_drain":
        before = aws.respond("ecs", "describe_container_instances", {})
        owned = copy.deepcopy(before)
        owned["containerInstances"][0]["status"] = "DRAINING"
        aws.read_overrides[("ecs", "describe_container_instances")] = [before, owned]
    if action in {"waf_rule_modify", "waf_rate_limit_modify"}:
        before = aws.respond("wafv2", "get_web_acl", {})
        owned = copy.deepcopy(before)
        if action == "waf_rule_modify":
            owned["WebACL"]["Rules"][0]["Action"] = {"Count": {}}
        else:
            owned["WebACL"]["Rules"][0]["Statement"]["RateBasedStatement"]["Limit"] = (
                action_configs()[kind]["limit"]
            )
        aws.read_overrides[("wafv2", "get_web_acl")] = [before, owned, owned, before]
    item, values = experiment(kind, aws)
    orchestrator = object.__new__(framework.ChaosOrchestrator)
    if kind in framework.CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS:
        assert item.dry_run
        assert (
            orchestrator._execute_experiment(item, kind, values).status == "completed"
        )
        assert not item.mutation_attempts
        assert all(
            operation in framework.READ_ONLY_OPERATIONS.get(service, ())
            for service, operation, _ in aws.calls
        )
        return
    result = orchestrator._execute_experiment(item, kind, values)
    assert result.status == "completed", result.errors
    item.run_rollback()
    assert item.rollback_verified
    item.rollback_verified = False
    # Successful recovery writes cannot compensate for unreadable post-state.
    respond = aws.respond

    def missing_state(service, operation, request):
        if operation in framework.READ_ONLY_OPERATIONS.get(service, ()):
            return {}
        return respond(service, operation, request)

    aws.respond = missing_state
    with pytest.raises((framework.SafetyViolation, KeyError)):
        item._verify_additional_recovery()
    assert not item.rollback_verified


def test_constructor_live_token_matches_offline_token_without_config_mutation(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    for suite_config in config["experiment_suites"].values():
        for action in suite_config["experiments"]:
            if action.get("instance_ids") in ("@discovered", "@random_discovered"):
                action["instance_ids"] = ["i-0123456789abcdef0"]
    path = tmp_path / "config.yaml"
    path.write_text(framework.yaml.safe_dump(config))
    aws = FakeAWS()
    identity = SimpleNamespace(
        get_caller_identity=lambda: {
            "Account": ACCOUNT_ID,
            "Arn": f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/ChaosOperator",
        }
    )
    frozen = SimpleNamespace(access_key="ASIA" + "Z" * 16, token="synthetic")
    session = SimpleNamespace(
        client=lambda service, **kwargs: (
            identity if service == "sts" else aws.client(service)
        ),
        get_credentials=lambda: SimpleNamespace(get_frozen_credentials=lambda: frozen),
    )
    monkeypatch.setattr(framework.boto3, "Session", lambda **kwargs: session)
    monkeypatch.setattr(framework.atexit, "register", lambda *args: None)
    monkeypatch.setattr(framework.signal, "signal", lambda *args: None)
    item = framework.ChaosOrchestrator(
        str(path),
        live=True,
        profile="test",
        seed=7,
        output_dir=str(tmp_path / "reports"),
    )
    suite = next(iter(config["experiment_suites"]))
    scope = {"profile": "test", "role_arn": None, "vpc_id": None, "seed": 7}
    token = framework.confirmation_token(config, suite, scope)
    assert item.expected_confirmation(suite, False) == token
    assert "dry_run" not in item.config["global"]
    for key, value in (
        ("vpc_id", "vpc-0123456789abcdef0"),
        ("seed", 8),
        ("role_arn", f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/another-approved-role"),
        ("profile", "other"),
    ):
        assert (
            framework.confirmation_token(config, suite, {**scope, key: value}) != token
        )


@pytest.mark.parametrize(
    "kind",
    [
        framework.ChaosType.LAMBDA_TIMEOUT_MODIFY,
        framework.ChaosType.LAMBDA_MEMORY_LIMIT,
    ],
)
def test_lambda_scalar_forward_write_rejects_revision_conflict(kind):
    aws = FakeAWS(reject_writes=False)
    initial = aws.respond("lambda", "get_function_configuration", {})
    initial["RevisionId"] = "reviewed-revision"
    aws.read_overrides[("lambda", "get_function_configuration")] = [initial]
    respond = aws.respond

    def concurrent(service, operation, request):
        if operation == "update_function_configuration":
            assert request["RevisionId"] == "reviewed-revision"
            raise RuntimeError("PreconditionFailedException: concurrent revision")
        return respond(service, operation, request)

    aws.respond = concurrent
    item, values = experiment(kind, aws)
    result = object.__new__(framework.ChaosOrchestrator)._execute_experiment(
        item, kind, values
    )
    assert result.status == "failed"
    assert any("concurrent revision" in value for value in result.errors)


def test_rds_parameter_filter_uses_service_supported_name():
    aws = FakeAWS(reject_writes=False)
    item, _ = experiment(framework.ChaosType.RDS_PARAMETER_GROUP_MODIFY, aws)
    item._wait_for_parameters(
        "synthetic",
        [{"ParameterName": "max_connections", "ParameterValue": "100"}],
        False,
    )
    requests = [
        args for service, op, args in aws.calls if op == "describe_db_parameters"
    ]
    assert requests and all(
        args["Filters"][0]["Name"] == "parameter-name" for args in requests
    )


@pytest.mark.parametrize("placeholder", ["@discovered", "@random_discovered"])
def test_live_discovery_cannot_bypass_reviewed_target_approval(placeholder):
    item = object.__new__(framework.ChaosOrchestrator)
    item.live = True
    with pytest.raises(framework.SafetyViolation, match="concrete"):
        item._prepare_experiment_config({"instance_ids": placeholder})
    item.config = {"safety": {"max_blast_radius": 1, "target_allowlist": []}}
    item._discovered_target_values = {"i-0123456789abcdef0"}
    with pytest.raises(framework.SafetyViolation, match="allowlist"):
        item._validate_target_scope(
            framework.ChaosType.EC2_STOP, {"instance_ids": ["i-0123456789abcdef0"]}
        )


def test_managed_fis_recovery_is_required_when_auto_rollback_disabled():
    aws = FakeAWS(reject_writes=False)
    values = {
        **action_configs()[framework.ChaosType.FIS_TEMPLATE],
        "auto_rollback": False,
    }
    with pytest.raises(
        framework.ConfigurationError, match="Live FIS approval is disabled"
    ):
        make_experiment(framework.ChaosType.FIS_TEMPLATE, values, aws, dry_run=False)
    assert not aws.calls
    metadata = framework.experiment_metadata(framework.ChaosType.FIS_TEMPLATE)
    assert metadata.rollback == "managed"
    evidence = SimpleNamespace(
        rollback_errors=[], rollback_verified=False, rollback_attempts=[]
    )
    assert not framework.ChaosOrchestrator._rollback_outcome(metadata, evidence)


def test_waf_ip_set_recovery_preserves_concurrent_addresses_and_description():
    aws = FakeAWS(reject_writes=False)
    original = aws.respond("wafv2", "get_ip_set", {})
    original["IPSet"]["Addresses"] = ["192.0.2.0/24"]
    original["IPSet"]["Description"] = "original"
    concurrent = copy.deepcopy(original)
    concurrent["IPSet"]["Addresses"] += ["198.51.100.0/24", "203.0.113.0/24"]
    concurrent["IPSet"]["Description"] = "operator update"
    concurrent["LockToken"] = "operator-lock"
    restored = copy.deepcopy(concurrent)
    restored["IPSet"]["Addresses"].remove("198.51.100.0/24")
    aws.read_overrides[("wafv2", "get_ip_set")] = [original, concurrent, restored]
    item, values = experiment(
        framework.ChaosType.WAF_IP_SET_MODIFY,
        aws,
        addresses_to_add=["192.0.2.0/24", "198.51.100.0/24"],
    )
    item.safety_controller.config.update(
        target_allowlist=sorted(
            framework.ChaosOrchestrator._target_values(
                {"type": "waf_ip_set_modify", **values}
            )
        ),
        max_blast_radius=3,
    )
    assert item.modify_ip_set(**values).status == "completed"
    item.run_rollback()
    writes = [
        request for _, operation, request in aws.calls if operation == "update_ip_set"
    ]
    assert writes[-1]["Addresses"] == ["192.0.2.0/24", "203.0.113.0/24"]
    assert writes[-1]["Description"] == "operator update"
    assert writes[-1]["LockToken"] == "operator-lock"
    assert item.rollback_verified


@pytest.mark.parametrize("ipv4", [["192.0.2.10"], []])
def test_directory_service_restores_and_verifies_dual_stack_targets(ipv4):
    aws = FakeAWS(reject_writes=False)
    original = aws.respond("ds", "describe_conditional_forwarders", {})
    forwarder = original["ConditionalForwarders"][0]
    forwarder["DnsIpAddrs"] = ipv4
    forwarder["DnsIpv6Addrs"] = ["2001:db8::10"]
    aws.read_overrides[("ds", "describe_conditional_forwarders")] = [original, original]
    item, values = experiment(framework.ChaosType.DS_CONDITIONAL_FORWARDER_DELETE, aws)
    assert item.delete_conditional_forwarder(**values).status == "completed"
    item.run_rollback()
    request = next(
        request
        for _, operation, request in aws.calls
        if operation == "create_conditional_forwarder"
    )
    assert request["DnsIpv6Addrs"] == ["2001:db8::10"]
    assert request.get("DnsIpAddrs", []) == ipv4
    assert item.rollback_verified
    missing_ipv6 = copy.deepcopy(original)
    missing_ipv6["ConditionalForwarders"][0]["DnsIpv6Addrs"] = []
    aws.read_overrides[("ds", "describe_conditional_forwarders")] = [missing_ipv6]
    with pytest.raises(framework.SafetyViolation):
        item._verify_additional_recovery()
    wrong_scope = copy.deepcopy(original)
    wrong_scope["ConditionalForwarders"][0]["ReplicationScope"] = "Forest"
    aws.read_overrides[("ds", "describe_conditional_forwarders")] = [wrong_scope]
    with pytest.raises(framework.SafetyViolation):
        item._verify_additional_recovery()


def test_directory_service_rejects_unrestorable_replication_scope_before_delete():
    aws = FakeAWS(reject_writes=False)
    original = aws.respond("ds", "describe_conditional_forwarders", {})
    original["ConditionalForwarders"][0]["ReplicationScope"] = "Forest"
    aws.read_overrides[("ds", "describe_conditional_forwarders")] = [original]
    item, values = experiment(framework.ChaosType.DS_CONDITIONAL_FORWARDER_DELETE, aws)
    assert item.delete_conditional_forwarder(**values).status == "failed"
    assert not any(
        operation == "delete_conditional_forwarder" for _, operation, _ in aws.calls
    )


@pytest.mark.parametrize("ambiguous", [False, True])
def test_waf_rejected_or_ambiguous_forward_write_never_claims_address_ownership(
    ambiguous,
):
    from botocore.exceptions import ClientError

    aws = FakeAWS(reject_writes=False)
    original = aws.respond("wafv2", "get_ip_set", {})
    original["IPSet"]["Addresses"] = ["192.0.2.0/24"]
    concurrent = copy.deepcopy(original)
    concurrent["IPSet"]["Addresses"] += ["198.51.100.0/24", "203.0.113.0/24"]
    concurrent["IPSet"]["Description"] = "operator-owned"
    aws.read_overrides[("wafv2", "get_ip_set")] = [original, concurrent]
    respond = aws.respond

    def race(service, operation, request):
        if operation == "update_ip_set":
            if ambiguous:
                raise TimeoutError("unknown forward outcome")
            raise ClientError(
                {
                    "Error": {
                        "Code": "WAFOptimisticLockException",
                        "Message": "stale lock",
                    }
                },
                operation,
            )
        return respond(service, operation, request)

    aws.respond = race
    values = {
        **action_configs()[framework.ChaosType.WAF_IP_SET_MODIFY],
        "addresses_to_add": ["198.51.100.0/24"],
    }
    from test_aws_chaos_framework import make_orchestrator

    orchestrator = make_orchestrator(
        framework.ChaosType.WAF_IP_SET_MODIFY, values, aws, dry_run=False
    )
    result = orchestrator._run_single_experiment(
        {"type": "waf_ip_set_modify", **values}
    )
    assert result.status == "failed"
    assert result.rollback_successful is False
    assert not result.rollback_attempts
    assert not result.rollback_operations
    assert not any(op == "update_ip_set" for _, op, _ in aws.calls)


# Offline controls for the validated d104 target-identity findings.
DIGEST = "sha256:" + "1" * 64


def config_for(values):
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    config["global"]["region"] = REGION
    config["experiment_suites"] = {"reviewed": {"experiments": [values]}}
    return config


@pytest.mark.parametrize(
    "kind,key,service,resource",
    [
        (
            "kms_grant_revoke",
            "key_id",
            "kms",
            "key/01234567-89ab-cdef-0123-456789abcdef",
        ),
        (
            "sns_subscription_delete",
            "subscription_arn",
            "sns",
            "reviewed-topic:01234567-89ab-cdef-0123-456789abcdef",
        ),
        ("sns_topic_policy_restrict", "topic_arn", "sns", "reviewed-topic"),
        (
            "elb_remove_targets",
            "target_group_arn",
            "elasticloadbalancing",
            "targetgroup/reviewed/0123456789abcdef",
        ),
        ("ecs_task_stop", "cluster", "ecs", "cluster/reviewed"),
        ("ecs_task_stop", "task_arns", "ecs", "task/reviewed/0123456789abcdef"),
        ("lambda_throttle", "function_name", "lambda", "function:reviewed"),
    ],
)
@pytest.mark.parametrize(
    "change", ["account", "region", "partition", "service", "wildcard", "valid"]
)
def test_offline_config_and_token_bind_typed_arn(kind, key, service, resource, change):
    arn = f"arn:aws-us-gov:{service}:{REGION}:{ACCOUNT_ID}:{resource}"
    if change == "account":
        arn = arn.replace(ACCOUNT_ID, "999900001111")
    elif change == "region":
        arn = arn.replace(REGION, "us-gov-east-1")
    elif change == "partition":
        arn = arn.replace("aws-us-gov", "aws", 1)
    elif change == "service":
        arn = arn.replace(f":{service}:", ":s3:", 1)
    elif change == "wildcard":
        arn += "*"
    values = {"type": kind, **action_configs()[framework.ChaosType(kind)]}
    values[key] = [arn] if key == "task_arns" else arn
    config = config_for(values)
    if change == "valid":
        framework.validate_config_data(config)
        if framework.ChaosType(kind) in framework.CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS:
            with pytest.raises(
                framework.ConfigurationError,
                match="Live (approval is unavailable|FIS approval is disabled)",
            ):
                framework.confirmation_token(config, "reviewed")
        else:
            assert framework.confirmation_token(config, "reviewed").startswith("LIVE")
    else:
        with pytest.raises(framework.ConfigurationError):
            framework.validate_config_data(config)
        with pytest.raises(framework.ConfigurationError):
            framework.confirmation_token(config, "reviewed")


@pytest.mark.parametrize(
    "service,operation,key",
    [
        ("kms", "revoke_grant", "KeyId"),
        ("sns", "unsubscribe", "SubscriptionArn"),
        ("ecs", "stop_task", "task"),
        ("elbv2", "deregister_targets", "TargetGroupArn"),
    ],
)
@pytest.mark.parametrize("recovery", [False, True])
def test_direct_sdk_foreign_arn_never_reaches_mutation(
    service, operation, key, recovery
):
    aws = FakeAWS(reject_writes=False)
    owner = raw_owner(
        {"account_id": ACCOUNT_ID, "region": REGION, "dry_run": False},
        FakeSafetyController(aws, live=True),
    )
    owner._in_rollback = recovery
    arn_service = "elasticloadbalancing" if service == "elbv2" else service
    arn = f"arn:aws-us-gov:{arn_service}:{REGION}:999900001111:reviewed-resource"
    with pytest.raises(framework.SafetyViolation):
        getattr(owner.client(service), operation)(**{key: arn})
    assert not aws.calls and not owner.mutation_attempts and not owner.rollback_attempts


def test_global_arn_exceptions_are_narrow_and_explicit():
    framework.validate_resource_arn(
        f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/Reviewed", "iam", ACCOUNT_ID, REGION
    )
    framework.validate_resource_arn(
        "arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess",
        "iam",
        ACCOUNT_ID,
        REGION,
        aws_managed_policy=True,
    )
    framework.validate_resource_arn(
        "arn:aws-us-gov:s3:::reviewed-bucket", "s3", ACCOUNT_ID, REGION
    )
    framework.validate_resource_arn(
        f"arn:aws:cloudfront::{ACCOUNT_ID}:distribution/REVIEWED",
        "cloudfront",
        ACCOUNT_ID,
        "us-east-1",
    )
    for arn, service in [
        ("arn:aws-us-gov:kms:::key/reviewed", "kms"),
        ("arn:aws-us-gov:iam::aws:role/Reviewed", "iam"),
        ("arn:aws-us-gov:s3:::reviewed-bucket/objects", "s3"),
        (f"arn:aws-us-gov:iam:{REGION}:{ACCOUNT_ID}:role/Reviewed", "iam"),
    ]:
        with pytest.raises(framework.SafetyViolation):
            framework.validate_resource_arn(
                arn, service, ACCOUNT_ID, REGION, aws_managed_policy=True
            )


@pytest.mark.parametrize(
    "selector",
    [
        [{"imageTag": "chaos-test"}],
        [{"imageDigest": DIGEST, "imageTag": "chaos-test"}],
        [{"imageDigest": "sha256:short"}],
        [{"imageDigest": DIGEST}, {"imageDigest": DIGEST}],
    ],
)
def test_live_tag_or_unproven_digest_refused_before_reads_and_token(selector):
    aws = FakeAWS(reject_writes=False)
    values = {"repository_name": "chaos-test-repository", "image_ids": selector}
    with pytest.raises((framework.ConfigurationError, framework.SafetyViolation)):
        make_experiment(
            framework.ChaosType.ECR_IMAGE_DELETE, values, aws, dry_run=False
        )
    assert not aws.calls
    config = config_for({"type": "ecr_image_delete", **values})
    with pytest.raises((framework.ConfigurationError, framework.SafetyViolation)):
        framework.confirmation_token(config, "reviewed")


def test_reviewed_digest_reaches_ecr_with_account_binding_not_a_tag():
    aws = FakeAWS(reject_writes=False)
    values = {
        "repository_name": "chaos-test-repository",
        "image_ids": [{"imageDigest": DIGEST}],
    }
    item = make_experiment(
        framework.ChaosType.ECR_IMAGE_DELETE, values, aws, dry_run=False
    )
    item.safety_controller.config.update(
        target_allowlist=[values["repository_name"], DIGEST], max_blast_radius=1
    )
    result = item.delete_images(**values)
    assert result.status == "completed", result.errors
    request = next(r for _, op, r in aws.calls if op == "batch_delete_image")
    assert request["imageIds"] == [{"imageDigest": DIGEST}]
    assert request["registryId"] == ACCOUNT_ID
    assert result.affected_resources == [values["repository_name"] + "/" + DIGEST]


def test_tags_remain_planning_only_without_changing_delete_semantics():
    aws = FakeAWS()
    values = {
        "repository_name": "chaos-test-repository",
        "image_ids": [{"imageTag": "chaos-test"}],
    }
    item = make_experiment(framework.ChaosType.ECR_IMAGE_DELETE, values, aws)
    assert item.delete_images(**values).status == "completed"
    assert all(op != "batch_delete_image" for _, op, _ in aws.calls)


@pytest.mark.parametrize(
    "kind,key",
    [
        (framework.ChaosType.CLOUDFRONT_CACHE_INVALIDATE, "paths"),
        (framework.ChaosType.WAF_IP_SET_MODIFY, "addresses_to_add"),
    ],
)
def test_child_digest_scope_changes_and_counts_all_children(kind, key):
    values = {"type": kind.value, **action_configs()[kind]}
    values[key] = (
        ["/reviewed", "/other"]
        if key == "paths"
        else ["198.51.100.1/24", "203.0.113.0/24"]
    )
    approved = framework.ChaosOrchestrator._target_values(values)
    assert any(target.startswith(f"selector:{kind.value}:") for target in approved)
    assert framework.ChaosOrchestrator._blast_radius(kind, values) == 3
    canonical = copy.deepcopy(values)
    canonical[key] = (
        sorted(set(values[key]))
        if key == "paths"
        else ["198.51.100.0/24", "203.0.113.0/24"]
    )
    assert framework.ChaosOrchestrator._target_values(canonical) == approved
    changed = copy.deepcopy(values)
    changed[key] = ["/unreviewed"] if key == "paths" else ["192.0.2.0/24"]
    assert framework.ChaosOrchestrator._target_values(changed) - approved
    if key == "addresses_to_add":
        changed = {**values, "scope": "CLOUDFRONT"}
        assert framework.ChaosOrchestrator._target_values(changed) - approved


@pytest.mark.parametrize(
    "kind,method",
    [
        (framework.ChaosType.CLOUDFRONT_CACHE_INVALIDATE, "invalidate_cache"),
        (framework.ChaosType.WAF_IP_SET_MODIFY, "modify_ip_set"),
    ],
)
@pytest.mark.parametrize("approval", ["parent_only", "over_radius", "exact"])
def test_direct_child_calls_require_scope_and_emit_approved_digest(
    kind, method, approval
):
    values = action_configs()[kind]
    aws = FakeAWS(reject_writes=False)
    item = make_experiment(kind, values, aws, dry_run=False)
    if kind == framework.ChaosType.CLOUDFRONT_CACHE_INVALIDATE:
        respond = aws.respond

        def cloudfront_response(service, operation, request):
            result = respond(service, operation, request)
            if operation == "create_invalidation":
                return {
                    "Invalidation": {
                        "Id": "synthetic-invalidation",
                        "Status": "InProgress",
                    }
                }
            return result

        aws.respond = cloudfront_response
    targets = framework.ChaosOrchestrator._target_values({"type": kind.value, **values})
    item.safety_controller.config.update(
        target_allowlist=sorted(targets), max_blast_radius=2
    )
    if approval == "parent_only":
        item.safety_controller.config["target_allowlist"] = [
            t for t in targets if not t.startswith("selector:")
        ]
    elif approval == "over_radius":
        item.safety_controller.config["max_blast_radius"] = 1
    result = getattr(item, method)(**values)
    if approval == "exact":
        assert result.status == "completed", result.errors
        assert set(result.affected_resources) == targets
    else:
        assert result.status == "failed"
        assert not aws.calls and not item.mutation_attempts


def test_ec2_termination_has_no_live_authority_in_token_handler_or_sdk():
    values = action_configs()[framework.ChaosType.EC2_TERMINATE]
    assert not framework.experiment_metadata(
        framework.ChaosType.EC2_TERMINATE
    ).live_supported
    config = config_for({"type": "ec2_terminate", **values})
    framework.validate_config_data(config)
    with pytest.raises(framework.ConfigurationError):
        framework.confirmation_token(config, "reviewed")
    aws = FakeAWS(reject_writes=False)
    with pytest.raises(
        framework.ConfigurationError,
        match="Live (approval is unavailable|FIS approval is disabled)",
    ):
        make_experiment(framework.ChaosType.EC2_TERMINATE, values, aws, dry_run=False)
    item = make_experiment(framework.ChaosType.EC2_TERMINATE, values, aws, dry_run=True)
    assert not aws.calls
    with pytest.raises(framework.SafetyViolation):
        item.ec2.terminate_instances(InstanceIds=[INSTANCE_ID])
    assert not aws.calls and not item.mutation_attempts


# Native botocore controls use synthetic credentials and Stubber, never transport.
def native_target_experiment(kind, values):
    session = framework.boto3.Session(
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
        region_name=REGION,
    )
    return make_experiment(
        kind,
        values,
        SimpleNamespace(
            client=lambda service: session.client(service, region_name=REGION)
        ),
        dry_run=False,
    )


@pytest.mark.parametrize(
    "attack",
    [
        "valid",
        "registry",
        "repository",
        "digest",
        "missing",
        "extra",
        "response_missing",
        "response_foreign",
        "many_tags",
    ],
)
def test_native_ecr_digest_provenance_and_response_proof(attack):
    from botocore.stub import Stubber

    values = {
        "repository_name": "reviewed-repo",
        "image_ids": [{"imageDigest": DIGEST}],
    }
    item = native_target_experiment(framework.ChaosType.ECR_IMAGE_DELETE, values)
    request = {
        "registryId": ACCOUNT_ID,
        "repositoryName": values["repository_name"],
        "imageIds": values["image_ids"],
    }
    detail = {
        "registryId": ACCOUNT_ID,
        "repositoryName": values["repository_name"],
        "imageDigest": DIGEST,
    }
    details = [detail]
    if attack == "registry":
        detail["registryId"] = "999900001111"
    elif attack == "repository":
        detail["repositoryName"] = "other-repo"
    elif attack == "digest":
        detail["imageDigest"] = "sha256:" + "2" * 64
    elif attack == "missing":
        details = []
    elif attack == "extra":
        details.append({**detail, "imageDigest": "sha256:" + "2" * 64})
    good_read = attack in {"valid", "response_missing", "response_foreign", "many_tags"}
    with Stubber(item.ecr._client) as stub:
        stub.add_response("describe_images", {"imageDetails": details}, request)
        if good_read:
            deleted = [{"imageDigest": DIGEST}]
            if attack == "response_missing":
                deleted = []
            elif attack == "response_foreign":
                deleted = [{"imageDigest": "sha256:" + "2" * 64}]
            elif attack == "many_tags":
                deleted = [
                    {"imageDigest": DIGEST, "imageTag": "one"},
                    {"imageDigest": DIGEST, "imageTag": "two"},
                ]
            stub.add_response(
                "batch_delete_image",
                (
                    {"failures": []}
                    if attack == "response_missing"
                    else {"imageIds": deleted, "failures": []}
                ),
                request,
            )
        result = item.delete_images(**values)
        stub.assert_no_pending_responses()

    assert result.status == (
        "completed" if attack in {"valid", "many_tags"} else "failed"
    ), result.errors
    assert bool(item.mutation_attempts) == good_read
    assert (
        bool(item.mutation_operations) == good_read
    )  # Bad responses cannot erase the mutation.


@pytest.mark.parametrize(
    "attack",
    [
        "valid",
        "alias",
        "bare_id",
        "alias_arn",
        "foreign_account",
        "foreign_region",
        "wrong_key_response",
        "wrong_sdk_region",
        "unapproved",
    ],
)
def test_native_kms_grant_key_identity_before_dispatch(attack):
    from botocore.stub import Stubber

    key = f"arn:aws-us-gov:kms:{REGION}:{ACCOUNT_ID}:key/01234567-89ab-cdef-0123-456789abcdef"
    supplied = {
        "alias": "alias/reviewed",
        "bare_id": key.rsplit("/", 1)[1],
        "alias_arn": key.replace("key/", "alias/"),
        "foreign_account": key.replace(ACCOUNT_ID, "999900001111"),
        "foreign_region": key.replace(REGION, "us-gov-east-1"),
    }.get(attack, key)
    values = {"key_id": supplied, "grant_id": "1" * 64}
    if attack in {"alias", "bare_id", "alias_arn", "foreign_account", "foreign_region"}:
        # These identities cannot obtain public live approval. The same cases
        # now stop before a client can perform the formerly tested lookup.
        with pytest.raises((framework.SafetyViolation, framework.ConfigurationError)):
            native_target_experiment(framework.ChaosType.KMS_GRANT_REVOKE, values)
        return
    item = native_target_experiment(framework.ChaosType.KMS_GRANT_REVOKE, values)
    if attack == "unapproved":
        item.safety_controller.config["target_allowlist"] = []
    if attack == "wrong_sdk_region":
        item.kms._client = framework.boto3.Session(
            aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
        ).client("kms", region_name="us-gov-east-1")
    read = attack in {"valid", "wrong_key_response", "wrong_sdk_region"}
    with Stubber(item.kms._client) as stub:
        if read:
            entry = {
                "KeyId": key
                if attack != "wrong_key_response"
                else key.replace(ACCOUNT_ID, "999900001111"),
                "GrantId": values["grant_id"],
            }
            stub.add_response(
                "list_grants",
                {"Grants": [entry]},
                {"KeyId": key, "GrantId": values["grant_id"]},
            )
        if attack == "valid":
            stub.add_response(
                "revoke_grant", {}, {"KeyId": key, "GrantId": values["grant_id"]}
            )
        result = item.revoke_grant(**values)
        stub.assert_no_pending_responses()
    assert result.status == ("completed" if attack == "valid" else "failed"), (
        result.errors
    )
    assert bool(item.mutation_attempts) == (attack == "valid")


@pytest.mark.parametrize("attack", ["cycle", "deep", "wide", "malformed_arn", "valid"])
def test_bounded_sdk_arguments_refuse_before_tracking(attack):
    aws = FakeAWS(reject_writes=False)
    owner = raw_owner(
        {"account_id": ACCOUNT_ID, "region": REGION, "dry_run": False},
        FakeSafetyController(aws, live=True),
    )
    payload = {"Arn": f"arn:aws-us-gov:sns:{REGION}:{ACCOUNT_ID}:reviewed"}
    if attack == "cycle":
        payload["cycle"] = payload
    elif attack == "deep":
        for _ in range(18):
            payload = {"child": payload}
    elif attack == "wide":
        payload = {"children": ["x"] * 20001}
    elif attack == "malformed_arn":
        payload = {"Arn": "arn:"}
    if attack == "valid":
        assert list(framework.bounded_argument_leaves(payload))
        framework.validate_sdk_request_arns(
            "sns",
            "unsubscribe",
            {"SubscriptionArn": payload["Arn"]},
            ACCOUNT_ID,
            REGION,
        )
        with pytest.raises(framework.SafetyViolation, match="active approved handler"):
            owner.client("sns").unsubscribe(SubscriptionArn=payload["Arn"])
        assert not aws.calls and not owner.mutation_attempts
    else:
        with pytest.raises(framework.SafetyViolation):
            if attack == "malformed_arn":
                owner.client("sns").unsubscribe(SubscriptionArn=payload["Arn"])
            else:
                owner.client("sns").unsubscribe(Nested=payload)
        assert not aws.calls and not owner.mutation_attempts


@pytest.mark.parametrize("attack", ["valid", "paths", "limit"])
def test_native_cloudfront_canonical_child_admission(attack):
    from botocore.stub import ANY, Stubber

    values = {"distribution_id": "EREVIEWED", "paths": ["/b", "/a", "/a"]}
    kind = framework.ChaosType.CLOUDFRONT_CACHE_INVALIDATE
    session = framework.boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    )
    safety = framework.SafetyController(
        {
            "target_allowlist": list(
                framework.ChaosOrchestrator._target_values(
                    {"type": kind.value, **values}
                )
            ),
            "max_blast_radius": 3 if attack != "limit" else 2,
        },
        session,
        "us-east-1",
        True,
        ACCOUNT_ID,
    )
    item = make_experiment(
        kind,
        {"region": "us-east-1", **values},
        SimpleNamespace(
            client=lambda service: session.client(service, region_name="us-east-1")
        ),
        dry_run=False,
    )
    item.safety_controller.config.update(safety.config)
    supplied = {**values, "paths": ["/secret"]} if attack == "paths" else values
    with Stubber(item.cloudfront._client) as stub:
        if attack == "valid":
            stub.add_response(
                "create_invalidation",
                {
                    "Invalidation": {
                        "Id": "IREVIEWED",
                        "Status": "InProgress",
                        "CreateTime": framework.utc_now(),
                        "InvalidationBatch": {
                            "Paths": {"Quantity": 2, "Items": ["/a", "/b"]},
                            "CallerReference": "offline",
                        },
                    }
                },
                {
                    "DistributionId": "EREVIEWED",
                    "InvalidationBatch": {
                        "Paths": {"Quantity": 2, "Items": ["/a", "/b"]},
                        "CallerReference": ANY,
                    },
                },
            )
        result = item.invalidate_cache(**supplied)
        stub.assert_no_pending_responses()
    assert result.status == ("completed" if attack == "valid" else "failed"), (
        result.errors
    )
    assert bool(item.mutation_attempts) == (attack == "valid")
    if attack == "valid":
        assert any(value.startswith("selector:") for value in result.affected_resources)


@pytest.mark.parametrize("attack", ["valid", "cidr", "scope", "limit", "zero_prefix"])
def test_native_waf_canonical_children_and_scope_before_mutation(attack):
    from botocore.stub import Stubber

    values = {
        "ip_set_id": "01234567-89ab-cdef-0123-456789abcdef",
        "ip_set_name": "Reviewed",
        "scope": "REGIONAL",
        "addresses_to_add": ["198.51.100.0/24", "198.51.100.0/24"],
    }
    kind = framework.ChaosType.WAF_IP_SET_MODIFY
    session = framework.boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    )
    safety = framework.SafetyController(
        {
            "target_allowlist": list(
                framework.ChaosOrchestrator._target_values(
                    {"type": kind.value, **values}
                )
            ),
            "max_blast_radius": 2 if attack != "limit" else 1,
        },
        session,
        REGION,
        True,
        ACCOUNT_ID,
    )
    item = make_experiment(
        kind,
        values,
        SimpleNamespace(
            client=lambda service: session.client(service, region_name=REGION)
        ),
        dry_run=False,
    )
    item.safety_controller.config.update(safety.config)
    supplied = dict(values)
    if attack == "cidr":
        supplied["addresses_to_add"] = ["203.0.113.0/24"]
    elif attack == "scope":
        supplied["scope"] = "CLOUDFRONT"
    elif attack == "zero_prefix":
        supplied["addresses_to_add"] = ["0.0.0.0/0"]
    with Stubber(item.wafv2._client) as stub:
        if attack == "valid":
            request = {
                "Scope": "REGIONAL",
                "Name": "Reviewed",
                "Id": values["ip_set_id"],
            }
            token = "1" + values["ip_set_id"][1:]
            stub.add_response(
                "get_ip_set",
                {
                    "LockToken": token,
                    "IPSet": {
                        "Id": values["ip_set_id"],
                        "Name": "Reviewed",
                        "ARN": f"arn:aws-us-gov:wafv2:{REGION}:{ACCOUNT_ID}:regional/ipset/Reviewed/{values['ip_set_id']}",
                        "IPAddressVersion": "IPV4",
                        "Addresses": ["192.0.2.0/24"],
                    },
                },
                request,
            )
            stub.add_response(
                "update_ip_set",
                {"NextLockToken": token},
                {
                    **request,
                    "LockToken": token,
                    "Addresses": ["192.0.2.0/24", "198.51.100.0/24"],
                },
            )
        result = item.modify_ip_set(**supplied)
        stub.assert_no_pending_responses()
    assert result.status == ("completed" if attack == "valid" else "failed"), (
        result.errors
    )
    assert bool(item.mutation_attempts) == (attack == "valid")


@pytest.mark.parametrize("rollback", [False, True])
@pytest.mark.parametrize("allowlisted", [False, True])
@pytest.mark.parametrize("service", ["kms", "ecr", "cloudfront", "wafv2"])
def test_native_raw_protected_requests_have_no_handler_authority(
    service, allowlisted, rollback
):
    """Even literal target approval cannot authorize an unbound raw SDK call."""
    from botocore.stub import Stubber

    region = "us-east-1" if service == "cloudfront" else REGION
    key = f"arn:aws-us-gov:kms:{REGION}:{ACCOUNT_ID}:key/01234567-89ab-cdef-0123-456789abcdef"
    ip_set_id = "01234567-89ab-cdef-0123-456789abcdef"
    cases = {
        "kms": (
            "revoke_grant",
            framework.ChaosType.KMS_GRANT_REVOKE,
            {"KeyId": key, "GrantId": "1" * 64},
            {"key_id": key, "grant_id": "1" * 64},
        ),
        "ecr": (
            "batch_delete_image",
            framework.ChaosType.ECR_IMAGE_DELETE,
            {
                "registryId": ACCOUNT_ID,
                "repositoryName": "reviewed-repo",
                "imageIds": [{"imageDigest": DIGEST}],
            },
            {
                "repository_name": "reviewed-repo",
                "image_ids": [{"imageDigest": DIGEST}],
            },
        ),
        "cloudfront": (
            "create_invalidation",
            framework.ChaosType.CLOUDFRONT_CACHE_INVALIDATE,
            {
                "DistributionId": "EREVIEWED",
                "InvalidationBatch": {
                    "Paths": {"Quantity": 1, "Items": ["/reviewed"]},
                    "CallerReference": "offline",
                },
            },
            {"distribution_id": "EREVIEWED", "paths": ["/reviewed"]},
        ),
        "wafv2": (
            "update_ip_set",
            framework.ChaosType.WAF_IP_SET_MODIFY,
            {
                "Scope": "REGIONAL",
                "Name": "Reviewed",
                "Id": "01234567-89ab-cdef-0123-456789abcdef",
                "Addresses": ["198.51.100.0/24"],
                "LockToken": ip_set_id,
            },
            {
                "scope": "REGIONAL",
                "ip_set_name": "Reviewed",
                "ip_set_id": "01234567-89ab-cdef-0123-456789abcdef",
                "addresses_to_add": ["198.51.100.0/24"],
            },
        ),
    }
    operation, kind, request, values = cases[service]
    raw = framework.boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    ).client(service, region_name=region)
    from types import SimpleNamespace

    safety = framework.SafetyController(
        {
            "target_allowlist": sorted(
                framework.ChaosOrchestrator._target_values(
                    {"type": kind.value, **values}
                )
            )
            if allowlisted
            else [],
            "max_blast_radius": 100,
        },
        SimpleNamespace(client=lambda *args, **kwargs: raw),
        region,
        True,
        ACCOUNT_ID,
    )
    safety.check_safety_conditions = lambda: (True, [])
    owner = make_experiment(
        kind,
        {**values, "region": region},
        SimpleNamespace(client=lambda service: raw),
        dry_run=False,
    )
    owner.safety_controller.config.update(safety.config)
    owner._in_rollback = rollback
    with Stubber(raw) as stub:
        # No response is queued. A dispatch would fail the native SDK guard.
        with pytest.raises(framework.SafetyViolation, match="active approved handler"):
            getattr(owner.client(service), operation)(**request)
        stub.assert_no_pending_responses()
    assert not owner.mutation_attempts and not owner.rollback_attempts


@pytest.mark.parametrize("attack", ["valid", "account", "region", "partition"])
def test_native_elb_cognito_snapshot_is_restorable_before_fault(attack):
    from botocore.stub import Stubber

    rule = f"arn:aws-us-gov:elasticloadbalancing:{REGION}:{ACCOUNT_ID}:listener-rule/app/reviewed/123/456/789"
    pool = f"arn:aws-us-gov:cognito-idp:{REGION}:{ACCOUNT_ID}:userpool/{REGION}_Offline"
    pool = {
        "account": pool.replace(ACCOUNT_ID, "999900001111"),
        "region": pool.replace(REGION, "us-gov-east-1"),
        "partition": pool.replace("aws-us-gov", "aws"),
    }.get(attack, pool)
    actions = [
        {
            "Type": "authenticate-cognito",
            "Order": 1,
            "AuthenticateCognitoConfig": {
                "UserPoolArn": pool,
                "UserPoolClientId": "offline",
                "UserPoolDomain": "offline",
            },
        },
        {
            "Type": "forward",
            "Order": 2,
            "TargetGroupArn": f"arn:aws-us-gov:elasticloadbalancing:{REGION}:{ACCOUNT_ID}:targetgroup/reviewed/123",
        },
    ]
    session = framework.boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    )
    item = make_experiment(
        framework.ChaosType.ELB_LISTENER_RULE_MODIFY,
        {"rule_arn": rule},
        SimpleNamespace(
            client=lambda service: session.client(service, region_name=REGION)
        ),
        dry_run=False,
    )
    fault = [
        {
            "Type": "fixed-response",
            "FixedResponseConfig": {
                "StatusCode": "503",
                "ContentType": "text/plain",
                "MessageBody": "Service Unavailable - Chaos Experiment",
            },
        }
    ]
    original = {"Rules": [{"RuleArn": rule, "Actions": actions}]}
    with Stubber(item.elbv2._client) as stub:
        stub.add_response("describe_rules", original, {"RuleArns": [rule]})
        if attack == "valid":
            stub.add_response(
                "modify_rule", {"Rules": []}, {"RuleArn": rule, "Actions": fault}
            )
            stub.add_response(
                "modify_rule", original, {"RuleArn": rule, "Actions": actions}
            )
            stub.add_response("describe_rules", original, {"RuleArns": [rule]})
        result = item.modify_listener_rule(rule)
        assert result.status == ("completed" if attack == "valid" else "failed"), (
            result.errors
        )
        if attack == "valid":
            item.run_rollback()
            assert item.rollback_verified
            assert item.rollback_operations == ["elbv2.modify_rule"]
        else:
            assert not item.mutation_attempts
        stub.assert_no_pending_responses()


def test_lambda_recovery_preserves_opaque_arn_values():
    aws = FakeAWS(reject_writes=False)
    initial = aws.respond("lambda", "get_function_configuration", {})
    initial["RevisionId"] = "rev-original"
    initial["Environment"]["Variables"]["OPAQUE"] = "arn:foreign:application:data"
    owned = copy.deepcopy(initial)
    owned["Environment"]["Variables"]["MODE"] = (
        "arn:aws:sns:us-east-1:999900001111:application-text"
    )
    current = copy.deepcopy(owned)
    current["RevisionId"] = "rev-current"
    restored = copy.deepcopy(current)
    restored["Environment"]["Variables"]["MODE"] = "normal"
    aws.read_overrides[("lambda", "get_function_configuration")] = [
        initial,
        owned,
        current,
        restored,
        restored,
    ]
    item, values = experiment(
        framework.ChaosType.LAMBDA_ENVIRONMENT_CORRUPT,
        aws,
        corrupt_vars={"MODE": owned["Environment"]["Variables"]["MODE"]},
    )
    assert item.corrupt_environment(**values).status == "completed"
    item.run_rollback()
    assert item.rollback_verified
    writes = [
        args for _, op, args in aws.calls if op == "update_function_configuration"
    ]
    assert (
        writes[0]["Environment"]["Variables"]["OPAQUE"]
        == "arn:foreign:application:data"
    )
    assert (
        writes[-1]["Environment"]["Variables"] == restored["Environment"]["Variables"]
    )


@pytest.mark.parametrize(
    "attack", ["opaque", "foreign_function", "foreign_role", "oversized"]
)
def test_native_lambda_application_text_does_not_erase_identity_checks(attack):
    from types import SimpleNamespace

    from botocore.stub import Stubber

    function = f"arn:aws-us-gov:lambda:{REGION}:{ACCOUNT_ID}:function:reviewed"
    request = {
        "FunctionName": function,
        "Environment": {"Variables": {"OPAQUE": "arn:foreign:application:data"}},
    }
    if attack == "foreign_function":
        request["FunctionName"] = function.replace(ACCOUNT_ID, "999900001111")
    elif attack == "foreign_role":
        request["Role"] = "arn:aws-us-gov:iam::999900001111:role/foreign"
    elif attack == "oversized":
        request["Environment"]["Variables"]["OPAQUE"] = "x" * (
            framework.MAX_CONFIG_BYTES + 1
        )
    raw = framework.boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    ).client("lambda", region_name=REGION)
    safety = framework.SafetyController(
        {},
        SimpleNamespace(client=lambda *args, **kwargs: raw),
        REGION,
        True,
        ACCOUNT_ID,
    )
    safety.check_safety_conditions = lambda: (True, [])
    owner = raw_owner(
        {"account_id": ACCOUNT_ID, "region": REGION, "dry_run": False}, safety
    )
    with Stubber(raw) as stub:
        if attack == "opaque":
            framework.validate_sdk_request_arns(
                "lambda", "update_function_configuration", request, ACCOUNT_ID, REGION
            )
            with pytest.raises(
                framework.SafetyViolation, match="active approved handler"
            ):
                owner.client("lambda").update_function_configuration(**request)
            assert not owner.mutation_attempts
        else:
            with pytest.raises(framework.SafetyViolation):
                owner.client("lambda").update_function_configuration(**request)
            assert not owner.mutation_attempts
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("attack", ["replay", "changed", "thread", "detached"])
def test_native_protected_dispatch_ticket_is_single_use_exact_and_thread_local(attack):
    from concurrent.futures import ThreadPoolExecutor

    from botocore.stub import Stubber

    key = f"arn:aws-us-gov:kms:{REGION}:{ACCOUNT_ID}:key/01234567-89ab-cdef-0123-456789abcdef"
    values = {"key_id": key, "grant_id": "1" * 64}
    owner = native_target_experiment(framework.ChaosType.KMS_GRANT_REVOKE, values)
    owner.safety_controller.check_safety_conditions = lambda: (True, [])
    request = {"KeyId": key, "GrantId": values["grant_id"]}
    expected = copy.deepcopy(request)
    with Stubber(owner.kms._client) as stub:
        with owner._approved_sdk_request("kms", "revoke_grant", request) as admitted:
            if attack == "changed":
                admitted["GrantId"] = "2" * 64
                with pytest.raises(
                    framework.SafetyViolation, match="active approved handler"
                ):
                    owner.kms.revoke_grant(**admitted)
                with pytest.raises(framework.SafetyViolation):
                    owner.kms.revoke_grant(**expected)
            else:
                if attack == "thread":
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        pending = executor.submit(owner.kms.revoke_grant, **admitted)
                        with pytest.raises(framework.SafetyViolation):
                            pending.result()
                elif attack == "detached":
                    request["GrantId"] = "2" * 64
                    assert admitted == expected
                with pytest.raises(
                    framework.SafetyViolation, match="active approved handler"
                ):
                    owner.kms.revoke_grant(**admitted)
                with pytest.raises(framework.SafetyViolation):
                    owner.kms.revoke_grant(**admitted)
        with pytest.raises(framework.SafetyViolation):
            owner.kms.revoke_grant(**expected)
        stub.assert_no_pending_responses()
    assert not owner.mutation_attempts
    assert owner._sdk_request_authority.ticket is None


@pytest.mark.parametrize("path", ["target_group", "forward_group", "misplaced_cognito"])
def test_nested_identity_fields_do_not_gain_opaque_data_exemption(path):
    foreign = f"arn:aws-us-gov:elasticloadbalancing:{REGION}:999900001111:targetgroup/other/123"
    action = {
        "target_group": {"Type": "forward", "TargetGroupArn": foreign},
        "forward_group": {
            "Type": "forward",
            "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": foreign}]},
        },
        "misplaced_cognito": {
            "Type": "forward",
            "Unknown": {
                "UserPoolArn": f"arn:aws-us-gov:cognito-idp:{REGION}:{ACCOUNT_ID}:userpool/offline"
            },
        },
    }[path]
    with pytest.raises(framework.SafetyViolation):
        framework.validate_sdk_request_arns(
            "elbv2", "modify_rule", {"Actions": [action]}, ACCOUNT_ID, REGION
        )


@pytest.mark.parametrize(
    "attack", ["root_width", "key_bytes", "value_bytes", "aggregate_bytes", "valid"]
)
def test_sdk_request_budget_covers_root_keys_and_aggregate_text(attack):
    values = {
        "root_width": {str(i): "x" for i in range(20001)},
        "key_bytes": {"x" * (framework.MAX_CONFIG_BYTES + 1): "small"},
        "value_bytes": {"small": "Ã©" * (framework.MAX_CONFIG_BYTES // 2 + 1)},
        "aggregate_bytes": {
            "a": "x" * (framework.MAX_CONFIG_BYTES // 2),
            "b": "y" * (framework.MAX_CONFIG_BYTES // 2),
        },
        "valid": {
            "FunctionName": "reviewed",
            "Environment": {"Variables": {"TEXT": "ordinary application data"}},
        },
    }[attack]
    if attack == "valid":
        assert list(framework.bounded_argument_leaves(values))
    else:
        with pytest.raises(framework.SafetyViolation, match="budget"):
            list(framework.bounded_argument_leaves(values))


@pytest.mark.parametrize(
    "attack",
    [
        "valid",
        "role_account",
        "role_partition",
        "role_region",
        "role_service",
        "role_type",
        "missing_role",
        "misplaced_role",
        "non_firehose",
        "endpoint_account",
    ],
)
def test_native_sns_firehose_role_reference_is_narrow_and_owner_bound(attack):
    from types import SimpleNamespace

    from botocore.stub import Stubber

    topic = f"arn:aws-us-gov:sns:{REGION}:{ACCOUNT_ID}:reviewed"
    role = f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/reviewed"
    request = {
        "TopicArn": topic,
        "Protocol": "firehose",
        "Endpoint": f"arn:aws-us-gov:firehose:{REGION}:{ACCOUNT_ID}:deliverystream/reviewed",
        "Attributes": {"SubscriptionRoleArn": role},
    }
    if attack == "role_account":
        request["Attributes"]["SubscriptionRoleArn"] = role.replace(
            ACCOUNT_ID, "999900001111"
        )
    elif attack == "role_partition":
        request["Attributes"]["SubscriptionRoleArn"] = role.replace("aws-us-gov", "aws")
    elif attack == "role_region":
        request["Attributes"]["SubscriptionRoleArn"] = role.replace(
            "iam::", f"iam:{REGION}:"
        )
    elif attack == "role_service":
        request["Attributes"]["SubscriptionRoleArn"] = role.replace(":iam:", ":kms:")
    elif attack == "role_type":
        request["Attributes"]["SubscriptionRoleArn"] = role.replace("role/", "user/")
    elif attack == "missing_role":
        request.pop("Attributes")
    elif attack == "misplaced_role":
        request["Attributes"] = {"Other": role}
    elif attack == "non_firehose":
        request["Protocol"] = "lambda"
        request["Endpoint"] = (
            f"arn:aws-us-gov:lambda:{REGION}:{ACCOUNT_ID}:function:reviewed"
        )
    elif attack == "endpoint_account":
        request["Endpoint"] = request["Endpoint"].replace(ACCOUNT_ID, "999900001111")
    raw = framework.boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    ).client("sns", region_name=REGION)
    safety = framework.SafetyController(
        {},
        SimpleNamespace(client=lambda *args, **kwargs: raw),
        REGION,
        True,
        ACCOUNT_ID,
    )
    safety.check_safety_conditions = lambda: (True, [])
    owner = raw_owner(
        {"account_id": ACCOUNT_ID, "region": REGION, "dry_run": False}, safety
    )
    with Stubber(raw) as stub:
        if attack == "valid":
            framework.validate_sdk_request_arns(
                "sns", "subscribe", request, ACCOUNT_ID, REGION
            )
            with pytest.raises(
                framework.SafetyViolation, match="active approved handler"
            ):
                owner.client("sns").subscribe(**request)
            assert not owner.mutation_attempts
        else:
            with pytest.raises(framework.SafetyViolation):
                owner.client("sns").subscribe(**request)
            assert not owner.mutation_attempts
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("protocol", ["lambda", "firehose"])
@pytest.mark.parametrize(
    "attack",
    [
        "valid",
        "endpoint_account",
        "endpoint_region",
        "endpoint_partition",
        "topic_account",
        "role_account",
        "missing_role",
    ],
)
def test_native_sns_snapshot_admission_precedes_irreversible_fault(protocol, attack):
    from botocore.stub import Stubber

    topic = f"arn:aws-us-gov:sns:{REGION}:{ACCOUNT_ID}:reviewed"
    subscription = topic + ":01234567-89ab-cdef-0123-456789abcdef"
    leaf = "function:reviewed" if protocol == "lambda" else "deliverystream/reviewed"
    endpoint = f"arn:aws-us-gov:{protocol}:{REGION}:{ACCOUNT_ID}:{leaf}"
    details = {"TopicArn": topic, "Protocol": protocol, "Endpoint": endpoint}
    if protocol == "firehose":
        details["SubscriptionRoleArn"] = (
            f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/reviewed"
        )
    if attack == "endpoint_account":
        details["Endpoint"] = endpoint.replace(ACCOUNT_ID, "999900001111")
    elif attack == "endpoint_region":
        details["Endpoint"] = endpoint.replace(REGION, "us-gov-east-1")
    elif attack == "endpoint_partition":
        details["Endpoint"] = endpoint.replace("aws-us-gov", "aws")
    elif attack == "topic_account":
        details["TopicArn"] = topic.replace(ACCOUNT_ID, "999900001111")
    elif protocol == "firehose" and attack == "role_account":
        details["SubscriptionRoleArn"] = details["SubscriptionRoleArn"].replace(
            ACCOUNT_ID, "999900001111"
        )
    elif protocol == "firehose" and attack == "missing_role":
        details.pop("SubscriptionRoleArn")
    good = attack == "valid" or (
        protocol == "lambda" and attack in {"role_account", "missing_role"}
    )
    request = {
        "TopicArn": details["TopicArn"],
        "Protocol": protocol,
        "Endpoint": details["Endpoint"],
    }
    if protocol == "firehose" and "SubscriptionRoleArn" in details:
        request["Attributes"] = {"SubscriptionRoleArn": details["SubscriptionRoleArn"]}
    session = framework.boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    )
    owner = make_experiment(
        framework.ChaosType.SNS_SUBSCRIPTION_DELETE,
        {"subscription_arn": subscription},
        SimpleNamespace(
            client=lambda service: session.client(service, region_name=REGION)
        ),
        dry_run=False,
    )
    with Stubber(owner.sns._client) as stub:
        stub.add_response(
            "get_subscription_attributes",
            {"Attributes": details},
            {"SubscriptionArn": subscription},
        )
        if good:
            stub.add_response("unsubscribe", {}, {"SubscriptionArn": subscription})
            stub.add_response("subscribe", {"SubscriptionArn": subscription}, request)
        result = owner.delete_subscription(subscription)
        assert result.status == ("completed" if good else "failed"), result.errors
        owner.run_rollback()
        if good:
            assert owner.mutation_operations == ["sns.unsubscribe"]
            assert owner.rollback_operations == ["sns.subscribe"]
            assert (
                not owner.rollback_verified
            )  # Recreation never proves full irreversible recovery.
        else:
            assert not owner.mutation_attempts and not owner.rollback_attempts
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("entrypoint", ["direct", "delete"])
@pytest.mark.parametrize(
    "resource, valid",
    [
        ("role/reviewed", True),
        ("role/team/component/reviewed", True),
        ("role/" + "n" * 64, True),
        ("role/" + "p" * 510 + "/reviewed", True),
        ("role/a:b/role_+=,.@-", True),
        ("role/team//reviewed", True),
        ("role/team/", False),
        ("role//", False),
        ("role/", False),
        ("role/na:me", False),
        ("role/" + "n" * 65, False),
        ("role/" + "p" * 511 + "/reviewed", False),
        ("role/na me", False),
        ("role/na%me", False),
        ("role/n\u00e4me", False),
        ("role/t\u00e4m/reviewed", False),
        ("role/team space/reviewed", False),
        ("role/team\x7f/reviewed", False),
        ("role/team\n/reviewed", False),
        ("user/reviewed", False),
    ],
)
def test_native_sns_role_grammar_precedes_dispatch_and_irreversible_fault(
    entrypoint, resource, valid
):
    from botocore.stub import Stubber

    topic = f"arn:aws-us-gov:sns:{REGION}:{ACCOUNT_ID}:reviewed"
    subscription = topic + ":01234567-89ab-cdef-0123-456789abcdef"
    role = f"arn:aws-us-gov:iam::{ACCOUNT_ID}:{resource}"
    endpoint = f"arn:aws-us-gov:firehose:{REGION}:{ACCOUNT_ID}:deliverystream/reviewed"
    request = {
        "TopicArn": topic,
        "Protocol": "firehose",
        "Endpoint": endpoint,
        "Attributes": {"SubscriptionRoleArn": role},
    }
    session = framework.boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    )
    owner = make_experiment(
        framework.ChaosType.SNS_SUBSCRIPTION_DELETE,
        {"subscription_arn": subscription},
        SimpleNamespace(
            client=lambda service: session.client(service, region_name=REGION)
        ),
        dry_run=False,
    )
    with Stubber(owner.sns._client) as stub:
        if entrypoint == "delete":
            stub.add_response(
                "get_subscription_attributes",
                {
                    "Attributes": {
                        "TopicArn": topic,
                        "Protocol": "firehose",
                        "Endpoint": endpoint,
                        "SubscriptionRoleArn": role,
                    }
                },
                {"SubscriptionArn": subscription},
            )
            if valid:
                stub.add_response("unsubscribe", {}, {"SubscriptionArn": subscription})
                stub.add_response(
                    "subscribe", {"SubscriptionArn": subscription}, request
                )
            result = owner.delete_subscription(subscription)
            assert result.status == ("completed" if valid else "failed"), result.errors
            owner.run_rollback()
            if valid:
                assert owner.mutation_operations == ["sns.unsubscribe"]
                assert owner.rollback_operations == ["sns.subscribe"]
                assert not owner.rollback_verified
            else:
                assert not owner.mutation_attempts and not owner.rollback_attempts
        else:
            if valid:
                framework.validate_sdk_request_arns(
                    "sns", "subscribe", request, ACCOUNT_ID, REGION
                )
            else:
                with pytest.raises(framework.SafetyViolation):
                    framework.validate_sdk_request_arns(
                        "sns", "subscribe", request, ACCOUNT_ID, REGION
                    )
            # Subscribe has authority only inside the owned delete recovery.
            with pytest.raises(
                framework.SafetyViolation, match="active approved handler"
            ):
                owner.sns.subscribe(**request)
            assert not owner.mutation_attempts
        stub.assert_no_pending_responses()
