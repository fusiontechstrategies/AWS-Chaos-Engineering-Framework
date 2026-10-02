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


def test_rds_retention_rollback_refuses_concurrent_change():
    aws = FakeAWS(reject_writes=False)
    original = aws.respond("rds", "describe_db_instances", {})
    owned = copy.deepcopy(original)
    owned["DBInstances"][0]["BackupRetentionPeriod"] = 0
    operator = copy.deepcopy(original)
    operator["DBInstances"][0]["BackupRetentionPeriod"] = 14
    aws.read_overrides[("rds", "describe_db_instances")] = [original, owned, operator]
    item, values = experiment(framework.ChaosType.RDS_BACKUP_RETENTION_MODIFY, aws)
    assert item.modify_backup_retention(**values).status == "completed"
    with pytest.raises(framework.SafetyViolation, match="concurrent"):
        item.run_rollback()
    assert len([call for call in aws.calls if call[1] == "modify_db_instance"]) == 1
    assert not item.rollback_verified


def test_rds_original_retention_with_pending_change_is_not_verified():
    aws = FakeAWS(reject_writes=False)
    item, _ = experiment(framework.ChaosType.RDS_BACKUP_RETENTION_MODIFY, aws)
    item.original_retention = 7
    item.owned_retention = 0
    item.db_identifier = "synthetic"
    item.mutation_attempts.append("rds.modify_db_instance")
    current = aws.respond("rds", "describe_db_instances", {})
    current["DBInstances"][0]["PendingModifiedValues"] = {"BackupRetentionPeriod": 0}
    aws.read_overrides[("rds", "describe_db_instances")] = [current]
    with pytest.raises(framework.SafetyViolation, match="pending"):
        item.run_rollback()
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
    item, values = experiment(kind, aws)
    orchestrator = object.__new__(framework.ChaosOrchestrator)
    result = orchestrator._execute_experiment(item, kind, values)
    assert result.status == "completed", result.errors
    item.run_rollback()
    assert item.rollback_verified
    item.rollback_verified = False
    # Successful recovery writes cannot compensate for unreadable post-state.
    respond = aws.respond

    def missing_state(service, operation, request):
        if operation.startswith(framework.READ_ONLY_OPERATION_PREFIXES):
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
        ("role_arn", "different-role"),
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
    import threading

    from test_aws_chaos_framework import (
        BREAK_GLASS_ARN,
        OTHER_ACCESS_KEY,
        FakeSafetyController,
    )

    aws = FakeAWS(reject_writes=False)
    item, values = experiment(framework.ChaosType.FIS_TEMPLATE, aws)
    item.fis_experiment_id = "synthetic"
    item.recovery_instance_ids = ["i-0123456789abcdef0"]
    item.mutation_attempts = ["fis.start_experiment"]
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
    orchestrator = object.__new__(framework.ChaosOrchestrator)
    orchestrator.config = {"global": {}, "safety": {}}
    orchestrator.region = REGION
    orchestrator.dry_run = False
    orchestrator.live = True
    orchestrator.operator_principal_arn = BREAK_GLASS_ARN
    orchestrator.active_access_key_id = OTHER_ACCESS_KEY
    orchestrator._report_sensitive_values = set()
    orchestrator._sensitive_values_lock = threading.Lock()
    orchestrator._active_experiments_lock = threading.Lock()
    orchestrator.active_experiments = []
    orchestrator.safety_controller = FakeSafetyController(aws, live=True)
    orchestrator._validate_target_scope = lambda *args: None
    orchestrator._create_experiment = lambda *args: item
    orchestrator._execute_experiment = lambda *args: framework.ExperimentResult(
        experiment_id="synthetic",
        experiment_type=framework.ChaosType.FIS_TEMPLATE,
        start_time=framework.utc_now(),
        status="completed",
    )
    result = orchestrator._run_single_experiment(
        {**values, "type": "fis_template", "auto_rollback": False}
    )
    assert result.status == "failed"
    assert result.rollback_successful is False
    assert any("not yet verified" in error for error in result.rollback_errors)
