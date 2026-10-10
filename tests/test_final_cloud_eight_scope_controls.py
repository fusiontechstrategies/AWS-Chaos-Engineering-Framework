"""Offline regressions for the eight-finding Cloud scan of main 6191c33.

Every AWS response is a deterministic local fake or an offline botocore
before-send answer; no credentials are resolved and no network is contacted.
"""

from __future__ import annotations

import copy
import hashlib
import io
import itertools
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

import boto3
import botocore.session
import pytest
from botocore.awsrequest import AWSResponse
from botocore.credentials import (
    CredentialProvider,
    Credentials,
    RefreshableCredentials,
)
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    INSTANCE_ID,
    REGION,
    FakeAWS,
    FakeClientError,
    action_configs,
    make_experiment,
    make_orchestrator,
    planning_only_experiment,
)

import aws_chaos_framework as framework

OTHER_ACCOUNT = "999900001111"


def writes(aws: FakeAWS) -> list[str]:
    return [
        f"{service}.{operation}"
        for service, operation, _request in aws.calls
        if operation not in framework.READ_ONLY_OPERATIONS.get(service, ())
    ]


# 1. Refreshable profile credentials are pinned at live admission.

KEY_A = "ASIA" + "A" * 16
KEY_B = "ASIA" + "B" * 16


class SyntheticClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.value


class SwitchingProvider(CredentialProvider):
    """Deterministic refreshable source: account A until refresh, then B."""

    METHOD = "synthetic-refreshable"
    CANONICAL_NAME = "SyntheticRefreshable"

    def __init__(self, clock: SyntheticClock) -> None:
        super().__init__()
        self.clock = clock
        self.refreshes = 0

    def _refresh(self) -> dict[str, str]:
        self.refreshes += 1
        return {
            "access_key": KEY_B,
            "secret_key": "secret-b",
            "token": "token-b",
            "expiry_time": (self.clock.now() + timedelta(hours=2)).isoformat(),
        }

    def load(self) -> RefreshableCredentials:
        return RefreshableCredentials(
            KEY_A,
            "secret-a",
            "token-a",
            self.clock.now() + timedelta(hours=1),
            self._refresh,
            self.METHOD,
            time_fetcher=self.clock.now,
        )


def identity_xml(account: str, partition: str = "aws-us-gov") -> bytes:
    return (
        '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        "<GetCallerIdentityResult>"
        f"<Arn>arn:{partition}:sts::{account}:assumed-role/ChaosOperator/s</Arn>"
        f"<UserId>AROAEXAMPLE:s</UserId><Account>{account}</Account>"
        "</GetCallerIdentityResult>"
        "<ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>"
        "</GetCallerIdentityResponse>"
    ).encode()


class OfflineBody:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def stream(self, **_kwargs: Any):
        yield self.body


def live_config(
    tmp_path, experiments: list[dict[str, Any]], region: str = REGION
) -> str:
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    config["global"]["region"] = region
    config["safety"]["safety_alarms"] = ["synthetic-alarm"]
    config["safety"]["target_allowlist"] = sorted(
        target
        for experiment in experiments
        for target in framework.ChaosOrchestrator._target_values(experiment)
    )
    config["experiment_suites"] = {"ordinary": {"experiments": experiments}}
    path = tmp_path / "config.yaml"
    path.write_text(framework.yaml.safe_dump(config), encoding="utf-8")
    return str(path)


# A named shared-config profile whose non-credential settings must survive
# pinning. FIPS endpoints differ from regional ones in the commercial region.
PROFILE = "chaos-pinned"
PROFILE_REGION = "us-east-1"


def ec2_instances_xml(state: str) -> bytes:
    return (
        '<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
        "<requestId>r</requestId><reservationSet><item>"
        "<reservationId>r-0123456789abcdef0</reservationId>"
        f"<ownerId>{ACCOUNT_ID}</ownerId><instancesSet><item>"
        f"<instanceId>{INSTANCE_ID}</instanceId>"
        f"<instanceState><code>16</code><name>{state}</name></instanceState>"
        "</item></instancesSet></item></reservationSet>"
        "</DescribeInstancesResponse>"
    ).encode()


REBOOT_XML = (
    b'<RebootInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
    b"<requestId>r</requestId><return>true</return>"
    b"</RebootInstancesResponse>"
)


def offline_profile_aws(monkeypatch, tmp_path, provider=None):
    """Real boto3/botocore sessions over temporary shared config, answered offline.

    The Session factory passes every keyword through unchanged, so a dropped
    profile_name reaches botocore exactly as it would in production.
    """
    bundle = tmp_path / "profile-ca.pem"
    bundle.write_text("offline placeholder; never loaded\n", encoding="ascii")
    config_file = tmp_path / "aws-config"
    config_file.write_text(
        f"[profile {PROFILE}]\nregion = {PROFILE_REGION}\n"
        f"ca_bundle = {bundle.as_posix()}\nuse_fips_endpoint = true\n",
        encoding="ascii",
    )
    credentials_file = tmp_path / "aws-credentials"
    credentials_file.write_text(
        f"[{PROFILE}]\naws_access_key_id = {KEY_A}\n"
        "aws_secret_access_key = secret-a\naws_session_token = token-a\n",
        encoding="ascii",
    )
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_CA_BUNDLE",
        "AWS_USE_FIPS_ENDPOINT",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config_file))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials_file))
    signed: list[tuple[str, str, str]] = []

    def offline(request, event_name, **_kwargs):
        operation = event_name.rsplit(".", 1)[-1]
        header = request.headers.get("Authorization", b"")
        header = header.decode() if isinstance(header, bytes) else header
        key = re.search(r"Credential=([A-Z0-9]+)/", header).group(1)
        signed.append((operation, urlsplit(request.url).netloc, key))
        if operation == "GetCallerIdentity":
            account = ACCOUNT_ID if key == KEY_A else OTHER_ACCOUNT
            body = identity_xml(account, "aws")
        elif operation == "DescribeInstances":
            body = ec2_instances_xml("running")
        elif operation == "RebootInstances":
            body = REBOOT_XML
        else:
            raise AssertionError(f"Unexpected offline request {operation}")
        return AWSResponse(request.url, 200, {}, OfflineBody(body))

    real_session = boto3.Session

    def session_factory(**kwargs):
        core = botocore.session.Session()
        session = real_session(botocore_session=core, **kwargs)
        # Hardened before the custom provider builds the credential resolver,
        # which then omits the env provider for the explicit profile; the
        # custom provider still leads the chain.
        framework.harden_session_origin(session)
        if provider is not None:
            core.get_component("credential_provider").providers.insert(0, provider)
        session.events.register("before-send", offline)
        return session

    monkeypatch.setattr(framework.boto3, "Session", session_factory)
    monkeypatch.setattr(framework.atexit, "register", lambda *args: None)
    monkeypatch.setattr(framework.signal, "signal", lambda *args: None)
    return bundle, signed


def profile_orchestrator(tmp_path):
    # RDS reboot is planning only, so the live-supported EC2 reboot carries the
    # admitted mutation that must sign with the pinned snapshot.
    values = action_configs()[framework.ChaosType.EC2_REBOOT]
    orchestrator = framework.ChaosOrchestrator(
        live_config(tmp_path, [{"type": "ec2_reboot", **values}], PROFILE_REGION),
        live=True,
        profile=PROFILE,
        output_dir=str(tmp_path / "reports"),
    )
    return orchestrator, values


def test_pinned_session_keeps_the_named_profile_shared_configuration(
    tmp_path, monkeypatch
):
    bundle, signed = offline_profile_aws(monkeypatch, tmp_path)
    orchestrator, _values = profile_orchestrator(tmp_path)
    assert orchestrator.actual_account == ACCOUNT_ID
    session = orchestrator.session
    assert orchestrator.safety_controller.session is session
    assert session.profile_name == PROFILE
    core = session._session
    assert core.get_config_variable("use_fips_endpoint") is True
    assert core.get_config_variable("ca_bundle") == bundle.as_posix()
    # The pinned credentials are static, not the profile's provider chain.
    assert type(core.get_credentials()) is Credentials
    assert core.get_credentials().access_key == KEY_A
    # STS admission and every later client use the pinned, profile-scoped session.
    assert signed == [("GetCallerIdentity", "sts-fips.us-east-1.amazonaws.com", KEY_A)]
    for service in ("sts", "rds", "kinesis"):
        client = orchestrator.safety_controller.client(service)._client
        assert client.meta.endpoint_url == (
            f"https://{service}-fips.{PROFILE_REGION}.amazonaws.com"
        )
        assert client._endpoint.http_session._verify == bundle.as_posix()


def test_refreshable_profile_cannot_sign_as_another_account_after_admission(
    tmp_path, monkeypatch
):
    clock = SyntheticClock()
    provider = SwitchingProvider(clock)
    _bundle, signed = offline_profile_aws(monkeypatch, tmp_path, provider)
    orchestrator, values = profile_orchestrator(tmp_path)
    assert orchestrator.actual_account == ACCOUNT_ID
    assert orchestrator.active_access_key_id == KEY_A

    # The provider now rotates to account B. Every later live client, cached or
    # new, must still sign with the snapshot verified at admission, including
    # an admitted EC2 mutation on the profile's FIPS endpoint.
    clock.value += timedelta(hours=3)
    controller = orchestrator.safety_controller
    assert controller.client("sts").get_caller_identity()["Account"] == ACCOUNT_ID
    orchestrator.suite_name = "ordinary"
    controller.check_safety_conditions = lambda: (True, [])
    orchestrator.confirmation = orchestrator.expected_confirmation("ordinary", False)
    kind = framework.ChaosType.EC2_REBOOT
    experiment = orchestrator._create_experiment(kind, copy.deepcopy(values))
    monkeypatch.setattr(experiment, "_wait_forward", lambda seconds: None)
    result = experiment.reboot_instances(values["instance_ids"])
    assert result.status == "completed", result.errors
    assert experiment.mutation_operations == ["ec2.reboot_instances"]
    assert ("RebootInstances", "ec2-fips.us-east-1.amazonaws.com", KEY_A) in signed
    assert {key for _operation, _host, key in signed} == {KEY_A}
    assert provider.refreshes == 0


def test_live_admission_without_resolvable_credentials_is_refused(tmp_path):
    session = SimpleNamespace(get_credentials=lambda: None)
    with (
        patch.object(framework.boto3, "Session", lambda **kwargs: session),
        patch.object(framework.signal, "signal"),
        patch.object(framework.atexit, "register"),
        pytest.raises(framework.SafetyViolation, match="no credentials"),
    ):
        framework.ChaosOrchestrator(
            live_config(tmp_path, [{"type": "ec2_reboot", "instance_ids": ["i-1"]}]),
            live=True,
            output_dir=str(tmp_path / "reports"),
        )


RDS_ARN = f"arn:aws-us-gov:rds:{REGION}:{ACCOUNT_ID}:db:chaos-test-db"
STREAM_ARN = f"arn:aws-us-gov:kinesis:{REGION}:{ACCOUNT_ID}:stream/chaos-test-stream"
# RDS reboot, retention and failover and Kinesis retention are planning only: a
# live attempt is refused before any name-only read. Their ARN checks remain as
# defence in depth and are exercised directly below.
RDS_NAME_ONLY = {
    framework.ChaosType.RDS_REBOOT: "reboot_db_instance",
    framework.ChaosType.RDS_BACKUP_RETENTION_MODIFY: "modify_db_instance",
    framework.ChaosType.RDS_FAILOVER: "failover_db_cluster",
    framework.ChaosType.KINESIS_RETENTION_MODIFY: "decrease_stream_retention_period",
}


def substitute(arn: str, case: str) -> str | None:
    parts = arn.split(":", 5)
    if case == "account":
        parts[4] = OTHER_ACCOUNT
    elif case == "region":
        parts[3] = "us-gov-east-1"
    elif case == "partition":
        parts[1] = "aws"
    elif case == "resource":
        parts[5] = parts[5] + "-other"
    elif case == "missing":
        return None
    return ":".join(parts)


def run_named(kind, aws, monkeypatch=None):
    experiment = make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    if monkeypatch is not None:
        # Deterministic bounded polling: no real waiting between observations.
        ticks = itertools.count()
        monkeypatch.setattr(framework.time, "monotonic", lambda: next(ticks))
        monkeypatch.setattr(framework.time, "sleep", lambda seconds: None)
        monkeypatch.setattr(experiment, "_wait_forward", lambda seconds: None)
    return experiment, framework.ChaosOrchestrator._execute_experiment(
        object.__new__(framework.ChaosOrchestrator),
        experiment,
        kind,
        action_configs()[kind],
    )


@pytest.mark.parametrize(
    "case", ["account", "region", "partition", "resource", "missing"]
)
def test_name_only_rds_and_kinesis_reads_bind_the_reviewed_arn_before_mutation(case):
    # Kinesis retention is planning only, so its handler's name-only ARN check is
    # defence in depth. The same reviewed-identity binding still refuses every
    # substituted or missing stream ARN.
    value = substitute(STREAM_ARN, case)
    with pytest.raises(framework.SafetyViolation):
        framework.validate_named_response_arn(
            value, "kinesis", "stream/chaos-test-stream", ACCOUNT_ID, REGION
        )


@pytest.mark.parametrize("kind", sorted(RDS_NAME_ONLY, key=lambda item: item.value))
def test_name_only_rds_live_reads_are_never_reached(kind, monkeypatch):
    aws = FakeAWS(reject_writes=False)
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        run_named(kind, aws, monkeypatch)
    assert aws.calls == []
    planned = planning_only_experiment(kind, action_configs()[kind], aws)
    result = framework.ChaosOrchestrator._execute_experiment(
        object.__new__(framework.ChaosOrchestrator),
        planned,
        kind,
        action_configs()[kind],
    )
    assert result.status == "completed", result.errors
    assert RDS_NAME_ONLY[kind] not in [operation for _s, operation, _r in aws.calls]
    assert planned.mutation_attempts == []


def test_name_only_arn_binding_accepts_the_exact_reviewed_identity():
    framework.validate_named_response_arn(
        RDS_ARN.replace("db:chaos-test-db", "db:Chaos-Test-DB"),
        "rds",
        "db:chaos-test-db",
        ACCOUNT_ID,
        REGION,
        case_insensitive=True,
    )
    with pytest.raises(framework.SafetyViolation):
        framework.validate_named_response_arn(
            STREAM_ARN.replace("chaos-test-stream", "Chaos-Test-Stream"),
            "kinesis",
            "stream/chaos-test-stream",
            ACCOUNT_ID,
            REGION,
        )
    framework.validate_named_response_arn(
        STREAM_ARN, "kinesis", "stream/chaos-test-stream", ACCOUNT_ID, REGION
    )
    aws = FakeAWS(reject_writes=False)
    assert (
        aws.respond("kinesis", "describe_stream", {})["StreamDescription"]["StreamARN"]
        == STREAM_ARN
    )


# 2. S3 lifecycle expiration carries the reviewed prefix and is planning only.

LIFECYCLE = framework.ChaosType.S3_LIFECYCLE_MODIFY
LIFECYCLE_VALUES = action_configs()[LIFECYCLE]
BUCKET = LIFECYCLE_VALUES["bucket_name"]
UNRELATED_RULES = [
    {
        "ID": "operator-archive",
        "Status": "Enabled",
        "Filter": {"Prefix": "archive/"},
        "Transitions": [{"Days": 30, "StorageClass": "GLACIER"}],
    },
    {
        "ID": "operator-logs",
        "Status": "Disabled",
        "Filter": {"Prefix": "logs/"},
        "Expiration": {"Days": 365},
    },
]


def lifecycle_suite(experiment: dict[str, Any]) -> dict[str, Any]:
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    config["safety"]["allow_irreversible"] = True
    config["experiment_suites"] = {
        "reviewed": {"experiments": [{"type": LIFECYCLE.value, **experiment}]}
    }
    return config


def test_reviewed_prefix_is_the_exact_planned_filter_and_unrelated_rules_survive():
    aws = FakeAWS(reject_writes=True)
    aws.read_overrides[("s3", "get_bucket_lifecycle_configuration")] = [
        {"Rules": copy.deepcopy(UNRELATED_RULES)}
    ]
    plan = planning_only_experiment(LIFECYCLE, LIFECYCLE_VALUES, aws)
    result = framework.ChaosOrchestrator._execute_experiment(
        object.__new__(framework.ChaosOrchestrator), plan, LIFECYCLE, LIFECYCLE_VALUES
    )
    assert result.status == "completed", result.errors
    rules = plan.planned_lifecycle["Rules"]
    assert rules[:2] == UNRELATED_RULES
    assert rules[2] == {
        "ID": framework.S3_LIFECYCLE_RULE_ID,
        "Status": "Enabled",
        "Filter": {"Prefix": LIFECYCLE_VALUES["prefix"]},
        "Expiration": {"Days": LIFECYCLE_VALUES["expire_days"]},
    }
    assert all(rule["Filter"].get("Prefix") for rule in rules)
    assert writes(aws) == [] and plan.mutation_attempts == []
    # The assembled plan is also structured result evidence.
    evidence = result.additional_info["lifecycle_plan"]
    assert evidence == {
        "rule_count": 3,
        "preserved_rules": [
            {
                "ordinal": 1,
                "status": "Enabled",
                "actions": ["Transitions"],
                "sha256": rule_digest(UNRELATED_RULES[0]),
            },
            {
                "ordinal": 2,
                "status": "Disabled",
                "actions": ["Expiration"],
                "sha256": rule_digest(UNRELATED_RULES[1]),
            },
        ],
        "chaos_rule": {
            "ordinal": 3,
            "status": "Enabled",
            "filter_prefix": LIFECYCLE_VALUES["prefix"],
            "expiration_days": LIFECYCLE_VALUES["expire_days"],
            "sha256": rule_digest(rules[2]),
        },
    }


def rule_digest(rule: dict[str, Any]) -> str:
    encoded = json.dumps(rule, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def test_lifecycle_plan_is_in_diagnostic_reports_without_unrelated_rule_values():
    aws = FakeAWS(reject_writes=True)
    aws.read_overrides[("s3", "get_bucket_lifecycle_configuration")] = [
        {"Rules": copy.deepcopy(UNRELATED_RULES)}
    ]
    orchestrator = make_orchestrator(LIFECYCLE, LIFECYCLE_VALUES, aws)
    orchestrator.config["reporting"] = {"include_diagnostics": True}
    assert orchestrator.run_experiment_suite("ordinary") is True
    report_text = orchestrator.report_path.read_text(encoding="utf-8")
    plan = json.loads(report_text)["experiments"][0]["additional_info"][
        "lifecycle_plan"
    ]
    assert plan["rule_count"] == 3
    assert [rule["sha256"] for rule in plan["preserved_rules"]] == [
        rule_digest(rule) for rule in UNRELATED_RULES
    ]
    # Unrelated rule IDs and filters are not disclosed; the reviewed prefix is a
    # registered target and stays redacted in diagnostics.
    for value in ("operator-archive", "operator-logs", "archive/", "logs/"):
        assert value not in report_text
    assert LIFECYCLE_VALUES["prefix"] not in report_text
    assert writes(aws) == []


@pytest.mark.parametrize(
    "prefix", [None, "", " chaos-test/", "chaos-test/ ", "chaos\n/", "x" * 1025]
)
def test_implicit_empty_or_noncanonical_prefix_is_rejected_before_token(prefix):
    experiment = {"bucket_name": BUCKET, "expire_days": 1}
    if prefix is not None:
        experiment["prefix"] = prefix
    config = lifecycle_suite(experiment)
    with pytest.raises(framework.ConfigurationError, match="prefix"):
        framework.validate_config_data(config)
    with pytest.raises(framework.ConfigurationError, match="prefix"):
        framework.confirmation_token(config, "reviewed")
    aws = FakeAWS(reject_writes=True)
    plan = make_experiment(LIFECYCLE, LIFECYCLE_VALUES, FakeAWS(), dry_run=True)
    plan.s3 = framework.AwsClientProxy("s3", aws.client("s3"), plan)
    assert plan.modify_lifecycle(BUCKET, 1, prefix).status == "failed"
    assert aws.calls == []


@pytest.mark.parametrize(
    "extra",
    [
        {"objects": [{"Key": "chaos-test/a"}]},
        {"max_objects": 1},
        {"instance_ids": ["i-0123456789abcdef0"]},
        {"queue_url": "https://example.invalid/q"},
        {"filter": {"Prefix": ""}},
        {"lifecycle_rules": []},
        {"whole_bucket": True},
    ],
)
def test_extraneous_lifecycle_selectors_are_rejected_before_token(extra):
    config = lifecycle_suite({**LIFECYCLE_VALUES, **extra})
    with pytest.raises(framework.ConfigurationError, match="does not use"):
        framework.validate_config_data(config)
    with pytest.raises(framework.ConfigurationError, match="does not use"):
        framework.confirmation_token(config, "reviewed")


def test_lifecycle_metadata_keys_remain_accepted():
    metadata = {
        "name": "expire-chaos-prefix",
        "description": "planning only",
        "duration_seconds": 60,
        "state_timeout_seconds": 60,
    }
    framework.validate_config_data(lifecycle_suite({**LIFECYCLE_VALUES, **metadata}))


def test_reviewed_lifecycle_prefix_is_bound_into_allowlist_and_digest():
    reviewed = {"type": LIFECYCLE.value, **LIFECYCLE_VALUES}
    other = {**LIFECYCLE_VALUES, "prefix": "chaos-other/"}
    targets = framework.ChaosOrchestrator._target_values(reviewed)
    assert LIFECYCLE_VALUES["prefix"] in targets
    assert "chaos-other/" not in targets
    assert framework.ChaosOrchestrator._blast_radius(LIFECYCLE, reviewed) == 1
    # No live token digest exists for lifecycle; generation is refused for both.
    for values in (LIFECYCLE_VALUES, other):
        with pytest.raises(framework.ConfigurationError, match="Live approval"):
            framework.confirmation_token(lifecycle_suite(values), "reviewed")
    # The plan evidence digest binds the exact reviewed rule and its prefix.
    digests = []
    for values in (LIFECYCLE_VALUES, other):
        plan = make_experiment(LIFECYCLE, values, FakeAWS(), dry_run=True)
        result = plan.modify_lifecycle(**values)
        chaos = result.additional_info["lifecycle_plan"]["chaos_rule"]
        assert chaos["filter_prefix"] == values["prefix"]
        assert chaos["sha256"] == rule_digest(plan.planned_lifecycle["Rules"][-1])
        digests.append(chaos["sha256"])
    assert digests[0] != digests[1]


def test_existing_chaos_rule_id_is_never_replaced():
    aws = FakeAWS(reject_writes=True)
    existing = {
        **copy.deepcopy(UNRELATED_RULES[0]),
        "ID": framework.S3_LIFECYCLE_RULE_ID,
    }
    aws.read_overrides[("s3", "get_bucket_lifecycle_configuration")] = [
        {"Rules": [existing]}
    ]
    plan = make_experiment(LIFECYCLE, LIFECYCLE_VALUES, aws, dry_run=True)
    result = plan.modify_lifecycle(**LIFECYCLE_VALUES)
    assert result.status == "failed"
    assert not hasattr(plan, "planned_lifecycle")
    assert writes(aws) == []


def test_live_lifecycle_replacement_is_refused_at_token_admission_and_sdk():
    assert not framework.experiment_metadata(LIFECYCLE).live_supported
    with pytest.raises(framework.ConfigurationError, match="Live approval"):
        framework.confirmation_token(lifecycle_suite(LIFECYCLE_VALUES), "reviewed")
    aws = FakeAWS(reject_writes=False)
    planning_only_experiment(LIFECYCLE, LIFECYCLE_VALUES, aws)
    # Even an admitted owner inside its forward dispatch cannot send the write.
    owner = make_experiment(
        framework.ChaosType.EC2_REBOOT,
        action_configs()[framework.ChaosType.EC2_REBOOT],
        aws,
        dry_run=False,
    )
    owner._sdk_request_authority.execution = owner._execution_grant
    owner._sdk_request_authority.phase = "forward"
    aws.calls.clear()
    with pytest.raises(framework.SafetyViolation, match="Live mutation is disabled"):
        owner.client("s3").put_bucket_lifecycle_configuration(
            Bucket=BUCKET,
            LifecycleConfiguration={"Rules": copy.deepcopy(UNRELATED_RULES)},
        )
    assert aws.calls == [] and owner.mutation_attempts == []


# 3. The original subnet NACL is an explicit reviewed recovery target.

NACL_KIND = framework.ChaosType.VPC_SUBNET_ACL_MODIFY
NACL_VALUES = action_configs()[NACL_KIND]
ORIGINAL = NACL_VALUES["original_nacl_id"]
OTHER_ORIGINAL = "acl-0fedcba9876543219"


def nacl_suite(values: dict[str, Any]) -> dict[str, Any]:
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    config["experiment_suites"] = {
        "reviewed": {"experiments": [{"type": NACL_KIND.value, **values}]}
    }
    return config


def test_original_nacl_is_required_and_bound_into_token_and_allowlist():
    missing = {
        key: value for key, value in NACL_VALUES.items() if key != "original_nacl_id"
    }
    with pytest.raises(framework.ConfigurationError, match="original_nacl_id"):
        framework.confirmation_token(nacl_suite(missing), "reviewed")
    token = framework.confirmation_token(nacl_suite(NACL_VALUES), "reviewed")
    changed = {**NACL_VALUES, "original_nacl_id": OTHER_ORIGINAL}
    assert framework.confirmation_token(nacl_suite(changed), "reviewed") != token
    targets = framework.ChaosOrchestrator._target_values(
        {"type": NACL_KIND.value, **NACL_VALUES}
    )
    assert ORIGINAL in targets
    orchestrator = make_orchestrator(NACL_KIND, NACL_VALUES, FakeAWS(), dry_run=False)
    experiment = orchestrator._create_experiment(NACL_KIND, copy.deepcopy(NACL_VALUES))
    assert ORIGINAL in experiment._execution_grant.targets
    assert json.loads(experiment._execution_grant.config_json)["original_nacl_id"] == (
        ORIGINAL
    )


def test_live_admission_fails_when_original_nacl_is_absent_from_allowlist():
    aws = FakeAWS(reject_writes=False)
    orchestrator = make_orchestrator(NACL_KIND, NACL_VALUES, aws, dry_run=False)
    allowlist = orchestrator.config["safety"]["target_allowlist"]
    allowlist.remove(ORIGINAL)
    orchestrator.confirmation = orchestrator.expected_confirmation("ordinary", False)
    aws.calls.clear()
    with pytest.raises(framework.SafetyViolation, match="exact target allowlist"):
        orchestrator._create_experiment(NACL_KIND, copy.deepcopy(NACL_VALUES))
    assert aws.calls == []


def test_changing_original_nacl_after_token_creation_invalidates_execution():
    aws = FakeAWS(reject_writes=False)
    orchestrator = make_orchestrator(NACL_KIND, NACL_VALUES, aws, dry_run=False)
    changed = {**NACL_VALUES, "original_nacl_id": OTHER_ORIGINAL}
    orchestrator.config["experiment_suites"]["ordinary"]["experiments"][0][
        "original_nacl_id"
    ] = OTHER_ORIGINAL
    orchestrator.config["safety"]["target_allowlist"].append(OTHER_ORIGINAL)
    aws.calls.clear()
    with pytest.raises(framework.SafetyViolation, match="confirmed reviewed suite"):
        orchestrator._create_experiment(NACL_KIND, copy.deepcopy(changed))
    assert aws.calls == []


@pytest.mark.parametrize("dry_run", [False, True])
def test_observed_original_nacl_that_differs_refuses_before_any_write(dry_run):
    aws = FakeAWS(reject_writes=dry_run)
    current = aws.respond("ec2", "describe_network_acls", {})
    current["NetworkAcls"][0]["NetworkAclId"] = OTHER_ORIGINAL
    aws.read_overrides[("ec2", "describe_network_acls")] = [current]
    experiment = make_experiment(NACL_KIND, NACL_VALUES, aws, dry_run=dry_run)
    aws.calls.clear()
    result = framework.ChaosOrchestrator._execute_experiment(
        object.__new__(framework.ChaosOrchestrator), experiment, NACL_KIND, NACL_VALUES
    )
    assert result.status == "failed"
    assert "original_nacl_id" in " ".join(result.errors)
    assert writes(aws) == [] and experiment.mutation_attempts == []
    assert not hasattr(experiment, "original_nacl_id")


def confirmed_nacl_forward(aws):
    original = aws.respond("ec2", "describe_network_acls", {})
    changed = copy.deepcopy(original)
    changed["NetworkAcls"][0]["NetworkAclId"] = NACL_VALUES["nacl_id"]
    changed["NetworkAcls"][0]["Associations"][0]["NetworkAclAssociationId"] = (
        "aclassoc-0fedcba9876543210"
    )
    aws.read_overrides[("ec2", "describe_network_acls")] = [original, changed, original]
    respond = aws.respond

    def response(service, operation, request):
        value = respond(service, operation, request)
        if operation == "replace_network_acl_association":
            return {"NewAssociationId": "aclassoc-0fedcba9876543210"}
        return value

    aws.respond = response
    experiment = make_experiment(NACL_KIND, NACL_VALUES, aws, dry_run=False)
    assert experiment.modify_subnet_acl(**NACL_VALUES).status == "completed"
    return experiment


def recovery_targets(aws) -> list[str]:
    return [
        request["NetworkAclId"]
        for _service, operation, request in aws.calls
        if operation == "replace_network_acl_association"
    ][1:]


def test_recovery_writes_only_the_reviewed_original_nacl():
    aws = FakeAWS(reject_writes=False)
    experiment = confirmed_nacl_forward(aws)
    experiment.run_rollback()
    assert experiment.rollback_verified
    assert recovery_targets(aws) == [ORIGINAL]


def test_recovery_refuses_an_original_nacl_outside_the_execution_grant():
    aws = FakeAWS(reject_writes=False)
    experiment = confirmed_nacl_forward(aws)
    experiment.original_nacl_id = OTHER_ORIGINAL
    with pytest.raises(framework.SafetyViolation, match="reviewed original_nacl_id"):
        experiment.run_rollback()
    assert recovery_targets(aws) == []
    assert not experiment.rollback_verified


def test_vpc_scope_requires_the_original_nacl_in_tagged_inventory():
    inventory = {
        "subnets": [NACL_VALUES["subnet_id"]],
        "nacls": [NACL_VALUES["nacl_id"]],
    }
    with pytest.raises(framework.ConfigurationError, match="original_nacl_id"):
        framework.validate_vpc_target_scope(
            NACL_KIND, NACL_VALUES, "vpc-0123456789abcdef0", inventory
        )
    inventory["nacls"].append(ORIGINAL)
    framework.validate_vpc_target_scope(
        NACL_KIND, NACL_VALUES, "vpc-0123456789abcdef0", inventory
    )


# 4. FIS target aliases never enter free-form diagnostics.

ALIASES = [
    "PayrollDbAliasSensitive",
    "ledger-Primary-Hosts",
    "TeamSecretTargetName",
    "customer_alpha_fleet",
    "OpsAliasWithArnLookalike",
]


def alias_template() -> dict[str, Any]:
    instance = f"arn:aws-us-gov:ec2:{REGION}:{ACCOUNT_ID}:instance/i-0123456789abcdef0"
    foreign = (
        f"arn:aws-us-gov:ec2:{REGION}:{OTHER_ACCOUNT}:instance/i-0123456789abcdef1"
    )
    selections = [
        {"selectionMode": "PERCENT(500)"},
        {"selectionMode": "ALL", "resourceTags": {}},
        {"selectionMode": "COUNT(5)"},
        {"selectionMode": f"BOGUS {ALIASES[3]}"},
        {"selectionMode": "COUNT(1)", "resourceArns": [instance, foreign]},
    ]
    return {
        "id": "EXT1234567890abcdef0",
        "roleArn": f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/ChaosFisRole",
        "actions": {},
        "targets": {
            alias: {"resourceType": "aws:ec2:instance", **selection}
            for alias, selection in zip(ALIASES, selections, strict=True)
        },
        "stopConditions": [],
    }


def assert_no_alias(text: str) -> None:
    for alias in ALIASES:
        assert alias not in text


def test_every_fis_guardrail_branch_names_targets_by_ordinal_only():
    kind = framework.ChaosType.FIS_TEMPLATE
    plan = make_experiment(kind, action_configs()[kind], FakeAWS())
    violations = plan._validate_template(alias_template())
    # Live-only branches (unbounded selection, allowlist and tag checks) are
    # evaluated on the same template without dispatching anything.
    plan.dry_run = False
    violations += plan._validate_template(alias_template())
    text = "\n".join(violations)
    assert_no_alias(text)
    for expected in (
        "FIS target #1 has an invalid selection mode",
        "FIS target #2 uses unbounded selection mode ALL",
        "FIS target #2 is missing required target tags",
        "FIS target #3 exceeds max_blast_radius",
        "FIS target #4 has an invalid selection mode",
        "FIS target #5 contains ARNs not in target_allowlist",
    ):
        assert expected in text


@pytest.mark.parametrize("diagnostics", [False, True])
def test_fis_aliases_are_absent_from_logs_and_default_report(diagnostics):
    kind = framework.ChaosType.FIS_TEMPLATE
    aws = FakeAWS()
    aws.read_overrides[("fis", "get_experiment_template")] = [
        {"experimentTemplate": alias_template()}
    ]
    orchestrator = make_orchestrator(kind, action_configs()[kind], aws)
    orchestrator.config["reporting"] = {"include_diagnostics": diagnostics}
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(framework.PrivacyFormatter("%(levelname)s %(message)s"))
    framework.logger.addHandler(handler)
    level = framework.logger.level
    framework.logger.setLevel(logging.DEBUG)
    try:
        assert orchestrator.run_experiment_suite("ordinary") is False
    finally:
        framework.logger.removeHandler(handler)
        framework.logger.setLevel(level)
    log_text = stream.getvalue()
    report_text = orchestrator.report_path.read_text(encoding="utf-8")
    assert "FIS target #1" in log_text
    assert "FIS target #1" in report_text
    assert_no_alias(log_text)
    assert_no_alias(report_text)
    assert writes(aws) == []


# 5. ECS multi-task stop keeps per-task evidence after a partial failure.

ECS_KIND = framework.ChaosType.ECS_TASK_STOP
TASKS = [
    f"arn:aws-us-gov:ecs:{REGION}:{ACCOUNT_ID}:task/chaos-test/0123456789abcdef",
    f"arn:aws-us-gov:ecs:{REGION}:{ACCOUNT_ID}:task/chaos-test/fedcba9876543210",
]
ECS_VALUES = {"cluster": "chaos-test-cluster", "task_arns": TASKS}


def ecs_partial(second):
    aws = FakeAWS(reject_writes=False)
    aws.read_overrides[("ecs", "describe_tasks")] = [
        {
            "tasks": [{"taskArn": task, "lastStatus": "RUNNING"} for task in TASKS],
            "failures": [],
        }
    ]
    respond = aws.respond

    def response(service, operation, request):
        value = respond(service, operation, request)
        if operation == "stop_task" and request["task"] == TASKS[1]:
            if isinstance(second, Exception):
                raise second
            return second
        return value

    aws.respond = response
    orchestrator = make_orchestrator(ECS_KIND, ECS_VALUES, aws, dry_run=False)
    experiment = orchestrator._create_experiment(ECS_KIND, copy.deepcopy(ECS_VALUES))
    result = experiment.stop_tasks(**ECS_VALUES)
    return orchestrator, experiment, result, aws


@pytest.mark.parametrize(
    "second",
    [
        FakeClientError("ThrottlingException"),
        {"task": {"taskArn": TASKS[0], "desiredStatus": "STOPPED"}},
        {},
    ],
    ids=["raises", "wrong-task", "unconfirmed"],
)
def test_partial_ecs_stop_keeps_exactly_the_confirmed_task(second, tmp_path):
    orchestrator, experiment, result, aws = ecs_partial(second)
    assert result.status == "failed"
    assert result.affected_resources == [TASKS[0]]
    assert result.additional_info["task_outcomes"] == [
        {"ordinal": 1, "outcome": "stopped"},
        {"ordinal": 2, "outcome": "unconfirmed"},
    ]
    stops = [r["task"] for _s, op, r in aws.calls if op == "stop_task"]
    assert stops == TASKS
    assert experiment.mutation_attempts == ["ecs.stop_task", "ecs.stop_task"]

    result.mutation_attempts = list(experiment.mutation_attempts)
    orchestrator.results = [result]
    orchestrator.output_dir = tmp_path
    # Default report: privacy-filtered count and status, no identifiers.
    default = json.loads(orchestrator._generate_report().read_text(encoding="utf-8"))
    entry = default["experiments"][0]
    assert entry["status"] == "failed"
    assert entry["affected_resource_count"] == 1
    assert "affected_resources" not in entry
    assert all(task not in json.dumps(default) for task in TASKS)
    # Opt-in disclosure shows exactly the confirmed task and ordinal outcomes.
    orchestrator.run_id = "ecs-disclosed"
    orchestrator.config["reporting"] = {
        "include_resource_ids": True,
        "include_identity": True,
        "include_diagnostics": True,
    }
    disclosed = json.loads(orchestrator._generate_report().read_text(encoding="utf-8"))[
        "experiments"
    ][0]
    assert disclosed["affected_resources"] == [TASKS[0]]
    assert disclosed["additional_info"]["task_outcomes"][1] == {
        "ordinal": 2,
        "outcome": "unconfirmed",
    }
    assert TASKS[1] not in json.dumps(disclosed["additional_info"])


def test_complete_ecs_stop_confirms_every_task():
    _orchestrator, _experiment, result, _aws = ecs_partial(
        {"task": {"taskArn": TASKS[1], "desiredStatus": "STOPPED"}}
    )
    assert result.status == "completed", result.errors
    assert result.affected_resources == TASKS
    assert [item["outcome"] for item in result.additional_info["task_outcomes"]] == [
        "stopped",
        "stopped",
    ]
