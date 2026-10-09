"""Offline regressions for the two-finding Cloud scan of main a8767d8.

1. Live account binding trusts identity only from canonical AWS origins: every
   SDK client ignores configured endpoint URLs and refuses any request whose
   host is not botocore's bundled canonical host for the partition, service,
   region and approved FIPS choice.
2. Protected promotion attests only wheels whose every member is source-bound.

Round 2 adds credential-provider clients (assume-role, web identity, SSO and
SSO-OIDC refresh), the IMDS/container credential address policy, disabled
account-based endpoints, exact generated sdist bytes and the Host header check.
Round 3 adds reviewed parent domains outside the partition dnsSuffix (AWS
Sign-In, used by the login provider's token refresh) and login refresh.

Every AWS answer is an offline botocore before-send response; no credentials
are resolved and no network is contacted.
"""

from __future__ import annotations

import base64
import copy
import csv
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import boto3
import botocore.credentials
import botocore.httpsession
import botocore.session
import botocore.tokens
import botocore.utils
import pytest
from botocore.awsrequest import AWSResponse
from botocore.config import Config
from test_aws_chaos_framework import ACCOUNT_ID, FakeEvents, action_configs
from test_final_cloud_eight_scope_controls import (
    KEY_A,
    OTHER_ACCOUNT,
    PROFILE,
    PROFILE_REGION,
    REBOOT_XML,
    OfflineBody,
    ec2_instances_xml,
    identity_xml,
    live_config,
)

import aws_chaos_framework as framework
from scripts import normalize_sdist, normalize_wheel
from scripts import verify_distribution as verifier

ROOT = Path(__file__).resolve().parents[1]
EPOCH = 315532800
ATTACKER = "https://sts.attacker.example"
# An AWS-domain host whose TLS certificate is valid but whose responder is any
# customer's API: a DNS-suffix check alone would admit it.
CUSTOMER_AWS_HOST = "https://a1b2c3d4e5.execute-api.us-east-1.amazonaws.com"
KEY_ROLE = "ASIA" + "R" * 16
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/ChaosOperator"
ENDPOINT_VARIABLES = (
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_STS",
    "AWS_ENDPOINT_URL_EC2",
    "AWS_ENDPOINT_URL_RDS",
    "AWS_ENDPOINT_URL_KINESIS",
    "AWS_ENDPOINT_URL_S3",
    "AWS_ENDPOINT_URL_IAM",
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
)


class Delivered(Exception):
    """Raised by the offline transport once a request was admitted for sending."""


def assume_role_xml() -> bytes:
    return (
        '<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        "<AssumeRoleResult><Credentials>"
        f"<AccessKeyId>{KEY_ROLE}</AccessKeyId>"
        "<SecretAccessKey>secret-role</SecretAccessKey>"
        "<SessionToken>token-role</SessionToken>"
        "<Expiration>2099-01-01T00:00:00Z</Expiration>"
        "</Credentials><AssumedRoleUser>"
        f"<Arn>arn:aws:sts::{ACCOUNT_ID}:assumed-role/ChaosOperator/s</Arn>"
        "<AssumedRoleId>AROAEXAMPLE:s</AssumedRoleId>"
        "</AssumedRoleUser></AssumeRoleResult>"
        "<ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>"
        "</AssumeRoleResponse>"
    ).encode()


def forged_ruleset_path(tmp_path: Path, service: str, version: str) -> Path:
    """A customer data path whose endpoint ruleset redirects one service."""
    root = tmp_path / "customer-models"
    target = root / service / version
    target.mkdir(parents=True)
    ruleset = {
        "version": "1.0",
        "parameters": {
            "Region": {"builtIn": "AWS::Region", "required": False, "type": "String"}
        },
        "rules": [
            {
                "conditions": [],
                "endpoint": {"url": ATTACKER, "properties": {}, "headers": {}},
                "type": "endpoint",
            }
        ],
    }
    (target / "endpoint-rule-set-1.json").write_text(
        json.dumps(ruleset), encoding="utf-8"
    )
    return root


def offline_aws(
    monkeypatch,
    tmp_path,
    *,
    profile_lines: str = "",
    extra_config: str = "",
    environment: dict[str, str] | None = None,
    credential_account: str = ACCOUNT_ID,
) -> list[tuple[str, str, str]]:
    """Real boto3/botocore sessions over temporary shared config, answered offline.

    Canonical AWS hosts answer truthfully for the account that owns KEY_A.
    Any other host answers a forged identity claiming the configured account,
    so trusting a non-canonical origin is observable as a successful admission.
    """
    config_file = tmp_path / "aws-config"
    config_file.write_text(
        f"[profile {PROFILE}]\nregion = {PROFILE_REGION}\n{profile_lines}"
        f"{extra_config}",
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
        "AWS_USE_DUALSTACK_ENDPOINT",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_DATA_PATH",
        *ENDPOINT_VARIABLES,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config_file))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials_file))
    for name, value in (environment or {}).items():
        monkeypatch.setenv(name, value)
    signed: list[tuple[str, str, str]] = []

    def offline(request, event_name, **_kwargs):
        operation = event_name.rsplit(".", 1)[-1]
        header = request.headers.get("Authorization", b"")
        header = header.decode() if isinstance(header, bytes) else header
        key = header.split("Credential=", 1)[1].split("/", 1)[0]
        host = urlsplit(request.url).netloc
        signed.append((operation, host, key))
        canonical = host.endswith(".amazonaws.com") and "execute-api" not in host
        if operation == "GetCallerIdentity":
            # A forged responder claims the reviewed account; canonical STS
            # reports the account that really owns the signing credentials
            # (assumed-role KEY_ROLE credentials belong to the reviewed account).
            truthful = canonical and key != KEY_ROLE
            body = identity_xml(credential_account if truthful else ACCOUNT_ID, "aws")
        elif operation == "AssumeRole":
            body = assume_role_xml()
        elif operation == "DescribeInstances":
            body = ec2_instances_xml("running")
        elif operation == "RebootInstances":
            body = REBOOT_XML
        else:
            raise AssertionError(f"Unexpected offline request {operation}")
        return AWSResponse(request.url, 200, {}, OfflineBody(body))

    real_session = boto3.Session

    def session_factory(**kwargs):
        session = real_session(botocore_session=botocore.session.Session(), **kwargs)
        session.events.register("before-send", offline)
        return session

    monkeypatch.setattr(framework.boto3, "Session", session_factory)
    monkeypatch.setattr(framework.atexit, "register", lambda *args: None)
    monkeypatch.setattr(framework.signal, "signal", lambda *args: None)
    return signed


def live_orchestrator(tmp_path, *, live: bool = True, role: bool = False):
    values = action_configs()[framework.ChaosType.EC2_REBOOT]
    path = live_config(tmp_path, [{"type": "ec2_reboot", **values}], PROFILE_REGION)
    if role:
        config = framework.yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        config["global"]["role_arn"] = ROLE_ARN
        config["global"]["external_id"] = "synthetic-external-id"
        Path(path).write_text(framework.yaml.safe_dump(config), encoding="utf-8")
    orchestrator = framework.ChaosOrchestrator(
        path, live=live, profile=PROFILE, output_dir=str(tmp_path / "reports")
    )
    return orchestrator, values


def reboot(orchestrator, values, monkeypatch):
    """Drive the reviewed opaque-ID mutator exactly as an approved run would."""
    orchestrator.suite_name = "ordinary"
    orchestrator.safety_controller.check_safety_conditions = lambda: (True, [])
    orchestrator.confirmation = orchestrator.expected_confirmation("ordinary", False)
    experiment = orchestrator._create_experiment(
        framework.ChaosType.EC2_REBOOT, copy.deepcopy(values)
    )
    monkeypatch.setattr(experiment, "_wait_forward", lambda seconds: None)
    return experiment.reboot_instances(values["instance_ids"])


def admit_then_reach_mutator(tmp_path, monkeypatch) -> str | None:
    """Return the live refusal, or drive the mutator if a forged identity won."""
    try:
        orchestrator, values = live_orchestrator(tmp_path)
    except framework.SafetyViolation as exc:
        return str(exc)
    reboot(orchestrator, values, monkeypatch)
    return None


PROFILE_ENDPOINTS = {
    "profile_endpoint_url": (f"endpoint_url = {ATTACKER}\n", ""),
    "profile_sts_services_section": (
        "services = forged\n",
        f"[services forged]\nsts =\n  endpoint_url = {ATTACKER}\n",
    ),
    "aws_domain_customer_host": (f"endpoint_url = {CUSTOMER_AWS_HOST}\n", ""),
}


@pytest.mark.parametrize("style", sorted(PROFILE_ENDPOINTS))
def test_profile_sts_endpoint_cannot_supply_the_live_identity(
    tmp_path, monkeypatch, style
):
    profile_lines, extra_config = PROFILE_ENDPOINTS[style]
    # KEY_A really belongs to another account; the configured endpoint claims
    # the reviewed one. Only the canonical STS answer may decide admission.
    signed = offline_aws(
        monkeypatch,
        tmp_path,
        profile_lines=profile_lines,
        extra_config=extra_config,
        credential_account=OTHER_ACCOUNT,
    )
    refusal = admit_then_reach_mutator(tmp_path, monkeypatch)
    assert refusal is not None
    assert "Configured account does not match the active AWS identity" in refusal
    assert signed == [("GetCallerIdentity", "sts.us-east-1.amazonaws.com", KEY_A)]
    assert not any(operation == "RebootInstances" for operation, _h, _k in signed)


def test_plan_identity_never_comes_from_a_configured_endpoint(tmp_path, monkeypatch):
    signed = offline_aws(
        monkeypatch,
        tmp_path,
        profile_lines=f"endpoint_url = {ATTACKER}\n",
        credential_account=OTHER_ACCOUNT,
    )
    orchestrator, _values = live_orchestrator(tmp_path, live=False)
    assert orchestrator.actual_account == OTHER_ACCOUNT
    assert {host for _operation, host, _key in signed} == {
        "sts.us-east-1.amazonaws.com"
    }


@pytest.mark.parametrize("service_specific", [False, True])
def test_endpoint_environment_variables_are_ignored_by_every_live_client(
    tmp_path, monkeypatch, service_specific
):
    environment = (
        {
            name: ATTACKER
            for name in ENDPOINT_VARIABLES
            if name.startswith("AWS_ENDPOINT_URL_")
        }
        if service_specific
        else {"AWS_ENDPOINT_URL": ATTACKER}
    )
    environment["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "false"
    signed = offline_aws(monkeypatch, tmp_path, environment=environment)
    orchestrator, values = live_orchestrator(tmp_path)
    assert orchestrator.actual_account == ACCOUNT_ID
    result = reboot(orchestrator, values, monkeypatch)
    assert result.status == "completed", result.errors
    assert {host for _operation, host, _key in signed} == {
        "sts.us-east-1.amazonaws.com",
        "ec2.us-east-1.amazonaws.com",
    }
    assert ("RebootInstances", "ec2.us-east-1.amazonaws.com", KEY_A) in signed
    # Every reviewed service client, including ones first built after
    # admission, resolves to its canonical host despite the variables.
    controller = orchestrator.safety_controller
    for service in sorted(framework.READ_ONLY_OPERATIONS):
        raw = controller.client(service)._client
        parents, hosts = framework.canonical_endpoint_origin(
            service, PROFILE_REGION, False
        )
        host = urlsplit(raw.meta.endpoint_url).hostname
        assert "attacker" not in raw.meta.endpoint_url
        assert framework.is_under_domains(host, parents)


def test_pre_role_sts_and_external_id_stay_on_the_canonical_origin(
    tmp_path, monkeypatch
):
    signed = offline_aws(
        monkeypatch,
        tmp_path,
        profile_lines=f"endpoint_url = {ATTACKER}\n",
        environment={"AWS_ENDPOINT_URL_STS": ATTACKER},
    )
    orchestrator, _values = live_orchestrator(tmp_path, role=True)
    assert orchestrator.actual_account == ACCOUNT_ID
    assert signed == [
        ("AssumeRole", "sts.us-east-1.amazonaws.com", KEY_A),
        ("GetCallerIdentity", "sts.us-east-1.amazonaws.com", KEY_ROLE),
    ]


def test_customer_endpoint_rules_cannot_supply_a_forged_live_identity(
    tmp_path, monkeypatch
):
    # A customer data path replaces the STS ruleset itself, which redirects the
    # request even though endpoint_url is ignored. The request is refused at
    # send time, so the forged identity can never reach the reboot mutator.
    data_path = forged_ruleset_path(tmp_path, "sts", "2011-06-15")
    signed = offline_aws(
        monkeypatch,
        tmp_path,
        environment={"AWS_DATA_PATH": str(data_path)},
        credential_account=OTHER_ACCOUNT,
    )
    refusal = admit_then_reach_mutator(tmp_path, monkeypatch)
    assert refusal is not None
    assert "routed to a non-canonical endpoint" in refusal
    assert signed == []


def test_redirected_pre_role_sts_never_receives_the_external_id(tmp_path, monkeypatch):
    data_path = forged_ruleset_path(tmp_path, "sts", "2011-06-15")
    signed = offline_aws(
        monkeypatch, tmp_path, environment={"AWS_DATA_PATH": str(data_path)}
    )
    with pytest.raises(framework.SafetyViolation, match="non-canonical endpoint"):
        live_orchestrator(tmp_path, role=True)
    assert signed == []


def test_redirected_service_client_cannot_reach_the_opaque_id_mutator(
    tmp_path, monkeypatch
):
    data_path = forged_ruleset_path(tmp_path, "ec2", "2016-11-15")
    signed = offline_aws(
        monkeypatch, tmp_path, environment={"AWS_DATA_PATH": str(data_path)}
    )
    orchestrator, values = live_orchestrator(tmp_path)
    result = reboot(orchestrator, values, monkeypatch)
    assert result.status == "failed"
    assert any("non-canonical endpoint" in error for error in result.errors)
    assert signed == [("GetCallerIdentity", "sts.us-east-1.amazonaws.com", KEY_A)]


def test_every_framework_client_is_built_by_the_origin_bound_factory():
    seen: list[tuple[str, str, Any]] = []

    def client(service, region_name, config):
        seen.append((service, region_name, config))
        return SimpleNamespace(
            meta=SimpleNamespace(
                endpoint_url="https://"
                + min(
                    framework.canonical_endpoint_origin(service, region_name, False)[1]
                ),
                events=FakeEvents(),
                region_name=region_name,
                method_to_api_mapping={
                    name: name for name in framework.S3_OWNER_BOUND_OPERATIONS
                },
            )
        )

    controller = framework.SafetyController(
        {}, SimpleNamespace(client=client), "us-gov-west-1", True
    )
    for service in sorted(framework.READ_ONLY_OPERATIONS):
        raw = controller.client(service)._client
        handlers = [event for event, _handler in raw.meta.events.first]
        assert handlers[0] == "before-send"
    assert {service for service, _region, _config in seen} == set(
        framework.READ_ONLY_OPERATIONS
    )
    for _service, _region, config in seen:
        assert config.ignore_configured_endpoint_urls is True
        assert config.use_dualstack_endpoint is False
        assert config.use_fips_endpoint is False
        assert config.account_id_endpoint_mode == "disabled"
        assert config.s3 == {
            "use_accelerate_endpoint": False,
            "use_dualstack_endpoint": False,
        }


@pytest.mark.parametrize(
    "service,region,use_fips,host,suffix",
    [
        ("sts", "us-east-1", False, "sts.us-east-1.amazonaws.com", "amazonaws.com"),
        ("ec2", "eu-west-1", False, "ec2.eu-west-1.amazonaws.com", "amazonaws.com"),
        ("iam", "us-east-1", False, "iam.amazonaws.com", "amazonaws.com"),
        (
            "sts",
            "us-gov-west-1",
            False,
            "sts.us-gov-west-1.amazonaws.com",
            "amazonaws.com",
        ),
        ("iam", "us-gov-west-1", False, "iam.us-gov.amazonaws.com", "amazonaws.com"),
        (
            "sts",
            "cn-north-1",
            False,
            "sts.cn-north-1.amazonaws.com.cn",
            "amazonaws.com.cn",
        ),
        (
            "ec2",
            "cn-northwest-1",
            False,
            "ec2.cn-northwest-1.amazonaws.com.cn",
            "amazonaws.com.cn",
        ),
        ("sts", "us-east-1", True, "sts-fips.us-east-1.amazonaws.com", "amazonaws.com"),
        (
            "ecr",
            "us-east-1",
            True,
            "api.ecr-fips.us-east-1.amazonaws.com",
            "amazonaws.com",
        ),
        (
            "ec2",
            "us-gov-west-1",
            True,
            "ec2.us-gov-west-1.amazonaws.com",
            "amazonaws.com",
        ),
    ],
)
def test_canonical_commercial_govcloud_china_and_fips_origins_are_bound(
    monkeypatch, service, region, use_fips, host, suffix
):
    parents, hosts = framework.canonical_endpoint_origin(service, region, use_fips)
    assert parents == frozenset({suffix})
    assert host in hosts
    assert all(item.endswith("." + suffix) for item in hosts)
    for name in ("AWS_DATA_PATH", "AWS_USE_FIPS_ENDPOINT", *ENDPOINT_VARIABLES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    if use_fips:
        monkeypatch.setenv("AWS_USE_FIPS_ENDPOINT", "true")
    session = boto3.Session(
        botocore_session=botocore.session.Session(),
        aws_access_key_id=KEY_A,
        aws_secret_access_key="secret-a",
        aws_session_token="token-a",
        region_name=region,
    )
    sent: list[str] = []

    def offline(request, **_kwargs):
        sent.append(urlsplit(request.url).hostname)
        raise Delivered(request.url)

    session.events.register("before-send", offline)
    client = framework.origin_bound_client(session, service, region, Config())
    operation = {
        "sts": "get_caller_identity",
        "ec2": "describe_vpcs",
        "iam": "list_roles",
        "ecr": "describe_repositories",
    }[service]
    with pytest.raises(Delivered):
        getattr(client, operation)()
    # The origin hook admitted the request; it reached the offline transport
    # at exactly the canonical host, with no FIPS downgrade or upgrade.
    assert sent and set(sent) <= hosts


def test_fips_approval_selects_exactly_one_canonical_variant():
    _parents, regional = framework.canonical_endpoint_origin("sts", "us-east-1", False)
    _parents, fips = framework.canonical_endpoint_origin("sts", "us-east-1", True)
    assert fips == {"sts-fips.us-east-1.amazonaws.com"}
    assert not regional & fips
    assert not framework.is_canonical_request_url(
        "sts", "https://sts-fips.us-east-1.amazonaws.com/", regional
    )
    assert not framework.is_canonical_request_url(
        "sts", "https://sts.us-east-1.amazonaws.com/", fips
    )
    session = SimpleNamespace(
        _session=SimpleNamespace(get_config_variable=lambda name: True)
    )
    assert framework.configured_fips_endpoint(session) is True
    assert framework.configured_fips_endpoint(SimpleNamespace()) is False


@pytest.mark.parametrize(
    "service,url,allowed",
    [
        ("sts", "https://sts.us-east-1.amazonaws.com/", True),
        ("sts", "https://sts.amazonaws.com/", True),
        ("s3", "https://chaos-bucket.s3.us-east-1.amazonaws.com/key", True),
        ("s3", "https://s3.us-east-1.amazonaws.com/chaos-bucket", True),
        ("sts", "http://sts.us-east-1.amazonaws.com/", False),
        ("sts", "https://sts.us-east-1.amazonaws.com:8443/", False),
        ("sts", "https://user@sts.us-east-1.amazonaws.com/", False),
        ("sts", "https://sts.us-east-1.amazonaws.com.attacker.example/", False),
        ("sts", "https://x.sts.us-east-1.amazonaws.com/", False),
        ("sts", CUSTOMER_AWS_HOST + "/", False),
        ("sts", "https://sts.us-west-2.amazonaws.com/", False),
        ("sts", "https://sts.us-gov-west-1.amazonaws.com/", False),
        ("sts", "https://sts.cn-north-1.amazonaws.com.cn/", False),
        ("sts", "https://sts.us-east-1.api.aws/", False),
        ("s3", "https://s3.us-east-1.amazonaws.com.attacker.example/", False),
        ("s3", "https://bucket.s3-accelerate.amazonaws.com/", False),
    ],
)
def test_request_origin_check_admits_only_canonical_hosts(service, url, allowed):
    _parents, hosts = framework.canonical_endpoint_origin(service, "us-east-1", False)
    assert framework.is_canonical_request_url(service, url, hosts) is allowed


@pytest.mark.parametrize(
    "endpoint",
    [
        None,
        ATTACKER,
        "http://sts.us-east-1.amazonaws.com",
        "https://sts.us-east-1.amazonaws.com:444",
        "https://sts.us-east-1.amazonaws.com/prefix",
        "https://localhost:4566",
    ],
)
def test_client_endpoint_outside_the_aws_partition_fails_before_any_request(
    endpoint,
):
    parents, hosts = framework.canonical_endpoint_origin("sts", "us-east-1", False)
    client = SimpleNamespace(
        meta=SimpleNamespace(endpoint_url=endpoint, events=FakeEvents())
    )
    with pytest.raises(framework.SafetyViolation, match="not a canonical AWS origin"):
        framework.bind_endpoint_origin(client, "sts", parents, hosts)
    assert client.meta.events.first == []


def test_client_without_a_request_event_system_fails_closed():
    parents, hosts = framework.canonical_endpoint_origin("sts", "us-east-1", False)
    client = SimpleNamespace(
        meta=SimpleNamespace(endpoint_url="https://sts.us-east-1.amazonaws.com")
    )
    with pytest.raises(framework.SafetyViolation, match="cannot bind"):
        framework.bind_endpoint_origin(client, "sts", parents, hosts)


@pytest.mark.parametrize(
    "service,region,use_fips",
    [
        ("sts", "xx-unknown-1", False),
        ("sts", "aws-global", False),
        ("sts", "us-iso-east-1", False),
        ("not-a-service", "us-east-1", False),
        ("s3", "cn-north-1", True),
    ],
)
def test_unknown_partition_region_service_or_variant_fails_closed(
    service, region, use_fips
):
    with pytest.raises(framework.SafetyViolation):
        framework.canonical_endpoint_origin(service, region, use_fips)


def test_canonical_origin_ignores_customer_endpoint_data(tmp_path, monkeypatch):
    data_path = forged_ruleset_path(tmp_path, "sts", "2011-06-15")
    monkeypatch.setenv("AWS_DATA_PATH", str(data_path))
    monkeypatch.setattr(framework, "_CANONICAL_ENDPOINTS", {})
    loader = framework._bundled_endpoint_loader()
    assert loader.search_paths == [loader.BUILTIN_DATA_PATH]
    _parents, hosts = framework.canonical_endpoint_origin("sts", "us-east-1", False)
    assert hosts == {"sts.us-east-1.amazonaws.com", "sts.amazonaws.com"}


def test_bundled_rules_that_name_a_foreign_host_fail_closed(monkeypatch):
    class Provider:
        def __init__(self, *_args):
            pass

        def resolve_endpoint(self, **_parameters):
            return SimpleNamespace(url=ATTACKER)

    monkeypatch.setattr(framework, "_CANONICAL_ENDPOINTS", {})
    monkeypatch.setattr(framework, "EndpointProvider", Provider)
    with pytest.raises(framework.SafetyViolation, match="non-canonical AWS origin"):
        framework.canonical_endpoint_origin("sts", "us-east-1", False)


def test_rules_without_a_fips_input_cannot_satisfy_a_fips_choice(monkeypatch):
    bundled = framework._bundled_endpoint_loader()
    regional = {
        "version": "1.0",
        "parameters": {
            "Region": {"builtIn": "AWS::Region", "required": False, "type": "String"}
        },
        "rules": [
            {
                "conditions": [],
                "endpoint": {
                    "url": "https://sts.us-east-1.amazonaws.com",
                    "properties": {},
                    "headers": {},
                },
                "type": "endpoint",
            }
        ],
    }
    loader = SimpleNamespace(
        load_data=bundled.load_data,
        load_service_model=lambda service, type_name: regional,
    )
    monkeypatch.setattr(framework, "_CANONICAL_ENDPOINTS", {})
    monkeypatch.setattr(framework, "_bundled_endpoint_loader", lambda: loader)
    _parents, hosts = framework.canonical_endpoint_origin("sts", "us-east-1", False)
    assert hosts == {"sts.us-east-1.amazonaws.com"}
    with pytest.raises(framework.SafetyViolation, match="cannot bind"):
        framework.canonical_endpoint_origin("sts", "us-east-1", True)


# 2. Every admitted wheel member is source-bound before protected attestation.


@pytest.fixture(scope="module")
def clean_wheel(tmp_path_factory):
    output = tmp_path_factory.mktemp("c13-wheel")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--wheel"]
        + ["--outdir", str(output)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    wheel = next(output.glob("*.whl"))
    normalize_wheel.normalize_wheel(wheel, EPOCH)
    return wheel


def version() -> str:
    return verifier._project_version(ROOT / "pyproject.toml")


def info(name: str) -> str:
    return f"aws_chaos_engineering_framework-{version()}.dist-info/{name}"


def record_for(members: dict[str, bytes], record: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(members):
        if name == record:
            writer.writerow((name, "", ""))
            continue
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(members[name]).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        writer.writerow((name, "sha256=" + digest, str(len(members[name]))))
    return output.getvalue().encode("utf-8")


def candidate(
    wheel: Path,
    destination: Path,
    changes: dict[str, bytes],
    *,
    normalize: bool = True,
) -> Path:
    """A candidate-authored wheel: changed members and a recomputed valid RECORD,
    normalized as the candidate workflow would publish it unless disabled."""
    with zipfile.ZipFile(wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members.update(changes)
    record = info("RECORD")
    members[record] = record_for(members, record)
    altered = destination / wheel.name
    with zipfile.ZipFile(altered, "w") as archive:
        for name in sorted(members):
            archive.writestr(name, members[name])
    if normalize:
        normalize_wheel.normalize_wheel(altered, EPOCH)
    return altered


def member(wheel: Path, name: str) -> bytes:
    with zipfile.ZipFile(wheel) as archive:
        return archive.read(name)


def test_clean_deterministic_wheel_is_exactly_source_derived(clean_wheel):
    verifier._verify_wheel(clean_wheel, version(), ROOT)
    project = verifier._approved_project(ROOT)
    expected = verifier._expected_wheel_metadata(project, ROOT)
    for name, value in expected.items():
        assert member(clean_wheel, info(name)) == value
    assert expected["licenses/LICENSE"] == (ROOT / "LICENSE").read_bytes()


WHEEL_HEADER_MUTATIONS = {
    "wheel_version": (b"Wheel-Version: 1.0", b"Wheel-Version: 9.0"),
    "generator": (b"Generator: setuptools (84.0.0)", b"Generator: other (1.0)"),
    "purelib": (b"Root-Is-Purelib: true", b"Root-Is-Purelib: false"),
    "tag": (b"Tag: py3-none-any", b"Tag: py3-none-any\nTag: cp312-cp312-win_amd64"),
    "extra_header": (b"Tag: py3-none-any", b"Tag: py3-none-any\nBuild: 1"),
}


@pytest.mark.parametrize("mutation", sorted(WHEEL_HEADER_MUTATIONS))
def test_each_wheel_header_mutation_is_rejected(clean_wheel, tmp_path, mutation):
    old, new = WHEEL_HEADER_MUTATIONS[mutation]
    value = member(clean_wheel, info("WHEEL"))
    assert old in value
    altered = candidate(clean_wheel, tmp_path, {info("WHEEL"): value.replace(old, new)})
    with pytest.raises(ValueError, match="WHEEL differs"):
        verifier._verify_wheel(altered, version(), ROOT)


@pytest.mark.parametrize(
    "name,value",
    [
        ("top_level.txt", b"aws_chaos_framework\nsitecustomize\n"),
        ("top_level.txt", b""),
        ("licenses/LICENSE", None),
        ("licenses/LICENSE", b"MIT License\n"),
        (
            "entry_points.txt",
            b"[console_scripts]\naws-chaos-framework=aws_chaos_framework:main\n",
        ),
    ],
)
def test_top_level_license_and_entry_point_bytes_are_source_bound(
    clean_wheel, tmp_path, name, value
):
    if value is None:
        value = member(clean_wheel, info(name)) + b"\nAdditional grant.\n"
    altered = candidate(clean_wheel, tmp_path, {info(name): value})
    with pytest.raises(ValueError, match=f"{name} differs"):
        verifier._verify_wheel(altered, version(), ROOT)


FIELD_LEVEL = "differs from static project metadata"
METADATA_MUTATIONS = {
    "summary": (b"Summary: Guarded", b"Summary: Unguarded", FIELD_LEVEL),
    "home_page": (
        b"Requires-Python:",
        b"Home-page: https://attacker.example\nRequires-Python:",
        FIELD_LEVEL,
    ),
    "license_expression": (
        b"License-Expression: Apache-2.0",
        b"License-Expression: MIT",
        FIELD_LEVEL,
    ),
    "obsoletes": (
        b"Dynamic: license-file",
        b"Dynamic: license-file\nObsoletes-Dist: boto3",
        FIELD_LEVEL,
    ),
    "folded_summary": (b"Summary: Guarded", b"Summary: Guarded\n", FIELD_LEVEL),
    "description": (
        b"\n\n",
        b"\n\nUnreviewed description preface.\n",
        "description differs from static README",
    ),
    # Field-equal reordering passes the field comparison; only the exact
    # source-derived text (shared with the sdist PKG-INFO check) refuses it.
    "header_order": (
        b"Description-Content-Type: text/markdown\nLicense-File: LICENSE",
        b"License-File: LICENSE\nDescription-Content-Type: text/markdown",
        "not the exact source-derived metadata",
    ),
}


@pytest.mark.parametrize("mutation", sorted(METADATA_MUTATIONS))
def test_unchecked_metadata_field_mutation_is_rejected(clean_wheel, tmp_path, mutation):
    old, new, message = METADATA_MUTATIONS[mutation]
    value = member(clean_wheel, info("METADATA"))
    assert old in value
    altered = candidate(
        clean_wheel, tmp_path, {info("METADATA"): value.replace(old, new, 1)}
    )
    with pytest.raises(ValueError, match=message):
        verifier._verify_wheel(altered, version(), ROOT)


def test_unnormalized_metadata_bytes_are_rejected(clean_wheel, tmp_path):
    # A candidate need not normalize. A carriage return is invisible to the
    # line-ending-tolerant field comparison but changes what installers parse.
    value = member(clean_wheel, info("METADATA"))
    altered = candidate(
        clean_wheel,
        tmp_path,
        {info("METADATA"): value.replace(b"Summary: Guarded", b"Summary: Guarded\r")},
        normalize=False,
    )
    with pytest.raises(ValueError, match="wheel METADATA differs"):
        verifier._verify_wheel(altered, version(), ROOT)


def test_reordered_but_self_consistent_record_is_rejected(clean_wheel, tmp_path):
    with zipfile.ZipFile(clean_wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    record = info("RECORD")
    rows = members[record].decode("utf-8").splitlines(keepends=True)
    members[record] = "".join(reversed(rows)).encode("utf-8")
    altered = tmp_path / clean_wheel.name
    with zipfile.ZipFile(altered, "w") as archive:
        for name in sorted(members):
            archive.writestr(name, members[name])
    with pytest.raises(ValueError, match="canonical source-derived RECORD"):
        verifier._verify_wheel(altered, version(), ROOT)


def test_metadata_derivation_is_shared_with_the_sdist(tmp_path):
    project = verifier._approved_project(ROOT)
    text = verifier._expected_package_metadata(project, ROOT)
    verifier._verify_package_metadata(text.encode("utf-8"), project, ROOT)
    with pytest.raises(ValueError, match="metadata"):
        verifier._verify_package_metadata(
            text.replace("Summary: ", "Summary:  ").encode("utf-8"), project, ROOT
        )
    assert verifier._pinned_backend_version("setuptools") == "84.0.0"
    with pytest.raises(ValueError, match="does not pin"):
        verifier._pinned_backend_version("flit-core")


# Round 2. Credential-provider clients, credential transports, account-based
# endpoints, exact sdist bytes and the request Host header.

SSO_REGION = "us-west-2"
SSO_START = "https://example.awsapps.com/start"
PROVIDER_OVERRIDES = {
    "AWS_ENDPOINT_URL": ATTACKER,
    "AWS_ENDPOINT_URL_STS": ATTACKER,
    "AWS_ENDPOINT_URL_SSO": ATTACKER,
    "AWS_ENDPOINT_URL_SSO_OIDC": ATTACKER,
    "AWS_ENDPOINT_URL_SIGNIN": ATTACKER,
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "false",
}
TRANSPORT_VARIABLES = (
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
)


def web_identity_xml() -> bytes:
    return (
        '<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        "<AssumeRoleWithWebIdentityResult><Credentials>"
        f"<AccessKeyId>{KEY_ROLE}</AccessKeyId>"
        "<SecretAccessKey>secret-role</SecretAccessKey>"
        "<SessionToken>token-role</SessionToken>"
        "<Expiration>2099-01-01T00:00:00Z</Expiration>"
        "</Credentials><AssumedRoleUser>"
        f"<Arn>arn:aws:sts::{ACCOUNT_ID}:assumed-role/ChaosWeb/s</Arn>"
        "<AssumedRoleId>AROAEXAMPLE:s</AssumedRoleId>"
        "</AssumedRoleUser></AssumeRoleWithWebIdentityResult>"
        "<ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>"
        "</AssumeRoleWithWebIdentityResponse>"
    ).encode()


def provider_aws(
    monkeypatch, tmp_path, config_text: str, credentials_text: str = ""
) -> list[tuple[str, str, dict[str, str]]]:
    """Real sessions whose credentials come from a provider chain, offline.

    Every configured endpoint override names an attacker host. The offline
    transport answers any host, so a provider client that honoured an override
    would be visible as a recorded attacker request.
    """
    config_file = tmp_path / "aws-config"
    config_file.write_text(config_text, encoding="ascii")
    credentials_file = tmp_path / "aws-credentials"
    credentials_file.write_text(credentials_text, encoding="ascii")
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
        "AWS_DATA_PATH",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        *ENDPOINT_VARIABLES,
        *TRANSPORT_VARIABLES,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config_file))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials_file))
    for name, value in PROVIDER_OVERRIDES.items():
        monkeypatch.setenv(name, value)
    cache = tmp_path / "sso-cache"
    cache.mkdir()
    monkeypatch.setattr(
        botocore.tokens.SSOTokenProvider, "_SSO_TOKEN_CACHE_DIR", str(cache)
    )
    sent: list[tuple[str, str, dict[str, str]]] = []

    def offline(request, event_name, **_kwargs):
        operation = event_name.rsplit(".", 1)[-1]
        headers = {
            str(key).lower(): (value.decode() if isinstance(value, bytes) else value)
            for key, value in request.headers.items()
        }
        sent.append((operation, urlsplit(request.url).netloc, headers))
        json_headers = {"Content-Type": "application/json"}
        if operation == "AssumeRole":
            return AWSResponse(request.url, 200, {}, OfflineBody(assume_role_xml()))
        if operation == "AssumeRoleWithWebIdentity":
            return AWSResponse(request.url, 200, {}, OfflineBody(web_identity_xml()))
        if operation == "CreateToken":
            body = {
                "accessToken": "refreshed-access-token",
                "tokenType": "Bearer",
                "expiresIn": 3600,
                "refreshToken": "refresh-2",
            }
            return AWSResponse(
                request.url, 200, json_headers, OfflineBody(json.dumps(body).encode())
            )
        if operation == "CreateOAuth2Token":
            body = {
                "accessToken": {
                    "accessKeyId": KEY_ROLE,
                    "secretAccessKey": "secret-role",
                    "sessionToken": "token-role",
                },
                "tokenType": "aws_sigv4",
                "expiresIn": 900,
                "refreshToken": "refresh-2",
            }
            return AWSResponse(
                request.url, 200, json_headers, OfflineBody(json.dumps(body).encode())
            )
        if operation == "GetRoleCredentials":
            body = {
                "roleCredentials": {
                    "accessKeyId": KEY_ROLE,
                    "secretAccessKey": "secret-role",
                    "sessionToken": "token-role",
                    "expiration": 4102444800000,
                }
            }
            return AWSResponse(
                request.url, 200, json_headers, OfflineBody(json.dumps(body).encode())
            )
        if operation == "GetCallerIdentity":
            key = headers.get("authorization", "").split("Credential=")[-1][:20]
            account = ACCOUNT_ID if key == KEY_ROLE else OTHER_ACCOUNT
            return AWSResponse(
                request.url, 200, {}, OfflineBody(identity_xml(account, "aws"))
            )
        raise Delivered(request.url)

    real_session = boto3.Session

    def session_factory(**kwargs):
        session = real_session(botocore_session=botocore.session.Session(), **kwargs)
        session.events.register("before-send", offline)
        return session

    monkeypatch.setattr(framework.boto3, "Session", session_factory)
    monkeypatch.setattr(framework.atexit, "register", lambda *args: None)
    monkeypatch.setattr(framework.signal, "signal", lambda *args: None)
    return sent


def sso_token(tmp_path: Path, expires_in: timedelta) -> None:
    now = datetime.now(timezone.utc)
    token = {
        "startUrl": SSO_START,
        "region": SSO_REGION,
        "accessToken": "cached-access-token",
        "expiresAt": (now + expires_in).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "clientId": "client-id",
        "clientSecret": "client-secret",
        "registrationExpiresAt": (now + timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "refreshToken": "refresh-1",
    }
    name = hashlib.sha1(b"corp").hexdigest() + ".json"  # botocore's cache key
    (tmp_path / "sso-cache" / name).write_text(json.dumps(token), encoding="utf-8")


ASSUME_ROLE_CHAIN = (
    f"[profile {PROFILE}]\nregion = {PROFILE_REGION}\n"
    f"role_arn = {ROLE_ARN}\nsource_profile = base\n"
    "external_id = synthetic-external-id\n"
    f"endpoint_url = {ATTACKER}\n"
    "[profile base]\nregion = us-east-1\n"
)
ASSUME_ROLE_CREDENTIALS = (
    f"[base]\naws_access_key_id = {KEY_A}\n"
    "aws_secret_access_key = secret-a\naws_session_token = token-a\n"
)
SSO_PROFILE = (
    f"[profile {PROFILE}]\nregion = {PROFILE_REGION}\nsso_session = corp\n"
    f"sso_account_id = {ACCOUNT_ID}\nsso_role_name = ChaosOperator\n"
    f"endpoint_url = {ATTACKER}\n"
    f"[sso-session corp]\nsso_region = {SSO_REGION}\nsso_start_url = {SSO_START}\n"
    "sso_registration_scopes = sso:account:access\n"
)


def provider_hosts(sent) -> list[tuple[str, str]]:
    return [(operation, host) for operation, host, _headers in sent]


def test_profile_assume_role_chain_stays_on_canonical_sts(tmp_path, monkeypatch):
    sent = provider_aws(
        monkeypatch, tmp_path, ASSUME_ROLE_CHAIN, ASSUME_ROLE_CREDENTIALS
    )
    orchestrator, _values = live_orchestrator(tmp_path)
    assert orchestrator.actual_account == ACCOUNT_ID
    assert provider_hosts(sent) == [
        ("AssumeRole", "sts.us-east-1.amazonaws.com"),
        ("GetCallerIdentity", "sts.us-east-1.amazonaws.com"),
    ]


def test_web_identity_token_stays_on_canonical_sts(tmp_path, monkeypatch):
    token_file = tmp_path / "web-identity-token"
    token_file.write_text("synthetic-web-identity-token", encoding="ascii")
    config = (
        f"[profile {PROFILE}]\nregion = {PROFILE_REGION}\n"
        f"role_arn = arn:aws:iam::{ACCOUNT_ID}:role/ChaosWeb\n"
        f"web_identity_token_file = {token_file.as_posix()}\n"
        f"endpoint_url = {ATTACKER}\n"
    )
    sent = provider_aws(monkeypatch, tmp_path, config)
    orchestrator, _values = live_orchestrator(tmp_path)
    assert orchestrator.actual_account == ACCOUNT_ID
    assert provider_hosts(sent) == [
        ("AssumeRoleWithWebIdentity", "sts.us-east-1.amazonaws.com"),
        ("GetCallerIdentity", "sts.us-east-1.amazonaws.com"),
    ]


def test_sso_bearer_token_goes_only_to_the_canonical_sso_portal(tmp_path, monkeypatch):
    sent = provider_aws(monkeypatch, tmp_path, SSO_PROFILE)
    sso_token(tmp_path, timedelta(hours=8))
    orchestrator, _values = live_orchestrator(tmp_path)
    assert orchestrator.actual_account == ACCOUNT_ID
    assert provider_hosts(sent) == [
        ("GetRoleCredentials", f"portal.sso.{SSO_REGION}.amazonaws.com"),
        ("GetCallerIdentity", "sts.us-east-1.amazonaws.com"),
    ]
    assert sent[0][2]["x-amz-sso_bearer_token"] == "cached-access-token"


def test_sso_oidc_refresh_and_role_credentials_stay_canonical(tmp_path, monkeypatch):
    sent = provider_aws(monkeypatch, tmp_path, SSO_PROFILE)
    sso_token(tmp_path, timedelta(minutes=5))  # inside botocore's refresh window
    orchestrator, _values = live_orchestrator(tmp_path)
    assert orchestrator.actual_account == ACCOUNT_ID
    assert provider_hosts(sent) == [
        ("CreateToken", f"oidc.{SSO_REGION}.amazonaws.com"),
        ("GetRoleCredentials", f"portal.sso.{SSO_REGION}.amazonaws.com"),
        ("GetCallerIdentity", "sts.us-east-1.amazonaws.com"),
    ]
    assert sent[1][2]["x-amz-sso_bearer_token"] == "refreshed-access-token"
    # SSO credentials carry the account ID; a later Kinesis read still uses the
    # canonical regional host rather than an account-qualified one.
    kinesis = orchestrator.safety_controller.client("kinesis")
    with pytest.raises(Delivered):
        kinesis.describe_stream(StreamName="chaos-test-stream")
    assert sent[-1][1] == "kinesis.us-east-1.amazonaws.com"


@pytest.mark.parametrize(
    "provider,service,version",
    [
        ("assume_role", "sts", "2011-06-15"),
        ("web_identity", "sts", "2011-06-15"),
        ("sso", "sso", "2019-06-10"),
        ("sso_oidc_refresh", "sso-oidc", "2019-06-10"),
    ],
)
def test_provider_client_routed_off_origin_is_refused_before_sending(
    tmp_path, monkeypatch, provider, service, version
):
    # A customer endpoint ruleset redirects even with endpoint URLs ignored
    # session-wide. Only the per-client request check stops the provider's
    # first request (role parameters and ExternalId, the web identity token,
    # the SSO bearer token or the SSO refresh token) from being sent.
    data_path = forged_ruleset_path(tmp_path, service, version)
    if provider == "assume_role":
        config, credentials = ASSUME_ROLE_CHAIN, ASSUME_ROLE_CREDENTIALS
    elif provider == "web_identity":
        token_file = tmp_path / "web-identity-token"
        token_file.write_text("synthetic-web-identity-token", encoding="ascii")
        config = (
            f"[profile {PROFILE}]\nregion = {PROFILE_REGION}\n"
            f"role_arn = arn:aws:iam::{ACCOUNT_ID}:role/ChaosWeb\n"
            f"web_identity_token_file = {token_file.as_posix()}\n"
        )
        credentials = ""
    else:
        config, credentials = SSO_PROFILE, ""
    sent = provider_aws(monkeypatch, tmp_path, config, credentials)
    if provider.startswith("sso"):
        expiry = timedelta(minutes=5 if provider == "sso_oidc_refresh" else 480)
        sso_token(tmp_path, expiry)
    monkeypatch.setenv("AWS_DATA_PATH", str(data_path))
    with pytest.raises(framework.SafetyViolation, match="non-canonical endpoint"):
        live_orchestrator(tmp_path)
    assert sent == []


def test_hardened_session_binds_every_created_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent-config"))
    for name in (*ENDPOINT_VARIABLES, "AWS_USE_FIPS_ENDPOINT", "AWS_DATA_PATH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ENDPOINT_URL", ATTACKER)
    session = boto3.Session(
        botocore_session=botocore.session.Session(),
        aws_access_key_id=KEY_A,
        aws_secret_access_key="secret-a",
        region_name="us-east-1",
    )
    assert framework.harden_session_origin(session) is session
    assert framework.is_origin_hardened(session)
    core = session._session
    assert core.get_config_variable("ignore_configured_endpoint_urls") is True
    assert core.get_config_variable("use_dualstack_endpoint") is False
    assert core.get_config_variable("account_id_endpoint_mode") == "disabled"
    assert core.get_config_variable("use_fips_endpoint") is False
    sent: list[str] = []

    def offline(request, **_kwargs):
        sent.append(urlsplit(request.url).netloc)
        raise Delivered(request.url)

    session.events.register("before-send", offline)
    # A nested client created exactly as botocore's providers create them.
    nested = botocore.utils.create_nested_client(
        core, "sso", config=Config(region_name=SSO_REGION)
    )
    assert nested.meta.region_name == SSO_REGION
    with pytest.raises(Delivered):
        nested.list_accounts(accessToken="token")
    assert sent == [f"portal.sso.{SSO_REGION}.amazonaws.com"]
    with pytest.raises(framework.SafetyViolation, match="explicit endpoint"):
        session.client("sts", endpoint_url=ATTACKER)
    with pytest.raises(framework.SafetyViolation, match="keyword"):
        core.create_client("sts", "us-east-1")
    unhardened = boto3.Session(
        botocore_session=botocore.session.Session(),
        aws_access_key_id=KEY_A,
        aws_secret_access_key="secret-a",
        region_name="us-east-1",
    )
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.pin_session_credentials(unhardened, "us-east-1")
    pinned = framework.pin_session_credentials(session, "us-east-1")
    assert framework.is_origin_hardened(pinned)


@pytest.mark.parametrize(
    "variables",
    [
        {},
        {"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://169.254.169.254/"},
        {"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://[fd00:ec2::254]"},
        {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/abc"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://[fd00:ec2::23]/v1/credentials"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.0.0.1:8080/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.0.0.2/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://[::1]:51679/creds"},
    ],
)
def test_default_imds_and_documented_container_addresses_are_admitted(
    tmp_path, monkeypatch, variables
):
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent-config"))
    for name in TRANSPORT_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    for name, value in variables.items():
        monkeypatch.setenv(name, value)
    session = boto3.Session(botocore_session=botocore.session.Session())
    framework.require_credential_transport_policy(session)


@pytest.mark.parametrize(
    "variables",
    [
        {"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://attacker.example/"},
        {"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://169.254.169.254:8080/"},
        {"AWS_EC2_METADATA_SERVICE_ENDPOINT": "https://169.254.169.254/"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "https://attacker.example/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.169.254/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://u@169.254.170.2/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "ftp://169.254.170.2/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.2:99999/"},
        {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "@attacker.example/creds"},
        # A host name is never admitted by spelling, not even localhost.
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://localhost:51679/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "https://localhost/creds"},
        # Only normalized numeric loopback literals are admitted.
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.1/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://[0:0:0:0:0:0:0:1]/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://[::ffff:127.0.0.1]/creds"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://[::1%25lo]/creds"},
    ],
)
def test_configured_credential_transport_overrides_fail_closed(
    tmp_path, monkeypatch, variables
):
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent-config"))
    for name in TRANSPORT_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    for name, value in variables.items():
        monkeypatch.setenv(name, value)
    session = boto3.Session(botocore_session=botocore.session.Session())
    with pytest.raises(
        framework.SafetyViolation, match="Credential resolution refuses"
    ):
        framework.require_credential_transport_policy(session)


@pytest.mark.parametrize(
    "name,value",
    [
        ("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://attacker.example/"),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "https://attacker.example/creds"),
    ],
)
def test_live_and_plan_admission_refuse_transport_override_before_any_request(
    tmp_path, monkeypatch, name, value
):
    signed = offline_aws(monkeypatch, tmp_path, environment={name: value})
    with pytest.raises(
        framework.SafetyViolation, match="Credential resolution refuses"
    ):
        live_orchestrator(tmp_path)
    assert signed == []
    # Plan mode also resolves credentials, so it is refused the same way.
    with pytest.raises(
        framework.SafetyViolation, match="Credential resolution refuses"
    ):
        live_orchestrator(tmp_path, live=False)
    assert signed == []


def provider_only_aws(
    monkeypatch, tmp_path, environment: dict[str, str], profile_lines: str = ""
) -> tuple[list[tuple[str, str, str]], list[tuple[str, Any]]]:
    """Offline sessions whose only credential source is a raw provider.

    No static credential exists and instance metadata is enabled, so without
    the transport policy botocore would reach the IMDS or container provider.
    SDK requests are answered offline by ``offline_aws``; the providers' own
    plain HTTP sessions are recorded and never sent.
    """
    signed = offline_aws(
        monkeypatch, tmp_path, environment=environment, profile_lines=profile_lines
    )
    (tmp_path / "aws-credentials").write_text("", encoding="ascii")
    for variable in (
        "AWS_EC2_METADATA_DISABLED",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    ):
        if variable not in environment:
            monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("BOTO_CONFIG", str(tmp_path / "absent-boto-config"))
    provider: list[tuple[str, Any]] = []

    def record_provider_request(_session, request):
        provider.append(
            (urlsplit(request.url).netloc, request.headers.get("Authorization"))
        )
        raise Delivered(request.url)

    monkeypatch.setattr(
        botocore.httpsession.URLLib3Session, "send", record_provider_request
    )
    return signed, provider


def plan_orchestrator_or_refusal(tmp_path) -> str | None:
    """Construct a plan-mode orchestrator; return its refusal, if any."""
    try:
        live_orchestrator(tmp_path, live=False)
    except framework.SafetyViolation as exc:
        return str(exc)
    except Delivered:
        return None
    return None


@pytest.mark.parametrize(
    "environment,profile_lines",
    [
        ({"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://attacker.example/"}, ""),
        ({}, "ec2_metadata_service_endpoint = http://attacker.example/\n"),
    ],
    ids=["environment", "profile"],
)
def test_plan_mode_refuses_non_default_imds_endpoint_before_any_request(
    tmp_path, monkeypatch, environment, profile_lines
):
    signed, provider = provider_only_aws(
        monkeypatch, tmp_path, environment, profile_lines
    )
    refusal = plan_orchestrator_or_refusal(tmp_path)
    assert refusal == (
        "Credential resolution refuses a non-default EC2 instance metadata endpoint"
    )
    assert provider == []
    assert signed == []


@pytest.mark.parametrize("token", ["none", "token", "token-file"])
def test_plan_mode_refuses_arbitrary_https_container_uri_without_sending(
    tmp_path, monkeypatch, token
):
    environment = {
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": "https://attacker.example/creds"
    }
    if token == "token":
        environment["AWS_CONTAINER_AUTHORIZATION_TOKEN"] = "synthetic-provider-token"
    elif token == "token-file":
        token_file = tmp_path / "container-token"
        token_file.write_text("synthetic-provider-token", encoding="ascii")
        environment["AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"] = str(token_file)
    signed, provider = provider_only_aws(monkeypatch, tmp_path, environment)
    refusal = plan_orchestrator_or_refusal(tmp_path)
    assert refusal == (
        "Credential resolution refuses a container credential URL outside the "
        "documented link-local and loopback addresses"
    )
    assert provider == []
    assert signed == []


@pytest.mark.parametrize("token", ["token", "token-file"])
@pytest.mark.parametrize(
    "url", ["http://localhost:51679/creds", "https://localhost/creds"]
)
def test_plan_mode_refuses_localhost_container_uri_before_provider_transport(
    tmp_path, monkeypatch, url, token
):
    # localhost is a name: resolution could select a non-loopback recipient.
    environment = {"AWS_CONTAINER_CREDENTIALS_FULL_URI": url}
    if token == "token":
        environment["AWS_CONTAINER_AUTHORIZATION_TOKEN"] = "synthetic-provider-token"
    else:
        token_file = tmp_path / "container-token"
        token_file.write_text("synthetic-provider-token", encoding="ascii")
        environment["AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"] = str(token_file)
    signed, provider = provider_only_aws(monkeypatch, tmp_path, environment)
    refusal = plan_orchestrator_or_refusal(tmp_path)
    assert refusal == (
        "Credential resolution refuses a container credential URL outside the "
        "documented link-local and loopback addresses"
    )
    assert provider == []
    assert signed == []


@pytest.mark.parametrize(
    "url,netloc",
    [("http://127.0.0.1:9/creds", "127.0.0.1:9"), ("http://[::1]:9/creds", "[::1]:9")],
)
def test_plan_mode_admitted_loopback_container_uri_reaches_only_that_provider(
    tmp_path, monkeypatch, url, netloc
):
    # Control: the same harness observes a provider request once admitted.
    environment = {"AWS_CONTAINER_CREDENTIALS_FULL_URI": url}
    signed, provider = provider_only_aws(monkeypatch, tmp_path, environment)
    assert plan_orchestrator_or_refusal(tmp_path) is None
    assert {host for host, _ in provider} == {netloc}
    assert signed == []


DIRECT_ENTRY_POINTS = ("safety-controller", "planning-experiment", "pinning")


def resolve_through_direct_entry(entry: str) -> str:
    """Drive one library entry point that resolves credentials without an orchestrator.

    Returns "refused: <message>", "provider-request" when the offline provider
    recorder was reached, or "resolved".
    """
    session = framework.boto3.Session(profile_name=PROFILE, region_name=PROFILE_REGION)
    try:
        if entry == "pinning":
            framework.pin_session_credentials(
                framework.harden_session_origin(session), PROFILE_REGION
            )
        else:
            # A caller-supplied session, exactly as direct library planning uses it.
            controller = framework.SafetyController(
                {}, session, PROFILE_REGION, False, expected_account=ACCOUNT_ID
            )
            if entry == "safety-controller":
                controller.client("sts")
            else:
                framework.LambdaChaosExperiment(
                    {"region": PROFILE_REGION, "dry_run": True}, controller
                )
    except framework.SafetyViolation as exc:
        return f"refused: {exc}"
    except Delivered:
        return "provider-request"
    return "resolved"


@pytest.mark.parametrize("entry", DIRECT_ENTRY_POINTS)
@pytest.mark.parametrize(
    "environment,expected",
    [
        (
            {"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://attacker.example/"},
            "refused: Credential resolution refuses a non-default EC2 instance "
            "metadata endpoint",
        ),
        (
            {
                "AWS_CONTAINER_CREDENTIALS_FULL_URI": "https://attacker.example/creds",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN": "synthetic-provider-token",
            },
            "refused: Credential resolution refuses a container credential URL "
            "outside the documented link-local and loopback addresses",
        ),
    ],
    ids=["imds-endpoint", "container-uri-with-token"],
)
def test_direct_entry_points_refuse_provider_overrides_before_any_request(
    tmp_path, monkeypatch, entry, environment, expected
):
    signed, provider = provider_only_aws(monkeypatch, tmp_path, environment)
    assert resolve_through_direct_entry(entry) == expected
    assert provider == []
    assert signed == []


@pytest.mark.parametrize("entry", DIRECT_ENTRY_POINTS)
@pytest.mark.parametrize(
    "environment,host",
    [
        (
            {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.0.0.1:9/creds"},
            "127.0.0.1:9",
        ),
        ({}, "169.254.169.254"),
    ],
    ids=["loopback-container", "default-imds"],
)
def test_direct_entry_points_admit_default_and_loopback_providers(
    tmp_path, monkeypatch, entry, environment, host
):
    # Control: the same harness observes the admitted provider's request.
    signed, provider = provider_only_aws(monkeypatch, tmp_path, environment)
    assert resolve_through_direct_entry(entry) == "provider-request"
    assert {recorded for recorded, _ in provider} == {host}
    assert signed == []


def kinesis_session(monkeypatch, tmp_path) -> tuple[Any, list[str]]:
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent-config"))
    for name in (*ENDPOINT_VARIABLES, "AWS_USE_FIPS_ENDPOINT", "AWS_DATA_PATH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("AWS_ACCOUNT_ID_ENDPOINT_MODE", raising=False)
    session = boto3.Session(
        botocore_session=botocore.session.Session(),
        aws_access_key_id=KEY_A,
        aws_secret_access_key="secret-a",
        aws_session_token="token-a",
        aws_account_id=ACCOUNT_ID,
        region_name="us-east-1",
    )
    sent: list[str] = []

    def offline(request, **_kwargs):
        sent.append(urlsplit(request.url).netloc)
        raise Delivered(request.url)

    session.events.register("before-send", offline)
    return session, sent


def test_account_bearing_credentials_keep_kinesis_on_the_canonical_host(
    tmp_path, monkeypatch
):
    session, sent = kinesis_session(monkeypatch, tmp_path)
    framework.harden_session_origin(session)
    client = framework.origin_bound_client(session, "kinesis", "us-east-1", Config())
    assert client.meta.config.account_id_endpoint_mode == "disabled"
    for call in (
        lambda: client.describe_stream(StreamName="chaos-test-stream"),
        lambda: client.describe_stream_summary(StreamName="chaos-test-stream"),
        lambda: client.decrease_stream_retention_period(
            StreamName="chaos-test-stream", RetentionPeriodHours=24
        ),
    ):
        with pytest.raises(Delivered):
            call()
    assert set(sent) == {"kinesis.us-east-1.amazonaws.com"}


def test_origin_bound_client_disables_account_endpoints_without_session_hardening(
    tmp_path, monkeypatch
):
    # The per-client setting alone keeps the host canonical, independent of the
    # session-wide defence-in-depth settings.
    session, sent = kinesis_session(monkeypatch, tmp_path)
    assert not framework.is_origin_hardened(session)
    client = framework.origin_bound_client(session, "kinesis", "us-east-1", Config())
    with pytest.raises(Delivered):
        client.describe_stream(StreamName="chaos-test-stream")
    assert sent == ["kinesis.us-east-1.amazonaws.com"]


def test_default_account_endpoint_mode_selects_a_host_outside_the_canonical_set(
    tmp_path, monkeypatch
):
    # The regression case: botocore's default "preferred" mode with
    # account-bearing credentials picks an account-qualified control host.
    session, sent = kinesis_session(monkeypatch, tmp_path)
    plain = session.client("kinesis", region_name="us-east-1")
    with pytest.raises(Delivered):
        plain.describe_stream(StreamName="chaos-test-stream")
    _parents, hosts = framework.canonical_endpoint_origin("kinesis", "us-east-1", False)
    assert sent == [f"{ACCOUNT_ID}.control-kinesis.us-east-1.amazonaws.com"]
    assert sent[0] not in hosts


def test_canonical_derivation_uses_the_disabled_account_endpoint_mode(monkeypatch):
    seen: list[dict[str, Any]] = []
    real = framework.EndpointProvider

    class Recorder(real):
        def resolve_endpoint(self, **parameters):
            seen.append(parameters)
            return super().resolve_endpoint(**parameters)

    monkeypatch.setattr(framework, "_CANONICAL_ENDPOINTS", {})
    monkeypatch.setattr(framework, "EndpointProvider", Recorder)
    framework.canonical_endpoint_origin("kinesis", "us-east-1", False)
    assert seen
    assert all(item["AccountIdEndpointMode"] == "disabled" for item in seen)


def bound_sts(monkeypatch, tmp_path) -> tuple[Any, list[str]]:
    session, sent = kinesis_session(monkeypatch, tmp_path)
    framework.harden_session_origin(session)
    return framework.origin_bound_client(session, "sts", "us-east-1", Config()), sent


@pytest.mark.parametrize(
    "host,admitted",
    [
        ("attacker.example", False),
        ("sts.us-east-1.amazonaws.com:8443", False),
        ("STS.us-east-1.amazonaws.com", True),
    ],
)
def test_explicit_host_header_must_name_the_request_authority(
    tmp_path, monkeypatch, host, admitted
):
    client, sent = bound_sts(monkeypatch, tmp_path)

    def set_host(request, **_kwargs):
        request.headers["Host"] = host

    client.meta.events.register("before-sign.sts.GetCallerIdentity", set_host)
    if admitted:
        with pytest.raises(Delivered):
            client.get_caller_identity()
        assert sent == ["sts.us-east-1.amazonaws.com"]
    else:
        with pytest.raises(framework.SafetyViolation, match="Host header"):
            client.get_caller_identity()
        assert sent == []


def test_operation_specific_before_send_redirect_is_checked(tmp_path, monkeypatch):
    client, sent = bound_sts(monkeypatch, tmp_path)

    def redirect(request, **_kwargs):
        request.url = ATTACKER + "/"

    client.meta.events.register("before-send.sts.GetCallerIdentity", redirect)
    with pytest.raises(framework.SafetyViolation, match="non-canonical endpoint"):
        client.get_caller_identity()
    assert sent == []


@pytest.mark.parametrize(
    "headers,matches",
    [
        ({}, True),
        ({"Content-Type": "x"}, True),
        ({"host": b"sts.us-east-1.amazonaws.com"}, True),
        ({"Host": "other.amazonaws.com"}, False),
        ({"HOST": b"sts.us-east-1.amazonaws.com.attacker.example"}, False),
    ],
)
def test_host_header_comparison(headers, matches):
    assert (
        framework.host_header_matches_url(
            "https://sts.us-east-1.amazonaws.com/", headers
        )
        is matches
    )


@pytest.fixture(scope="module")
def clean_sdist(tmp_path_factory):
    output = tmp_path_factory.mktemp("c13-sdist")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--sdist"]
        + ["--outdir", str(output)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    sdist = next(output.glob("*.tar.gz"))
    normalize_sdist.normalize_sdist(sdist, EPOCH)
    return sdist


def rewrite_sdist_member(original: Path, destination: Path, name: str, change) -> Path:
    altered = destination / original.name
    with (
        tarfile.open(original, "r:gz") as source,
        tarfile.open(altered, "w:gz") as target,
    ):
        root = source.getmembers()[0].name.split("/")[0]
        found = False
        for item in source.getmembers():
            data = source.extractfile(item).read() if item.isfile() else None
            if item.name == f"{root}/{name}":
                data, found = change(data), True
                item = copy.copy(item)
                item.size = len(data)
            target.addfile(item, io.BytesIO(data) if data is not None else None)
    assert found
    return altered


def test_clean_sdist_generated_members_are_exact(clean_sdist):
    verifier._verify_sdist(clean_sdist, ROOT)


@pytest.mark.parametrize(
    "name,change,message",
    [
        (
            "PKG-INFO",
            lambda data: data.replace(b"\n", b"\r\n"),
            "bytes are not exact",
        ),
        (
            verifier.EGG_INFO + "PKG-INFO",
            lambda data: data.replace(b"Summary: Guarded", b"Summary: Guarded\r", 1),
            "bytes are not exact",
        ),
        (
            verifier.EGG_INFO + "SOURCES.txt",
            lambda data: data.replace(b"\n", b"\r\n"),
            "unreviewed generated source metadata",
        ),
        (
            "setup.cfg",
            lambda data: data.replace(b"\n", b"\r\n"),
            "unreviewed generated source metadata",
        ),
        (
            verifier.EGG_INFO + "requires.txt",
            lambda data: data.replace(b"\n", b"\r", 1),
            "unreviewed generated source metadata",
        ),
    ],
)
def test_carriage_return_variants_of_generated_sdist_members_are_rejected(
    clean_sdist, tmp_path, name, change, message
):
    altered = rewrite_sdist_member(clean_sdist, tmp_path, name, change)
    with pytest.raises(ValueError, match=message):
        verifier._verify_sdist(altered, ROOT)


# Round 3. Services whose packaged rules emit hosts outside the partition
# dnsSuffix: only AWS Sign-In (the login provider's refresh client) among the
# services the framework or botocore's credential providers can create.

PROVIDER_SERVICES = frozenset({"sts", "sso", "sso-oidc", "signin"})
EXPECTED_REVIEWED_DOMAINS = {
    ("signin", "aws"): frozenset({"signin.aws.amazon.com"}),
    ("signin", "aws-cn"): frozenset({"signin.amazonaws.cn"}),
    ("signin", "aws-us-gov"): frozenset(
        {"signin.amazonaws-us-gov.com", "signin-fips.amazonaws-us-gov.com"}
    ),
}


def reachable_services() -> frozenset[str]:
    """Every service the framework source or a credential provider can create."""
    source = (ROOT / "aws_chaos_framework.py").read_text(encoding="utf-8")
    created = set(re.findall(r'client\(\s*"([a-z0-9-]+)"', source))
    return frozenset(created | set(framework.READ_ONLY_OPERATIONS) | PROVIDER_SERVICES)


def test_reviewed_domains_are_exactly_what_packaged_rules_emit_for_reachable_services():
    # Widening an allowance (for example to aws.amazon.com or amazon.com), or
    # dropping one, fails here; so does a new out-of-suffix family after an SDK
    # update, until it is reviewed.
    assert framework.REVIEWED_SERVICE_DOMAINS == EXPECTED_REVIEWED_DOMAINS
    partitions = framework._bundled_endpoint_loader().load_data("partitions")
    used: set[tuple[str, str, str]] = set()
    checked = 0
    for service in sorted(reachable_services()):
        for partition in partitions["partitions"]:
            suffix = partition["outputs"]["dnsSuffix"]
            for region in partition["regions"]:
                if not framework.REGION_PATTERN.fullmatch(region):
                    continue  # the framework refuses this region before any client
                for use_fips in (False, True):
                    try:
                        parents, hosts = framework.canonical_endpoint_origin(
                            service, region, use_fips
                        )
                    except framework.SafetyViolation as exc:
                        # Only an absent endpoint (for example FIPS where a
                        # partition has none) may refuse; never a rejected origin.
                        assert str(exc).startswith(
                            (
                                "No canonical AWS endpoint",
                                "Bundled endpoint rules cannot",
                            )
                        ), (service, region, use_fips, str(exc))
                        continue
                    checked += 1
                    reviewed = EXPECTED_REVIEWED_DOMAINS.get(
                        (service, partition["id"]), frozenset()
                    )
                    assert parents == frozenset({suffix}) | reviewed
                    for host in hosts:
                        if host.endswith("." + suffix):
                            continue
                        matched = {
                            domain
                            for domain in reviewed
                            if host == domain or host.endswith("." + domain)
                        }
                        assert matched, (service, region, use_fips, host)
                        used.update((service, partition["id"], d) for d in matched)
    assert checked > 1000
    assert used == {
        (service, partition, domain)
        for (service, partition), domains in EXPECTED_REVIEWED_DOMAINS.items()
        for domain in domains
    }


SIGNIN_CASES = [
    ("us-east-1", False, "us-east-1.signin.aws.amazon.com"),
    ("eu-west-1", False, "eu-west-1.signin.aws.amazon.com"),
    ("us-east-1", True, "signin-fips.us-east-1.amazonaws.com"),
    ("us-gov-west-1", False, "us-gov-west-1.signin.amazonaws-us-gov.com"),
    ("us-gov-west-1", True, "signin-fips.amazonaws-us-gov.com"),
    ("us-gov-east-1", True, "us-gov-east-1.signin-fips.amazonaws-us-gov.com"),
    ("cn-north-1", False, "cn-north-1.signin.amazonaws.cn"),
]


@pytest.mark.parametrize("region,use_fips,host", SIGNIN_CASES)
def test_signin_origin_is_bound_to_its_packaged_host(
    tmp_path, monkeypatch, region, use_fips, host
):
    parents, hosts = framework.canonical_endpoint_origin("signin", region, use_fips)
    assert hosts == {host}
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent-config"))
    for name in (*ENDPOINT_VARIABLES, "AWS_USE_FIPS_ENDPOINT", "AWS_DATA_PATH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ENDPOINT_URL_SIGNIN", ATTACKER)
    if use_fips:
        monkeypatch.setenv("AWS_USE_FIPS_ENDPOINT", "true")
    session = framework.harden_session_origin(
        boto3.Session(
            botocore_session=botocore.session.Session(),
            aws_access_key_id=KEY_A,
            aws_secret_access_key="secret-a",
            region_name=region,
        )
    )
    sent: list[str] = []

    def offline(request, **_kwargs):
        sent.append(urlsplit(request.url).netloc)
        raise Delivered(request.url)

    session.events.register("before-send", offline)
    # Created exactly as the login provider creates its refresh client.
    client = session._session.create_client(
        "signin", config=Config(signature_version=botocore.UNSIGNED)
    )
    # The descriptive endpoint passes the same parent-domain check.
    assert framework.is_under_domains(
        urlsplit(client.meta.endpoint_url).hostname, parents
    )
    with pytest.raises(Delivered):
        client.create_o_auth2_token(
            tokenInput={
                "clientId": "client-id",
                "refreshToken": "refresh-1",
                "grantType": "refresh_token",
            }
        )
    assert sent == [host]
    framework.bind_endpoint_origin(
        SimpleNamespace(
            meta=SimpleNamespace(endpoint_url="https://" + host, events=FakeEvents())
        ),
        "signin",
        parents,
        hosts,
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.aws.amazon.com/v1/token",
        "https://signin.aws.amazon.com/v1/token",
        "https://x.us-east-1.signin.aws.amazon.com/v1/token",
        "https://us-west-2.signin.aws.amazon.com/v1/token",
        "https://us-east-1.signin.aws.amazon.com.attacker.example/v1/token",
        "https://us-east-1.signin.amazonaws-us-gov.com/v1/token",
        "http://us-east-1.signin.aws.amazon.com/v1/token",
    ],
)
def test_signin_lookalike_hosts_are_refused(url):
    _parents, hosts = framework.canonical_endpoint_origin("signin", "us-east-1", False)
    assert not framework.is_canonical_request_url("signin", url, hosts)


@pytest.mark.parametrize(
    "service,endpoint",
    [
        ("signin", "https://evil.aws.amazon.com"),
        ("signin", "https://attacker.amazon.com"),
        ("signin", "https://evilsignin.aws.amazon.com"),
        ("signin", "https://signin.aws.amazon.com.attacker.example"),
        ("sts", "https://us-east-1.signin.aws.amazon.com"),
        ("kinesis", "https://cn-north-1.signin.amazonaws.cn"),
    ],
)
def test_reviewed_domain_is_service_specific_and_not_a_broad_suffix(service, endpoint):
    parents, hosts = framework.canonical_endpoint_origin(service, "us-east-1", False)
    if service != "signin":
        assert parents == frozenset({"amazonaws.com"})
    client = SimpleNamespace(
        meta=SimpleNamespace(endpoint_url=endpoint, events=FakeEvents())
    )
    with pytest.raises(framework.SafetyViolation, match="not a canonical AWS origin"):
        framework.bind_endpoint_origin(client, service, parents, hosts)


def test_bundled_rule_host_outside_the_reviewed_domains_fails_closed(monkeypatch):
    class Provider:
        def __init__(self, *_args):
            pass

        def resolve_endpoint(self, **_parameters):
            return SimpleNamespace(url="https://us-east-1.signin.aws.amazon.com.evil")

    monkeypatch.setattr(framework, "_CANONICAL_ENDPOINTS", {})
    monkeypatch.setattr(framework, "EndpointProvider", Provider)
    with pytest.raises(framework.SafetyViolation, match="non-canonical AWS origin"):
        framework.canonical_endpoint_origin("signin", "us-east-1", False)


LOGIN_SESSION = f"arn:aws:iam::{ACCOUNT_ID}:user/chaos-operator"
LOGIN_PROFILE = (
    f"[profile {PROFILE}]\nregion = {PROFILE_REGION}\n"
    f"login_session = {LOGIN_SESSION}\nendpoint_url = {ATTACKER}\n"
)


def login_environment(monkeypatch, tmp_path, crt: bool) -> None:
    """Expired cached login credentials, so freezing forces the refresh path."""
    if crt:
        pytest.importorskip("awscrt.crypto")
    else:
        # Without botocore's optional CRT the provider refuses to load; the
        # stand-in satisfies only that gate and the private-key decoding.
        monkeypatch.setattr(
            botocore.credentials,
            "EC",
            SimpleNamespace(new_key_from_der_data=lambda data: "offline-key"),
        )
    monkeypatch.setattr(
        botocore.credentials.LoginCredentialFetcher,
        "_load_private_key",
        staticmethod(lambda token: "offline-key"),
    )
    # DPoP proof signing is CRT cryptography, unrelated to request origin.
    monkeypatch.setattr(
        botocore.credentials, "_build_dpop_header", lambda key, url: "offline-dpop"
    )
    cache = tmp_path / "login-cache"
    cache.mkdir()
    monkeypatch.setenv("AWS_LOGIN_CACHE_DIRECTORY", str(cache))
    expired = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    token = {
        "accessToken": {
            "accessKeyId": KEY_A,
            "secretAccessKey": "secret-a",
            "sessionToken": "token-a",
            "accountId": ACCOUNT_ID,
            "expiresAt": expired,
        },
        "refreshToken": "refresh-1",
        "dpopKey": "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----",
        "clientId": "client-id",
    }
    name = botocore.utils.generate_login_cache_key(LOGIN_SESSION) + ".json"
    (cache / name).write_text(json.dumps(token), encoding="utf-8")


@pytest.mark.parametrize("crt", [False, True])
def test_login_refresh_reaches_only_the_canonical_signin_host(
    tmp_path, monkeypatch, crt
):
    sent = provider_aws(monkeypatch, tmp_path, LOGIN_PROFILE)
    login_environment(monkeypatch, tmp_path, crt)
    orchestrator, _values = live_orchestrator(tmp_path)
    assert orchestrator.actual_account == ACCOUNT_ID
    assert provider_hosts(sent) == [
        ("CreateOAuth2Token", "us-east-1.signin.aws.amazon.com"),
        ("GetCallerIdentity", "sts.us-east-1.amazonaws.com"),
    ]
    assert sent[0][2]["dpop"] == "offline-dpop"


def test_redirected_login_refresh_is_refused_before_sending(tmp_path, monkeypatch):
    data_path = forged_ruleset_path(tmp_path, "signin", "2023-01-01")
    sent = provider_aws(monkeypatch, tmp_path, LOGIN_PROFILE)
    login_environment(monkeypatch, tmp_path, crt=False)
    monkeypatch.setenv("AWS_DATA_PATH", str(data_path))
    with pytest.raises(framework.SafetyViolation, match="non-canonical endpoint"):
        live_orchestrator(tmp_path)
    assert sent == []
