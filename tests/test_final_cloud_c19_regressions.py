"""Offline regressions for the one-finding Cloud scan of main d35003e.

Direct-library sessions must be origin-hardened before the framework resolves
credentials. ``SafetyController`` construction, ``origin_bound_client`` (the
factory of every framework client) and planning experiment construction refuse
a real botocore-backed session that ``harden_session_origin`` has not marked,
before any credential or token is resolved, and ``harden_session_origin``
refuses a session whose credential or token provider was already built with an
unwrapped client creator. Session objects without a botocore core (test
doubles) keep their direct-library behaviour.

Every provider profile below also configures attacker endpoint overrides
(profile ``endpoint_url`` and ``AWS_ENDPOINT_URL*``). Every AWS answer is an
offline botocore before-send response; no network is contacted.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from botocore.config import Config
from test_aws_chaos_framework import ACCOUNT_ID
from test_final_cloud_c13_regressions import (
    ASSUME_ROLE_CHAIN,
    ASSUME_ROLE_CREDENTIALS,
    ATTACKER,
    LOGIN_PROFILE,
    SSO_PROFILE,
    SSO_REGION,
    Delivered,
    login_environment,
    provider_aws,
    provider_hosts,
    sso_token,
)
from test_final_cloud_eight_scope_controls import PROFILE, PROFILE_REGION

import aws_chaos_framework as framework

UNHARDENED = "origin-hardened AWS session"
STS = f"sts.{PROFILE_REGION}.amazonaws.com"
# The canonical provider requests each refreshable profile makes before the
# first framework client exists.
CANONICAL_PROVIDER_REQUESTS = {
    "assume-role-external-id": [("AssumeRole", STS)],
    "web-identity": [("AssumeRoleWithWebIdentity", STS)],
    "sso": [("GetRoleCredentials", f"portal.sso.{SSO_REGION}.amazonaws.com")],
    "sso-oidc-refresh": [
        ("CreateToken", f"oidc.{SSO_REGION}.amazonaws.com"),
        ("GetRoleCredentials", f"portal.sso.{SSO_REGION}.amazonaws.com"),
    ],
    "login": [("CreateOAuth2Token", f"{PROFILE_REGION}.signin.aws.amazon.com")],
}
PROVIDERS = tuple(CANONICAL_PROVIDER_REQUESTS)


def provider_profile(monkeypatch, tmp_path, provider: str):
    """Select one refreshable provider profile; every endpoint names the attacker."""
    if provider == "assume-role-external-id":
        return provider_aws(
            monkeypatch, tmp_path, ASSUME_ROLE_CHAIN, ASSUME_ROLE_CREDENTIALS
        )
    if provider == "web-identity":
        token_file = tmp_path / "web-identity-token"
        token_file.write_text("synthetic-web-identity-token", encoding="ascii")
        config = (
            f"[profile {PROFILE}]\nregion = {PROFILE_REGION}\n"
            f"role_arn = arn:aws:iam::{ACCOUNT_ID}:role/ChaosWeb\n"
            f"web_identity_token_file = {token_file.as_posix()}\n"
            f"endpoint_url = {ATTACKER}\n"
        )
        return provider_aws(monkeypatch, tmp_path, config)
    if provider == "login":
        sent = provider_aws(monkeypatch, tmp_path, LOGIN_PROFILE)
        login_environment(monkeypatch, tmp_path, crt=False)
        return sent
    sent = provider_aws(monkeypatch, tmp_path, SSO_PROFILE)
    # Five minutes is inside botocore's SSO-OIDC refresh window.
    refresh = provider == "sso-oidc-refresh"
    sso_token(tmp_path, timedelta(minutes=5) if refresh else timedelta(hours=8))
    return sent


def caller_session():
    """A normal caller-created boto3 session for the selected profile."""
    return framework.boto3.Session(profile_name=PROFILE, region_name=PROFILE_REGION)


def unresolved(session) -> bool:
    """No credential resolver was built and no credential or token resolved."""
    core = session._session
    return (
        "credential_provider" not in core._components._components
        and core._credentials is None
        and core._auth_token is None
    )


def controller_for(session):
    return framework.SafetyController(
        {}, session, PROFILE_REGION, False, expected_account=ACCOUNT_ID
    )


@pytest.mark.parametrize("provider", PROVIDERS)
def test_safety_controller_refuses_an_unhardened_session_before_resolution(
    tmp_path, monkeypatch, provider
):
    sent = provider_profile(monkeypatch, tmp_path, provider)
    session = caller_session()
    with pytest.raises(framework.SafetyViolation, match=UNHARDENED):
        controller_for(session)
    assert unresolved(session)
    assert sent == []


@pytest.mark.parametrize("provider", PROVIDERS)
def test_origin_bound_client_refuses_an_unhardened_session_before_resolution(
    tmp_path, monkeypatch, provider
):
    sent = provider_profile(monkeypatch, tmp_path, provider)
    session = caller_session()
    with pytest.raises(framework.SafetyViolation, match=UNHARDENED):
        framework.origin_bound_client(session, "sts", PROFILE_REGION, Config())
    assert unresolved(session)
    assert sent == []


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("entry", ["client-factory", "planning-experiment"])
@pytest.mark.parametrize("cached", [False, True])
def test_controller_session_replaced_after_construction_is_refused(
    tmp_path, monkeypatch, provider, entry, cached
):
    sent = provider_profile(monkeypatch, tmp_path, provider)
    controller = controller_for(framework.harden_session_origin(caller_session()))
    if cached and entry == "client-factory":
        controller.client("sts")
        sent.clear()
    session = caller_session()
    controller.session = session
    with pytest.raises(framework.SafetyViolation, match=UNHARDENED):
        if entry == "client-factory":
            controller.client("sts")
        else:
            # The base constructor creates no client, so its own check refuses.
            framework.ChaosExperiment(
                {"region": PROFILE_REGION, "dry_run": True}, controller
            )
    assert unresolved(session)
    assert sent == []


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("entry", ["safety-controller", "planning-experiment"])
def test_hardened_caller_session_keeps_provider_and_service_origins_canonical(
    tmp_path, monkeypatch, provider, entry
):
    sent = provider_profile(monkeypatch, tmp_path, provider)
    controller = controller_for(framework.harden_session_origin(caller_session()))
    if entry == "safety-controller":
        controller.client("sts").get_caller_identity()
        service_request = ("GetCallerIdentity", STS)
    else:
        experiment = framework.LambdaChaosExperiment(
            {"region": PROFILE_REGION, "dry_run": True}, controller
        )
        # The first plan read resolves the provider credentials.
        with pytest.raises(Delivered):
            experiment.lambda_client.get_function_configuration(
                FunctionName="chaos-test-function"
            )
        service_request = (
            "GetFunctionConfiguration",
            f"lambda.{PROFILE_REGION}.amazonaws.com",
        )
    assert provider_hosts(sent) == [
        *CANONICAL_PROVIDER_REQUESTS[provider],
        service_request,
    ]
    if provider.startswith("sso"):
        bearer = sent[-2][2]["x-amz-sso_bearer_token"]
        expected = "cached-access-token" if provider == "sso" else "refreshed"
        assert bearer.startswith(expected)


@pytest.mark.parametrize("provider", ["sso", "login", "assume-role-external-id"])
def test_session_whose_resolver_was_built_before_hardening_is_refused(
    tmp_path, monkeypatch, provider
):
    sent = provider_profile(monkeypatch, tmp_path, provider)
    session = caller_session()
    # The SSO and login providers capture the unwrapped create_client here.
    session._session.get_component("credential_provider")
    with pytest.raises(
        framework.SafetyViolation, match="credential or token providers"
    ):
        framework.harden_session_origin(session)
    assert not framework.is_origin_hardened(session)
    with pytest.raises(framework.SafetyViolation, match=UNHARDENED):
        controller_for(session)
    assert sent == []


def test_session_with_prebuilt_token_provider_is_refused_before_hardening(
    tmp_path, monkeypatch
):
    sent = provider_profile(monkeypatch, tmp_path, "sso-oidc-refresh")
    session = framework.boto3.Session(
        profile_name=PROFILE,
        region_name=PROFILE_REGION,
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
    )
    core = session._session
    provider = core.get_component("token_provider").get_provider("sso")
    # Constructing an unsigned nested client caches it without sending a request.
    assert provider._client is not None
    assert "_client" in provider.__dict__
    assert "token_provider" in core._components._components
    assert "credential_provider" not in core._components._components
    with pytest.raises(
        framework.SafetyViolation, match="credential or token providers"
    ):
        framework.harden_session_origin(session)
    assert not framework.is_origin_hardened(session)
    assert sent == []


class OpaqueComponents:
    """A component store that does not expose which components were built."""

    def __init__(self, inner) -> None:
        self._inner = inner

    def get_component(self, name):
        return self._inner.get_component(name)


def test_session_whose_component_store_cannot_be_inspected_is_refused(
    tmp_path, monkeypatch
):
    sent = provider_profile(monkeypatch, tmp_path, "sso")
    session = caller_session()
    core = session._session
    core._components = OpaqueComponents(core._components)
    with pytest.raises(
        framework.SafetyViolation, match="credential or token providers"
    ):
        framework.harden_session_origin(session)
    assert not framework.is_origin_hardened(session)
    assert sent == []


def test_sessions_without_a_botocore_core_keep_direct_library_compatibility():
    created: list[tuple[str, str]] = []
    raw = framework.boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    ).client("lambda", region_name=PROFILE_REGION)

    def client(service, **kwargs):
        created.append((service, kwargs["region_name"]))
        return raw

    fake = SimpleNamespace(client=client)
    assert not framework.is_origin_hardened(fake)
    controller = controller_for(fake)
    assert controller.session is fake
    experiment = framework.LambdaChaosExperiment(
        {"region": PROFILE_REGION, "dry_run": True}, controller
    )
    assert experiment.safety_controller is controller
    assert created == [("lambda", PROFILE_REGION)]
    assert framework.harden_session_origin(fake) is fake
