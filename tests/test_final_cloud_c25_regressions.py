"""Offline regressions for the four validated findings on main 7525415."""

from __future__ import annotations

import json
import os
import threading
from collections import defaultdict
from types import MappingProxyType, MethodType, SimpleNamespace

import boto3
import pytest
from botocore import httpsession, xform_name
from botocore.config import Config
from botocore.model import ServiceModel
from botocore.stub import Stubber
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    BREAK_GLASS_ARN,
    REGION,
    FakeAWS,
    action_configs,
    provider_free_session,
)
from test_final_cloud_c19_regressions import (
    PROVIDERS,
    caller_session,
    provider_profile,
    unresolved,
)
from test_security_regressions import native_target_experiment

import aws_chaos_framework as framework


def synthetic_session() -> boto3.Session:
    return boto3.Session(
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
        region_name=REGION,
    )


def metadata_session(monkeypatch, tmp_path) -> boto3.Session:
    """Force the offline credential chain to reach IMDS without other providers."""
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "false")
    monkeypatch.setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-creds"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    return boto3.Session(region_name=REGION)


def clear_proxy_environment(monkeypatch) -> None:
    for name in list(os.environ):
        if name.lower() in {"http_proxy", "https_proxy", "all_proxy"}:
            monkeypatch.delenv(name)


@pytest.mark.parametrize("name", ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"])
@pytest.mark.parametrize(
    "endpoint", ["http://169.254.169.254", "http://[fd00:ec2::254]"]
)
def test_metadata_proxy_configuration_fails_before_credentials(
    monkeypatch, name, endpoint
):
    clear_proxy_environment(monkeypatch)
    monkeypatch.setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", endpoint)
    monkeypatch.setenv("NO_PROXY", "169.254.169.254,fd00:ec2::254")
    session = framework.harden_session_origin(synthetic_session())
    monkeypatch.setenv(name, "http://127.0.0.1:18080")
    with pytest.raises(framework.SafetyViolation, match="proxy"):
        framework.origin_bound_client(session, "sts", REGION, Config())
    with pytest.raises(framework.SafetyViolation, match="proxy"):
        framework.SafetyController({}, session, REGION, True, ACCOUNT_ID)
    with pytest.raises(framework.SafetyViolation, match="proxy"):
        framework.pin_session_credentials(session, REGION)


@pytest.mark.parametrize(
    "endpoint", ["http://169.254.169.254", "http://[fd00:ec2::254]"]
)
def test_default_metadata_endpoints_have_proven_direct_policy(monkeypatch, endpoint):
    clear_proxy_environment(monkeypatch)
    monkeypatch.setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", endpoint)
    session = framework.harden_session_origin(synthetic_session())
    framework.require_credential_transport_policy(session)


@pytest.mark.parametrize(
    "endpoint", ["http://169.254.169.254", "http://[fd00:ec2::254]"]
)
def test_offline_imds_token_uses_direct_transport(monkeypatch, tmp_path, endpoint):
    clear_proxy_environment(monkeypatch)
    monkeypatch.setattr(framework.urllib.request, "getproxies", lambda: {})
    monkeypatch.setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", endpoint)
    observed = []

    class OfflineTransport:
        def __init__(self, **kwargs):
            observed.append(("config", kwargs.get("proxies")))

        def send(self, request):
            observed.append(("request", request.url))
            if request.method == "PUT":
                return SimpleNamespace(
                    status_code=200,
                    text="offline-token",
                    content=b"offline-token",
                    url=request.url,
                )
            return SimpleNamespace(
                status_code=404, text="", content=b"", url=request.url
            )

    monkeypatch.setattr(httpsession, "URLLib3Session", OfflineTransport)
    session = framework.harden_session_origin(metadata_session(monkeypatch, tmp_path))
    with pytest.raises(framework.SafetyViolation, match="no credentials resolved"):
        framework.pin_session_credentials(session, REGION)
    assert all(value in (None, {}) for kind, value in observed if kind == "config")
    assert (
        len(
            [
                1
                for kind, value in observed
                if kind == "request" and str(value).startswith(endpoint)
            ]
        )
        >= 2
    )


@pytest.mark.parametrize("name", ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"])
def test_offline_imds_proxy_refused_before_transport(monkeypatch, tmp_path, name):
    clear_proxy_environment(monkeypatch)
    monkeypatch.setattr(framework.urllib.request, "getproxies", lambda: {})
    monkeypatch.setenv(name, "http://127.0.0.1:18080")
    observed = []
    monkeypatch.setattr(
        httpsession, "URLLib3Session", lambda **kwargs: observed.append(kwargs)
    )
    session = framework.harden_session_origin(metadata_session(monkeypatch, tmp_path))
    with pytest.raises(framework.SafetyViolation, match="proxy"):
        framework.pin_session_credentials(session, REGION)
    assert observed == []


@pytest.mark.parametrize("source", ["environment", "system", "default-config"])
@pytest.mark.parametrize(
    "endpoint", ["http://169.254.169.254", "http://[fd00:ec2::254]"]
)
def test_unresolved_imds_proxy_sources_never_start_transport(
    monkeypatch, tmp_path, source, endpoint
):
    clear_proxy_environment(monkeypatch)
    monkeypatch.setattr(framework.urllib.request, "getproxies", lambda: {})
    monkeypatch.setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", endpoint)
    observed = []
    monkeypatch.setattr(
        httpsession, "URLLib3Session", lambda **kwargs: observed.append(kwargs)
    )
    session = framework.harden_session_origin(metadata_session(monkeypatch, tmp_path))
    proxy = "http://127.0.0.1:18080"
    if source == "environment":
        monkeypatch.setenv("HTTP_PROXY", proxy)
    elif source == "system":
        monkeypatch.setattr(
            framework.urllib.request, "getproxies", lambda: {"http": proxy}
        )
    else:
        session._session.set_default_client_config(Config(proxies={"http": proxy}))
    with pytest.raises(framework.SafetyViolation, match="proxy"):
        framework.pin_session_credentials(session, REGION)
    assert unresolved(session)
    assert observed == []


def test_botocore_proxy_configuration_fails_closed(monkeypatch):
    clear_proxy_environment(monkeypatch)
    session = framework.harden_session_origin(synthetic_session())
    session._session.set_config_variable("proxies", {"http": "http://127.0.0.1:18080"})
    with pytest.raises(framework.SafetyViolation, match="proxy"):
        framework.require_credential_transport_policy(session)


def test_per_client_botocore_proxy_configuration_fails_closed(monkeypatch):
    clear_proxy_environment(monkeypatch)
    session = framework.harden_session_origin(synthetic_session())
    with pytest.raises(framework.SafetyViolation, match="proxy"):
        framework.origin_bound_client(
            session,
            "sts",
            REGION,
            Config(proxies={"http": "http://127.0.0.1:18080"}),
        )


def test_system_proxy_discovery_fails_closed(monkeypatch):
    clear_proxy_environment(monkeypatch)
    session = framework.harden_session_origin(synthetic_session())
    monkeypatch.setattr(
        framework.urllib.request,
        "getproxies",
        lambda: {"http": "http://127.0.0.1:18080"},
    )
    with pytest.raises(framework.SafetyViolation, match="proxy"):
        framework.pin_session_credentials(session, REGION)


def test_default_botocore_client_proxy_fails_closed(monkeypatch):
    clear_proxy_environment(monkeypatch)
    session = framework.harden_session_origin(synthetic_session())
    session._session.set_default_client_config(
        Config(proxies={"http": "http://127.0.0.1:18080"})
    )
    with pytest.raises(framework.SafetyViolation, match="proxy"):
        framework.origin_bound_client(session, "sts", REGION, Config())


def test_session_wrappers_cannot_hide_unhardened_or_swapped_client(monkeypatch):
    clear_proxy_environment(monkeypatch)
    original = synthetic_session()
    bound = SimpleNamespace(
        client=original.client, get_credentials=original.get_credentials
    )
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.origin_bound_client(bound, "sts", REGION, Config())
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.SafetyController({}, bound, REGION, True, ACCOUNT_ID)
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.pin_session_credentials(bound, REGION)
    fake_controller = SimpleNamespace(session=bound)
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.ChaosExperiment({"dry_run": True}, fake_controller)
    framework.harden_session_origin(original)
    wrapper = SimpleNamespace(
        client=original.client, get_credentials=original.get_credentials
    )
    assert framework.is_origin_hardened(wrapper)
    assert (
        framework.origin_bound_client(wrapper, "sts", REGION, Config()).meta.region_name
        == REGION
    )
    wrapper.client = lambda *args, **kwargs: original.client(*args, **kwargs)
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.origin_bound_client(wrapper, "sts", REGION, Config())
    wrapper.client = MethodType(
        lambda self, *args, **kwargs: original.client(*args, **kwargs), original
    )
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.origin_bound_client(wrapper, "sts", REGION, Config())
    fake = provider_free_session(
        client=lambda service, **kwargs: FakeAWS().client(service)
    )
    framework.require_origin_hardened_session(fake)


def test_session_wrapper_credentials_must_share_hardened_core(monkeypatch):
    clear_proxy_environment(monkeypatch)
    hardened = framework.harden_session_origin(synthetic_session())
    other = synthetic_session()
    mixed = SimpleNamespace(
        client=hardened.client, get_credentials=other.get_credentials
    )
    assert not framework.is_origin_hardened(mixed)
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.pin_session_credentials(mixed, REGION)
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.origin_bound_client(mixed, "sts", REGION, Config())
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.SafetyController({}, mixed, REGION, True, ACCOUNT_ID)


def test_forged_bound_method_metadata_never_reaches_provider(monkeypatch):
    clear_proxy_environment(monkeypatch)
    hardened = framework.harden_session_origin(synthetic_session())
    delegated = []

    def false_client(*args, **kwargs):
        delegated.append("client")
        raise AssertionError("unverified client delegate ran")

    def false_credentials(*args, **kwargs):
        delegated.append("credentials")
        raise AssertionError("unverified credential delegate ran")

    false_client.__self__ = hardened
    false_client.__func__ = framework.BOTO3_CLIENT_METHOD
    false_credentials.__self__ = hardened
    false_credentials.__func__ = framework.BOTO3_CREDENTIALS_METHOD

    def assert_refused(forged):
        entry_points = (
            lambda: framework.harden_session_origin(forged),
            lambda: framework.pin_session_credentials(forged, REGION),
            lambda: framework.SafetyController({}, forged, REGION, True, ACCOUNT_ID),
            lambda: framework.ChaosExperiment(
                {"dry_run": True}, SimpleNamespace(session=forged)
            ),
            lambda: framework.origin_bound_client(forged, "sts", REGION, Config()),
        )
        for entry in entry_points:
            with pytest.raises(framework.SafetyViolation):
                entry()

    for forged in (
        SimpleNamespace(client=false_client, get_credentials=hardened.get_credentials),
        SimpleNamespace(client=hardened.client, get_credentials=false_credentials),
    ):
        assert_refused(forged)
    assert delegated == []


def test_wrapper_lookup_cannot_swap_dispatch_after_verification(monkeypatch):
    clear_proxy_environment(monkeypatch)
    hardened = framework.harden_session_origin(synthetic_session())
    delegated = []

    class ChangingWrapper:
        client_reads = 0
        credential_reads = 0

        @property
        def client(self):
            self.client_reads += 1
            if self.client_reads > 1:
                return lambda *args, **kwargs: delegated.append("client")
            return hardened.client

        @property
        def get_credentials(self):
            self.credential_reads += 1
            if self.credential_reads > 1:
                return lambda: delegated.append("credentials")
            return hardened.get_credentials

    wrapper = ChangingWrapper()
    client = framework.origin_bound_client(wrapper, "sts", REGION, Config())
    assert client.meta.region_name == REGION
    assert wrapper.client_reads == wrapper.credential_reads == 1
    assert delegated == []

    wrapper = ChangingWrapper()
    pinned = framework.pin_session_credentials(wrapper, REGION)
    assert framework.is_origin_hardened(pinned)
    assert wrapper.client_reads == wrapper.credential_reads == 1
    assert delegated == []


def test_changing_core_owner_and_spoofed_class_refuse_all_entry_points(monkeypatch):
    clear_proxy_environment(monkeypatch)
    hardened = framework.harden_session_origin(synthetic_session())
    raw = synthetic_session()

    class ChangingCore(boto3.Session):
        reads = 0

        @property
        def _session(self):
            self.reads += 1
            return hardened._session if self.reads <= 4 else raw._session

    subclass = object.__new__(ChangingCore)

    class SpoofedClass:
        reads = 0

        @property
        def __class__(self):
            return boto3.Session

        @property
        def _session(self):
            self.reads += 1
            return hardened._session if self.reads <= 4 else raw._session

    impostor = SpoofedClass()

    class StoredCoreSpoof:
        reads = 0

        @property
        def __class__(self):
            return boto3.Session

    stored = StoredCoreSpoof()
    stored._session = hardened._session

    def reject_all(wrapper):
        entry_points = (
            lambda: framework.harden_session_origin(wrapper),
            lambda: framework.pin_session_credentials(wrapper, REGION),
            lambda: framework.SafetyController({}, wrapper, REGION, True, ACCOUNT_ID),
            lambda: framework.ChaosExperiment(
                {"dry_run": True}, SimpleNamespace(session=wrapper)
            ),
            lambda: framework.origin_bound_client(wrapper, "sts", REGION, Config()),
        )
        for entry in entry_points:
            with pytest.raises(framework.SafetyViolation):
                entry()

    for owner in (subclass, impostor, stored):
        wrapper = SimpleNamespace(
            client=MethodType(framework.BOTO3_CLIENT_METHOD, owner),
            get_credentials=MethodType(framework.BOTO3_CREDENTIALS_METHOD, owner),
        )
        reject_all(wrapper)
        assert owner.reads == 0

    inherited_core = synthetic_session()

    class DerivedCore(framework.BotocoreSession):
        pass

    inherited_core._session = DerivedCore()
    with pytest.raises(framework.SafetyViolation):
        framework.harden_session_origin(inherited_core)


def test_captured_core_remains_fixed_after_caller_swaps_native_owner(monkeypatch):
    clear_proxy_environment(monkeypatch)
    hardened = framework.harden_session_origin(synthetic_session())
    raw = synthetic_session()
    fixed = framework._checked_origin_session(hardened)
    assert fixed is not hardened
    original_core = hardened._session
    hardened._session = raw._session
    try:
        credentials = framework.BOTO3_CREDENTIALS_METHOD(fixed)
        assert credentials.access_key == "synthetic"
        client = framework.BOTO3_CLIENT_METHOD(
            fixed, "sts", region_name=REGION, config=Config()
        )
        assert client.meta.region_name == REGION
        assert not framework.is_origin_hardened(hardened)
    finally:
        hardened._session = original_core


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize(
    "entry", ["origin-bound-client", "safety-controller", "planning", "pin"]
)
def test_network_provider_wrappers_refuse_before_any_provider_request(
    monkeypatch, tmp_path, provider, entry
):
    clear_proxy_environment(monkeypatch)
    sent = provider_profile(monkeypatch, tmp_path, provider)
    raw = caller_session()
    wrapper = SimpleNamespace(client=raw.client, get_credentials=raw.get_credentials)
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        if entry == "origin-bound-client":
            framework.origin_bound_client(wrapper, "sts", REGION, Config())
        elif entry == "safety-controller":
            framework.SafetyController({}, wrapper, REGION, True, ACCOUNT_ID)
        elif entry == "planning":
            framework.ChaosExperiment(
                {"dry_run": True}, SimpleNamespace(session=wrapper)
            )
        else:
            framework.pin_session_credentials(wrapper, REGION)
    assert unresolved(raw)
    assert sent == []


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize(
    "entry", ["origin-bound-client", "safety-controller", "planning", "pin"]
)
def test_mixed_method_provider_wrappers_refuse_before_resolution(
    monkeypatch, tmp_path, provider, entry
):
    clear_proxy_environment(monkeypatch)
    sent = provider_profile(monkeypatch, tmp_path, provider)
    hardened = framework.harden_session_origin(caller_session())
    other = caller_session()
    mixed = SimpleNamespace(
        client=hardened.client, get_credentials=other.get_credentials
    )
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        if entry == "origin-bound-client":
            framework.origin_bound_client(mixed, "sts", REGION, Config())
        elif entry == "safety-controller":
            framework.SafetyController({}, mixed, REGION, True, ACCOUNT_ID)
        elif entry == "planning":
            framework.ChaosExperiment({"dry_run": True}, SimpleNamespace(session=mixed))
        else:
            framework.pin_session_credentials(mixed, REGION)
    assert unresolved(other)
    assert sent == []


def test_provider_free_injection_refuses_dynamic_session_factory():
    invoked = []

    def delegate(service):
        invoked.append(service)
        return synthetic_session().client(service)

    with pytest.raises(framework.SafetyViolation, match="fixed service map"):
        framework._ProviderFreeSession(delegate)
    assert invoked == []


def test_provider_free_adapter_cannot_be_subclassed_or_shadowed():
    with pytest.raises(TypeError, match="cannot be subclassed"):

        class DelegatingSession(framework._ProviderFreeSession):
            def get_credentials(self):
                return synthetic_session().get_credentials()

    fake = framework._ProviderFreeSession({"sts": FakeAWS().client("sts")})
    with pytest.raises(AttributeError):
        fake.client = synthetic_session().client
    with pytest.raises(AttributeError):
        fake._clients = {"sts": synthetic_session().client("sts")}
    with pytest.raises(TypeError):
        fake._clients["sts"] = synthetic_session().client("sts")
    with pytest.raises(AttributeError):
        del fake._clients
    with pytest.raises(AttributeError):
        del fake._credentials
    with pytest.raises(AttributeError):
        fake._credentials = synthetic_session().get_credentials()
    with pytest.raises(AttributeError):
        object.__setattr__(fake, "_credentials", synthetic_session().get_credentials())
    assert fake.get_credentials() is None
    assert fake.client("sts") is not None


@pytest.mark.parametrize("payload", [(), ({"sts": object()}, None)])
def test_tuple_base_allocation_cannot_bypass_provider_free_constructor(payload):
    forged = tuple.__new__(framework._ProviderFreeSession, payload)
    with pytest.raises(framework.SafetyViolation, match="payload is not static"):
        framework.require_origin_hardened_session(forged)


def test_tuple_base_allocation_refuses_provider_before_resolution():
    resolved = []

    class ProviderCredentials:
        def get_frozen_credentials(self):
            resolved.append(True)
            raise AssertionError("provider credentials must not resolve")

    forged = tuple.__new__(
        framework._ProviderFreeSession,
        ((("sts", FakeAWS().client("sts")),), ProviderCredentials()),
    )
    entry_points = (
        lambda: framework.harden_session_origin(forged),
        lambda: framework.pin_session_credentials(forged, REGION),
        lambda: framework.SafetyController({}, forged, REGION, True, ACCOUNT_ID),
        lambda: framework.ChaosExperiment(
            {"dry_run": True}, SimpleNamespace(session=forged)
        ),
        lambda: framework.origin_bound_client(forged, "sts", REGION, Config()),
    )
    for entry in entry_points:
        with pytest.raises(framework.SafetyViolation, match="payload is not static"):
            entry()
    assert resolved == []


def test_exact_static_credential_delegate_cannot_run_at_any_entry_point():
    invoked = []
    credentials = framework.BotocoreCredentials("ASIA" + "Z" * 16, "synthetic-secret")

    def delegated_freeze():
        invoked.append(True)
        raise AssertionError("caller credential delegate must not run")

    credentials.get_frozen_credentials = delegated_freeze
    fixed = framework._ProviderFreeSession(
        {"sts": FakeAWS().client("sts")}, credentials
    )
    assert (
        fixed.get_credentials().get_frozen_credentials().access_key
        == credentials.access_key
    )
    assert invoked == []

    forged = tuple.__new__(
        framework._ProviderFreeSession,
        ((("sts", FakeAWS().client("sts")),), credentials),
    )
    entry_points = (
        lambda: framework.harden_session_origin(forged),
        lambda: framework.pin_session_credentials(forged, REGION),
        lambda: framework.SafetyController({}, forged, REGION, True, ACCOUNT_ID),
        lambda: framework.ChaosExperiment(
            {"dry_run": True}, SimpleNamespace(session=forged)
        ),
        lambda: framework.origin_bound_client(forged, "sts", REGION, Config()),
    )
    for entry in entry_points:
        with pytest.raises(framework.SafetyViolation, match="payload is not static"):
            entry()
    assert invoked == []


def test_tuple_base_allocation_refuses_lazy_client_mapping_before_factory():
    created = []

    def create_client():
        created.append(True)
        return synthetic_session().client("sts")

    forged = tuple.__new__(
        framework._ProviderFreeSession,
        (MappingProxyType(defaultdict(create_client)), None),
    )
    entry_points = (
        lambda: framework.harden_session_origin(forged),
        lambda: framework.pin_session_credentials(forged, REGION),
        lambda: framework.SafetyController({}, forged, REGION, True, ACCOUNT_ID),
        lambda: framework.ChaosExperiment(
            {"dry_run": True}, SimpleNamespace(session=forged)
        ),
        lambda: framework.origin_bound_client(forged, "sts", REGION, Config()),
    )
    for entry in entry_points:
        with pytest.raises(framework.SafetyViolation, match="payload is not static"):
            entry()
    assert created == []


def test_packaged_models_reject_customer_wire_redefinition(monkeypatch, tmp_path):
    clear_proxy_environment(monkeypatch)
    data = json.loads(
        json.dumps(
            framework._bundled_endpoint_loader().load_service_model("s3", "service-2")
        )
    )
    data["operations"]["GetBucketPolicy"]["http"]["method"] = "DELETE"
    model_path = tmp_path / "s3/2006-03-01/service-2.json"
    model_path.parent.mkdir(parents=True)
    model_path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setenv("AWS_DATA_PATH", str(tmp_path))
    session = framework.harden_session_origin(synthetic_session())
    assert session._session.get_component("data_loader").search_paths == [
        framework.BotocoreLoader.BUILTIN_DATA_PATH
    ]
    client = framework.origin_bound_client(session, "s3", REGION, Config())
    proxy = framework.AwsClientProxy("s3", client, None)
    assert (
        client.meta.service_model.operation_model("GetBucketPolicy").http["method"]
        == "GET"
    )
    assert callable(proxy.get_bucket_policy)
    saved_modes = [
        framework.AwsClientProxy(
            "s3", client, SimpleNamespace(dry_run=dry_run, expected_account=ACCOUNT_ID)
        ).get_bucket_policy
        for dry_run in (True, False)
    ]
    client.meta.service_model._service_description["operations"]["GetBucketPolicy"][
        "http"
    ]["method"] = "DELETE"
    with pytest.raises(framework.SafetyViolation, match="reviewed package"):
        assert callable(proxy.get_bucket_policy)

    # The same dispatch guard runs for plan and live owners before Botocore
    # prepares a request, including a retained callable.
    for saved in saved_modes:
        prepared = []
        client.meta.events.register(
            "before-parameter-build.s3.GetBucketPolicy",
            lambda prepared=prepared, **kwargs: prepared.append(kwargs),
        )
        with pytest.raises(framework.SafetyViolation, match="reviewed package"):
            saved(Bucket="offline-bucket")
        assert prepared == []


def test_customer_model_directory_and_loader_swap_are_refused(monkeypatch, tmp_path):
    clear_proxy_environment(monkeypatch)
    data = json.loads(
        json.dumps(
            framework._new_bundled_loader().load_service_model("s3", "service-2")
        )
    )
    data["operations"]["GetBucketPolicy"]["http"]["method"] = "DELETE"
    model_path = tmp_path / ".aws/models/s3/2006-03-01/service-2.json"
    model_path.parent.mkdir(parents=True)
    model_path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.delenv("AWS_DATA_PATH", raising=False)
    original = synthetic_session()
    customer_loader = original._session.get_component("data_loader")
    customer_loader.search_paths.insert(0, str(tmp_path / ".aws/models"))
    assert (
        customer_loader.load_service_model("s3", "service-2")["operations"][
            "GetBucketPolicy"
        ]["http"]["method"]
        == "DELETE"
    )
    session = framework.harden_session_origin(original)
    client = framework.origin_bound_client(session, "s3", REGION, Config())
    assert (
        client.meta.service_model.operation_model("GetBucketPolicy").http["method"]
        == "GET"
    )
    session._session.register_component("data_loader", framework.BotocoreLoader())
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.origin_bound_client(session, "s3", REGION, Config())


def test_mutated_loader_paths_and_cache_cannot_supply_service_model(
    monkeypatch, tmp_path
):
    clear_proxy_environment(monkeypatch)
    session = framework.harden_session_origin(synthetic_session())
    loader = session._session.get_component("data_loader")
    loader.search_paths.append(str(tmp_path))
    with pytest.raises(framework.SafetyViolation, match="origin-hardened"):
        framework.origin_bound_client(session, "s3", REGION, Config())

    session = framework.harden_session_origin(synthetic_session())
    loader = session._session.get_component("data_loader")
    loader.load_service_model("s3", "service-2")["operations"]["GetBucketPolicy"][
        "http"
    ]["method"] = "DELETE"
    client = framework.origin_bound_client(session, "s3", REGION, Config())
    assert (
        client.meta.service_model.operation_model("GetBucketPolicy").http["method"]
        == "GET"
    )


def test_saved_read_and_paginator_recheck_model_at_dispatch(monkeypatch):
    clear_proxy_environment(monkeypatch)
    session = framework.harden_session_origin(synthetic_session())
    client = framework.origin_bound_client(session, "ec2", REGION, Config())
    proxy = framework.AwsClientProxy("ec2", client, None)
    saved = proxy.describe_instances
    paginator = proxy.get_paginator("describe_instances")
    client.meta.service_model._service_description["operations"]["DescribeInstances"][
        "http"
    ]["method"] = "DELETE"
    with pytest.raises(framework.SafetyViolation, match="reviewed package"):
        saved()
    with pytest.raises(framework.SafetyViolation, match="reviewed package"):
        next(paginator.paginate())


@pytest.mark.parametrize("field", ["name", "wire_name"])
def test_retained_read_refuses_changed_operation_dispatch_name(monkeypatch, field):
    clear_proxy_environment(monkeypatch)
    session = framework.harden_session_origin(synthetic_session())
    client = framework.origin_bound_client(session, "ec2", REGION, Config())
    saved = framework.AwsClientProxy("ec2", client, None).describe_instances
    operation = client.meta.service_model.operation_model("DescribeInstances")
    if field == "name":
        operation.name = "TerminateInstances"
    else:
        operation._operation_model["name"] = "TerminateInstances"
    with pytest.raises(framework.SafetyViolation, match="operation name"):
        saved()


def test_paginator_rechecks_operation_before_each_page(monkeypatch):
    clear_proxy_environment(monkeypatch)
    session = framework.harden_session_origin(synthetic_session())
    client = framework.origin_bound_client(session, "ec2", REGION, Config())
    paginator = framework.AwsClientProxy("ec2", client, None).get_paginator(
        "describe_instances"
    )
    with Stubber(client) as stub:
        stub.add_response(
            "describe_instances", {"Reservations": [], "NextToken": "next"}, {}
        )
        pages = paginator.paginate()
        assert next(pages)["NextToken"] == "next"
        client.meta.service_model.operation_model(
            "DescribeInstances"
        ).name = "TerminateInstances"
        with pytest.raises(framework.SafetyViolation, match="operation name"):
            next(pages)
        stub.assert_no_pending_responses()


def test_every_reviewed_read_matches_locked_packaged_wire_manifest():
    loader = framework._new_bundled_loader()
    assert {
        service: set(names)
        for service, names in framework.READ_ONLY_WIRE_MANIFEST.items()
    } == {
        service: set(names) for service, names in framework.READ_ONLY_OPERATIONS.items()
    }
    for service, names in framework.READ_ONLY_OPERATIONS.items():
        model = ServiceModel(loader.load_service_model(service, "service-2"), service)
        operations = {xform_name(api): api for api in model.operation_names}
        for name in names:
            api = operations[name]
            op = model.operation_model(api)
            assert op.name == api
            assert op.wire_name == (
                "GetDistributionConfig2020_05_31"
                if service == "cloudfront" and name == "get_distribution_config"
                else api
            )
            assert framework.READ_ONLY_WIRE_MANIFEST[service][name] == (
                api,
                op.http["method"],
                op.http["requestUri"],
                model.metadata.get("protocol"),
                model.metadata.get("signatureVersion"),
                model.metadata.get("endpointPrefix"),
                model.resolved_protocol,
                model.signing_name,
                model.metadata.get("targetPrefix"),
            )


@pytest.mark.parametrize("principal_field", ["GranteePrincipal", "RetiringPrincipal"])
@pytest.mark.parametrize("form", ["iam", "sts"])
def test_kms_grant_refuses_protected_operator_principal(principal_field, form):
    kind = framework.ChaosType.KMS_GRANT_REVOKE
    values = dict(action_configs()[kind])
    protected = BREAK_GLASS_ARN
    if form == "sts":
        protected = f"arn:aws-us-gov:sts::{ACCOUNT_ID}:assumed-role/{BREAK_GLASS_ARN.rsplit('/', 1)[-1]}/offline"
    config_key = (
        "grantee_principal_arn"
        if principal_field == "GranteePrincipal"
        else "retiring_principal_arn"
    )
    values[config_key] = protected
    item = native_target_experiment(kind, values)
    result = item.revoke_grant(**values)
    assert result.status == "failed" and "protected principal" in result.errors[0]
    assert not item.mutation_attempts


@pytest.mark.parametrize("principal_field", ["GranteePrincipal", "RetiringPrincipal"])
@pytest.mark.parametrize("form", ["iam", "sts"])
def test_kms_grant_refuses_protected_principal_in_returned_grant(principal_field, form):
    kind = framework.ChaosType.KMS_GRANT_REVOKE
    values = dict(action_configs()[kind])
    values["operator_principal_arn"] = BREAK_GLASS_ARN
    item = native_target_experiment(kind, values)
    protected = BREAK_GLASS_ARN
    if form == "sts":
        protected = (
            f"arn:aws-us-gov:sts::{ACCOUNT_ID}:assumed-role/"
            f"{BREAK_GLASS_ARN.rsplit('/', 1)[-1]}/offline"
        )
    returned = {
        "KeyId": values["key_id"],
        "GrantId": values["grant_id"],
        "GranteePrincipal": values["grantee_principal_arn"],
        "RetiringPrincipal": values["retiring_principal_arn"],
    }
    returned[principal_field] = protected
    with Stubber(item.kms._client) as stub:
        stub.add_response(
            "list_grants",
            {"Grants": [returned]},
            {"KeyId": values["key_id"], "GrantId": values["grant_id"]},
        )
        result = item.revoke_grant(
            **{
                key: values[key]
                for key in (
                    "key_id",
                    "grant_id",
                    "grantee_principal_arn",
                    "retiring_principal_arn",
                )
            }
        )
        assert result.status == "failed"
        assert "non-protected principals" in result.errors[0]
        stub.assert_no_pending_responses()
    assert not item.mutation_attempts


def test_kms_grant_preserves_configured_recovery_identity():
    kind = framework.ChaosType.KMS_GRANT_REVOKE
    values = dict(action_configs()[kind])
    values["recovery_principal_arn"] = values["grantee_principal_arn"]
    item = native_target_experiment(kind, values)
    result = item.revoke_grant(
        values["key_id"],
        values["grant_id"],
        values["grantee_principal_arn"],
        values["retiring_principal_arn"],
    )
    assert result.status == "failed" and "protected principal" in result.errors[0]
    assert not item.mutation_attempts


def test_kms_global_recovery_identity_survives_experiment_null_override():
    kind = framework.ChaosType.KMS_GRANT_REVOKE
    values = dict(action_configs()[kind])
    values["recovery_principal_arn"] = None
    item = native_target_experiment(kind, values)
    item._global_grant_protected_principals = (values["grantee_principal_arn"],)
    result = item.revoke_grant(
        values["key_id"],
        values["grant_id"],
        values["grantee_principal_arn"],
        values["retiring_principal_arn"],
    )
    assert result.status == "failed" and "protected principal" in result.errors[0]
    assert not item.mutation_attempts


def test_orchestrator_preserves_global_recovery_identity_before_kms_execution():
    kind = framework.ChaosType.KMS_GRANT_REVOKE
    protected = BREAK_GLASS_ARN
    orchestrator = object.__new__(framework.ChaosOrchestrator)
    orchestrator.config = {
        "global": {"account_id": ACCOUNT_ID, "recovery_principal_arn": protected}
    }
    orchestrator.expected_account = ACCOUNT_ID
    orchestrator.region = REGION
    orchestrator.dry_run = True
    orchestrator.live = False
    orchestrator.operator_principal_arn = None
    orchestrator.active_access_key_id = None
    orchestrator._sensitive_values_lock = threading.Lock()
    orchestrator._report_sensitive_values = set()
    orchestrator._active_experiments_lock = threading.Lock()
    orchestrator.active_experiments = []
    orchestrator.safety_controller = SimpleNamespace(
        experiment_started=lambda: None, experiment_finished=lambda: None
    )
    orchestrator._prepare_experiment_config = lambda config: config
    orchestrator._target_values = lambda config: []
    orchestrator._validate_target_scope = lambda experiment_type, config: None
    orchestrator._blast_radius = lambda experiment_type, config: 1
    experiment = SimpleNamespace(
        mutation_operations=[],
        mutation_attempts=[],
        rollback_operations=[],
        rollback_attempts=[],
        rollback_errors=[],
    )
    orchestrator._create_experiment = lambda experiment_type, config: experiment
    observed = []

    def execute(item, experiment_type, config):
        observed.append(
            (item._global_grant_protected_principals, config["recovery_principal_arn"])
        )
        result = framework.ExperimentResult(
            experiment_id="offline-kms",
            experiment_type=experiment_type,
            start_time=framework.utc_now(),
        )
        result.status = "failed"
        return result

    orchestrator._execute_experiment = execute
    result = orchestrator._run_single_experiment_locked(
        {"type": kind.value, "recovery_principal_arn": None}
    )
    assert result.status == "failed"
    assert observed == [((protected,), None)]


def test_kms_grant_execution_cannot_change_approved_principal():
    kind = framework.ChaosType.KMS_GRANT_REVOKE
    values = dict(action_configs()[kind])
    item = native_target_experiment(kind, values)
    changed = dict(values)
    changed["grantee_principal_arn"] = f"arn:aws-us-gov:iam::{ACCOUNT_ID}:role/Other"
    result = item.revoke_grant(**changed)
    assert result.status == "failed"
    assert "differ from the immutable approved request" in result.errors[0]
    assert not item.mutation_attempts


@pytest.mark.parametrize(
    "field,value",
    [
        ("GranteePrincipal", None),
        ("RetiringPrincipal", None),
        ("GranteePrincipal", "not-an-arn"),
        ("RetiringPrincipal", "not-an-arn"),
    ],
)
def test_kms_grant_refuses_missing_or_malformed_returned_principal(field, value):
    kind = framework.ChaosType.KMS_GRANT_REVOKE
    values = dict(action_configs()[kind])
    item = native_target_experiment(kind, values)
    grant = {
        "GrantId": values["grant_id"],
        "KeyId": values["key_id"],
        "GranteePrincipal": values["grantee_principal_arn"],
        "RetiringPrincipal": values["retiring_principal_arn"],
    }
    if value is None:
        del grant[field]
    else:
        grant[field] = value
    with Stubber(item.kms._client) as stub:
        stub.add_response(
            "list_grants",
            {"Grants": [grant]},
            {"KeyId": values["key_id"], "GrantId": values["grant_id"]},
        )
        result = item.revoke_grant(**values)
        stub.assert_no_pending_responses()
    assert result.status == "failed"
    assert not item.mutation_attempts
