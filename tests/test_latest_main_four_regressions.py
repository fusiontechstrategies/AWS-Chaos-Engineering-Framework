"""Offline adversarial closure for the four validated 27f6421 findings."""

import copy
import io
import shutil
import subprocess
import sys
import tarfile
import threading
from pathlib import Path
from types import SimpleNamespace

import boto3
import botocore.session
import pytest
from botocore.stub import Stubber
from test_aws_chaos_framework import ACCOUNT_ID, INSTANCE_ID, REGION, FakeAWS

import aws_chaos_framework as f
from scripts import normalize_sdist
from scripts import verify_distribution as verifier

ROOT = Path(__file__).resolve().parents[1]
BUCKET = ACCOUNT_ID + "private-bucket"
PREFIX = "chaos-test/"


def native_controller(aws=None):
    aws = aws or FakeAWS(reject_writes=False)
    session = SimpleNamespace(client=lambda service, **_kwargs: aws.client(service))
    controller = f.SafetyController(
        {}, session, REGION, True, expected_account=ACCOUNT_ID
    )
    controller.check_safety_conditions = lambda: (True, [])
    return controller, aws


def live_ec2():
    controller, aws = native_controller()
    owner = f.EC2ChaosExperiment(
        {"account_id": ACCOUNT_ID, "region": REGION, "dry_run": False}, controller
    )
    return owner, controller, aws


@pytest.mark.parametrize("account", [None, "", ACCOUNT_ID])
@pytest.mark.parametrize("operation", sorted(f.S3_OWNER_BOUND_OPERATIONS))
def test_ownerless_controller_s3_bucket_reads_and_writes_refuse(account, operation):
    controller, aws = native_controller()
    controller.expected_account = account
    with pytest.raises(f.SafetyViolation, match="require an experiment owner"):
        getattr(controller.client("s3"), operation)(Bucket=BUCKET)
    assert not aws.calls


@pytest.mark.parametrize("stopped", [False, True])
def test_ownerless_controller_mutation_refuses_before_and_after_latch(stopped):
    controller, aws = native_controller()
    if stopped:
        controller.emergency_stop_all()
        assert controller.emergency_stop.is_set()
    with pytest.raises(f.SafetyViolation, match="require an experiment owner"):
        controller.client("ec2").reboot_instances(InstanceIds=[INSTANCE_ID])
    assert not aws.calls


def test_ownerless_controller_safety_identity_reads_remain_usable_after_stop():
    controller, aws = native_controller()
    aws.read_overrides[("sts", "get_caller_identity")] = [{"Account": ACCOUNT_ID}]
    aws.read_overrides[("guardduty", "list_detectors")] = [{"DetectorIds": ["offline"]}]
    aws.read_overrides[("securityhub", "get_findings")] = [{"Findings": []}]
    controller.emergency_stop_all()
    assert controller.client("sts").get_caller_identity()["Account"] == ACCOUNT_ID
    assert controller.client("cloudwatch").describe_alarms()["MetricAlarms"]
    assert controller.client("guardduty").list_detectors()["DetectorIds"]
    assert controller.client("securityhub").get_findings()["Findings"] == []
    assert all(call[1].startswith(f.READ_ONLY_OPERATION_PREFIXES) for call in aws.calls)


@pytest.mark.parametrize(
    "service,operation", [("ec2", "reboot_instances"), ("s3", "delete_objects")]
)
@pytest.mark.parametrize("rollback", [False, True])
def test_plan_owner_cannot_dispatch_direct_mutation_even_as_recovery(
    service, operation, rollback
):
    controller, aws = native_controller()
    owner = f.ChaosExperiment({"dry_run": True}, controller)
    owner._in_rollback = rollback
    request = {"Bucket": BUCKET} if service == "s3" else {"InstanceIds": [INSTANCE_ID]}
    with pytest.raises(f.SafetyViolation, match="Plan mode refuses"):
        getattr(controller.client(service, owner), operation)(**request)
    assert not aws.calls
    assert not owner.mutation_attempts


@pytest.mark.parametrize("owned", [False, True])
@pytest.mark.parametrize(
    "operation,arguments",
    [
        ("get_paginator", ["list_objects_v2"]),
        ("get_waiter", ["bucket_exists"]),
        ("generate_presigned_url", ["get_object"]),
        ("generate_presigned_post", [BUCKET, "key"]),
        ("head_bucket", []),
        ("get_object", []),
        ("list_objects", []),
    ],
)
def test_raw_s3_delegates_and_unreviewed_bucket_methods_refuse(
    owned, operation, arguments
):
    raw = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
    )
    controller = f.SafetyController(
        {},
        SimpleNamespace(client=lambda *args, **kwargs: raw),
        REGION,
        True,
        expected_account=ACCOUNT_ID,
    )
    owner = f.ChaosExperiment({"dry_run": False}, controller) if owned else None
    with Stubber(raw) as stub:
        # No response is authorized. Any leaked delegate/call must fail this guard
        # before it can obtain an unwrapped operation or reach the SDK endpoint.
        with pytest.raises(f.SafetyViolation, match="only reviewed owner-bound"):
            getattr(controller.client("s3", owner), operation)(*arguments)
        stub.assert_no_pending_responses()


def test_ec2_readonly_approval_inventory_paginator_remains_supported():
    raw = boto3.client(
        "ec2",
        region_name=REGION,
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
    )
    controller = f.SafetyController(
        {},
        SimpleNamespace(client=lambda *args, **kwargs: raw),
        REGION,
        True,
        expected_account=ACCOUNT_ID,
    )
    with Stubber(raw) as stub:
        stub.add_response("describe_instances", {"Reservations": []}, {})
        assert list(
            controller.client("ec2").get_paginator("describe_instances").paginate()
        ) == [{"Reservations": []}]
        stub.assert_no_pending_responses()


def invoke_thread(action, errors):
    def invoke():
        try:
            action()
        except Exception as error:  # Keep assertion failures visible in the main test.
            errors.append(error)

    worker = threading.Thread(target=invoke, daemon=True)
    worker.start()
    return worker


def test_stop_requested_after_admission_blocks_dispatch_and_latches_on_exit():
    owner, controller, aws = live_ec2()
    errors = []
    workers = []
    record = owner._record_mutation_attempt

    def stop_during_record(operation):
        record(operation)
        workers.append(invoke_thread(controller.emergency_stop_all, errors))
        assert controller.emergency_stop.wait(3)
        # The request is immediate; stop activation waits for this admitted call.
        assert not controller.emergency_stop.is_set()

    owner._record_mutation_attempt = stop_during_record
    with pytest.raises(f.EmergencyStop, match="admitted SDK dispatch"):
        owner.ec2.reboot_instances(InstanceIds=[INSTANCE_ID])
    for worker in workers:
        worker.join(3)
        assert not worker.is_alive()
    assert not errors
    assert controller.emergency_stop.is_set()
    assert not any(name == "reboot_instances" for _, name, _ in aws.calls)
    assert owner.mutation_attempts == ["ec2.reboot_instances"]
    assert not owner.mutation_operations


def test_same_thread_signal_request_is_deferred_without_dispatch_or_deadlock():
    owner, controller, aws = live_ec2()
    orchestrator = object.__new__(f.ChaosOrchestrator)
    orchestrator.safety_controller = controller
    record = owner._record_mutation_attempt

    def signal_during_record(operation):
        record(operation)
        orchestrator._signal_handler(f.signal.SIGTERM, None)
        assert controller.emergency_stop.stop_requested()
        assert not controller.emergency_stop.is_set()

    owner._record_mutation_attempt = signal_during_record
    with pytest.raises(f.EmergencyStop):
        owner.ec2.reboot_instances(InstanceIds=[INSTANCE_ID])
    assert controller.emergency_stop.is_set()
    assert not any(name == "reboot_instances" for _, name, _ in aws.calls)


def test_stop_waits_for_accepted_sdk_call_and_blocks_later_calls_but_not_recovery():
    owner, controller, _ = live_ec2()
    entered = threading.Event()
    release = threading.Event()
    starts = []
    errors = []

    def admitted_call(**_kwargs):
        starts.append(controller.emergency_stop.is_set())
        entered.set()
        assert release.wait(3)
        return {}

    owner.ec2 = f.AwsClientProxy(
        "ec2",
        SimpleNamespace(reboot_instances=admitted_call, start_instances=lambda **_: {}),
        owner,
    )
    worker = invoke_thread(
        lambda: owner.ec2.reboot_instances(InstanceIds=[INSTANCE_ID]), errors
    )
    assert entered.wait(3)
    stopper = invoke_thread(controller.emergency_stop_all, errors)
    try:
        assert controller.emergency_stop.wait(3)
        assert not controller.emergency_stop.is_set()
        assert stopper.is_alive()
    finally:
        release.set()
        worker.join(3)
        stopper.join(3)
    assert not worker.is_alive() and not stopper.is_alive() and not errors
    assert starts == [False]
    assert controller.emergency_stop.is_set()
    with pytest.raises(f.EmergencyStop):
        owner.ec2.reboot_instances(InstanceIds=[INSTANCE_ID])
    owner._in_rollback = True
    owner.ec2.start_instances(InstanceIds=[INSTANCE_ID])
    assert owner.rollback_operations == ["ec2.start_instances"]


def test_reentrant_stop_inside_already_started_sdk_call_latches_after_return():
    owner, controller, _ = live_ec2()
    states = []

    def admitted_call(**_kwargs):
        states.append(controller.emergency_stop.is_set())
        controller.emergency_stop_all()
        states.append(controller.emergency_stop.is_set())
        return {}

    proxy = f.AwsClientProxy(
        "ec2", SimpleNamespace(reboot_instances=admitted_call), owner
    )
    proxy.reboot_instances(InstanceIds=[INSTANCE_ID])
    assert states == [False, False]
    assert controller.emergency_stop.is_set()
    assert owner.mutation_operations == ["ec2.reboot_instances"]
    with pytest.raises(f.EmergencyStop):
        proxy.reboot_instances(InstanceIds=[INSTANCE_ID])


def test_stop_dispatch_stress_has_no_sdk_start_after_latch(monkeypatch):
    for _ in range(40):
        monkeypatch.setattr(f, "_PROCESS_EMERGENCY_STOP", f.EmergencyStopLatch())
        owner, controller, _ = live_ec2()
        ready = threading.Barrier(3)
        states = []
        errors = []

        def raw_call(states=states, controller=controller, **_kwargs):
            states.append(controller.emergency_stop.is_set())
            return {}

        proxy = f.AwsClientProxy(
            "ec2", SimpleNamespace(reboot_instances=raw_call), owner
        )

        def dispatch(ready=ready, proxy=proxy):
            ready.wait(3)
            proxy.reboot_instances(InstanceIds=[INSTANCE_ID])

        def stop(ready=ready, controller=controller):
            ready.wait(3)
            controller.emergency_stop_all()

        workers = [invoke_thread(dispatch, errors), invoke_thread(stop, errors)]
        ready.wait(3)
        for worker in workers:
            worker.join(3)
            assert not worker.is_alive()
        assert all(isinstance(error, f.EmergencyStop) for error in errors)
        assert not any(states)
        assert controller.emergency_stop.is_set()
        with pytest.raises(f.EmergencyStop):
            proxy.reboot_instances(InstanceIds=[INSTANCE_ID])


@pytest.mark.parametrize("operation", sorted(f.S3_OWNER_BOUND_OPERATIONS))
def test_all_s3_bucket_reads_writes_and_verifications_bind_captured_owner(operation):
    calls = []
    client = SimpleNamespace(**{operation: lambda **kwargs: calls.append(kwargs) or {}})
    controller, _ = native_controller()
    owner = f.ChaosExperiment({"account_id": ACCOUNT_ID, "dry_run": False}, controller)
    # An unrelated later mapping edit cannot replace the authenticated account.
    owner.config["account_id"] = "999999999999"
    proxy = f.AwsClientProxy("s3", client, owner)
    getattr(proxy, operation)(Bucket=BUCKET)
    assert calls == [{"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT_ID}]
    model = botocore.session.get_session().get_service_model("s3")
    api = next(
        name for name in model.operation_names if botocore.xform_name(name) == operation
    )
    assert "ExpectedBucketOwner" in model.operation_model(api).input_shape.members


@pytest.mark.parametrize("owner_value", [None, "", "123", 123456789012])
def test_s3_without_valid_reviewed_owner_fails_before_read(owner_value):
    calls = []
    controller, _ = native_controller()
    controller.expected_account = owner_value
    owner = f.ChaosExperiment({"dry_run": True}, controller)
    proxy = f.AwsClientProxy(
        "s3",
        SimpleNamespace(list_objects_v2=lambda **kwargs: calls.append(kwargs)),
        owner,
    )
    with pytest.raises(f.SafetyViolation, match="reviewed twelve-digit"):
        proxy.list_objects_v2(Bucket=BUCKET)
    assert not calls


def test_s3_caller_cannot_override_captured_expected_owner():
    calls = []
    controller, _ = native_controller()
    owner = f.ChaosExperiment({"dry_run": True}, controller)
    proxy = f.AwsClientProxy(
        "s3",
        SimpleNamespace(list_objects_v2=lambda **kwargs: calls.append(kwargs)),
        owner,
    )
    with pytest.raises(f.SafetyViolation, match="differs from the reviewed"):
        proxy.list_objects_v2(Bucket=BUCKET, ExpectedBucketOwner="999999999999")
    assert not calls
    proxy.list_objects_v2(Bucket=BUCKET, ExpectedBucketOwner=ACCOUNT_ID)
    assert calls == [{"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT_ID}]


def test_experiment_account_override_is_refused_and_owner_changes_confirmation():
    controller, _ = native_controller()
    orchestrator = object.__new__(f.ChaosOrchestrator)
    orchestrator.config = {"global": {"account_id": ACCOUNT_ID, "region": REGION}}
    orchestrator.expected_account = ACCOUNT_ID
    orchestrator.safety_controller = controller
    with pytest.raises(f.SafetyViolation, match="cannot override"):
        orchestrator._create_experiment(
            f.ChaosType.S3_OBJECT_DELETE, {"account_id": "999999999999"}
        )
    with pytest.raises(f.SafetyViolation, match="cannot override"):
        orchestrator._run_single_experiment_locked(
            {"type": "s3_object_delete", "account_id": "999999999999"}
        )
    config = {
        "schema_version": 1,
        "global": {"account_id": ACCOUNT_ID, "region": REGION},
        "safety": {"target_allowlist": [], "fail_closed": True},
        "experiment_suites": {
            "test": {
                "experiments": [
                    {
                        "type": f.ChaosType.EC2_REBOOT.value,
                        "instance_ids": [INSTANCE_ID],
                    }
                ]
            }
        },
    }
    other = copy.deepcopy(config)
    other["global"]["account_id"] = "999999999999"
    assert f.confirmation_token(config, "test") != f.confirmation_token(other, "test")


@pytest.mark.parametrize("failure", [None, "list", "delete"])
def test_real_botocore_owner_mismatch_refuses_delete_and_valid_owner_succeeds(failure):
    client = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
    )
    controller = f.SafetyController(
        {},
        SimpleNamespace(client=lambda *args, **kwargs: client),
        REGION,
        True,
        expected_account=ACCOUNT_ID,
    )
    controller.check_safety_conditions = lambda: (True, [])
    owner = f.S3ChaosExperiment({"dry_run": False}, controller)
    read = {
        "Bucket": BUCKET,
        "Prefix": PREFIX,
        "MaxKeys": 1,
        "ExpectedBucketOwner": ACCOUNT_ID,
    }
    delete = {
        "Bucket": BUCKET,
        "Delete": {"Objects": [{"Key": PREFIX + "object"}]},
        "ExpectedBucketOwner": ACCOUNT_ID,
    }
    with Stubber(client) as stub:
        if failure == "list":
            stub.add_client_error(
                "list_objects_v2",
                service_error_code="AccessDenied",
                service_message="Owner mismatch",
                http_status_code=403,
                expected_params=read,
            )
        else:
            stub.add_response(
                "list_objects_v2", {"Contents": [{"Key": PREFIX + "object"}]}, read
            )
            if failure == "delete":
                stub.add_client_error(
                    "delete_objects",
                    service_error_code="AccessDenied",
                    service_message="Owner mismatch",
                    http_status_code=403,
                    expected_params=delete,
                )
            else:
                stub.add_response(
                    "delete_objects", {"Deleted": [{"Key": PREFIX + "object"}]}, delete
                )
        result = owner.delete_objects(BUCKET, PREFIX, 1)
        stub.assert_no_pending_responses()
    assert result.status == ("completed" if failure is None else "failed")
    assert owner.mutation_attempts == (
        [] if failure == "list" else ["s3.delete_objects"]
    )
    assert owner.mutation_operations == (
        ["s3.delete_objects"] if failure is None else []
    )


@pytest.mark.parametrize(
    "value",
    [
        BUCKET,
        "AKIA" + "A" * 16 + "-private-target",
        "arn:aws-us-gov:s3:::" + BUCKET,
        "[RESOURCE]",
        "key",
        "123456789012",
    ],
)
def test_registered_complete_targets_win_over_shorter_generic_prefixes(value):
    with f.sensitive_log_scope([value]):
        assert f.redact_runtime_text(value) == "[RESOURCE]"
        assert (
            f.redact_runtime_text("target=" + value + "; done")
            == "target=[RESOURCE]; done"
        )


def test_longest_target_and_longer_generic_arn_both_mask_complete_values():
    value = ACCOUNT_ID + "private-bucket"
    assert f.redact_runtime_text(value, [ACCOUNT_ID, value]) == "[RESOURCE]"
    parent = "arn:aws-us-gov:s3:::" + value
    # Giving exact values precedence must not expose a longer unregistered ARN.
    assert f.redact_runtime_text(parent + "/private-object", [parent]) == "[ARN]"
    assert f.redact_runtime_text(ACCOUNT_ID, []) == "[ACCOUNT]"
    assert f.redact_runtime_text("AKIA" + "A" * 16, []) == "[ACCESS_KEY]"
    assert f.redact_runtime_text(parent, []) == "[ARN]"


@pytest.fixture(scope="module")
def approved_sdist(tmp_path_factory):
    output = tmp_path_factory.mktemp("approved-main-four-distribution")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )  # noqa: S603
    sdist = next(output.glob("*.tar.gz"))
    normalize_sdist.normalize_sdist(sdist, 315532800)
    verifier._verify_sdist(sdist, ROOT)
    return sdist


def rewrite_sdist(
    original,
    destination,
    replacements=None,
    additions=None,
    deleted=None,
    metadata=None,
):
    replacements, additions, deleted = (
        replacements or {},
        additions or {},
        deleted or set(),
    )
    with (
        tarfile.open(original, "r:gz") as source,
        tarfile.open(destination, "w:gz") as target,
    ):
        root = source.getmembers()[0].name
        for member in source.getmembers():
            relative = member.name.removeprefix(root + "/")
            if relative in deleted:
                continue
            changed = copy.copy(member)
            data = source.extractfile(member).read() if member.isfile() else None
            if relative in replacements:
                data = replacements[relative]
                changed.size = len(data)
            if metadata and relative == metadata[0]:
                changed.mode = metadata[1]
            target.addfile(changed, io.BytesIO(data) if data is not None else None)
        for name, data in additions.items():
            member = tarfile.TarInfo(root + "/" + name)
            member.mode = 0o644
            member.size = len(data)
            target.addfile(member, io.BytesIO(data))


@pytest.mark.parametrize(
    "attack",
    [
        "backend",
        "backend_path",
        "build_requirement",
        "cmdclass",
        "dynamic",
        "setup_py",
        "manifest_helper",
    ],
)
def test_tag_controlled_backend_and_matching_hook_bytes_are_rejected(
    approved_sdist, tmp_path, attack
):
    source = tmp_path / "selected-source"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git", "build", "dist", "__pycache__", "*.egg-info"
        ),
    )
    project = (source / "pyproject.toml").read_text(encoding="utf-8")
    replacements, additions = {}, {}
    if attack == "backend":
        project = project.replace(
            'build-backend = "setuptools.build_meta"',
            'build-backend = "scripts.custom_backend"',
        )
    elif attack == "backend_path":
        project = project.replace(
            "[build-system]", '[build-system]\nbackend-path = ["."]'
        )
    elif attack == "build_requirement":
        project = project.replace('"setuptools==84.0.0"', '"unreviewed-backend==1.0.0"')
    elif attack == "cmdclass":
        project += (
            '\n[tool.setuptools.cmdclass]\nbuild_py = "scripts.custom_backend.Build"\n'
        )
    elif attack == "dynamic":
        project = project.replace('version = "2.0.4"', 'dynamic = ["version"]')
        project += '\n[tool.setuptools.dynamic]\nversion = {attr = "scripts.custom_backend.version"}\n'
    elif attack == "setup_py":
        additions["setup.py"] = (
            b"raise AssertionError('legacy hook must never execute')\n"
        )
        (source / "setup.py").write_bytes(additions["setup.py"])
    elif attack == "manifest_helper":
        manifest = (
            source / "MANIFEST.in"
        ).read_bytes() + b"\ninclude scripts/custom_backend.py\n"
        (source / "MANIFEST.in").write_bytes(manifest)
        replacements["MANIFEST.in"] = manifest
    if attack in {"backend", "backend_path", "cmdclass", "dynamic", "manifest_helper"}:
        additions["scripts/custom_backend.py"] = (
            b"raise AssertionError('custom backend must never execute')\n"
        )
        (source / "scripts/custom_backend.py").write_bytes(
            additions["scripts/custom_backend.py"]
        )
    (source / "pyproject.toml").write_text(project, encoding="utf-8")
    replacements["pyproject.toml"] = (source / "pyproject.toml").read_bytes()
    altered = tmp_path / approved_sdist.name
    rewrite_sdist(approved_sdist, altered, replacements, additions)
    with pytest.raises(ValueError, match="unreviewed|trusted packaging policy"):
        verifier._verify_sdist(altered, source)


def test_recursive_manifest_cannot_authorize_new_matching_python_helper(
    approved_sdist, tmp_path
):
    source = tmp_path / "selected-source"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git", "build", "dist", "__pycache__", "*.egg-info"
        ),
    )
    payload = b"raise AssertionError('not a trusted executable source member')\n"
    (source / "scripts/custom_backend.py").write_bytes(payload)
    altered = tmp_path / approved_sdist.name
    rewrite_sdist(
        approved_sdist, altered, additions={"scripts/custom_backend.py": payload}
    )
    with pytest.raises(ValueError, match="unreviewed file"):
        verifier._verify_sdist(altered, source)


@pytest.mark.parametrize(
    "attack",
    [
        "sources",
        "requires",
        "pkg_info",
        "entry_points",
        "setup_cfg",
        "missing",
        "executable_mode",
    ],
)
def test_generated_sdist_metadata_never_authorizes_new_members_or_hooks(
    approved_sdist, tmp_path, attack
):
    altered = tmp_path / approved_sdist.name
    replacements, deleted, metadata = {}, None, None
    egg = verifier.EGG_INFO
    if attack == "sources":
        replacements[egg + "SOURCES.txt"] = b"scripts/custom_backend.py\n"
    elif attack == "requires":
        replacements[egg + "requires.txt"] = b"unreviewed-backend==1.0.0\n"
    elif attack == "pkg_info":
        with tarfile.open(approved_sdist) as archive:
            member = next(
                item for item in archive if item.name.endswith(egg + "PKG-INFO")
            )
            value = archive.extractfile(member).read()
        replacements[egg + "PKG-INFO"] = value.replace(
            b"Requires-Dist: boto3==1.43.102",
            b"Requires-Dist: unreviewed-backend==1.0.0",
        )
    elif attack == "entry_points":
        replacements[egg + "entry_points.txt"] = (
            b"[console_scripts]\nextra = scripts.custom_backend:main\n"
        )
    elif attack == "setup_cfg":
        replacements["setup.cfg"] = (
            b"[egg_info]\ntag_build = \ntag_date = 0\n[build_py]\nforce = 1\n"
        )
    elif attack == "missing":
        deleted = {egg + "requires.txt"}
    else:
        metadata = (
            f.MODULE_NAME if hasattr(f, "MODULE_NAME") else "aws_chaos_framework.py",
            0o755,
        )
    rewrite_sdist(
        approved_sdist, altered, replacements, deleted=deleted, metadata=metadata
    )
    with pytest.raises(ValueError, match="metadata|canonical|mode"):
        verifier._verify_sdist(altered, ROOT)


def test_approved_static_sdist_builds_verify_without_importing_selected_helpers(
    approved_sdist,
):
    verifier._verify_sdist(approved_sdist, ROOT)
    assert verifier._approved_project(ROOT)["version"] == "2.0.4"
