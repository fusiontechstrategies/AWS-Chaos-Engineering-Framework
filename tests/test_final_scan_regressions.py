"""Offline adversarial regressions for the seven exact-main scan follow-ups."""

import copy
import hashlib
import json
import logging
import re
import shlex
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from test_aws_chaos_framework import (
    ACCOUNT_ID,
    BREAK_GLASS_ARN,
    OTHER_ACCESS_KEY,
    REGION,
    FakeAWS,
    action_configs,
    make_experiment,
    make_orchestrator,
    planning_only_experiment,
)

import aws_chaos_framework as framework
from scripts import publish_payload

ROOT = Path(__file__).resolve().parents[1]


def worker(aws, kind=framework.ChaosType.LAMBDA_MEMORY_LIMIT, values=None):
    values = values or action_configs()[kind]
    return make_orchestrator(kind, values, aws, dry_run=False)


# S3 lifecycle expiration is planning only (no conditional lifecycle revision),
# as are RDS backup retention (ApplyImmediately can activate changes queued by
# others) and Kinesis retention (name-only, no generation). KMS grant revocation
# is an irreversible change that keeps live support and the same dual approval.
@pytest.mark.parametrize("kind", ["kms_grant_revoke"])
@pytest.mark.parametrize(
    "cli,configuration", [(False, False), (True, False), (False, True), (True, True)]
)
def test_destructive_retention_requires_both_approvals_and_stronger_token(
    kind, cli, configuration
):
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    config["safety"]["allow_irreversible"] = configuration
    config["safety"]["safety_alarms"] = ["synthetic-alarm"]
    suite = next(iter(config["experiment_suites"]))
    values = {"type": kind, **action_configs()[framework.ChaosType(kind)]}
    config["experiment_suites"][suite]["experiments"] = [values]
    metadata = framework.experiment_metadata(framework.ChaosType(kind))
    assert metadata.risk == framework.RiskLevel.IRREVERSIBLE
    assert metadata.rollback == "none"
    config["safety"]["target_allowlist"] = sorted(
        framework.ChaosOrchestrator._target_values(values)
    )
    config["safety"]["max_blast_radius"] = framework.ChaosOrchestrator._blast_radius(
        framework.ChaosType(kind), values
    )
    token = framework.confirmation_token(config, suite)
    assert token.startswith("LIVE-IRREVERSIBLE:")
    item = worker(FakeAWS())
    item.config = config
    item.safety_controller.config = config["safety"]
    item.allow_irreversible = cli
    item.expected_account = ACCOUNT_ID
    item.approval_scope = {
        "profile": None,
        "role_arn": None,
        "vpc_id": None,
        "seed": None,
    }
    item.region = config["global"]["region"]
    item.vpc_id = None
    item.results = []
    item._failed_future_count = 0
    item._generate_report = lambda: None
    ran = []
    item._run_single_experiment = lambda value: (
        ran.append(value)
        or framework.ExperimentResult(
            "synthetic",
            framework.ChaosType(kind),
            framework.utc_now(),
            status="completed",
        )
    )
    item.confirmation = token.replace("LIVE-IRREVERSIBLE:", "LIVE:")
    with pytest.raises(framework.SafetyViolation):
        item.run_experiment_suite(suite)
    assert not ran
    item.confirmation = token
    if cli and configuration:
        assert item.run_experiment_suite(suite)
        assert len(ran) == 1
    else:
        with pytest.raises(framework.SafetyViolation, match="both"):
            item.run_experiment_suite(suite)
        assert not ran


@pytest.mark.parametrize("configuration", [False, True])
def test_rds_retention_receives_no_live_token_even_with_both_approvals(configuration):
    kind = framework.ChaosType.RDS_BACKUP_RETENTION_MODIFY
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["account_id"] = ACCOUNT_ID
    config["safety"]["allow_irreversible"] = configuration
    config["safety"]["safety_alarms"] = ["synthetic-alarm"]
    suite = next(iter(config["experiment_suites"]))
    values = {"type": kind.value, **action_configs()[kind]}
    config["experiment_suites"][suite]["experiments"] = [values]
    config["safety"]["target_allowlist"] = sorted(
        framework.ChaosOrchestrator._target_values(values)
    )
    assert not framework.experiment_metadata(kind).live_supported
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        framework.confirmation_token(config, suite)
    aws = FakeAWS(reject_writes=True)
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_orchestrator(kind, action_configs()[kind], aws, dry_run=False)
    assert not aws.calls


def test_s3_expiration_never_claims_recovery_of_deleted_objects():
    aws = FakeAWS(reject_writes=True)
    config = action_configs()[framework.ChaosType.S3_LIFECYCLE_MODIFY]
    item = planning_only_experiment(
        framework.ChaosType.S3_LIFECYCLE_MODIFY, config, aws
    )
    result = item.modify_lifecycle(**config)
    assert result.status == "completed"
    assert "deleted data" in result.additional_info["data_loss_warning"]
    before = list(aws.calls)
    item.run_rollback()
    assert aws.calls == before
    assert not item.rollback_verified
    assert not item.mutation_attempts and not item.rollback_attempts


def test_ec2_termination_creates_no_implicit_volume_copies():
    aws = FakeAWS(reject_writes=False)
    config = action_configs()[framework.ChaosType.EC2_TERMINATE]
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_experiment(framework.ChaosType.EC2_TERMINATE, config, aws, dry_run=False)
    assert not aws.calls
    item = make_experiment(framework.ChaosType.EC2_TERMINATE, config, aws, dry_run=True)
    item._get_instance_volumes = lambda *_: (_ for _ in ()).throw(
        AssertionError("Implicit volume expansion")
    )
    assert not item.mutation_attempts
    writes = [
        (operation, request)
        for service, operation, request in aws.calls
        if operation not in framework.READ_ONLY_OPERATIONS.get(service, ())
    ]
    assert writes == []
    plan = make_experiment(framework.ChaosType.EC2_TERMINATE, config, aws, dry_run=True)
    assert plan.terminate_instances(**config).status == "completed"
    assert not any(
        operation in {"terminate_instances", "create_snapshot"}
        for _, operation, _ in aws.calls
    )


def test_same_volume_workers_cannot_dispatch_planning_only_iops_changes():
    aws = FakeAWS(reject_writes=False)
    for value in (100, 200):
        with pytest.raises(
            framework.ConfigurationError, match="Live approval is unavailable"
        ):
            worker(
                aws,
                framework.ChaosType.EBS_THROTTLE_IOPS,
                {"volume_id": "vol-0123456789abcdef0", "iops": value},
            )

    assert not aws.calls


def synthetic_live_suite(item, experiments, delay=0):
    safety = copy.deepcopy(item.config["safety"])
    safety["target_allowlist"] = sorted(
        set().union(
            *(
                framework.ChaosOrchestrator._target_values(value)
                for value in experiments
            )
        )
    )
    safety["max_blast_radius"] = max(
        framework.ChaosOrchestrator._blast_radius(
            framework.ChaosType(value["type"]), value
        )
        for value in experiments
    )
    item.config = {
        "global": {"account_id": ACCOUNT_ID, "region": REGION},
        "safety": safety,
        "experiment_suites": {
            "synthetic": {
                "experiments": experiments,
                "max_concurrent": 3,
                "failure_policy": "continue",
                "delay_between_experiments": delay,
            }
        },
    }
    item.safety_controller.config = safety
    item.suite_name = "synthetic"
    item.results = []
    item._failed_future_count = 0
    item._generate_report = lambda: None
    item.confirmation = item.expected_confirmation("synthetic", True)


def test_failed_recovery_blocks_continue_policy_and_separate_orchestrators():
    aws = FakeAWS(reject_writes=False)
    state = aws.respond("lambda", "get_function_configuration", {})
    state["MemorySize"] = 512
    state["RevisionId"] = "initial-revision"
    original = aws.respond
    writes = []

    def model(service, operation, request):
        if service == "lambda" and operation == "get_function_configuration":
            aws.calls.append((service, operation, request))
            return copy.deepcopy(state)
        if service == "lambda" and operation == "update_function_configuration":
            aws.calls.append((service, operation, request))
            assert request["RevisionId"] == state["RevisionId"]
            value = request["MemorySize"]
            writes.append(value)
            if value == 512:
                raise RuntimeError("Synthetic recovery failed before restoration")
            state["MemorySize"] = value
            state["RevisionId"] = "updated-revision"
            # Like the service, the update returns the revision it created.
            return {"RevisionId": state["RevisionId"]}
        return original(service, operation, request)

    aws.respond = model
    configs = [
        {
            "type": "lambda_memory_limit",
            "function_name": "chaos-test-function",
            "memory_mb": value,
            "auto_rollback": True,
        }
        for value in (128, 256)
    ]
    first = worker(aws)
    synthetic_live_suite(first, configs)
    assert not first.run_experiment_suite("synthetic")
    assert writes == [128, 512]
    assert state["MemorySize"] == 128
    assert len(first.results) == 1
    assert first.results[0].rollback_successful is False
    assert first.safety_controller.emergency_stop.is_set()
    second = worker(aws)
    calls = list(aws.calls)
    assert framework._LIVE_RECOVERY_BLOCKED.is_set()
    with pytest.raises(framework.EmergencyStop, match="Process-wide emergency stop"):
        second._run_single_experiment(configs[1])
    assert aws.calls == calls
    assert not second.active_experiments


def test_disabled_live_automatic_recovery_is_rejected_before_sdk_calls():
    aws = FakeAWS(reject_writes=False)
    item = worker(aws)
    calls = list(aws.calls)
    with pytest.raises(framework.SafetyViolation, match="cannot be disabled"):
        item._run_single_experiment(
            {
                "type": "lambda_memory_limit",
                "function_name": "chaos-test-function",
                "memory_mb": 128,
                "auto_rollback": False,
            }
        )
    assert aws.calls == calls
    assert not item.active_experiments


def test_live_interexperiment_delay_starts_after_recovery_completes():
    item = worker(FakeAWS())
    configs = [
        {
            "type": "lambda_memory_limit",
            "function_name": "chaos-test-function",
            "memory_mb": value,
        }
        for value in (128, 256)
    ]
    synthetic_live_suite(item, configs, delay=7)
    trace = []

    def run(config):
        trace.append(f"recovered-{config['memory_mb']}")
        return framework.ExperimentResult(
            "synthetic",
            framework.ChaosType.LAMBDA_MEMORY_LIMIT,
            framework.utc_now(),
            status="completed",
            rollback_successful=True,
        )

    item._run_single_experiment = run
    item.safety_controller.emergency_stop.wait = lambda seconds: (
        trace.append(f"delay-{seconds}") or False
    )
    assert item.run_experiment_suite("synthetic")
    assert trace == ["recovered-128", "delay-7", "recovered-256"]


@pytest.mark.parametrize(
    "target", ["a", "ab", "abc", "test", "error", "RESOURCE", "ARN"]
)
def test_short_targets_are_exactly_redacted_without_substring_corruption(target):
    with framework.sensitive_log_scope([target]):
        record = logging.LogRecord(
            "synthetic",
            logging.ERROR,
            __file__,
            1,
            "target='%s'; testing contest terrorism",
            (target,),
            None,
        )
        text = framework.PrivacyFormatter("%(message)s").format(record)
        assert f"'{target}'" not in text
        assert "target='[RESOURCE]'" in text
        assert "testing contest terrorism" in text


@pytest.mark.parametrize("target", ["x", "test", "ARN", "RESOURCE"])
def test_formatter_redacts_bracketed_names_without_rewriting_emitted_markers(target):
    with framework.sensitive_log_scope([target]):
        record = logging.LogRecord(
            "synthetic",
            logging.ERROR,
            __file__,
            1,
            "targets=[%s] (%s); %s",
            (target, target, BREAK_GLASS_ARN),
            None,
        )
        text = framework.PrivacyFormatter("%(message)s").format(record)
        assert text == "targets=[[RESOURCE]] ([RESOURCE]); [ARN]"


def test_redaction_registry_is_bounded_and_scoped_across_runs_and_threads():
    with framework.sensitive_log_scope(["first"]):
        assert "[RESOURCE]" in framework.redact_runtime_text("first")
        with framework.sensitive_log_scope(["second"]):
            assert framework.redact_runtime_text("first second") == "first [RESOURCE]"
        assert framework.redact_runtime_text("first second") == "[RESOURCE] second"
    with framework.sensitive_log_scope(["second"]):
        assert framework.redact_runtime_text("first second") == "first [RESOURCE]"
        seen = []
        thread = threading.Thread(
            target=lambda: seen.append(framework.redact_runtime_text("second"))
        )
        thread.start()
        thread.join(5)
        assert seen == ["second"]
    with (
        pytest.raises(framework.ConfigurationError, match="Too many"),
        framework.sensitive_log_scope(
            str(i) for i in range(framework.MAX_SENSITIVE_LOG_VALUES + 1)
        ),
    ):
        pass


@pytest.mark.parametrize("utility", [True, False])
def test_configuration_errors_cannot_forge_terminal_or_log_records(
    tmp_path, capsys, utility
):
    config = framework.yaml.safe_load(framework.SAMPLE_CONFIG)
    config["global"]["region"] = "invalid\nFORGED\r\t\x1b[31m\u202e"
    path = tmp_path / "synthetic.yaml"
    path.write_text(framework.yaml.safe_dump(config), "utf-8")
    args = (
        ["--validate-config", str(path)]
        if utility
        else ["--config", str(path), "--suite", "synthetic"]
    )
    assert framework.main(args) == 2
    output = capsys.readouterr().err
    assert len(output.splitlines()) == 1
    for escaped in (r"\n", r"\r", r"\t", r"\u001b", r"\u202e"):
        assert escaped in output
    assert "\x1b" not in output


@pytest.mark.parametrize("identity", [False, True])
@pytest.mark.parametrize("resources", [False, True])
@pytest.mark.parametrize("diagnostics", [False, True])
def test_report_disclosure_flags_only_affect_their_typed_fields(
    tmp_path, identity, resources, diagnostics
):
    item = worker(FakeAWS())
    item.config = {
        "reporting": {
            "include_identity": identity,
            "include_resource_ids": resources,
            "include_diagnostics": diagnostics,
        }
    }
    sensitive = f"db {ACCOUNT_ID} {BREAK_GLASS_ARN} {OTHER_ACCESS_KEY}"
    item.results = [
        framework.ExperimentResult(
            "synthetic",
            framework.ChaosType.SQS_MESSAGE_DELAY,
            framework.utc_now(),
            affected_resources=["db", BREAK_GLASS_ARN],
            errors=[sensitive],
            rollback_errors=[sensitive],
            additional_info={"detail": sensitive, "password": "never-disclose"},
            metrics_before={"detail": sensitive},
            metrics_after={"detail": sensitive},
        )
    ]
    item.run_id = "synthetic"
    item.suite_name = "synthetic"
    item.seed = None
    item.actual_account = ACCOUNT_ID
    item.expected_account = ACCOUNT_ID
    item.caller_arn = BREAK_GLASS_ARN
    item.vpc_id = None
    item._failed_future_count = 0
    item.discovered_resources = {}
    item.output_dir = tmp_path
    report = json.loads(item._generate_report().read_text("utf-8"))
    details = report["experiments"][0]
    assert ("account_id" in report["run"]) is identity
    assert ("affected_resources" in details) is resources
    if resources:
        assert details["affected_resources"][0] == "db"
        assert (BREAK_GLASS_ARN in details["affected_resources"]) is identity
    for key in (
        "errors",
        "rollback_errors",
        "additional_info",
        "metrics_before",
        "metrics_after",
    ):
        if key in details:
            encoded = json.dumps(details[key])
            for value in (
                ACCOUNT_ID,
                BREAK_GLASS_ARN,
                OTHER_ACCESS_KEY,
                "never-disclose",
            ):
                assert value not in encoded
            assert "[RESOURCE]" in encoded
    assert ("additional_info" in details) is diagnostics


def release_fixture(root):
    root.mkdir()
    records = []
    for name in publish_payload.expected_names("v2.0.4"):
        data = b"verified synthetic package bytes: " + name.encode()
        (root / name).write_bytes(data)
        records.append(
            {
                "name": name,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    (root / "release-evidence.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tag": "v2.0.4",
                "version": "2.0.4",
                "source_commit": "a" * 40,
                "artifacts": records,
            }
        ),
        "utf-8",
    )


REPOSITORY = "owner/repo"
PROTECTED_SIGNER = (
    "https://github.com/owner/repo/.github/workflows/release-promotion.yml"
    "@refs/heads/main"
)


def attestation_result(subjects, **certificate_overrides):
    """Model `gh attestation verify --format json` output for one statement."""
    certificate = {
        "subjectAlternativeName": PROTECTED_SIGNER,
        "issuer": "https://token.actions.githubusercontent.com",
        "sourceRepositoryURI": "https://github.com/owner/repo",
        "sourceRepositoryRef": "refs/heads/main",
        "runnerEnvironment": "github-hosted",
        **certificate_overrides,
    }
    return {
        "verificationResult": {
            "signature": {"certificate": certificate},
            "statement": {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [
                    {"name": name, "digest": {"sha256": value}}
                    for name, value in sorted(subjects.items())
                ],
            },
        }
    }


def protected_release(tmp_path, release, **certificate_overrides):
    """Model the public release evidence and protected-job attestation results."""
    trusted = tmp_path / "trusted-release"
    trusted.mkdir()
    evidence = trusted / "release-evidence.json"
    evidence.write_bytes((release / "release-evidence.json").read_bytes())
    subjects = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in release.iterdir()
    }
    attestations = tmp_path / "trusted-attestations"
    attestations.mkdir()
    result = [attestation_result(subjects, **certificate_overrides)]
    for name in ["release-evidence.json", *publish_payload.expected_names("v2.0.4")]:
        (attestations / f"{name}.json").write_text(json.dumps(result), "utf-8")
    return evidence, attestations


def forge_payload(payload, version="v2.0.4", commit="a" * 40):
    """Replace both packages and the bundled manifest with a consistent forgery.

    Forged bytes keep the genuine size so only digest binding can detect them.
    """
    files = {}
    for name in publish_payload.expected_names(version):
        path = payload / "packages" / name
        data = bytes(255 - value for value in path.read_bytes())
        path.write_bytes(data)
        files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    (payload / "publish-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tag": version,
                "source_commit": commit,
                "files": files,
            }
        ),
        "utf-8",
    )
    return files


def test_actual_tag_verifier_replacement_cannot_survive_publish_digest_check(tmp_path):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    for source in release.glob("*.whl"):
        assert source.read_bytes() == (payload / "packages" / source.name).read_bytes()
    # Historical helper execution is modeled by a small copied-payload change.
    # The actual current verifier still computes the real digest and refuses it.
    packages = payload / "packages"
    name = next(iter(publish_payload.expected_names("v2.0.4")))
    (packages / name).write_bytes(b"ordinary copied-payload mismatch")
    assert (release / name).read_bytes() != (packages / name).read_bytes()
    with pytest.raises(ValueError, match="digest mismatch"):
        publish_payload.verify(payload, "v2.0.4", "a" * 40)


def test_publish_checker_is_isolated_from_tag_imports_and_binds_source_identity(
    tmp_path,
):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    evidence, attestations = protected_release(tmp_path, release)
    # Exercise the current isolated CLI only from an ordinary empty directory.
    # Launch isolation is also asserted against the reviewed workflow below.
    cli_directory = tmp_path / "clean-cli"
    cli_directory.mkdir()
    command = [
        sys.executable,
        "-I",
        str(ROOT / "scripts/publish_payload.py"),
        "verify",
        str(payload),
        "--tag",
        "v2.0.4",
        "--source-commit",
        "a" * 40,
    ]
    trusted = [
        "--trusted-evidence",
        str(evidence),
        "--attestations",
        str(attestations),
        "--repository",
        REPOSITORY,
    ]
    result = subprocess.run(
        command + trusted, cwd=cli_directory, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert list(cli_directory.iterdir()) == []
    # The bundled manifest alone can never satisfy the CLI verify mode.
    result = subprocess.run(command, cwd=cli_directory, capture_output=True, text=True)
    assert result.returncode != 0
    assert "requires --trusted-evidence" in result.stderr
    assert list(cli_directory.iterdir()) == []
    workflow = framework.yaml.safe_load(
        (ROOT / ".github/workflows/publish.yml").read_text("utf-8")
    )
    verify_command = workflow["jobs"]["publish"]["steps"][-2]["run"]
    assert (
        "python -I trusted-verifier/scripts/publish_payload.py verify" in verify_command
    )
    with pytest.raises(ValueError, match="identity mismatch"):
        publish_payload.verify(payload, "v2.0.4", "b" * 40)
    (payload / "packages" / "extra.whl").write_bytes(b"injected")
    with pytest.raises(ValueError, match="distribution set"):
        publish_payload.verify(payload, "v2.0.4", "a" * 40)


def test_publish_cli_verify_rejects_forged_self_consistent_handoff(tmp_path):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    evidence, attestations = protected_release(tmp_path, release)
    forge_payload(payload)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/publish_payload.py"),
            "verify",
            str(payload),
            "--tag",
            "v2.0.4",
            "--source-commit",
            "a" * 40,
            "--trusted-evidence",
            str(evidence),
            "--attestations",
            str(attestations),
            "--repository",
            REPOSITORY,
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "does not match protected release evidence" in result.stderr


def test_publish_workflow_never_executes_tag_verifier_or_publishes_unbound_bytes():
    workflow = framework.yaml.safe_load(
        (ROOT / ".github/workflows/publish.yml").read_text("utf-8")
    )
    verify = workflow["jobs"]["verify"]["steps"]
    assert any(
        step.get("with", {}).get("ref") == "${{ github.workflow_sha }}"
        for step in verify
    )
    code = "\n".join(step.get("run", "") for step in verify)
    assert "python scripts/verify_distribution.py" not in code
    assert "python -I trusted-verifier/scripts/verify_distribution.py" in code
    capture = next(
        i
        for i, step in enumerate(verify)
        if "publish_payload.py capture" in step.get("run", "")
    )
    assert all("run" not in step for step in verify[capture + 1 :])
    publish = workflow["jobs"]["publish"]["steps"]
    assert "publish_payload.py verify" in publish[-2]["run"]
    assert publish[-1]["with"]["packages-dir"] == "verified-payload/packages"


HELPER = "python -I trusted-verifier/scripts/release_asset_admission.py"


def _publish_steps():
    workflow = framework.yaml.safe_load(
        (ROOT / ".github/workflows/publish.yml").read_text("utf-8")
    )
    return workflow["jobs"]["verify"]["steps"], workflow["jobs"]["publish"]["steps"]


def _helper_commands(run):
    """Return each release_asset_admission.py invocation as shell words."""
    return [
        shlex.split(line)
        for line in run.replace("\\\n", " ").splitlines()
        if "release_asset_admission.py" in line
    ]


def test_publish_workflow_never_downloads_or_checks_release_assets_inline():
    verify, publish = _publish_steps()
    for step in (*verify, *publish):
        run = step.get("run", "")
        # Every public release download is metadata-admitted and size-bounded.
        assert "gh release download" not in run
        assert "curl" not in run and "wget" not in run
        # No downloaded manifest reaches a generic filesystem consumer.
        assert "sha256sum" not in run and "--check" not in run
        # No inline (stdin) Python reads downloaded evidence.
        assert "python -I - " not in run and "<<" not in run
        # The helper creates each output directory itself and refuses one that
        # already exists, so neither may be created beforehand.
        assert "mkdir release-assets" not in run
        assert "mkdir trusted-release" not in run
        for words in _helper_commands(run):
            assert words[:3] == HELPER.split()
            assert words[3] in {"download", "verify"}


def test_publish_verify_job_admits_downloads_and_parses_manifests_with_helper():
    verify, _publish = _publish_steps()
    index = next(
        i
        for i, step in enumerate(verify)
        if "release_asset_admission.py" in step.get("run", "")
    )
    step = verify[index]
    assert step["env"] == {"SOURCE_COMMIT": "${{ steps.identity.outputs.commit }}"}
    assert verify[index - 1].get("id") == "identity"
    assert _helper_commands(step["run"]) == [
        [
            *HELPER.split(),
            "download",
            "--repository",
            "$GH_REPO",
            "--tag",
            "$RELEASE_TAG",
            "--output",
            "release-assets",
        ],
        [
            *HELPER.split(),
            "verify",
            "release-assets",
            "--tag",
            "$RELEASE_TAG",
            "--source-commit",
            "$SOURCE_COMMIT",
            "--source",
            "aws_chaos_framework.py",
        ],
    ]
    run = step["run"]
    distribution = "python -I trusted-verifier/scripts/verify_distribution.py"
    assert run.startswith("set -euo pipefail\n")
    assert (
        run.index(f"{HELPER} download")
        < run.index(f"{HELPER} verify")
        < run.index(distribution)
    )
    # Trust order is unchanged: helper admission and parsing, then provenance,
    # then capture of the payload from the admitted bytes.
    provenance = next(
        i
        for i, step in enumerate(verify)
        if 'gh attestation verify "$asset"' in step.get("run", "")
    )
    capture = next(
        i
        for i, step in enumerate(verify)
        if "publish_payload.py capture release-assets" in step.get("run", "")
    )
    assert index < provenance < capture
    assert all(
        "release_asset_admission.py" not in step.get("run", "")
        for step in verify[index + 1 :]
    )


def test_publish_protected_job_admits_evidence_before_attestation():
    _verify, publish = _publish_steps()
    commands = [
        (i, words)
        for i, step in enumerate(publish)
        for words in _helper_commands(step.get("run", ""))
    ]
    trusted = next(i for i, step in enumerate(publish) if step.get("id") == "trusted")
    assert commands == [
        (
            trusted,
            [
                *HELPER.split(),
                "download",
                "--repository",
                "$GH_REPO",
                "--tag",
                "$RELEASE_TAG",
                "--output",
                "trusted-release",
                "--only",
                "release-evidence.json",
            ],
        )
    ]
    run = publish[trusted]["run"]
    assert "mkdir trusted-attestations\n" in run
    assert run.index(f"{HELPER} download") < run.index("gh attestation verify")
    assert run.index('test "$commit" = "$SOURCE_COMMIT"') < run.index(HELPER)


def test_protected_job_accepts_independently_attested_release_subjects(tmp_path):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    evidence, attestations = protected_release(tmp_path, release)
    publish_payload.authenticate(
        payload, "v2.0.4", "a" * 40, evidence, attestations, REPOSITORY
    )
    assert publish_payload.signer_identity(REPOSITORY) == PROTECTED_SIGNER


def test_forged_self_consistent_payload_is_rejected_by_independent_digests(
    tmp_path,
):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    evidence, attestations = protected_release(tmp_path, release)
    forge_payload(payload)
    # A compromised producer controls both the bytes and the bundled manifest,
    # so bundle-internal consistency alone accepts the forgery.
    publish_payload.verify(payload, "v2.0.4", "a" * 40)
    with pytest.raises(ValueError, match="protected release evidence"):
        publish_payload.authenticate(
            payload, "v2.0.4", "a" * 40, evidence, attestations, REPOSITORY
        )


@pytest.mark.parametrize(
    "override",
    [
        {
            "subjectAlternativeName": "https://github.com/owner/repo/"
            ".github/workflows/publish.yml@refs/heads/main"
        },
        {
            "subjectAlternativeName": "https://github.com/owner/repo/"
            ".github/workflows/release.yml@refs/tags/v2.0.4"
        },
        {
            "subjectAlternativeName": "https://github.com/owner/repo/"
            ".github/workflows/release-promotion.yml@refs/heads/feature"
        },
        {
            "subjectAlternativeName": "https://github.com/other/repo/"
            ".github/workflows/release-promotion.yml@refs/heads/main"
        },
        {"issuer": "https://issuer.example"},
        {"sourceRepositoryURI": "https://github.com/other/repo"},
        {"sourceRepositoryRef": "refs/tags/v2.0.4"},
        {"runnerEnvironment": "self-hosted"},
    ],
)
@pytest.mark.parametrize(
    "subject",
    [
        "release-evidence.json",
        "aws_chaos_engineering_framework-2.0.4-py3-none-any.whl",
        "aws_chaos_engineering_framework-2.0.4.tar.gz",
    ],
)
def test_forged_release_subjects_need_the_protected_signer_identity(
    tmp_path, override, subject
):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    evidence, attestations = protected_release(tmp_path, release)
    subjects = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in release.iterdir()
    }
    (attestations / f"{subject}.json").write_text(
        json.dumps([attestation_result(subjects, **override)]), "utf-8"
    )
    with pytest.raises(ValueError, match="No protected release attestation"):
        publish_payload.authenticate(
            payload, "v2.0.4", "a" * 40, evidence, attestations, REPOSITORY
        )


def test_forged_evidence_and_packages_cannot_borrow_protected_attestations(
    tmp_path,
):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    evidence, attestations = protected_release(tmp_path, release)
    forged = forge_payload(payload)
    # The forger also rewrites the release evidence to match the forged bytes,
    # but the protected signer never attested that evidence digest.
    records = [{"name": name, **value} for name, value in forged.items()]
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tag": "v2.0.4",
                "version": "2.0.4",
                "source_commit": "a" * 40,
                "artifacts": records,
            }
        ),
        "utf-8",
    )
    with pytest.raises(ValueError, match="No protected release attestation"):
        publish_payload.authenticate(
            payload, "v2.0.4", "a" * 40, evidence, attestations, REPOSITORY
        )
    # Even with a protected statement for that forged evidence, the forged
    # packages themselves carry no protected-signer provenance.
    forged_evidence_digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    (attestations / "release-evidence.json.json").write_text(
        json.dumps(
            [attestation_result({"release-evidence.json": forged_evidence_digest})]
        ),
        "utf-8",
    )
    with pytest.raises(ValueError, match="No protected release attestation"):
        publish_payload.authenticate(
            payload, "v2.0.4", "a" * 40, evidence, attestations, REPOSITORY
        )


@pytest.mark.parametrize(
    "identity",
    [
        {"tag": "v2.0.3"},
        {"version": "2.0.3"},
        {"source_commit": "b" * 40},
        {"schema_version": 2},
    ],
)
def test_tag_and_commit_strings_cannot_authenticate_substituted_bytes(
    tmp_path, identity
):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    evidence, attestations = protected_release(tmp_path, release)
    # Substituted bytes keep the exact trusted tag and source-commit strings.
    forge_payload(payload, "v2.0.4", "a" * 40)
    manifest = json.loads((payload / "publish-manifest.json").read_text("utf-8"))
    assert (manifest["tag"], manifest["source_commit"]) == ("v2.0.4", "a" * 40)
    with pytest.raises(ValueError, match="protected release evidence"):
        publish_payload.authenticate(
            payload, "v2.0.4", "a" * 40, evidence, attestations, REPOSITORY
        )
    # Genuine bytes are still refused when attested evidence names another
    # release identity, even though the payload strings match the dispatch.
    genuine = tmp_path / "payload-genuine"
    publish_payload.capture(release, genuine, "v2.0.4", "a" * 40)
    original = json.loads(evidence.read_text("utf-8"))
    evidence.write_text(json.dumps({**original, **identity}), "utf-8")
    subjects = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in release.iterdir()
    }
    subjects["release-evidence.json"] = hashlib.sha256(
        evidence.read_bytes()
    ).hexdigest()
    for name in ["release-evidence.json", *publish_payload.expected_names("v2.0.4")]:
        (attestations / f"{name}.json").write_text(
            json.dumps([attestation_result(subjects)]), "utf-8"
        )
    with pytest.raises(ValueError, match="evidence identity mismatch"):
        publish_payload.authenticate(
            genuine, "v2.0.4", "a" * 40, evidence, attestations, REPOSITORY
        )


def test_protected_publish_job_verifies_exact_subjects_before_pypi_action():
    workflow = framework.yaml.safe_load(
        (ROOT / ".github/workflows/publish.yml").read_text("utf-8")
    )
    producer = workflow["jobs"]["verify"]
    assert "environment" not in producer
    assert "id-token" not in producer.get("permissions", {})
    job = workflow["jobs"]["publish"]
    assert job["environment"]["name"] == "pypi"
    assert job["permissions"] == {
        "id-token": "write",
        "contents": "read",
        "actions": "read",
        "attestations": "read",
    }
    steps = job["steps"]
    download = next(
        i
        for i, step in enumerate(steps)
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    trusted = next(i for i, step in enumerate(steps) if step.get("id") == "trusted")
    final = len(steps) - 2
    assert download < trusted < final
    publish = steps[-1]
    assert publish["uses"].startswith("pypa/gh-action-pypi-publish@")
    pin = publish["uses"].split("@", 1)[1]
    assert len(pin) == 40 and all(c in "0123456789abcdef" for c in pin)
    assert publish["with"]["packages-dir"] == "verified-payload/packages"

    run = steps[trusted]["run"]
    assert "refs/tags/$RELEASE_TAG^{commit}" in run
    assert 'test "$commit" = "$SOURCE_COMMIT"' in run
    # The protected job admits the complete release metadata by size and then
    # streams only the evidence subject, before any attestation handling.
    admitted = (
        "python -I trusted-verifier/scripts/release_asset_admission.py download \\\n"
        '  --repository "$GH_REPO" --tag "$RELEASE_TAG" --output trusted-release \\\n'
        "  --only release-evidence.json"
    )
    assert admitted in run
    assert run.index(admitted) < run.index("gh attestation verify")
    assert "gh release download" not in run
    assert (
        'signer="https://github.com/$GH_REPO/.github/workflows/'
        'release-promotion.yml@refs/heads/main"'
    ) in run
    # The exact files later passed to the PyPI action are attested here.
    for subject in (
        "trusted-release/release-evidence.json",
        '"verified-payload/packages/aws_chaos_engineering_framework-'
        '${version}-py3-none-any.whl"',
        '"verified-payload/packages/aws_chaos_engineering_framework-${version}.tar.gz"',
    ):
        assert subject in run
    for flag in (
        'gh attestation verify "$subject" --repo "$GH_REPO"',
        '--cert-identity "$signer"',
        "--cert-oidc-issuer https://token.actions.githubusercontent.com",
        "--source-ref refs/heads/main --deny-self-hosted-runners",
        "--predicate-type https://slsa.dev/provenance/v1",
        '--format json > "trusted-attestations/${subject##*/}.json"',
    ):
        assert flag in run

    verify = steps[final]
    assert (
        verify["env"]["TRUSTED_SOURCE_COMMIT"]
        == "${{ steps.trusted.outputs.source-commit }}"
    )
    for argument in (
        "python -I trusted-verifier/scripts/publish_payload.py verify verified-payload",
        '--source-commit "$TRUSTED_SOURCE_COMMIT"',
        "--trusted-evidence trusted-release/release-evidence.json",
        '--attestations trusted-attestations --repository "$GH_REPO"',
    ):
        assert argument in verify["run"]
    assert '--source-commit "$SOURCE_COMMIT"' not in verify["run"]


CI_LOCKS = (
    "requirements-pip-lock.txt",
    "requirements-dev-lock.txt",
    "requirements-build-lock.txt",
    "requirements-runtime-lock.txt",
)


def _lock_entries(name):
    """Return {(package, marker): (version, hashes)} from a reviewed hash lock."""
    text = (ROOT / name).read_text("utf-8").replace("\\\n", " ")
    entries = {}
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        assert not line.startswith("-"), f"{name} has an unreviewed option: {line}"
        requirement, _, options = line.partition(" --hash=")
        hashes = {
            token.removeprefix("--hash=sha256:")
            for token in ("--hash=" + options).split()
        }
        assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes), line
        pin, _, marker = requirement.partition(";")
        package, separator, version = pin.strip().partition("==")
        assert separator and re.fullmatch(r"[a-z0-9][a-z0-9.-]*", package), line
        assert re.fullmatch(r"[0-9][A-Za-z0-9.+!]*", version), line
        key = (package, marker.strip())
        assert key not in entries, f"duplicate {key} in {name}"
        entries[key] = (version, hashes)
    return entries


def _requirement_inputs(name):
    result = {}
    for raw in (ROOT / name).read_text("utf-8").splitlines():
        line = raw.strip()
        if line.startswith("-r "):
            result.update(_requirement_inputs(line[3:].strip()))
        elif line and not line.startswith("#"):
            package, separator, version = line.partition("==")
            assert separator, line
            result[package.lower().replace("_", "-")] = version
    return result


def _ci_workflow():
    return framework.yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
    )


# Every workflow command line that mentions pip or another Python installer
# must fully match one reviewed form below; anything else fails closed, so a
# new install cannot slip past through unusual syntax (global options, a
# versioned or path-qualified pip, several commands on one line, a variable
# holding the installer, or a different installer).
_INSTALLER_MENTION = re.compile(
    r"pip(?!efail)|\buv\b|easy_install|poetry|\bpdm\b|conda", re.IGNORECASE
)
_PYTHON = (
    r"(?:python|\.wheel-smoke/bin/python|\.sdist-smoke/bin/python"
    r'|"\$RUNNER_TEMP/chaos-hashed-runtime/bin/python")'
)
_LOCK = r"-r requirements-(?:pip|dev|build|runtime)-lock\.txt"
LOCK_INSTALL = re.compile(
    _PYTHON + r" -m pip install --disable-pip-version-check --require-hashes"
    r" --only-binary :all: " + _LOCK + r"(?: " + _LOCK + r")*"
)
LOCAL_INSTALL = re.compile(
    r"\.wheel-smoke/bin/python -m pip install --disable-pip-version-check"
    r" --no-deps dist/\*\.whl"
    r"|\.sdist-smoke/bin/python -m pip install --disable-pip-version-check"
    r" --no-build-isolation --no-deps dist/\*\.tar\.gz"
)
PIP_CHECK = re.compile(_PYTHON + r" -m pip check")
PIP_AUDIT = re.compile(
    r"python -m pip_audit -r requirements-(?:runtime|dev|build)-lock\.txt"
    r" --require-hashes --disable-pip --progress-spinner off"
)
CI_INSTALLER_FORMS = (LOCK_INSTALL, LOCAL_INSTALL, PIP_CHECK, PIP_AUDIT)
RELEASE_INSTALLER_FORMS = (LOCK_INSTALL,)


def _installer_lines(run, forms):
    """Yield every installer-mentioning line, requiring a reviewed form.

    Lines are joined and unquoted as bash does (a backslash-newline is
    removed, quoted fragments concatenate), so a split or quoted installer
    name is still seen. Unparseable lines fail closed.
    """
    for raw in run.replace("\\\n", "").splitlines():
        line = raw.strip()
        try:
            words = " ".join(shlex.split(line))
        except ValueError:
            raise AssertionError(line) from None
        if not (_INSTALLER_MENTION.search(line) or _INSTALLER_MENTION.search(words)):
            continue
        assert any(form.fullmatch(line) for form in forms), line
        yield line


def _workflow_pip_installs(name, forms):
    workflow = framework.yaml.safe_load((ROOT / name).read_text("utf-8"))
    for job_name, job in workflow["jobs"].items():
        for step in job["steps"]:
            for line in _installer_lines(step.get("run", ""), forms):
                tokens = shlex.split(line)
                if tokens[tokens.index("-m") + 1 :][:2] == ["pip", "install"]:
                    yield job_name, line, tokens


def test_installer_lines_fail_closed_on_unreviewed_forms():
    reviewed = (
        "python -m pip install --disable-pip-version-check --require-hashes"
        " --only-binary :all: -r requirements-pip-lock.txt"
    )
    assert list(_installer_lines(reviewed, RELEASE_INSTALLER_FORMS)) == [reviewed]
    assert not list(_installer_lines("set -euo pipefail", RELEASE_INSTALLER_FORMS))
    for line in (
        "pip install x",
        "pip3 install x",
        "pip3.12 install x",
        "/usr/bin/pip3 install x",
        '"$RUNNER_TEMP/venv/bin/pip" install x',
        r"C:\venv\Scripts\pip.exe install x",
        "python -m pip --disable-pip-version-check install x",
        "python -m pip --isolated install -r requirements-dev.txt",
        "python3.12 -m pip3 install x",
        reviewed + " && pip install x",
        reviewed + "; pip install x",
        reviewed + " requests",
        "python -m pip check && pip install x",
        "PIP=pip3",
        "$PIP install x",
        "uv pip install x",
        "UV_SYSTEM_PYTHON=1 uv sync",
        "pipx install x",
        "easy_install x",
        "python -m ensurepip",
        "poetry install",
        "conda install x",
        "python -m pip_audit -r requirements-dev.txt --progress-spinner off",
        "python -m pi''p install x",
        'python -m p"i"p install x',
        "python -m pi\\\np install x",
        "u''v sync",
        'python -c "unbalanced',
    ):
        with pytest.raises(AssertionError):
            list(_installer_lines(line, CI_INSTALLER_FORMS))


# The exact bytes of these workflows are pinned to a reviewed digest, so no
# change of any kind (a command, its quoting or continuation, an environment
# value, an action or action revision, a runner, a condition, a permission, or
# a scalar spelling that a YAML parser might read differently) can pass until
# it has been reviewed against the hash-lock contract above and the digest
# updated deliberately. This includes Dependabot action bumps and comment or
# formatting edits. .gitattributes checks *.yml out with LF on every platform,
# so the bytes are the same on every runner.
REVIEWED_WORKFLOW_DIGESTS = {
    ".github/workflows/ci.yml": "f9d2b5d0160a0737fe41ccb68e88a4f42cd1f450686d488793e306319fe74a89",
    ".github/workflows/release.yml": "0deb2296fced8e48d30bcf197a9efad8cabc97814e1281fb86fd0d7c949b2fe3",
}


def _workflow_digest(name):
    return hashlib.sha256((ROOT / name).read_bytes()).hexdigest()


def test_workflows_match_reviewed_digests():
    for name, digest in REVIEWED_WORKFLOW_DIGESTS.items():
        assert _workflow_digest(name) == digest, (
            f"{name} changed: review every install and action against the "
            "hash-lock contract, then update REVIEWED_WORKFLOW_DIGESTS"
        )


def _pip_targets(tokens):
    targets, skip = [], False
    for token in tokens[tokens.index("install") + 1 :]:
        if skip:
            skip = False
        elif token in {"-r", "--only-binary"}:
            skip = True
        elif not token.startswith("-"):
            targets.append(token)
    return targets


def test_ci_installs_python_tooling_only_from_reviewed_hash_locks():
    installs = {}
    audited = set()
    for job in _ci_workflow()["jobs"].values():
        for step in job["steps"]:
            for line in step.get("run", "").replace("\\\n", " ").splitlines():
                tokens = shlex.split(line)
                if "pip_audit" in tokens:
                    # Audits read the hashed locks and never resolve or install.
                    files = [tokens[i + 1] for i, t in enumerate(tokens) if t == "-r"]
                    assert files and set(files) <= set(CI_LOCKS), line
                    assert {"--require-hashes", "--disable-pip"} <= set(tokens)
                    audited.update(files)
    for job_name, line, tokens in _workflow_pip_installs(
        ".github/workflows/ci.yml", CI_INSTALLER_FORMS
    ):
        files = [tokens[i + 1] for i, t in enumerate(tokens) if t == "-r"]
        assert not {
            "--upgrade",
            "-U",
            "--index-url",
            "-i",
            "--extra-index-url",
            "--find-links",
            "--trusted-host",
            "--no-index",
        } & set(tokens), line
        installs.setdefault(job_name, []).append(tokens)
        if files:
            # Every dependency install is a complete reviewed hash lock.
            assert set(files) <= set(CI_LOCKS), line
            assert "--require-hashes" in tokens, line
            # Wheels only: a source fallback would install its build
            # requirements without hash checking.
            assert "--only-binary" in tokens, line
            assert tokens[tokens.index("--only-binary") + 1] == ":all:", line
            assert not _pip_targets(tokens), line
            continue
        # Only the local candidate is installed without a lock, and it
        # never resolves dependencies from the index.
        targets = _pip_targets(tokens)
        assert "--no-deps" in tokens and targets, line
        assert all(re.fullmatch(r"dist/\*\.(whl|tar\.gz)", t) for t in targets)
        if any(t.endswith(".tar.gz") for t in targets):
            # The local sdist builds with the hashed build lock already
            # installed, never in an isolated unhashed build env.
            assert "--no-build-isolation" in tokens, line
    assert audited == {
        "requirements-runtime-lock.txt",
        "requirements-dev-lock.txt",
        "requirements-build-lock.txt",
    }
    # Each tooling job first installs the hashed pip pin, then the complete
    # development (and build) closure, all from wheels.
    for job_name in ("test", "platform-test", "security", "package-artifact"):
        bootstrap, tooling = installs[job_name][:2]
        assert bootstrap[:2] == ["python", "-m"]
        assert bootstrap[-2:] == ["-r", "requirements-pip-lock.txt"]
        assert tooling[-2:] == (
            ["-r", "requirements-dev-lock.txt"]
            if job_name == "security"
            else ["-r", "requirements-build-lock.txt"]
        )
        assert "requirements-dev-lock.txt" in tooling
        for tokens in (bootstrap, tooling):
            assert {"--require-hashes", "--only-binary", ":all:"} <= set(tokens)
    text = (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
    assert "--upgrade pip" not in text
    for unlocked in (
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-build.txt",
    ):
        assert f"-r {unlocked}" not in text


def test_release_installs_only_hash_locked_wheels():
    installs = []
    for _job, line, tokens in _workflow_pip_installs(
        ".github/workflows/release.yml", RELEASE_INSTALLER_FORMS
    ):
        installs.append(line)
        files = [tokens[i + 1] for i, t in enumerate(tokens) if t == "-r"]
        # Release dependencies come only from the reviewed hash locks, as
        # wheels, so no source fallback can install unhashed build requirements
        # in an isolated build environment.
        assert files and set(files) <= set(CI_LOCKS), line
        assert "--require-hashes" in tokens, line
        assert "--only-binary" in tokens, line
        assert tokens[tokens.index("--only-binary") + 1] == ":all:", line
        assert not _pip_targets(tokens), line
    assert len(installs) == 3


def test_ci_hash_locks_pin_inputs_consistently_and_cover_ci_platforms():
    # Transitive completeness is enforced at install time by pip's
    # hash-checking mode, which refuses any requirement that is not pinned and
    # hashed in the lock; this test checks direct pins, shared hashes and
    # marker coverage.
    from packaging.markers import Marker

    locks = {name: _lock_entries(name) for name in CI_LOCKS}
    # A pin shared between locks carries the identical reviewed hash set, so
    # installing locks together can never narrow or widen accepted artifacts.
    pins = {}
    for entries in locks.values():
        for (package, _marker), (version, hashes) in entries.items():
            assert pins.setdefault((package, version), hashes) == hashes, package
    for source, lock in (
        ("requirements.txt", "requirements-runtime-lock.txt"),
        ("requirements-dev.txt", "requirements-dev-lock.txt"),
        ("requirements-build.txt", "requirements-build-lock.txt"),
        ("requirements-pip.txt", "requirements-pip-lock.txt"),
    ):
        header = (ROOT / lock).read_text("utf-8").splitlines()[1]
        assert header.startswith(f"#    uv pip compile {source} ")
        assert "--generate-hashes" in header and "--universal" in header
        for package, version in _requirement_inputs(source).items():
            versions = {v for (p, _m), (v, _h) in locks[lock].items() if p == package}
            assert versions == {version}, (lock, package)
    assert {package for package, _marker in locks["requirements-pip-lock.txt"]} == {
        "pip"
    }
    assert {v for (p, v) in pins if p == "pip"} == {
        _requirement_inputs("requirements-pip.txt")["pip"]
    }
    # Exactly one pin applies per package for every CI interpreter and runner,
    # across the development and build locks installed in one pip invocation.
    workflow = _ci_workflow()
    environments = [
        ("linux", "posix", "x86_64", "Linux", version)
        for version in workflow["jobs"]["test"]["strategy"]["matrix"]["python-version"]
    ]
    assert len(environments) == 5
    runners = workflow["jobs"]["platform-test"]["strategy"]["matrix"]["os"]
    assert set(runners) == {"windows-latest", "macos-latest"}
    environments += [
        ("win32", "nt", "AMD64", "Windows", "3.12"),
        ("darwin", "posix", "arm64", "Darwin", "3.12"),
    ]
    groups = (
        ("requirements-dev-lock.txt", "requirements-build-lock.txt"),
        ("requirements-runtime-lock.txt",),
        ("requirements-build-lock.txt", "requirements-runtime-lock.txt"),
    )
    for sys_platform, os_name, machine, system, version in environments:
        environment = {
            "sys_platform": sys_platform,
            "os_name": os_name,
            "platform_machine": machine,
            "platform_system": system,
            "python_version": version,
            "python_full_version": version + ".0",
            "implementation_name": "cpython",
            "platform_python_implementation": "CPython",
        }
        for group in groups:
            selected = {}
            for name in group:
                for (package, marker), (pin, _hashes) in locks[name].items():
                    if not marker or Marker(marker).evaluate(environment):
                        assert selected.setdefault(package, pin) == pin, package
            for name in group:
                source = name.replace("-runtime", "").replace("-lock", "")
                assert set(_requirement_inputs(source)) <= set(selected), name
