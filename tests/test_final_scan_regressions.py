"""Offline adversarial regressions for the seven exact-main scan follow-ups."""

import copy
import hashlib
import json
import logging
import os
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
    FakeSafetyController,
    action_configs,
    make_experiment,
)

import aws_chaos_framework as framework
from scripts import publish_payload

ROOT = Path(__file__).resolve().parents[1]


def worker(aws):
    item = object.__new__(framework.ChaosOrchestrator)
    item.config = {"global": {}, "safety": {}}
    item.region = REGION
    item.dry_run = False
    item.live = True
    item.operator_principal_arn = BREAK_GLASS_ARN
    item.active_access_key_id = OTHER_ACCESS_KEY
    item._report_sensitive_values = set()
    item._sensitive_values_lock = threading.Lock()
    item._active_experiments_lock = threading.Lock()
    item.active_experiments = []
    item.safety_controller = FakeSafetyController(aws, live=True)
    item._validate_target_scope = lambda *_: None
    return item


@pytest.mark.parametrize("kind", ["rds_backup_retention_modify", "s3_lifecycle_modify"])
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
    token = framework.confirmation_token(config, suite)
    assert token.startswith("LIVE-IRREVERSIBLE:")
    item = worker(FakeAWS())
    item.config = config
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


def test_s3_expiration_never_claims_recovery_of_deleted_objects():
    aws = FakeAWS(reject_writes=False)
    config = action_configs()[framework.ChaosType.S3_LIFECYCLE_MODIFY]
    item = make_experiment(
        framework.ChaosType.S3_LIFECYCLE_MODIFY, config, aws, dry_run=False
    )
    result = item.modify_lifecycle(**config)
    assert result.status == "completed"
    assert "deleted data" in result.additional_info["data_loss_warning"]
    before = list(aws.calls)
    with pytest.raises(framework.SafetyViolation, match="irreversible"):
        item.run_rollback()
    assert aws.calls == before
    assert not item.rollback_verified


def test_ec2_termination_creates_no_implicit_volume_copies():
    aws = FakeAWS(reject_writes=False)
    config = action_configs()[framework.ChaosType.EC2_TERMINATE]
    item = make_experiment(
        framework.ChaosType.EC2_TERMINATE, config, aws, dry_run=False
    )
    item._get_instance_volumes = lambda *_: (_ for _ in ()).throw(
        AssertionError("Implicit volume expansion")
    )
    assert item.terminate_instances(**config).status == "completed"
    writes = [
        (operation, request)
        for _, operation, request in aws.calls
        if not operation.startswith(framework.READ_ONLY_OPERATION_PREFIXES)
    ]
    assert writes == [("terminate_instances", {"InstanceIds": config["instance_ids"]})]


def test_staggered_same_queue_workers_restore_the_authoritative_pre_state():
    aws = FakeAWS(reject_writes=False)
    baseline = aws.respond("sqs", "get_queue_attributes", {})
    baseline["Attributes"]["DelaySeconds"] = "0"
    state = copy.deepcopy(baseline)
    original = aws.respond
    first_mutated = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    second_mutated = threading.Event()
    writes = []
    captures = []

    def model(service, operation, request):
        if service == "sqs" and operation == "get_queue_attributes":
            aws.calls.append((service, operation, request))
            if request["AttributeNames"] == ["DelaySeconds"]:
                captures.append(state["Attributes"]["DelaySeconds"])
            return copy.deepcopy(state)
        if service == "sqs" and operation == "set_queue_attributes":
            aws.calls.append((service, operation, request))
            value = request["Attributes"]["DelaySeconds"]
            state["Attributes"]["DelaySeconds"] = value
            writes.append(value)
            if value == "5":
                first_mutated.set()
                assert release_first.wait(5)
            if value == "9":
                second_mutated.set()
            return {}
        return original(service, operation, request)

    aws.respond = model
    first, second = worker(aws), worker(aws)
    # Separate orchestrators and direct worker calls exercise the process-wide
    # guard, beyond the live suite's single-worker scheduler.
    results = []
    failures = []

    def run(item, value):
        try:
            if value == 9:
                second_started.set()
            results.append(
                item._run_single_experiment(
                    {
                        "type": "sqs_message_delay",
                        "queue_url": "https://sqs.us-gov-west-1.amazonaws.com/111122223333/synthetic",
                        "delay_seconds": value,
                        "auto_rollback": True,
                    }
                )
            )
        except Exception as error:
            failures.append(error)

    threads = [
        threading.Thread(target=run, args=(first, 5)),
        threading.Thread(target=run, args=(second, 9)),
    ]
    threads[0].start()
    try:
        assert first_mutated.wait(5)
        threads[1].start()
        assert second_started.wait(5)
        assert not second_mutated.wait(0.15)
    finally:
        release_first.set()
        for thread in threads:
            if thread.ident:
                thread.join(5)
    assert not failures
    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 2
    assert all(
        result.status == "completed" and result.rollback_successful
        for result in results
    )
    assert state["Attributes"]["DelaySeconds"] == "0"
    assert writes == ["5", "0", "9", "0"]
    assert captures[0] == "0"


def synthetic_live_suite(item, experiments, delay=0):
    item.config = {
        "global": {"account_id": ACCOUNT_ID, "region": REGION},
        "safety": {"safety_alarms": ["synthetic-alarm"]},
        "experiment_suites": {
            "synthetic": {
                "experiments": experiments,
                "max_concurrent": 3,
                "failure_policy": "continue",
                "delay_between_experiments": delay,
            }
        },
    }
    item.expected_account = ACCOUNT_ID
    item.approval_scope = {}
    item.vpc_id = None
    item.results = []
    item._failed_future_count = 0
    item._generate_report = lambda: None
    item.confirmation = framework.confirmation_token(item.config, "synthetic", {})


def test_failed_recovery_blocks_continue_policy_and_separate_orchestrators():
    aws = FakeAWS(reject_writes=False)
    state = aws.respond("sqs", "get_queue_attributes", {})
    state["Attributes"]["DelaySeconds"] = "0"
    original = aws.respond
    writes = []

    def model(service, operation, request):
        if service == "sqs" and operation == "get_queue_attributes":
            aws.calls.append((service, operation, request))
            return copy.deepcopy(state)
        if service == "sqs" and operation == "set_queue_attributes":
            aws.calls.append((service, operation, request))
            value = request["Attributes"]["DelaySeconds"]
            writes.append(value)
            if value == "0":
                raise RuntimeError("Synthetic recovery failed before restoration")
            state["Attributes"]["DelaySeconds"] = value
            return {}
        return original(service, operation, request)

    aws.respond = model
    configs = [
        {
            "type": "sqs_message_delay",
            "queue_url": "https://sqs.us-gov-west-1.amazonaws.com/111122223333/synthetic",
            "delay_seconds": value,
            "auto_rollback": True,
        }
        for value in (5, 9)
    ]
    first = worker(aws)
    synthetic_live_suite(first, configs)
    assert not first.run_experiment_suite("synthetic")
    assert writes == ["5", "0"]
    assert state["Attributes"]["DelaySeconds"] == "5"
    assert len(first.results) == 1
    assert first.results[0].rollback_successful is False
    assert first.safety_controller.emergency_stop.is_set()
    second = worker(aws)
    calls = list(aws.calls)
    with pytest.raises(framework.SafetyViolation, match="blocked after unverified"):
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
                "type": "sqs_message_delay",
                "queue_url": "synthetic-queue",
                "delay_seconds": 5,
                "auto_rollback": False,
            }
        )
    assert aws.calls == calls
    assert not item.active_experiments


def test_live_interexperiment_delay_starts_after_recovery_completes():
    item = worker(FakeAWS())
    configs = [
        {
            "type": "sqs_message_delay",
            "queue_url": "synthetic-queue",
            "delay_seconds": value,
        }
        for value in (5, 9)
    ]
    synthetic_live_suite(item, configs, delay=7)
    trace = []

    def run(config):
        trace.append(f"recovered-{config['delay_seconds']}")
        return framework.ExperimentResult(
            "synthetic",
            framework.ChaosType.SQS_MESSAGE_DELAY,
            framework.utc_now(),
            status="completed",
            rollback_successful=True,
        )

    item._run_single_experiment = run
    item.safety_controller.emergency_stop.wait = lambda seconds: (
        trace.append(f"delay-{seconds}") or False
    )
    assert item.run_experiment_suite("synthetic")
    assert trace == ["recovered-5", "delay-7", "recovered-9"]


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
        json.dumps({"tag": "v2.0.4", "source_commit": "a" * 40, "artifacts": records}),
        "utf-8",
    )


def test_actual_tag_verifier_replacement_cannot_survive_publish_digest_check(tmp_path):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    for source in release.glob("*.whl"):
        assert source.read_bytes() == (payload / "packages" / source.name).read_bytes()
    malicious = tmp_path / "tag-verifier.py"
    malicious.write_text(
        "from pathlib import Path\nimport sys\nfor path in Path(sys.argv[1]).glob('*'):\n path.write_bytes(b'after-verification replacement')\n",
        "utf-8",
    )
    subprocess.run(
        [sys.executable, "-I", str(malicious), str(payload / "packages")], check=True
    )
    with pytest.raises(ValueError, match="digest mismatch"):
        publish_payload.verify(payload, "v2.0.4", "a" * 40)


def test_publish_checker_is_isolated_from_tag_imports_and_binds_source_identity(
    tmp_path,
):
    release = tmp_path / "release-assets"
    payload = tmp_path / "payload"
    release_fixture(release)
    publish_payload.capture(release, payload, "v2.0.4", "a" * 40)
    hostile = tmp_path / "tag"
    hostile.mkdir()
    marker = tmp_path / "untrusted-imported"
    for module in ("hashlib.py", "sitecustomize.py"):
        (hostile / module).write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\nraise RuntimeError('tag-controlled import')\n",
            "utf-8",
        )
    environment = {**os.environ, "PYTHONPATH": str(hostile)}
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
        ],
        cwd=hostile,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    with pytest.raises(ValueError, match="identity mismatch"):
        publish_payload.verify(payload, "v2.0.4", "b" * 40)
    (payload / "packages" / "extra.whl").write_bytes(b"injected")
    with pytest.raises(ValueError, match="distribution set"):
        publish_payload.verify(payload, "v2.0.4", "a" * 40)


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
