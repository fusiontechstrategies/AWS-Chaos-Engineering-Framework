"""Small offline controls for the five 440f746 safety corrections."""

import copy
import hashlib
import io
import json
import stat
import urllib.error
import zipfile
from pathlib import Path
from types import SimpleNamespace

import botocore.session
import pytest
from test_aws_chaos_framework import FakeAWS, action_configs, make_experiment

import aws_chaos_framework as framework
from scripts import download_release_artifact as downloader
from scripts import prepare_release, source_files, verify_distribution

UNSAFE = (
    framework.ChaosType.S3_BUCKET_POLICY_DENY,
    framework.ChaosType.SNS_TOPIC_POLICY_RESTRICT,
    framework.ChaosType.EBS_THROTTLE_IOPS,
    framework.ChaosType.OPENSEARCH_CLUSTER_CONFIG_MODIFY,
    framework.ChaosType.VPC_SECURITY_GROUP_MODIFY,
)


@pytest.mark.parametrize("kind", UNSAFE)
def test_planning_only_metadata_and_handler_refusal(kind):
    assert kind in framework.CONCURRENCY_UNSAFE_LIVE_EXPERIMENTS
    assert framework.experiment_metadata(kind).rollback == "none"
    aws = FakeAWS(reject_writes=False)
    with pytest.raises(
        framework.ConfigurationError, match="Live approval is unavailable"
    ):
        make_experiment(kind, action_configs()[kind], aws, dry_run=False)
    assert not aws.calls


@pytest.mark.parametrize(
    "service,operation",
    [
        ("s3", "put_bucket_policy"),
        ("s3", "delete_bucket_policy"),
        ("sns", "set_topic_attributes"),
        ("ec2", "modify_volume"),
        ("opensearch", "update_domain_config"),
        ("ec2", "revoke_security_group_ingress"),
        ("ec2", "authorize_security_group_ingress"),
    ],
)
@pytest.mark.parametrize("recovery", [False, True])
def test_direct_proxy_refuses_unsafe_forward_and_recovery(service, operation, recovery):
    aws = FakeAWS(reject_writes=False)
    kind = framework.ChaosType.S3_BUCKET_POLICY_DENY
    item = make_experiment(kind, action_configs()[kind], aws)
    item._in_rollback = recovery
    with pytest.raises(framework.SafetyViolation):
        getattr(item.client(service), operation)()
    assert not aws.calls
    assert not item.mutation_attempts and not item.rollback_attempts


@pytest.mark.parametrize(
    "kind,attributes",
    [
        (
            UNSAFE[0],
            {
                "bucket_name": "owned-test-bucket",
                "owned_policy_statement": {},
                "mutation_attempts": ["s3.put_bucket_policy"],
            },
        ),
        (UNSAFE[1], {"topic_arn": "owned-test-topic", "owned_policy_statement": {}}),
        (
            UNSAFE[2],
            {"volume_id": "vol-test", "original_iops": 1000, "requested_iops": 500},
        ),
        (
            UNSAFE[3],
            {
                "domain_name": "owned-test-domain",
                "original_instance_count": 3,
                "requested_instance_count": 1,
            },
        ),
        (
            UNSAFE[4],
            {
                "group_id": "sg-test",
                "removed_rule": {},
                "ingress_write_confirmed": False,
            },
        ),
    ],
)
@pytest.mark.parametrize("dry_run", [False, True])
def test_legacy_recovery_state_does_not_restore_unconditionally(
    kind, attributes, dry_run
):
    aws = FakeAWS(reject_writes=False)
    if not dry_run:
        with pytest.raises(
            framework.ConfigurationError, match="Live approval is unavailable"
        ):
            make_experiment(kind, action_configs()[kind], aws, dry_run=False)
        assert not aws.calls
        return
    item = make_experiment(kind, action_configs()[kind], aws)
    for key, value in attributes.items():
        setattr(item, key, value)
    # The live case already refused construction and returned above.
    item.rollback()
    assert not aws.calls
    assert not item.rollback_verified


@pytest.mark.parametrize(
    "kind,method",
    [
        (framework.ChaosType.WAF_RULE_MODIFY, "modify_rule"),
        (framework.ChaosType.WAF_RATE_LIMIT_MODIFY, "modify_rate_limit"),
    ],
)
@pytest.mark.parametrize("outcome", ["exception", "poststate_mismatch", "confirmed"])
def test_waf_rollback_needs_confirmed_forward_write(kind, method, outcome):
    aws = FakeAWS(reject_writes=False)
    values = action_configs()[kind]
    before = aws.respond("wafv2", "get_web_acl", {})
    changed = copy.deepcopy(before)
    if method == "modify_rule":
        changed["WebACL"]["Rules"][0]["Action"] = {"Count": {}}
    else:
        changed["WebACL"]["Rules"][0]["Statement"]["RateBasedStatement"]["Limit"] = (
            values["limit"]
        )
    aws.read_overrides[("wafv2", "get_web_acl")] = [
        before,
        changed if outcome == "confirmed" else before,
        changed,
        before,
    ]
    respond = aws.respond

    def ordinary_response(service, operation, request):
        if operation == "update_web_acl" and outcome == "exception":
            aws.calls.append((service, operation, request))
            raise TimeoutError("synthetic unavailable response")
        return respond(service, operation, request)

    aws.respond = ordinary_response
    aws.calls.clear()
    item = make_experiment(kind, values, aws, dry_run=False)
    result = getattr(item, method)(**values)
    assert item.rule_write_confirmed is (outcome == "confirmed")
    if outcome == "confirmed":
        assert result.status == "completed"
        item.run_rollback()
        assert len([c for c in aws.calls if c[1] == "update_web_acl"]) == 2
        assert all(c[2]["LockToken"] for c in aws.calls if c[1] == "update_web_acl")
    else:
        assert result.status == "failed"
        before_calls = len(aws.calls)
        with pytest.raises(framework.SafetyViolation, match="not confirmed"):
            item.run_rollback()
        assert len(aws.calls) == before_calls


def test_native_sdk_shapes_support_only_waf_conditional_policy_update():
    session = botocore.session.get_session()
    for service, operation in [
        ("s3", "PutBucketPolicy"),
        ("sns", "SetTopicAttributes"),
        ("ec2", "ModifyVolume"),
        ("opensearch", "UpdateDomainConfig"),
        ("ec2", "RevokeSecurityGroupIngress"),
    ]:
        shape = (
            session.get_service_model(service).operation_model(operation).input_shape
        )
        assert not {"IfMatch", "RevisionId", "LockToken"} & set(shape.members)
    shape = (
        session.get_service_model("wafv2").operation_model("UpdateWebACL").input_shape
    )
    assert "LockToken" in shape.required_members


def test_bounded_source_positive_regular_file_and_preopen_size_refusal(
    tmp_path, monkeypatch
):
    (tmp_path / "data.txt").write_bytes(b"hello")
    assert source_files.read_bytes(tmp_path, "data.txt", 5) == b"hello"
    with monkeypatch.context() as scoped:
        scoped.setattr(
            source_files,
            "_file_descriptor",
            lambda *_: pytest.fail("oversized input was opened"),
        )
        with pytest.raises(ValueError, match="before opening"):
            source_files.read_bytes(tmp_path, "data.txt", 4)
    assert source_files.read_text(tmp_path, "data.txt", 5) == "hello"


@pytest.mark.parametrize(
    "relative", ["../data.txt", "/data.txt", "x\\data.txt", "x:data.txt", "x//data.txt"]
)
def test_source_path_refusal_precedes_filesystem_access(
    tmp_path, monkeypatch, relative
):
    monkeypatch.setattr(
        source_files, "_root", lambda *_: pytest.fail("unsafe path reached filesystem")
    )
    with pytest.raises(ValueError, match="path"):
        source_files.read_bytes(tmp_path, relative)


@pytest.mark.parametrize(
    "mode,attributes", [(stat.S_IFLNK, 0), (stat.S_IFIFO, 0), (stat.S_IFREG, 0x400)]
)
def test_synthetic_nonregular_metadata_refused_before_open(
    tmp_path, monkeypatch, mode, attributes
):
    # In-memory metadata only. No special file, junction or other hostile object.
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda self: SimpleNamespace(st_mode=mode, st_file_attributes=attributes),
    )
    with pytest.raises(ValueError):
        source_files._metadata(tmp_path / "synthetic", False)


def test_preparse_sources_share_bounded_reader(tmp_path, monkeypatch):
    calls = []

    def admitted(root, name, *args):
        calls.append(name)
        raise ValueError("synthetic admission refused")

    monkeypatch.setattr(prepare_release.source_files, "read_text", admitted)
    for read in (
        prepare_release.read_project_version,
        prepare_release.read_runtime_version,
        prepare_release.parse_runtime_dependencies,
    ):
        with pytest.raises(ValueError, match="admission"):
            read(tmp_path)
    with pytest.raises(ValueError, match="admission"):
        prepare_release.read_release_date(tmp_path, "2.0.4")
    monkeypatch.setattr(verify_distribution.source_files, "read_text", admitted)
    with pytest.raises(ValueError):
        verify_distribution._approved_project(tmp_path)
    with pytest.raises(ValueError, match="admission"):
        verify_distribution._approved_source_files(tmp_path)
    assert set(calls) == {
        "pyproject.toml",
        "aws_chaos_framework.py",
        "requirements.txt",
        "CHANGELOG.md",
        "MANIFEST.in",
    }


def outer_zip(tmp_path, names=None):
    path = tmp_path / "artifact.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in names or [f"leaf-{index}.txt" for index in range(6)]:
            archive.writestr(name, b"small ordinary fixture")
    return path


def test_small_outer_zip_admission_and_count_before_parser(tmp_path, monkeypatch):
    path = outer_zip(tmp_path)
    assert len(downloader.admit_outer_archive(path)) == 6
    path = outer_zip(tmp_path, [f"leaf-{index}.txt" for index in range(7)])
    monkeypatch.setattr(
        downloader.archive_budget.zipfile,
        "ZipFile",
        lambda *_: pytest.fail("count exceeded before ZIP parser"),
    )
    with pytest.raises(ValueError, match="count"):
        downloader.admit_outer_archive(path)


@pytest.mark.parametrize(
    "names",
    [
        ["same.txt", "SAME.txt", "a", "b", "c", "d"],
        ["nested/a", "b", "c", "d", "e", "f"],
        ["CON.txt", "b", "c", "d", "e", "f"],
    ],
)
def test_small_outer_names_are_flat_and_portable(tmp_path, names):
    with pytest.raises((ValueError, downloader.release.ReleaseError)):
        downloader.admit_outer_archive(outer_zip(tmp_path, names))


class Response(io.BytesIO):
    def __init__(self, value, headers=None):
        super().__init__(value)
        self.headers = (
            {"Content-Length": str(len(value))} if headers is None else headers
        )


@pytest.mark.parametrize(
    "failure", [None, "digest", "run", "expired", "declared", "extra"]
)
def test_mock_download_binds_identity_digest_and_preserves_output(
    tmp_path, monkeypatch, failure
):
    path = outer_zip(
        tmp_path, [f"leaf-{i}.txt" for i in range(7 if failure == "extra" else 6)]
    )
    value = path.read_bytes()
    digest = "sha256:" + hashlib.sha256(value).hexdigest()
    metadata = {
        "id": 12,
        "workflow_run": {"id": 34},
        "expired": False,
        "name": "release-assets",
        "size_in_bytes": len(value),
        "digest": digest,
    }
    if failure == "digest":
        metadata["digest"] = "sha256:" + "0" * 64
    if failure == "run":
        metadata["workflow_run"]["id"] = 35
    if failure == "expired":
        metadata["expired"] = True
    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            if request.full_url.endswith("/12"):
                return Response(json.dumps(metadata).encode())
            if request.full_url.endswith("/zip"):
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "storage",
                    {"Location": "https://storage.example/artifact"},
                    Response(b""),
                )
            assert request.get_header("Authorization") is None
            headers = (
                {"Content-Length": str(downloader.archive_budget.MAX_ARCHIVE_BYTES + 1)}
                if failure == "declared"
                else None
            )
            return Response(value, headers)

    monkeypatch.setenv("GH_TOKEN", "synthetic-artifact-read-token")
    monkeypatch.setattr(downloader.urllib.request, "build_opener", lambda *_: Opener())
    output = tmp_path / "output"
    if failure:
        with pytest.raises(ValueError):
            downloader.download("owner/repo", 12, 34, output)
        assert not output.exists()
    else:
        result = downloader.download("owner/repo", 12, 34, output)
        assert result["digest"] == digest
        assert len(list(output.iterdir())) == 6
        saved = {p.name: p.read_bytes() for p in output.iterdir()}
        with pytest.raises(ValueError, match="must be new"):
            downloader.download("owner/repo", 12, 34, output)
        assert saved == {p.name: p.read_bytes() for p in output.iterdir()}
    assert all(
        request.get_header("Authorization")
        for request in calls
        if request.full_url.startswith("https://api.github.com/")
    )


def test_transport_actual_byte_and_deadline_budgets_are_enforced(monkeypatch):
    with pytest.raises(ValueError, match="actual byte"):
        downloader._read(Response(b"small", {}), 4, float("inf"))
    monkeypatch.setattr(downloader.time, "monotonic", lambda: 10)
    with pytest.raises(ValueError, match="deadline"):
        downloader._read(Response(b"small"), 10, 9)


def test_protected_jobs_consume_only_verifier_uploaded_artifact():
    import yaml

    root = Path(__file__).resolve().parents[1]
    jobs = yaml.safe_load(
        (root / ".github/workflows/release-promotion.yml").read_text()
    )["jobs"]
    verified = next(s for s in jobs["verify"]["steps"] if s.get("id") == "verified")
    assert verified["with"]["compression-level"] == 0
    assert (
        jobs["verify"]["outputs"]["artifact-id"]
        == "${{ steps.verified.outputs.artifact-id }}"
    )
    for name in ("attest", "draft"):
        assert jobs[name]["environment"] == "release"
        steps = [
            s
            for s in jobs[name]["steps"]
            if "download_release_artifact.py" in s.get("run", "")
        ]
        assert len(steps) == 1
        assert (
            steps[0]["env"]["ARTIFACT_ID"] == "${{ needs.verify.outputs.artifact-id }}"
        )
        assert (
            steps[0]["env"]["ARTIFACT_RUN_ID"]
            == "${{ needs.verify.outputs.artifact-run-id }}"
        )
        assert "--expected-digest" in steps[0]["run"]
    assert not any(
        "download-artifact@" in s.get("uses", "")
        for job in jobs.values()
        for s in job["steps"]
    )


@pytest.mark.parametrize(
    "fail_on,body_failure", [(None, False), (None, True), (2, False), (4, False)]
)
def test_posix_descriptor_chain_closes_acquired_objects_on_every_exit(
    monkeypatch, fail_on, body_failure
):
    """Synthetic descriptor identities prove unwinding, not native hostile paths."""
    from pathlib import PurePosixPath

    acquired = []
    closed = []
    calls = []

    def open_descriptor(path, flags, *, dir_fd=None):
        calls.append((path, flags, dir_fd))
        if len(calls) == fail_on:
            raise OSError("ordinary acquisition failure")
        descriptor = 100 + len(calls)
        acquired.append(descriptor)
        return descriptor

    fake_os = SimpleNamespace(
        name="posix",
        O_RDONLY=0,
        O_DIRECTORY=0x10000,
        O_NOFOLLOW=0x20000,
        O_NONBLOCK=0x40000,
        open=open_descriptor,
        close=closed.append,
    )
    monkeypatch.setattr(source_files, "os", fake_os)
    if fail_on or body_failure:
        with (
            pytest.raises(OSError, match="ordinary"),
            source_files._file_descriptor(
                PurePosixPath("/owned/fixture"), ("data.txt",)
            ),
        ):
            if body_failure:
                raise OSError("ordinary bounded-read failure")
    else:
        with source_files._file_descriptor(
            PurePosixPath("/owned/fixture"), ("data.txt",)
        ) as descriptor:
            assert descriptor == acquired[-1]
            assert not closed
    assert closed == list(reversed(acquired))
    assert len(closed) == len(set(closed))
    assert all(flags & fake_os.O_NOFOLLOW for _, flags, _ in calls)
    assert calls[0][2] is None
    for index, (_, _, parent) in enumerate(calls[1:], 1):
        assert parent == acquired[index - 1]


@pytest.mark.parametrize("newline", [b"\r\n", b"\r"])
def test_admitted_text_matches_universal_newlines_without_altering_source_bytes(
    tmp_path, newline
):
    data = newline.join([b"include README.md", b"include MANIFEST.in", b""])
    (tmp_path / "MANIFEST.in").write_bytes(data)
    assert (
        source_files.read_text(tmp_path, "MANIFEST.in")
        == "include README.md\ninclude MANIFEST.in\n"
    )
    assert source_files.read_bytes(tmp_path, "MANIFEST.in") == data


@pytest.mark.parametrize("failure", [False, True])
def test_posix_directory_owner_has_one_entry_and_idempotent_release(
    monkeypatch, failure
):
    calls = []
    closed = []

    def open_descriptor(path, flags, *, dir_fd=None):
        calls.append((path, flags, dir_fd))
        if failure:
            raise OSError("ordinary directory acquisition failure")
        return 42

    fake_os = SimpleNamespace(
        O_RDONLY=0,
        O_DIRECTORY=1,
        O_NOFOLLOW=2,
        open=open_descriptor,
        close=closed.append,
    )
    monkeypatch.setattr(source_files, "os", fake_os)
    owner = source_files._PosixDirectory("owned", dir_fd=41)
    assert not calls and not closed
    if failure:
        with pytest.raises(OSError, match="ordinary directory"):
            owner.__enter__()
    else:
        assert owner.__enter__() == 42
    with pytest.raises(ValueError, match="only once"):
        owner.__enter__()
    owner.close()
    owner.close()
    owner.__exit__(None, None, None)
    assert calls == [("owned", 3, 41)]
    assert closed == ([] if failure else [42])
    with pytest.raises(ValueError, match="only once"):
        owner.__enter__()


def test_posix_directory_owner_does_not_retry_failed_close(monkeypatch):
    closed = []

    def close_descriptor(descriptor):
        closed.append(descriptor)
        raise OSError("ordinary close failure")

    fake_os = SimpleNamespace(
        O_RDONLY=0,
        O_DIRECTORY=1,
        O_NOFOLLOW=2,
        open=lambda *a, **k: 43,
        close=close_descriptor,
    )
    monkeypatch.setattr(source_files, "os", fake_os)
    owner = source_files._PosixDirectory("owned")
    assert owner.__enter__() == 43
    with pytest.raises(OSError, match="ordinary close failure"):
        owner.close()
    owner.close()
    assert closed == [43]
