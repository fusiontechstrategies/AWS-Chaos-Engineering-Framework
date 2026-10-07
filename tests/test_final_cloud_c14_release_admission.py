"""Public release assets are admitted by size and read only as fixed subjects.

1. Checksum and evidence manifests are untrusted until provenance is verified.
   The trusted helper accepts only the six fixed basenames, never joins a
   manifest name to a path, opens regular non-symlink files with bounded
   streaming, and refuses files that change while they are read.
2. Release metadata is admitted by per-file and aggregate size before any
   download; each asset is streamed under its declared size and a deadline
   into a new private file, and publish_payload bounds its reads too.

Offline fakes only: no GitHub, network or credentials.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

from scripts import publish_payload
from scripts import release_asset_admission as admission

ROOT = Path(__file__).resolve().parents[1]
TAG = "v2.0.4"
COMMIT = "a" * 40
NAMES = tuple(admission.expected_assets(TAG))
SOURCE, WHEEL, SDIST, SBOM, SUMS, EVIDENCE = NAMES


def release(root: Path) -> Path:
    """Write a consistent six-asset release as prepare_release.py lays it out."""
    root.mkdir()
    for name, value in (
        (SOURCE, b"print('synthetic standalone runtime')\n"),
        (WHEEL, b"synthetic wheel bytes"),
        (SDIST, b"synthetic sdist bytes"),
        (SBOM, b'{"spdxVersion": "SPDX-2.3"}\n'),
    ):
        (root / name).write_bytes(value)
    sums = "".join(
        f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n"
        for name in NAMES[:4]
    )
    (root / SUMS).write_bytes(sums.encode("ascii"))
    write_evidence(root)
    return root


def write_evidence(root: Path, **overrides) -> None:
    evidence = {
        "artifacts": [
            {
                "bytes": (root / name).stat().st_size,
                "name": name,
                "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
            }
            for name in NAMES[:5]
        ],
        "expected_release_assets": list(NAMES),
        "schema_version": 1,
        "source_commit": COMMIT,
        "tag": TAG,
        "version": TAG[1:],
        **overrides,
    }
    (root / EVIDENCE).write_text(json.dumps(evidence, indent=2), "utf-8")


def resum(root: Path, lines: list[str]) -> None:
    (root / SUMS).write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    write_evidence(root)


def sums_lines(root: Path) -> list[str]:
    return (root / SUMS).read_text("ascii").splitlines()


def test_valid_expected_subjects_and_hashes_succeed(tmp_path):
    root = release(tmp_path / "release-assets")
    source = tmp_path / "aws_chaos_framework.py"
    source.write_bytes((root / SOURCE).read_bytes())
    result = admission.verify_assets(root, TAG, COMMIT, source)
    assert set(result) == set(NAMES)
    for name in NAMES:
        data = (root / name).read_bytes()
        assert result[name] == {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    source.write_bytes(b"different tagged source")
    with pytest.raises(admission.AdmissionError, match="tagged source"):
        admission.verify_assets(root, TAG, COMMIT, source)


@pytest.mark.parametrize(
    "name,reason",
    [
        ("/etc/passwd", "absolute"),
        ("\\\\server\\share", "absolute"),
        ("C:\\Windows\\win.ini", "absolute"),
        ("C:relative", "absolute"),
        (SOURCE + ":stream", "absolute"),
        ("../" + SOURCE, "separator"),
        ("nested/" + SOURCE, "separator"),
        ("nested\\" + SOURCE, "separator"),
        ("..", "traverses"),
        (".." + SOURCE, "traverses"),
        (SOURCE + "\x00", "control"),
        (SOURCE + "\n", "control"),
        ("\u202e" + SOURCE, "control"),
        ("", "missing"),
        ("x" * 256, "too long"),
        ("unexpected.whl", "Unexpected"),
    ],
)
def test_name_parser_rejects_each_unsafe_category(name, reason):
    allowed = NAMES if reason == "Unexpected" else (*NAMES, name)
    with pytest.raises(admission.AdmissionError, match=reason):
        admission.admit_name(name, allowed)
    assert admission.admit_name(SOURCE, NAMES) == SOURCE


@pytest.mark.parametrize(
    "name",
    [
        "/etc/passwd",
        "\\\\server\\share",
        "C:\\Windows\\win.ini",
        "C:relative",
        "../SHA256SUMS.txt",
        "..",
        "nested/" + SOURCE,
        "nested\\" + SOURCE,
        SOURCE + "\x00",
        SOURCE + "\n",
        "\u202e" + SOURCE,
        "unexpected.whl",
        SUMS,
    ],
)
def test_checksum_manifest_rejects_paths_controls_and_unexpected_names(tmp_path, name):
    root = release(tmp_path / "release-assets")
    lines = sums_lines(root)
    lines[0] = lines[0][:66] + name
    resum(root, lines)
    with pytest.raises(admission.AdmissionError):
        admission.verify_assets(root, TAG, COMMIT)


def test_checksum_manifest_rejects_duplicates_missing_and_wrong_digest(tmp_path):
    root = release(tmp_path / "release-assets")
    lines = sums_lines(root)
    for changed, reason in (
        ([*lines, lines[0]], "twice"),
        (lines[1:], "every subject"),
        (["0" * 64 + lines[0][64:], *lines[1:]], "checksum subject"),
        ([lines[0].replace("  ", " *", 1), *lines[1:]], "invalid line format"),
    ):
        resum(root, changed)
        with pytest.raises(admission.AdmissionError, match=reason):
            admission.verify_assets(root, TAG, COMMIT)


@pytest.mark.parametrize(
    "name",
    ["/etc/passwd", "../" + WHEEL, "sub/" + WHEEL, WHEEL + "\x1b", "other.whl"],
)
def test_evidence_names_are_only_compared_never_opened(tmp_path, name, monkeypatch):
    root = release(tmp_path / "release-assets")
    evidence = json.loads((root / EVIDENCE).read_text("utf-8"))
    evidence["artifacts"][1]["name"] = name
    (root / EVIDENCE).write_text(json.dumps(evidence), "utf-8")
    opened = []
    real_open = os.open
    monkeypatch.setattr(
        admission.os,
        "open",
        lambda path, *args, **kwargs: (
            opened.append(Path(path)) or real_open(path, *args, **kwargs)
        ),
    )
    with pytest.raises(admission.AdmissionError):
        admission.verify_assets(root, TAG, COMMIT)
    # Only the asset directory and its fixed children were ever opened.
    assert all(
        path == root or (path.name in NAMES and path.parent in {root, Path(".")})
        for path in opened
    )


@pytest.mark.parametrize(
    "change",
    [
        {"tag": "v2.0.3"},
        {"version": "2.0.3"},
        {"source_commit": "b" * 40},
        {"schema_version": 2},
        {"expected_release_assets": [*NAMES[:5], NAMES[0]]},
        {"expected_release_assets": [*NAMES, "extra.txt"]},
    ],
)
def test_evidence_identity_and_asset_set_are_exact(tmp_path, change):
    root = release(tmp_path / "release-assets")
    write_evidence(root, **change)
    with pytest.raises(admission.AdmissionError):
        admission.verify_assets(root, TAG, COMMIT)


def test_evidence_rejects_duplicate_subjects_keys_and_mismatches(tmp_path):
    root = release(tmp_path / "release-assets")
    evidence = json.loads((root / EVIDENCE).read_text("utf-8"))
    duplicate = dict(
        evidence, artifacts=[*evidence["artifacts"][:4], evidence["artifacts"][0]]
    )
    variants = [
        json.dumps(duplicate),
        json.dumps(evidence)[:-1] + ', "tag": "v2.0.4"}',
        json.dumps(
            dict(
                evidence,
                artifacts=[
                    dict(evidence["artifacts"][0], bytes=True),
                    *evidence["artifacts"][1:],
                ],
            )
        ),
        json.dumps(
            dict(
                evidence,
                artifacts=[
                    dict(evidence["artifacts"][0], sha256="0" * 64),
                    *evidence["artifacts"][1:],
                ],
            )
        ),
    ]
    reasons = [
        "twice",
        "Duplicate JSON key",
        "Invalid release evidence subject",
        "evidence subject",
    ]
    for value, reason in zip(variants, reasons, strict=True):
        (root / EVIDENCE).write_text(value, "utf-8")
        with pytest.raises(admission.AdmissionError, match=reason):
            admission.verify_assets(root, TAG, COMMIT)


def test_directory_must_hold_exactly_the_six_regular_assets(tmp_path):
    root = release(tmp_path / "release-assets")
    (root / "extra.txt").write_bytes(b"x")
    with pytest.raises(admission.AdmissionError, match="Unexpected"):
        admission.verify_assets(root, TAG, COMMIT)
    (root / "extra.txt").unlink()
    (root / SBOM).unlink()
    with pytest.raises(admission.AdmissionError, match="exactly six"):
        admission.verify_assets(root, TAG, COMMIT)


def test_symlinked_asset_and_directory_are_rejected(tmp_path):
    root = release(tmp_path / "release-assets")
    outside = tmp_path / "outside.bin"
    outside.write_bytes((root / WHEEL).read_bytes())
    (root / WHEEL).unlink()
    try:
        os.symlink(outside, root / WHEEL)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable on this host")
    with pytest.raises(admission.AdmissionError, match="regular"):
        admission.verify_assets(root, TAG, COMMIT)
    linked = tmp_path / "linked-assets"
    os.symlink(release(tmp_path / "real-assets"), linked, target_is_directory=True)
    with pytest.raises(admission.AdmissionError, match="real directory"):
        admission.verify_assets(linked, TAG, COMMIT)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs need POSIX")
def test_fifo_asset_is_rejected_without_blocking(tmp_path):
    root = release(tmp_path / "release-assets")
    (root / SBOM).unlink()
    os.mkfifo(root / SBOM)
    with pytest.raises(admission.AdmissionError, match="regular"):
        admission.verify_assets(root, TAG, COMMIT)


@pytest.mark.parametrize("mode", [stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO])
def test_device_and_special_types_are_rejected_before_open(tmp_path, monkeypatch, mode):
    root = release(tmp_path / "release-assets")
    real_lstat = os.lstat

    def special(path, *args, **kwargs):
        value = real_lstat(path, *args, **kwargs)
        if Path(path).name == SBOM:
            fields = list(value)
            fields[0] = mode | 0o600
            return os.stat_result(fields)
        return value

    def refuse(*_args, **_kwargs):
        raise AssertionError("a special file must never be opened")

    monkeypatch.setattr(admission.os, "lstat", special)
    monkeypatch.setattr(admission.os, "open", refuse)
    with pytest.raises(admission.AdmissionError, match="regular"):
        admission.read_regular(root, SBOM, admission.MAX_SBOM_BYTES)


def test_file_replaced_between_check_and_open_is_rejected(tmp_path, monkeypatch):
    root = release(tmp_path / "release-assets")
    real_open = os.open

    def swap(path, *args, **kwargs):
        if Path(path).name == WHEEL:
            os.replace(tmp_path / "swapped", path)
        return real_open(path, *args, **kwargs)

    # Same size, so only the bound file identity reveals the replacement.
    (tmp_path / "swapped").write_bytes(b"x" * (root / WHEEL).stat().st_size)
    monkeypatch.setattr(admission.os, "open", swap)
    with pytest.raises(admission.AdmissionError, match="changed"):
        admission.read_regular(root, WHEEL, admission.MAX_ARCHIVE_BYTES)


def test_file_growing_during_the_read_is_rejected(tmp_path, monkeypatch):
    root = release(tmp_path / "release-assets")
    real_read = os.read
    grown = []

    def grow(descriptor, count):
        value = real_read(descriptor, count)
        if not grown:
            grown.append(True)
            with open(root / WHEEL, "ab") as handle:
                handle.write(b"appended while hashing")
        return value

    monkeypatch.setattr(admission.os, "read", grow)
    with pytest.raises(admission.AdmissionError, match="changed"):
        admission.read_regular(root, WHEEL, admission.MAX_ARCHIVE_BYTES)


def test_oversized_local_asset_is_rejected_before_open(tmp_path, monkeypatch):
    root = release(tmp_path / "release-assets")
    (root / SUMS).write_bytes(b"0" * (admission.MAX_CHECKSUMS_BYTES + 1))
    real_open = os.open

    def refuse_assets(path, *args, **kwargs):
        if Path(path).name in NAMES:
            pytest.fail("an asset was opened before every size was admitted")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(admission.os, "open", refuse_assets)
    with pytest.raises(admission.AdmissionError, match="byte limit"):
        admission.verify_assets(root, TAG, COMMIT)
    # A direct read admits the size before opening as well.
    with pytest.raises(admission.AdmissionError, match="byte limit"):
        admission.read_regular(root, SUMS, admission.MAX_CHECKSUMS_BYTES)


def test_local_aggregate_and_types_are_admitted_before_any_open(tmp_path, monkeypatch):
    root = release(tmp_path / "release-assets")
    real_open = os.open

    def refuse_assets(path, *args, **kwargs):
        if Path(path).name in NAMES:
            pytest.fail("an asset was opened before every asset was admitted")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(admission.os, "open", refuse_assets)
    monkeypatch.setattr(admission, "MAX_RELEASE_BYTES", 16)
    with pytest.raises(admission.AdmissionError, match="aggregate"):
        admission.verify_assets(root, TAG, COMMIT)
    monkeypatch.undo()
    real_lstat = os.lstat

    def special(path, *args, **kwargs):
        value = real_lstat(path, *args, **kwargs)
        if Path(path).name == SBOM:
            fields = list(value)
            fields[0] = stat.S_IFCHR | 0o600
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(admission.os, "open", refuse_assets)
    monkeypatch.setattr(admission.os, "lstat", special)
    with pytest.raises(admission.AdmissionError, match="regular"):
        admission.verify_assets(root, TAG, COMMIT)


# 2. Size admission before download and bounded streaming.


def metadata(sizes=None, payload=None, **overrides):
    sizes = sizes or {}
    payload = payload or PAYLOAD
    assets = [
        {
            "id": index + 100,
            "name": name,
            "size": sizes.get(name, len(payload[name])),
            "state": "uploaded",
            "digest": "sha256:" + hashlib.sha256(payload[name]).hexdigest(),
        }
        for index, name in enumerate(NAMES)
    ]
    return {
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "assets": assets,
        **overrides,
    }


PAYLOAD = {name: f"synthetic {name}\n".encode() for name in NAMES}


@pytest.mark.parametrize(
    "change",
    [
        {"sizes": {WHEEL: admission.MAX_ARCHIVE_BYTES + 1}},
        {"sizes": {SUMS: admission.MAX_CHECKSUMS_BYTES + 1}},
        {"sizes": {EVIDENCE: admission.MAX_EVIDENCE_BYTES + 1}},
        {"sizes": {WHEEL: 0}},
        {"tag_name": "v2.0.3"},
        {"draft": True},
        {"prerelease": None},
    ],
)
def test_metadata_admission_rejects_size_and_identity_violations(change):
    sizes = change.pop("sizes", None)
    with pytest.raises(admission.AdmissionError):
        admission.admit_release_metadata(metadata(sizes, **change), TAG)


def test_metadata_admission_enforces_the_aggregate_independently():
    sizes = {
        SOURCE: admission.MAX_SOURCE_BYTES,
        WHEEL: admission.MAX_ARCHIVE_BYTES,
        SDIST: admission.MAX_ARCHIVE_BYTES,
    }
    assert all(sizes[name] <= admission.expected_assets(TAG)[name] for name in sizes)
    with pytest.raises(admission.AdmissionError, match="aggregate"):
        admission.admit_release_metadata(metadata(sizes), TAG)


def test_metadata_admission_rejects_unexpected_duplicate_and_bad_records():
    for mutate, reason in (
        (
            lambda assets: assets.__setitem__(0, dict(assets[0], name="../" + SOURCE)),
            "separator",
        ),
        (lambda assets: assets.__setitem__(0, dict(assets[1])), "twice"),
        (lambda assets: assets.pop(), "asset set"),
        (
            lambda assets: assets.append(dict(assets[0], name="extra.txt")),
            "asset set",
        ),
        (
            lambda assets: assets.__setitem__(0, dict(assets[0], size=True)),
            "admission limits",
        ),
        (
            lambda assets: assets.__setitem__(0, dict(assets[0], id="100")),
            "admission limits",
        ),
        (
            lambda assets: assets.__setitem__(0, dict(assets[0], state="starter")),
            "admission limits",
        ),
        (
            lambda assets: assets.__setitem__(0, dict(assets[0], digest="md5:00")),
            "invalid digest",
        ),
    ):
        value = metadata()
        mutate(value["assets"])
        with pytest.raises(admission.AdmissionError, match=reason):
            admission.admit_release_metadata(value, TAG)
    assert set(admission.admit_release_metadata(metadata(), TAG)) == set(NAMES)


class Response(io.BytesIO):
    def __init__(self, value, headers=None):
        super().__init__(value)
        self.headers = {} if headers is None else headers


class Transport:
    """Model the release API, its storage redirect and asset storage."""

    def __init__(self, release_metadata, served=None):
        self.metadata = release_metadata
        self.served = served or PAYLOAD
        self.requests = []

    def open(self, request, timeout):
        assert timeout == admission.READ_TIMEOUT_SECONDS
        self.requests.append(request)
        url = request.full_url
        if url.endswith(f"/releases/tags/{TAG}"):
            assert request.get_header("Authorization")
            return Response(json.dumps(self.metadata).encode())
        if "/releases/assets/" in url:
            assert request.get_header("Authorization")
            assert request.get_header("Accept") == "application/octet-stream"
            identifier = int(url.rsplit("/", 1)[1])
            raise urllib.error.HTTPError(
                url,
                302,
                "storage",
                {"Location": f"https://storage.example/{identifier}"},
                Response(b""),
            )
        assert url.startswith("https://storage.example/")
        assert request.get_header("Authorization") is None
        name = NAMES[int(url.rsplit("/", 1)[1]) - 100]
        return Response(self.served[name])


def install(monkeypatch, transport):
    monkeypatch.setenv("GH_TOKEN", "synthetic-release-read-token")
    monkeypatch.setattr(
        admission.urllib.request, "build_opener", lambda *_args: transport
    )


def test_valid_six_subject_release_downloads_and_verifies(tmp_path, monkeypatch):
    assets = release(tmp_path / "source-release")
    payload = {name: (assets / name).read_bytes() for name in NAMES}
    install(monkeypatch, Transport(metadata(payload=payload), payload))
    output = tmp_path / "release-assets"
    result = admission.download("owner/repo", TAG, output)
    assert sorted(path.name for path in output.iterdir()) == sorted(NAMES)
    assert result == admission.verify_assets(output, TAG, COMMIT)
    assert [path.name for path in tmp_path.iterdir() if path.name.startswith(".")] == []


def test_oversized_metadata_is_rejected_before_any_asset_request(tmp_path, monkeypatch):
    transport = Transport(metadata({WHEEL: admission.MAX_ARCHIVE_BYTES + 1}))
    install(monkeypatch, transport)
    output = tmp_path / "release-assets"
    with pytest.raises(admission.AdmissionError, match="admission limits"):
        admission.download("owner/repo", TAG, output)
    assert len(transport.requests) == 1
    assert not output.exists() and list(tmp_path.iterdir()) == []


def test_protected_job_can_admit_only_the_evidence_subject(tmp_path, monkeypatch):
    transport = Transport(metadata({WHEEL: admission.MAX_ARCHIVE_BYTES + 1}))
    install(monkeypatch, transport)
    # Even a single-subject download admits the complete release first.
    with pytest.raises(admission.AdmissionError):
        admission.download("owner/repo", TAG, tmp_path / "trusted", [EVIDENCE])
    transport = Transport(metadata())
    install(monkeypatch, transport)
    result = admission.download("owner/repo", TAG, tmp_path / "trusted", [EVIDENCE])
    assert list(result) == [EVIDENCE]
    assert [p.name for p in (tmp_path / "trusted").iterdir()] == [EVIDENCE]
    with pytest.raises(admission.AdmissionError):
        admission.download("owner/repo", TAG, tmp_path / "other", ["../x"])


@pytest.mark.parametrize("extra", [1, 4096])
def test_stream_exceeding_metadata_stops_and_cleans_up(tmp_path, monkeypatch, extra):
    served = dict(PAYLOAD)
    served[SDIST] = PAYLOAD[SDIST] + b"x" * extra
    transport = Transport(metadata(), served)
    install(monkeypatch, transport)
    output = tmp_path / "release-assets"
    with pytest.raises(admission.AdmissionError, match="byte limit"):
        admission.download("owner/repo", TAG, output)
    assert not output.exists() and list(tmp_path.iterdir()) == []


def test_short_stream_digest_mismatch_and_deadline_clean_up(tmp_path, monkeypatch):
    served = dict(PAYLOAD)
    served[SBOM] = PAYLOAD[SBOM][:-1]
    install(monkeypatch, Transport(metadata(), served))
    with pytest.raises(admission.AdmissionError, match="length"):
        admission.download("owner/repo", TAG, tmp_path / "short")
    served[SBOM] = bytes(255 - value for value in PAYLOAD[SBOM])
    install(monkeypatch, Transport(metadata(), served))
    with pytest.raises(admission.AdmissionError, match="digest"):
        admission.download("owner/repo", TAG, tmp_path / "forged")
    clock = iter(range(0, 10_000, 100))
    monkeypatch.setattr(admission.time, "monotonic", lambda: next(clock))
    install(monkeypatch, Transport(metadata()))
    with pytest.raises(admission.AdmissionError, match="deadline"):
        admission.download("owner/repo", TAG, tmp_path / "slow")
    assert list(tmp_path.iterdir()) == []


def test_declared_length_and_existing_output_are_refused(tmp_path, monkeypatch):
    with pytest.raises(admission.AdmissionError, match="declared"):
        admission.stream(Response(b"abc", {"Content-Length": "4"}), 3, float("inf"))
    output = tmp_path / "release-assets"
    output.mkdir()
    install(monkeypatch, Transport(metadata()))
    with pytest.raises(admission.AdmissionError, match="must be new"):
        admission.download("owner/repo", TAG, output)
    assert list(output.iterdir()) == []


def test_publish_payload_bounds_evidence_and_package_reads(tmp_path, monkeypatch):
    root = tmp_path / "release-assets"
    root.mkdir()
    for name in publish_payload.expected_names(TAG):
        (root / name).write_bytes(b"package " + name.encode())
    (root / EVIDENCE).write_bytes(b" " * (publish_payload.MAX_EVIDENCE_BYTES + 1))
    with pytest.raises(ValueError, match="trusted verification input"):
        publish_payload.capture(root, tmp_path / "payload", TAG, COMMIT)
    assert not (tmp_path / "payload").exists()
    records = [
        {
            "name": name,
            "bytes": (root / name).stat().st_size,
            "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
        }
        for name in publish_payload.expected_names(TAG)
    ]
    (root / EVIDENCE).write_text(
        json.dumps({"tag": TAG, "source_commit": COMMIT, "artifacts": records}),
        "utf-8",
    )
    publish_payload.capture(root, tmp_path / "bounded", TAG, COMMIT)
    monkeypatch.setattr(publish_payload, "MAX_PACKAGE_BYTES", 8)
    with pytest.raises(ValueError, match="byte limit"):
        publish_payload.capture(root, tmp_path / "oversized", TAG, COMMIT)


def test_publish_capture_rejects_duplicate_evidence_records(tmp_path):
    root = tmp_path / "release-assets"
    root.mkdir()
    records = []
    for name in sorted(publish_payload.expected_names(TAG)):
        data = b"package " + name.encode()
        (root / name).write_bytes(data)
        records.append(
            {
                "name": name,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    forged = dict(records[0], sha256="0" * 64)
    (root / EVIDENCE).write_text(
        json.dumps(
            {"tag": TAG, "source_commit": COMMIT, "artifacts": [*records, forged]}
        ),
        "utf-8",
    )
    with pytest.raises(ValueError, match="Invalid release evidence"):
        publish_payload.capture(root, tmp_path / "payload", TAG, COMMIT)


def test_cli_verify_runs_isolated_and_prints_subjects(tmp_path):
    root = release(tmp_path / "release-assets")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/release_asset_admission.py"),
            "verify",
            str(root),
            "--tag",
            TAG,
            "--source-commit",
            COMMIT,
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert set(json.loads(result.stdout)) == set(NAMES)


def test_file_growing_past_its_limit_during_the_read_stops(tmp_path, monkeypatch):
    root = release(tmp_path / "release-assets")
    size = (root / WHEEL).stat().st_size
    real_read = os.read

    def grow(descriptor, count):
        with open(root / WHEEL, "ab") as handle:
            handle.write(b"x" * 8)
        return real_read(descriptor, count)

    monkeypatch.setattr(admission.os, "read", grow)
    with pytest.raises(admission.AdmissionError, match="byte limit"):
        admission.read_regular(root, WHEEL, size)


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not hasattr(os, "O_DIRECTORY"),
    reason="directory descriptors need POSIX",
)
def test_replaced_asset_directory_is_rejected(tmp_path, monkeypatch):
    root = release(tmp_path / "release-assets")
    other = release(tmp_path / "other-assets")
    real = admission._directory_descriptor
    monkeypatch.setattr(admission, "_directory_descriptor", lambda _path: real(other))
    with pytest.raises(admission.AdmissionError, match="directory changed"):
        admission.verify_assets(root, TAG, COMMIT)


def test_bytes_beyond_the_admitted_size_are_rejected(tmp_path, monkeypatch):
    root = release(tmp_path / "release-assets")
    real_read = os.read
    extra = []

    def longer(descriptor, count):
        value = real_read(descriptor, count)
        if value and not extra:
            extra.append(True)
            return value + b"x"
        return value

    monkeypatch.setattr(admission.os, "read", longer)
    with pytest.raises(admission.AdmissionError, match="changed while it was read"):
        admission.read_regular(root, WHEEL, admission.MAX_ARCHIVE_BYTES)


def test_same_size_rewrite_during_the_read_is_rejected(tmp_path, monkeypatch):
    root = release(tmp_path / "release-assets")
    path = root / WHEEL
    original = path.read_bytes()
    before = path.stat()
    real_read = os.read
    rewritten = []

    def rewrite(descriptor, count):
        value = real_read(descriptor, count)
        if not rewritten:
            rewritten.append(True)
            path.write_bytes(bytes(255 - byte for byte in original))
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 10**9))
        return value

    monkeypatch.setattr(admission.os, "read", rewrite)
    with pytest.raises(admission.AdmissionError, match="changed while it was read"):
        admission.read_regular(root, WHEEL, admission.MAX_ARCHIVE_BYTES)


def test_growth_after_the_final_read_is_rejected(tmp_path, monkeypatch):
    root = release(tmp_path / "release-assets")
    before = (root / WHEEL).stat()
    real_read = os.read

    def grow_at_end(descriptor, count):
        value = real_read(descriptor, count)
        if not value:
            with open(root / WHEEL, "ab") as handle:
                handle.write(b"late")
            # Keep the timestamp, so only the size comparison can detect it.
            os.utime(root / WHEEL, ns=(before.st_atime_ns, before.st_mtime_ns))
        return value

    monkeypatch.setattr(admission.os, "read", grow_at_end)
    with pytest.raises(admission.AdmissionError, match="changed while it was read"):
        admission.read_regular(root, WHEEL, admission.MAX_ARCHIVE_BYTES)
