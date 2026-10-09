"""Regressions for canonical release bytes and the hash-locked quick start.

Release tests use regular archives built by the current trusted scripts and
then altered only in raw representation bytes that decoded member views ignore.
Documentation tests read the repository files. Nothing contacts AWS or a
package index: the pip selection check uses a local ``--no-index`` directory.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest
import yaml

from scripts import normalize_sdist, normalize_wheel, prepare_release, publish_payload
from scripts import verify_release_handoff as handoff

ROOT = Path(__file__).resolve().parents[1]
SOURCE = subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
).strip()
EPOCH = 315532800
VERSION = "2.0.4"
WHEEL = f"aws_chaos_engineering_framework-{VERSION}-py3-none-any.whl"
SDIST = f"aws_chaos_engineering_framework-{VERSION}.tar.gz"
NOT_REGENERATED = "not byte-identical to its trusted canonical regeneration"
ZIP_GAP = "contiguously cover the bytes before the central directory"
ONE_MEMBER = "exactly one member with no trailing bytes"


@pytest.fixture(scope="module")
def release(tmp_path_factory):
    """Six assets prepared from the current tracked source by trusted scripts."""
    directory = tmp_path_factory.mktemp("c18-release")
    source = directory / "source"
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    for name in filter(None, (value.decode() for value in names)):
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    dist = directory / "dist"
    environment = dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
            "--outdir",
            str(dist),
            str(source),
        ],
        capture_output=True,
        env=environment,
    )
    assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()
    normalize_wheel.normalize_wheel(dist / WHEEL, EPOCH)
    normalize_sdist.normalize_sdist(dist / SDIST, EPOCH)
    assets = directory / "assets"
    prepare_release.prepare_release(
        source, dist, assets, VERSION, "v" + VERSION, SOURCE, EPOCH
    )
    return source, assets


def candidate(tmp_path, assets, name, value):
    """Copy the six assets and substitute one candidate distribution."""
    copied = tmp_path / "assets"
    shutil.copytree(assets, copied)
    (copied / name).write_bytes(value)
    alone = tmp_path / "alone"
    alone.mkdir()
    (alone / name).write_bytes(value)
    return copied, alone


def zip_with_gap(value: bytes, where: str, payload: bytes) -> bytes:
    """Insert raw bytes after a local record and update every later offset."""
    end = value.rfind(b"PK\x05\x06")
    count, central_size, central_offset = struct.unpack(
        "<HII", value[end + 10 : end + 20]
    )
    records, position = [], central_offset
    for _ in range(count):
        record = bytearray(value[position : position + 46])
        name, extra, comment = struct.unpack("<3H", record[28:34])
        size = 46 + name + extra + comment
        records.append(record + value[position + 46 : position + size])
        position += size
    starts = sorted(struct.unpack("<I", record[42:46])[0] for record in records)
    at = starts[1] if where == "between-records" else central_offset
    for record in records:
        offset = struct.unpack("<I", record[42:46])[0]
        if offset >= at:
            record[42:46] = struct.pack("<I", offset + len(payload))
    footer = bytearray(value[end:])
    footer[16:20] = struct.pack("<I", central_offset + len(payload))
    return (
        value[:at]
        + payload
        + value[at:central_offset]
        + b"".join(records)
        + bytes(footer)
    )


def empty_gzip_member_with_header_fields() -> bytes:
    """An empty member whose optional header fields carry arbitrary bytes."""
    extra = b"XX" + struct.pack("<H", 6) + b"hidden"
    encoder = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    deflate = encoder.compress(b"") + encoder.flush()
    return (
        b"\x1f\x8b\x08\x1c"
        + struct.pack("<I", EPOCH)
        + b"\x00\xff"
        + struct.pack("<H", len(extra))
        + extra
        + b"unreviewed-name\x00"
        + b"unreviewed-comment\x00"
        + deflate
        + struct.pack("<II", 0, 0)
    )


def tar_header_field_change(sdist: bytes) -> bytes:
    """Change an ignored TAR header field and re-wrap it canonically."""
    tar = bytearray(gzip.decompress(sdist))
    header = tar[:512]
    header[329:337] = b"0000001\x00"
    header[148:156] = b" " * 8
    header[148:156] = b"%06o\x00 " % sum(header)
    tar[:512] = header
    return normalize_sdist.build_stored_gzip(bytes(tar), EPOCH)


def synthetic_wheel(path: Path) -> Path:
    values = {
        "synthetic.py": b"synthetic source\n",
        "synthetic-1.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: synthetic\n",
        "synthetic-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
    }
    record = io.StringIO(newline="")
    for name, data in values.items():
        digest = normalize_wheel.sha256_record_digest(data)
        record.write(f"{name},{digest},{len(data)}\n")
    record.write("synthetic-1.0.dist-info/RECORD,,\n")
    values["synthetic-1.0.dist-info/RECORD"] = record.getvalue().encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in values.items():
            archive.writestr(name, data)
    normalize_wheel.normalize_wheel(path, EPOCH)
    return path


def synthetic_sdist(path: Path) -> Path:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        data = b"synthetic source\n"
        member = tarfile.TarInfo("synthetic-1.0/source.py")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    path.write_bytes(gzip.compress(raw.getvalue(), mtime=EPOCH))
    normalize_sdist.normalize_sdist(path, EPOCH)
    return path


# Noncanonical wheel and sdist bytes can receive protected release provenance.


@pytest.mark.parametrize("where", ["between-records", "before-central-directory"])
def test_zip_gap_before_central_directory_is_refused_by_protected_admission(
    tmp_path, release, where
):
    source, assets = release
    original = (assets / WHEEL).read_bytes()
    gapped = zip_with_gap(original, where, b"unreviewed raw bytes")
    # The stdlib member view is unchanged, so only raw admission sees the gap.
    with (
        zipfile.ZipFile(io.BytesIO(gapped)) as archive,
        zipfile.ZipFile(io.BytesIO(original)) as reference,
    ):
        assert [m.filename for m in archive.infolist()] == [
            m.filename for m in reference.infolist()
        ]
        assert all(
            archive.read(m.filename) == reference.read(m) for m in reference.infolist()
        )
    copied, alone = candidate(tmp_path, assets, WHEEL, gapped)
    with pytest.raises(ValueError, match=ZIP_GAP):
        handoff.preflight_archives(alone)
    with pytest.raises(ValueError, match=ZIP_GAP):
        handoff.verify_handoff(copied, source, SOURCE, EPOCH)
    with pytest.raises(prepare_release.ReleaseError, match=ZIP_GAP):
        prepare_release.wheel_inventory(alone / WHEEL, EPOCH)
    with pytest.raises(normalize_wheel.WheelNormalizationError, match=ZIP_GAP):
        normalize_wheel.read_values(alone / WHEEL)


def test_zip_coverage_admits_streamed_data_descriptors_and_binds_them(tmp_path):
    """Streamed ZIPs (such as an outer Actions artifact) remain admissible."""

    class Unseekable(io.RawIOBase):
        def __init__(self):
            self.buffer = bytearray()

        def writable(self):
            return True

        def write(self, value):
            self.buffer += value
            return len(value)

    stream = Unseekable()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("first.txt", b"first")
        archive.writestr("second.txt", b"second")
    value = bytes(stream.buffer)
    assert value.count(b"PK\x07\x08") == 2
    path = tmp_path / "streamed.zip"
    path.write_bytes(value)
    with handoff.archive_budget.open_zip(path) as archive:
        assert archive.read("second.txt") == b"second"
    descriptor = value.index(b"PK\x07\x08")
    tampered = bytearray(value)
    tampered[descriptor + 4] ^= 0xFF
    path.write_bytes(bytes(tampered))
    with (
        pytest.raises(ValueError, match="data descriptor differs"),
        handoff.archive_budget.open_zip(path),
    ):
        pytest.fail("A data descriptor that differs from its central record")


def test_appended_empty_gzip_member_is_refused_by_every_admission(tmp_path, release):
    source, assets = release
    original = (assets / SDIST).read_bytes()
    appended = original + empty_gzip_member_with_header_fields()
    # Python's own decoder yields the same TAR, so only framing differs.
    assert gzip.decompress(appended) == gzip.decompress(original)
    copied, alone = candidate(tmp_path, assets, SDIST, appended)
    with pytest.raises(ValueError, match=ONE_MEMBER):
        handoff.preflight_archives(alone)
    with pytest.raises(ValueError, match=ONE_MEMBER):
        handoff.verify_handoff(copied, source, SOURCE, EPOCH)
    with pytest.raises(prepare_release.ReleaseError, match=ONE_MEMBER):
        prepare_release.sdist_inventory(alone / SDIST, VERSION, EPOCH)
    with pytest.raises(normalize_sdist.SdistNormalizationError, match=ONE_MEMBER):
        normalize_sdist.read_members(alone / SDIST)


@pytest.mark.parametrize("suffix", [b"\x00", b"unreviewed trailing bytes"])
def test_gzip_trailing_bytes_are_refused_even_outside_canonical_admission(
    tmp_path, suffix
):
    path = synthetic_sdist(tmp_path / "synthetic-1.0.tar.gz")
    path.write_bytes(path.read_bytes() + suffix)
    with (
        pytest.raises(ValueError, match=ONE_MEMBER),
        handoff.archive_budget.open_tar(path),
    ):
        pytest.fail("Trailing gzip bytes admitted")


@pytest.mark.parametrize("form", ["header-name", "deflate-level-6"])
def test_canonical_gzip_admission_refuses_other_single_member_serializations(
    tmp_path, form
):
    path = synthetic_sdist(tmp_path / "synthetic-1.0.tar.gz")
    tar = gzip.decompress(path.read_bytes())
    if form == "header-name":
        output = io.BytesIO()
        with gzip.GzipFile("synthetic.tar", "wb", 0, output, mtime=EPOCH) as encoder:
            encoder.write(tar)
        value = output.getvalue()
        message = "header is not canonical"
    else:
        value = gzip.compress(tar, compresslevel=6, mtime=EPOCH)
        message = "canonical stored-block serialization"
    path.write_bytes(value)
    # The normalizer still reads such ordinary single-member input.
    assert normalize_sdist.read_members(path)[0][1] == b"synthetic source\n"
    with (
        pytest.raises(ValueError, match=message),
        handoff.archive_budget.open_tar(path, canonical_gzip=True),
    ):
        pytest.fail("Noncanonical gzip serialization admitted")
    with pytest.raises(ValueError, match=message):
        handoff.preflight_archives(tmp_path)


@pytest.mark.parametrize("kind", ["wheel-local-header", "sdist-tar-header"])
def test_raw_bytes_outside_member_views_are_refused_before_release_evidence(
    tmp_path, release, kind
):
    """Semantically identical candidates pass admission but not regeneration."""
    source, assets = release
    if kind == "wheel-local-header":
        name = WHEEL
        value = wheel_local_header_change((assets / WHEEL).read_bytes())
    else:
        name = SDIST
        value = tar_header_field_change((assets / SDIST).read_bytes())
    copied, alone = candidate(tmp_path, assets, name, value)
    handoff.preflight_archives(alone)
    written = []
    real_write = prepare_release.write_exclusive
    original_load = handoff.load_trusted_helper

    def load(name):
        module = original_load(name)
        if name == "prepare_release":
            module.write_exclusive = lambda path, data: (
                written.append((path.parent.name, path.name)),
                real_write(path, data),
            )
        return module

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(handoff, "load_trusted_helper", load)
        with pytest.raises(RuntimeError, match=NOT_REGENERATED) as refused:
            handoff.verify_handoff(copied, source, SOURCE, EPOCH)
    assert type(refused.value).__name__ == "ReleaseError"
    # Only the private captured copies were written; no release output exists.
    assert written and all(parent == "dist" for parent, _name in written)
    dist = tmp_path / "dist"
    dist.mkdir()
    shutil.copyfile(copied / WHEEL, dist / WHEEL)
    shutil.copyfile(copied / SDIST, dist / SDIST)
    with pytest.raises(prepare_release.ReleaseError, match=NOT_REGENERATED):
        prepare_release.prepare_release(
            source, dist, tmp_path / "out", VERSION, "v" + VERSION, SOURCE, EPOCH
        )
    assert not (tmp_path / "out").exists()


def test_protected_handoff_regenerates_both_distributions_before_evidence(release):
    source, assets = release
    events = []
    original_load = handoff.load_trusted_helper

    def load(name):
        module = original_load(name)
        if name != "prepare_release":
            return module
        for normalizer, attribute in (
            (module.normalize_wheel, "normalize_wheel"),
            (module.normalize_sdist, "normalize_sdist"),
        ):
            real = getattr(normalizer, attribute)

            def regenerate(path, epoch, real=real):
                digest = real(path, epoch)
                events.append(("regenerated", path.name, path.read_bytes()))
                return digest

            setattr(normalizer, attribute, regenerate)
        real_write = module.write_exclusive

        def write(path, data):
            # Release outputs only; private captured copies are not assets.
            if path.parent.name == "rebuilt":
                events.append(("written", path.name, data))
            real_write(path, data)

        module.write_exclusive = write
        return module

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(handoff, "load_trusted_helper", load)
        result = handoff.verify_handoff(assets, source, SOURCE, EPOCH)
    assert result["tag"] == "v" + VERSION
    regenerated = {name: data for kind, name, data in events if kind == "regenerated"}
    assert regenerated == {
        WHEEL: (assets / WHEEL).read_bytes(),
        SDIST: (assets / SDIST).read_bytes(),
    }
    kinds = [kind for kind, _name, _data in events]
    assert kinds[:2] == ["regenerated", "regenerated"]
    assert "regenerated" not in kinds[2:] and "written" in kinds
    written = {name: data for kind, name, data in events if kind == "written"}
    assert written[WHEEL] == regenerated[WHEEL]
    assert written[SDIST] == regenerated[SDIST]


def test_regeneration_returns_only_bytes_equal_to_trusted_normalizers(tmp_path):
    wheel = synthetic_wheel(tmp_path / "synthetic-1.0-py3-none-any.whl")
    sdist = synthetic_sdist(tmp_path / "synthetic-1.0.tar.gz")
    assert prepare_release.regenerate_canonical_distributions(wheel, sdist, EPOCH) == (
        wheel.read_bytes(),
        sdist.read_bytes(),
    )
    sdist.write_bytes(tar_header_field_change(sdist.read_bytes()))
    with pytest.raises(prepare_release.ReleaseError, match=NOT_REGENERATED):
        prepare_release.regenerate_canonical_distributions(wheel, sdist, EPOCH)
    sdist.write_bytes(b"not a gzip member")
    with pytest.raises(prepare_release.ReleaseError, match="regenerated canonically"):
        prepare_release.regenerate_canonical_distributions(wheel, sdist, EPOCH)


def wheel_local_header_change(wheel: bytes) -> bytes:
    """Flip the first local record's modification time, which no reader uses."""
    value = bytearray(wheel)
    value[10:12] = struct.pack("<H", struct.unpack("<H", value[10:12])[0] ^ 1)
    return bytes(value)


def test_distribution_swapped_after_capture_cannot_change_validated_bytes(
    tmp_path, release, monkeypatch
):
    """Validation, regeneration and output all use the single captured bytes."""
    source, assets = release
    dist = tmp_path / "dist"
    dist.mkdir()
    originals = {name: (assets / name).read_bytes() for name in (WHEEL, SDIST)}
    for name, value in originals.items():
        (dist / name).write_bytes(value)
    real_capture = prepare_release.capture_distribution
    swapped = []

    def capture_then_swap(path):
        value = real_capture(path)
        # A concurrent writer replaces the input immediately after capture.
        path.write_bytes(b"swapped after capture")
        swapped.append(path.name)
        return value

    monkeypatch.setattr(prepare_release, "capture_distribution", capture_then_swap)
    output = tmp_path / "out"
    prepare_release.prepare_release(
        source, dist, output, VERSION, "v" + VERSION, SOURCE, EPOCH
    )
    assert sorted(swapped) == sorted(originals)
    assert all(
        (dist / name).read_bytes() == b"swapped after capture" for name in swapped
    )
    for name, value in originals.items():
        assert (output / name).read_bytes() == value
    assert (output / "release-evidence.json").read_bytes() == (
        assets / "release-evidence.json"
    ).read_bytes()


# A previously attested noncanonical distribution must not receive PyPI provenance.

LEGACY_SIGNER = (
    "https://github.com/owner/repo/.github/workflows/release-promotion.yml"
    "@refs/heads/main"
)


def legacy_attestation(subjects: dict[str, str]) -> list[dict]:
    """Model `gh attestation verify --format json` for the pre-fix controller.

    The pre-fix promotion controller signed with the same protected-main
    workflow identity, so its provenance is valid for the current verifier.
    """
    return [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "subjectAlternativeName": LEGACY_SIGNER,
                        "issuer": "https://token.actions.githubusercontent.com",
                        "sourceRepositoryURI": "https://github.com/owner/repo",
                        "sourceRepositoryRef": "refs/heads/main",
                        "runnerEnvironment": "github-hosted",
                    }
                },
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
    ]


def legacy_publish(tmp_path, assets, replace=None, evidence_changes=None):
    """Public release assets, verified payload and legacy-signer provenance."""
    release_dir = tmp_path / "release-assets"
    shutil.copytree(assets, release_dir)
    for name, value in (replace or {}).items():
        (release_dir / name).write_bytes(value)
    evidence = json.loads((release_dir / "release-evidence.json").read_text("utf-8"))
    for record in evidence["artifacts"]:
        path = release_dir / record["name"]
        record["bytes"] = path.stat().st_size
        record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    evidence.update(evidence_changes or {})
    (release_dir / "release-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", "utf-8"
    )
    payload = tmp_path / "verified-payload"
    publish_payload.capture(release_dir, payload, "v" + VERSION, SOURCE)
    trusted = tmp_path / "trusted-release"
    trusted.mkdir()
    shutil.copyfile(
        release_dir / "release-evidence.json", trusted / "release-evidence.json"
    )
    attestations = tmp_path / "trusted-attestations"
    attestations.mkdir()
    subjects = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in release_dir.iterdir()
    }
    for name in ("release-evidence.json", WHEEL, SDIST):
        (attestations / f"{name}.json").write_text(
            json.dumps(legacy_attestation(subjects)), "utf-8"
        )
    return payload, trusted / "release-evidence.json", attestations


def publish_cli(payload, evidence, attestations, cwd):
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/publish_payload.py"),
            "verify",
            str(payload),
            "--tag",
            "v" + VERSION,
            "--source-commit",
            SOURCE,
            "--trusted-evidence",
            str(evidence),
            "--attestations",
            str(attestations),
            "--repository",
            "owner/repo",
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_publish_gate_is_the_last_trusted_step_before_the_pypi_action():
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/publish.yml").read_text("utf-8")
    )
    steps = workflow["jobs"]["publish"]["steps"]
    trusted_checkout = steps[0]
    assert trusted_checkout["with"]["ref"] == "${{ github.workflow_sha }}"
    assert trusted_checkout["with"]["path"] == "trusted-verifier"
    assert (
        "python -I trusted-verifier/scripts/publish_payload.py verify"
        in (steps[-2]["run"])
    )
    assert steps[-1]["uses"].startswith("pypa/gh-action-pypi-publish@")
    assert steps[-1]["with"]["packages-dir"] == "verified-payload/packages"


def test_publish_gate_admits_canonical_legacy_attested_packages(tmp_path, release):
    _source, assets = release
    payload, evidence, attestations = legacy_publish(tmp_path, assets)
    publish_payload.authenticate(
        payload, "v" + VERSION, SOURCE, evidence, attestations, "owner/repo"
    )
    cli = tmp_path / "cli"
    cli.mkdir()
    result = publish_cli(payload, evidence, attestations, cli)
    assert result.returncode == 0, result.stderr
    assert (payload / "packages" / WHEEL).read_bytes() == (assets / WHEEL).read_bytes()
    assert (payload / "packages" / SDIST).read_bytes() == (assets / SDIST).read_bytes()


@pytest.mark.parametrize("kind", ["wheel-local-header", "sdist-tar-header"])
def test_publish_gate_refuses_legacy_attested_noncanonical_packages(
    tmp_path, release, kind
):
    """Valid legacy provenance over noncanonical bytes is refused before PyPI."""
    _source, assets = release
    if kind == "wheel-local-header":
        replace = {WHEEL: wheel_local_header_change((assets / WHEEL).read_bytes())}
    else:
        replace = {SDIST: tar_header_field_change((assets / SDIST).read_bytes())}
    payload, evidence, attestations = legacy_publish(tmp_path, assets, replace)
    # Every pre-existing control accepts it: digests, evidence and provenance.
    publish_payload.verify(payload, "v" + VERSION, SOURCE)
    for name in (WHEEL, SDIST):
        publish_payload.require_attested(
            attestations / f"{name}.json",
            name,
            hashlib.sha256((payload / "packages" / name).read_bytes()).hexdigest(),
            "owner/repo",
        )
    with pytest.raises(ValueError, match=NOT_REGENERATED):
        publish_payload.authenticate(
            payload, "v" + VERSION, SOURCE, evidence, attestations, "owner/repo"
        )
    result = publish_cli(payload, evidence, attestations, tmp_path)
    assert result.returncode != 0
    assert NOT_REGENERATED in result.stderr


@pytest.mark.parametrize(
    "epoch", [None, "315532800", True, 315532799, 0x100000000, EPOCH + 2]
)
def test_publish_gate_uses_only_the_attested_evidence_epoch(tmp_path, release, epoch):
    _source, assets = release
    changes = {"source_date_epoch": epoch}
    payload, evidence, attestations = legacy_publish(tmp_path, assets, None, changes)
    message = NOT_REGENERATED if epoch == EPOCH + 2 else "valid SOURCE_DATE_EPOCH"
    with pytest.raises(ValueError, match=message):
        publish_payload.authenticate(
            payload, "v" + VERSION, SOURCE, evidence, attestations, "owner/repo"
        )


@pytest.mark.parametrize("when", ["after-capture", "after-regeneration"])
def test_publish_gate_binds_the_published_bytes_to_the_single_capture(
    tmp_path, release, monkeypatch, when
):
    """A package file changed after its one capture is never validated or published."""
    _source, assets = release
    payload, evidence, attestations = legacy_publish(tmp_path, assets)
    packages = payload / "packages"

    def noncanonical(name, value):
        if name == WHEEL:
            return wheel_local_header_change(value)
        return tar_header_field_change(value)

    if when == "after-capture":
        real_read = publish_payload._bounded_bytes

        def read_then_swap(path, limit):
            value = real_read(path, limit)
            if path.parent == packages:
                # A noncanonical variant replaces the file right after capture.
                path.write_bytes(noncanonical(path.name, value))
            return value

        monkeypatch.setattr(publish_payload, "_bounded_bytes", read_then_swap)
    else:
        real_gate = publish_payload.require_canonical_regeneration

        def gate_then_swap(name, value, epoch):
            real_gate(name, value, epoch)
            (packages / name).write_bytes(b"swapped after regeneration")

        monkeypatch.setattr(
            publish_payload, "require_canonical_regeneration", gate_then_swap
        )
    with pytest.raises(ValueError, match="changed after canonical verification"):
        publish_payload.authenticate(
            payload, "v" + VERSION, SOURCE, evidence, attestations, "owner/repo"
        )


# Quick-start setup executes an unpinned installer and unhashed dependencies.

INSTALL = re.compile(r"\bpip\s+install\b")
PRIMARY_SECTIONS = {
    "README.md": ("## Quick start", "## Testing and release assurance"),
    "CONTRIBUTING.md": ("## Development setup",),
}
LOCKFILE = re.compile(r"requirements-[a-z]+-lock\.txt")


def section(text: str, heading: str) -> list[str]:
    lines = text.splitlines()
    start = lines.index(heading) + 1
    end = next(
        (index for index in range(start, len(lines)) if lines[index][:3] == "## "),
        len(lines),
    )
    return lines[start:end]


def install_commands(lines: list[str]) -> list[str]:
    return [line.strip().strip("`") for line in lines if INSTALL.search(line)]


def verified_install_error(command: str) -> str | None:
    """Return why a documented install is not hash-locked, or None."""
    tokens = command.split()
    arguments = tokens[tokens.index("install") + 1 :]
    if arguments == ["--no-build-isolation", "--no-deps", "."]:
        return None
    if arguments[:3] != ["--require-hashes", "--only-binary", ":all:"]:
        return "dependency install omits --require-hashes --only-binary :all:"
    files = arguments[3:]
    if not files or len(files) % 2 or files[::2] != ["-r"] * (len(files) // 2):
        return "dependency install must read only -r lockfiles"
    for name in files[1::2]:
        if LOCKFILE.fullmatch(name.removeprefix(".\\")) is None:
            return f"dependency install reads an unlocked file: {name}"
        if not (ROOT / name.removeprefix(".\\")).is_file():
            return f"dependency install reads a missing lockfile: {name}"
    return None


@pytest.mark.parametrize(
    "document,heading",
    [
        (name, heading)
        for name, headings in PRIMARY_SECTIONS.items()
        for heading in headings
    ],
)
def test_primary_install_sections_use_only_hash_locked_installs(document, heading):
    commands = install_commands(section((ROOT / document).read_text("utf-8"), heading))
    assert commands
    assert {command: verified_install_error(command) for command in commands} == {
        command: None for command in commands
    }


@pytest.mark.parametrize("document", sorted(PRIMARY_SECTIONS))
def test_any_other_install_command_is_explicitly_labelled_non_verified(document):
    for line in (ROOT / document).read_text("utf-8").splitlines():
        if not INSTALL.search(line):
            continue
        commands = re.findall(r"`([^`]*\bpip\s+install\b[^`]*)`", line) or [
            line.strip()
        ]
        for command in commands:
            assert (
                verified_install_error(command) is None
                or "non-verified" in line.lower()
            ), line


def test_readme_quick_start_installs_locks_before_the_local_project():
    commands = install_commands(
        section((ROOT / "README.md").read_text("utf-8"), "## Quick start")
    )
    assert commands == [
        "python -m pip install --require-hashes --only-binary :all: "
        "-r requirements-pip-lock.txt",
        "python -m pip install --require-hashes --only-binary :all: "
        "-r requirements-build-lock.txt",
        "python -m pip install --require-hashes --only-binary :all: "
        "-r requirements-runtime-lock.txt",
        "python -m pip install --no-build-isolation --no-deps .",
    ]


@pytest.mark.parametrize(
    "lockfile",
    [
        "requirements-pip-lock.txt",
        "requirements-build-lock.txt",
        "requirements-runtime-lock.txt",
    ],
)
def test_quick_start_lockfiles_pin_every_artifact_by_hash(lockfile):
    logical = re.sub(r"\\\n\s*", " ", (ROOT / lockfile).read_text("utf-8"))
    requirements = [
        line.strip()
        for line in logical.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert requirements
    for requirement in requirements:
        assert re.match(r"^[A-Za-z0-9._-]+==[^\s;]+", requirement), requirement
        assert "--hash=sha256:" in requirement, requirement


def fake_pip_wheel(directory: Path, version: str) -> None:
    info = f"pip-{version}.dist-info"
    path = directory / f"pip-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("pip/__init__.py", "")
        archive.writestr(
            f"{info}/METADATA",
            f"Metadata-Version: 2.1\nName: pip\nVersion: {version}\n",
        )
        archive.writestr(
            f"{info}/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{info}/RECORD", "")


def test_verified_setup_never_selects_an_unpinned_higher_pip(tmp_path):
    """A local index offers pip 99.0.0 and an unhashed copy of the locked pin."""
    locked = re.search(
        r"(?m)^pip==(\S+)", (ROOT / "requirements-pip-lock.txt").read_text("utf-8")
    ).group(1)
    fake_pip_wheel(tmp_path, "99.0.0")
    fake_pip_wheel(tmp_path, locked)
    offline = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--isolated",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--dry-run",
        "--ignore-installed",
        "--no-index",
        "--find-links",
        str(tmp_path),
    ]
    environment = dict(os.environ, PIP_CONFIG_FILE=os.devnull)
    control = subprocess.run(
        [*offline, "pip"], capture_output=True, text=True, env=environment
    )
    assert control.returncode == 0 and "pip-99.0.0" in control.stdout
    documented = subprocess.run(
        [
            *offline,
            "--require-hashes",
            "--only-binary",
            ":all:",
            "-r",
            str(ROOT / "requirements-pip-lock.txt"),
        ],
        capture_output=True,
        text=True,
        env=environment,
    )
    output = documented.stdout + documented.stderr
    assert documented.returncode != 0
    assert "DO NOT MATCH THE HASHES" in output
    assert f"pip-{locked}-py3-none-any.whl" in output
    assert "99.0.0" not in output
