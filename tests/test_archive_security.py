"""Reject executable additions which are not part of reviewed release source."""

import base64
import csv
import hashlib
import io
import os
import struct
import subprocess
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from scripts import archive_budget
from scripts import verify_distribution as verifier_module
from scripts.normalize_sdist import normalize_sdist
from scripts.verify_distribution import (
    _project_version,
    _verify_sdist,
    _verify_wheel,
    run_with_actions_command_guard,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def distributions(tmp_path_factory):
    output = tmp_path_factory.mktemp("archive-security")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )  # noqa: S603
    sdist = next(output.glob("*.tar.gz"))
    normalize_sdist(sdist, 315532800)
    return next(output.glob("*.whl")), sdist


@pytest.mark.parametrize(
    "member",
    [
        "startup.pth",
        "aws_chaos_engineering_framework.data/scripts/launch",
        "native.dll",
    ],
)
def test_unreviewed_wheel_execution_members_fail(distributions, tmp_path, member):
    wheel, _ = distributions
    altered = tmp_path / wheel.name
    altered.write_bytes(wheel.read_bytes())
    with zipfile.ZipFile(altered, "a") as archive:
        archive.writestr(member, "unreviewed payload")
    with pytest.raises(ValueError, match="unreviewed"):
        _verify_wheel(altered, _project_version(ROOT / "pyproject.toml"), ROOT)


def test_unreviewed_sdist_build_hook_fails(distributions, tmp_path):
    _, sdist = distributions
    altered = tmp_path / sdist.name
    with (
        tarfile.open(sdist, "r:gz") as original,
        tarfile.open(altered, "w:gz") as output,
    ):
        for member in original.getmembers():
            output.addfile(
                member, original.extractfile(member) if member.isfile() else None
            )
        root = original.getmembers()[0].name.split("/")[0]
        payload = b"raise RuntimeError('unreviewed build hook')\n"
        member = tarfile.TarInfo(root + "/setup.py")
        member.size = len(payload)
        output.addfile(member, io.BytesIO(payload))
    with pytest.raises(ValueError, match="unreviewed"):
        _verify_sdist(altered, ROOT)


@pytest.mark.parametrize(
    "addition",
    [
        "extra = aws_chaos_framework:main\n",
        "[plugins]\nextra = aws_chaos_framework:main\n",
    ],
)
def test_valid_record_does_not_authorize_extra_wheel_entrypoints(
    distributions, tmp_path, addition
):
    wheel, _ = distributions
    with zipfile.ZipFile(wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    entry = next(name for name in members if name.endswith("/entry_points.txt"))
    record = next(name for name in members if name.endswith("/RECORD"))
    members[entry] += addition.encode("utf-8")
    rows = []
    for name, data in members.items():
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        rows.append(
            [name, "sha256=" + digest, str(len(data))]
            if name != record
            else [name, "", ""]
        )
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)
    members[record] = output.getvalue().encode("utf-8")
    altered = tmp_path / wheel.name
    with zipfile.ZipFile(altered, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    with pytest.raises(ValueError, match="entry points"):
        _verify_wheel(altered, _project_version(ROOT / "pyproject.toml"), ROOT)


@pytest.mark.parametrize(
    "attack",
    [
        "missing_record",
        "missing_wheel",
        "missing_row",
        "duplicate_row",
        "extra_row",
        "traversal_row",
        "bad_hash",
        "bad_size",
        "self_digest",
    ],
)
def test_wheel_record_and_required_metadata_fail_closed(
    distributions, tmp_path, attack
):
    wheel, _ = distributions
    with zipfile.ZipFile(wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    record = next(name for name in members if name.endswith("/RECORD"))
    if attack == "missing_record":
        members.pop(record)
    elif attack == "missing_wheel":
        members.pop(next(name for name in members if name.endswith("/WHEEL")))
    else:
        rows = list(csv.reader(io.StringIO(members[record].decode("utf-8"))))
        if attack == "missing_row":
            rows.pop(0)
        elif attack == "duplicate_row":
            rows.append(rows[0])
        elif attack == "extra_row":
            rows[0][0] = "unreviewed.py"
        elif attack == "traversal_row":
            rows[0][0] = "../unreviewed.py"
        elif attack == "bad_hash":
            rows[0][1] = "sha256=incorrect"
        elif attack == "bad_size":
            rows[0][2] = "999999"
        else:
            self_row = next(row for row in rows if row[0] == record)
            self_row[1] = "sha256=not-empty"
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(rows)
        members[record] = output.getvalue().encode("utf-8")
    altered = tmp_path / wheel.name
    with zipfile.ZipFile(altered, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    with pytest.raises(ValueError, match="RECORD|canonical metadata"):
        _verify_wheel(altered, _project_version(ROOT / "pyproject.toml"), ROOT)


@pytest.mark.parametrize("document", ["README.md", "CONTRIBUTING.md"])
def test_documented_audit_uses_committed_lock_without_resolution(document):
    commands = [
        line.strip()
        for line in (ROOT / document).read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("python -m pip_audit ")
    ]
    assert len(commands) == 1
    command = commands[0]
    assert "requirements-runtime-lock.txt" in command
    assert "requirements.txt" not in command
    assert "--require-hashes" in command
    assert "--disable-pip" in command
    assert "--progress-spinner off" in command
    arguments = [value.removeprefix(".\\") for value in command.split()[1:]]
    result = subprocess.run(
        [sys.executable, *arguments, "--dry-run"],
        cwd=ROOT,
        env={**os.environ, "PIP_NO_INDEX": "1"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Dry run: would have audited" in result.stderr


@pytest.mark.parametrize("command", ["warning", "add-mask"])
def test_wheel_control_name_has_one_line_diagnostic(tmp_path, command):
    wheel = tmp_path / "candidate.whl"
    name = "unexpected\\n::" + command + "::inert"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(name.replace("\\n", "\n"), b"inert")
    with pytest.raises(ValueError, match="control character") as error:
        _verify_wheel(wheel, _project_version(ROOT / "pyproject.toml"), ROOT)
    diagnostic = str(error.value)
    assert len(diagnostic.splitlines()) == 1
    assert "::" + command + "::" not in diagnostic


@pytest.mark.parametrize("record", ["central", "local"])
def test_raw_zip_name_control_is_rejected_before_zipfile_normalizes(tmp_path, record):
    wheel = tmp_path / "candidate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("unexpectedx", b"inert")
    data = bytearray(wheel.read_bytes())
    signature, offset = (
        (b"PK\x01\x02", 46) if record == "central" else (b"PK\x03\x04", 30)
    )
    position = data.index(signature) + offset + len("unexpected")
    assert data[position] == ord("x")
    data[position] = 0
    if record == "central":
        local_position = data.index(b"PK\x03\x04") + 30 + len("unexpected")
        assert data[local_position] == ord("x")
        data[local_position] = 0
    wheel.write_bytes(data)
    with (
        pytest.raises(
            archive_budget.ArchiveBudgetError, match="control character|differs from"
        ),
        archive_budget.open_zip(wheel),
    ):
        pass
    with pytest.raises(ValueError, match="control character|differs from") as error:
        _verify_wheel(wheel, _project_version(ROOT / "pyproject.toml"), ROOT)
    assert len(str(error.value).splitlines()) == 1


def test_decoded_zip_control_name_is_escaped_in_diagnostic(tmp_path):
    wheel = tmp_path / "candidate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("unexpected\u0085::warning::inert", b"inert")
    with pytest.raises(ValueError, match="control character") as error:
        _verify_wheel(wheel, _project_version(ROOT / "pyproject.toml"), ROOT)
    assert len(str(error.value).splitlines()) == 1
    assert "\\x85::warning::inert" in str(error.value)


@pytest.mark.parametrize("record", ["central", "local"])
def test_unicode_path_extra_is_rejected_before_name_normalization(tmp_path, record):
    wheel = tmp_path / "candidate.whl"
    name = "unexpected"
    hidden_name = (name + "\x00\ncontrol").encode("utf-8")
    payload = struct.pack("<BI", 1, zlib.crc32(name.encode("ascii"))) + hidden_name
    leading_extra = struct.pack("<HH", 0xCAFE, 1) + b"x"
    path_extra = struct.pack("<HH", 0x7075, len(payload)) + payload
    member = zipfile.ZipInfo(name)
    member.extra = leading_extra + path_extra
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(member, b"inert")
    data = bytearray(wheel.read_bytes())
    other = b"PK\x03\x04" if record == "central" else b"PK\x01\x02"
    header = data.index(other)
    name_size = struct.unpack_from(
        "<H", data, header + (26 if record == "central" else 28)
    )[0]
    extra_start = header + (30 if record == "central" else 46) + name_size
    field = extra_start + len(leading_extra)
    assert struct.unpack_from("<H", data, field)[0] == 0x7075
    struct.pack_into("<H", data, field, 0x7777)
    wheel.write_bytes(data)
    with (
        pytest.raises(archive_budget.ArchiveBudgetError, match="Unicode Path metadata"),
        archive_budget.open_zip(wheel),
    ):
        pass


@pytest.mark.parametrize("command", ["warning", "add-mask"])
def test_sdist_control_name_has_one_line_diagnostic(tmp_path, command):
    sdist = tmp_path / "candidate.tar.gz"
    name = f"aws_chaos_engineering_framework-2.0.4/unexpected\n::{command}::inert"
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.mode = 0o644
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="control character") as error:
        _verify_sdist(sdist, ROOT)
    diagnostic = str(error.value)
    assert len(diagnostic.splitlines()) == 1
    assert "\\n::" + command + "::" in diagnostic


def test_sdist_content_mismatch_uses_one_line_member_name(tmp_path):
    sdist = tmp_path / "candidate.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo("aws_chaos_engineering_framework-2.0.4/README.md")
        member.mode = 0o644
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="content differs") as error:
        _verify_sdist(sdist, ROOT)
    assert str(error.value).endswith("'README.md'")
    assert len(str(error.value).splitlines()) == 1


def test_actions_guard_suspends_and_resumes_around_failure(monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    def rejected_archive():
        raise ValueError("rejected member\n::warning::inert")

    tokens = []
    for _ in range(2):
        assert run_with_actions_command_guard(rejected_archive) == 1
        lines = capsys.readouterr().err.splitlines()
        assert lines[0].startswith("::stop-commands::")
        token = lines[0].removeprefix("::stop-commands::")
        assert len(token) == 64 and all(char in "0123456789abcdef" for char in token)
        assert lines[-1] == f"::{token}::"
        assert "::warning::inert" in "\n".join(lines[1:-1])
        tokens.append(token)
    assert tokens[0] != tokens[1]


def test_actions_guard_keeps_system_exit_diagnostic_inside_envelope(
    monkeypatch, capsys
):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    def rejected_release():
        raise SystemExit("rejected member\n::add-mask::inert")

    assert run_with_actions_command_guard(rejected_release) == 1
    lines = capsys.readouterr().err.splitlines()
    token = lines[0].removeprefix("::stop-commands::")
    assert lines[0] == f"::stop-commands::{token}"
    assert lines[-1] == f"::{token}::"
    assert lines[1:3] == ["rejected member", "::add-mask::inert"]


def test_actions_guard_flushes_buffered_stdout_before_resuming(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    events = []

    class BufferedStream:
        def __init__(self, label):
            self.label = label
            self.pending = ""

        def write(self, value):
            self.pending += value

        def flush(self):
            if self.pending:
                events.append((self.label, self.pending))
                self.pending = ""

    stdout = BufferedStream("stdout")
    stderr = BufferedStream("stderr")
    monkeypatch.setattr(archive_budget.sys, "stdout", stdout)
    monkeypatch.setattr(archive_budget.sys, "stderr", stderr)

    def successful_verification():
        print("Verified 'outer\\n::warning::inert.whl'")
        return 0

    assert archive_budget.run_with_actions_command_guard(successful_verification) == 0
    assert [label for label, _ in events] == ["stderr", "stdout", "stderr"]
    assert events[0][1].startswith("::stop-commands::")
    assert "\\n::warning::" in events[1][1]
    assert events[2][1] == "::" + events[0][1].split("::")[-1].strip() + "::\n"


def test_verifier_success_escapes_outer_artifact_names(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        verifier_module,
        "verify_distribution",
        lambda *_: (
            Path("wheel\n::warning::inert.whl"),
            Path("source\n::add-mask::inert.tar.gz"),
        ),
    )
    monkeypatch.setattr(sys, "argv", ["verify_distribution.py", str(tmp_path)])
    verifier_module.main()
    lines = capsys.readouterr().out.splitlines()
    assert lines == [
        "Verified 'wheel\\n::warning::inert.whl'",
        "Verified 'source\\n::add-mask::inert.tar.gz'",
    ]


@pytest.mark.parametrize(
    "script",
    [
        "verify_distribution.py",
        "prepare_release.py",
        "verify_release_handoff.py",
        "normalize_wheel.py",
        "normalize_sdist.py",
        "release_asset_admission.py",
        "publish_payload.py",
        "download_release_artifact.py",
    ],
)
def test_archive_verifier_cli_routes_guard_actions_output(script):
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts" / script), "--unknown-option"],
        cwd=ROOT,
        env={**os.environ, "GITHUB_ACTIONS": "true"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    lines = result.stderr.splitlines()
    assert lines[0].startswith("::stop-commands::")
    assert lines[-1] == "::" + lines[0].removeprefix("::stop-commands::") + "::"


def test_wheel_cli_diagnostic_stays_inside_actions_guard(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    with zipfile.ZipFile(dist / "candidate.whl", "w") as archive:
        archive.writestr("unexpected\n::warning::inert", b"x")
    with tarfile.open(dist / "candidate.tar.gz", "w:gz"):
        pass
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts" / "verify_distribution.py"),
            str(dist),
            "--repository-root",
            str(ROOT),
        ],
        cwd=ROOT,
        env={**os.environ, "GITHUB_ACTIONS": "true"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    lines = result.stderr.splitlines()
    assert lines[0].startswith("::stop-commands::")
    assert lines[-1] == "::" + lines[0].removeprefix("::stop-commands::") + "::"
    assert not any(line.startswith("::warning::") for line in lines[1:-1])
    assert "ZIP member name contains a control character" in result.stderr
