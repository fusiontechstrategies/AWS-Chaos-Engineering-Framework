"""Reject executable additions which are not part of reviewed release source."""

import base64
import csv
import hashlib
import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.verify_distribution import _project_version, _verify_sdist, _verify_wheel

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
    return next(output.glob("*.whl")), next(output.glob("*.tar.gz"))


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
