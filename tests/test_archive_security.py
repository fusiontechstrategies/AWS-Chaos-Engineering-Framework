"""Reject executable additions which are not part of reviewed release source."""

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
