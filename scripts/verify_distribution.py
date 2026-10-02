"""Inspect wheel and source-distribution contents before release."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import email
import hashlib
import io
import re
import shlex
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

PROJECT_NAME = "aws-chaos-engineering-framework"
MODULE_NAME = "aws_chaos_framework.py"
BLOCKED_SUFFIXES = {".env", ".key", ".p12", ".pem", ".pfx", ".pyc"}


def _project_version(pyproject_path: Path) -> str:
    text = pyproject_path.read_text(encoding="utf-8")
    project = re.search(r"(?ms)^\[project\]\s*$.*?(?=^\[|\Z)", text)
    if project is None:
        raise ValueError("pyproject.toml has no [project] table")
    version = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', project.group(0))
    if version is None:
        raise ValueError("[project] has no literal version")
    return version.group(1)


def _assert_safe_names(names: list[str]) -> None:
    if len(names) != len(set(names)):
        raise ValueError("archive contains duplicate paths")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"archive contains an unsafe path: {name}")
        lower_name = name.lower()
        if any(lower_name.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
            raise ValueError(f"archive contains a blocked file type: {name}")
        if "__pycache__" in path.parts:
            raise ValueError(f"archive contains a Python cache: {name}")


def _runtime_requirements(requirements_path: Path) -> set[str]:
    return {
        line.strip()
        for line in requirements_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "-r "))
    }


def validate_record(values: dict[str, bytes], record_name: str) -> None:
    """Bind every canonical wheel member to exactly one safe SHA-256 RECORD row."""
    try:
        rows = list(
            csv.reader(
                io.StringIO(values[record_name].decode("utf-8"), newline=""),
                strict=True,
            )
        )
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ValueError("wheel RECORD is malformed") from exc
    if len(rows) != len(values):
        raise ValueError("wheel RECORD does not cover the exact member set")
    recorded = {}
    for row in rows:
        if len(row) != 3:
            raise ValueError("wheel RECORD row is malformed")
        name, digest, size = row
        if name not in values or name in recorded:
            raise ValueError("wheel RECORD has an unsafe, extra or duplicate member")
        recorded[name] = (digest, size)
    if set(recorded) != set(values) or recorded[record_name] != ("", ""):
        raise ValueError(
            "wheel RECORD must cover every member and leave its own identity empty"
        )
    for name, value in values.items():
        if name == record_name:
            continue
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(value).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        if recorded[name] != ("sha256=" + digest, str(len(value))):
            raise ValueError("wheel RECORD hash or size does not match member bytes")


def validate_entry_points(entry_points: str, repository_root: Path) -> None:
    """Accept exactly one literal launcher, with no extra installer behavior."""
    lines = [line for line in entry_points.splitlines() if line.strip()]
    if (
        len(lines) != 2
        or lines[0] != "[console_scripts]"
        or not re.fullmatch(
            r"aws-chaos-framework[ ]*=[ ]*aws_chaos_framework:main", lines[1]
        )
    ):
        raise ValueError("wheel entry points do not match the reviewed launcher")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(entry_points)
    expected = {"aws-chaos-framework": "aws_chaos_framework:main"}
    if (
        parser.defaults()
        or parser.sections() != ["console_scripts"]
        or dict(parser["console_scripts"]) != expected
    ):
        raise ValueError("wheel entry point metadata is ambiguous")
    project = (repository_root / "pyproject.toml").read_text(encoding="utf-8")
    tables = re.findall(r"(?ms)^\[project\.scripts\]\s*\n(.*?)(?=^\[|\Z)", project)
    if (
        len(tables) != 1
        or tables[0].strip() != 'aws-chaos-framework = "aws_chaos_framework:main"'
    ):
        raise ValueError(
            "project.scripts does not contain exactly the reviewed launcher"
        )


def _verify_wheel(wheel_path: Path, version: str, repository_root: Path) -> None:
    with zipfile.ZipFile(wheel_path) as archive:
        names = archive.namelist()
        _assert_safe_names(names)
        info = f"aws_chaos_engineering_framework-{version}.dist-info/"
        allowed = {MODULE_NAME} | {
            info + name
            for name in (
                "METADATA",
                "WHEEL",
                "entry_points.txt",
                "top_level.txt",
                "RECORD",
                "licenses/LICENSE",
            )
        }
        unexpected = set(names) - allowed
        if unexpected:
            raise ValueError(f"wheel contains unreviewed files: {sorted(unexpected)}")
        if set(names) != allowed:
            raise ValueError("wheel is missing canonical metadata members")
        members = archive.infolist()
        if (
            any(member.file_size > 8_388_608 or member.is_dir() for member in members)
            or sum(member.file_size for member in members) > 33_554_432
        ):
            raise ValueError("wheel expanded members exceed the verification budget")
        values = {name: archive.read(name) for name in names}
        validate_record(values, info + "RECORD")
        if MODULE_NAME not in names:
            raise ValueError(f"wheel is missing {MODULE_NAME}")
        if values[MODULE_NAME] != (repository_root / MODULE_NAME).read_bytes():
            raise ValueError(
                "wheel runtime module does not match the repository source"
            )
        executable_python = [name for name in names if name.endswith(".py")]
        if executable_python != [MODULE_NAME]:
            raise ValueError(
                f"wheel has unexpected Python modules: {executable_python}"
            )

        metadata_names = [
            name for name in names if name.endswith(".dist-info/METADATA")
        ]
        entry_point_names = [
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        ]
        if len(metadata_names) != 1 or len(entry_point_names) != 1:
            raise ValueError(
                "wheel must contain one METADATA file and one entry_points.txt"
            )

        metadata = email.message_from_bytes(values[metadata_names[0]])
        if metadata.get("Name") != PROJECT_NAME:
            raise ValueError(f"unexpected project name: {metadata.get('Name')}")
        if metadata.get("Version") != version:
            raise ValueError(f"unexpected project version: {metadata.get('Version')}")
        python_specifiers = {
            value.strip()
            for value in (metadata.get("Requires-Python") or "").split(",")
            if value.strip()
        }
        if python_specifiers != {">=3.10", "<3.15"}:
            raise ValueError(
                f"unexpected Python range: {metadata.get('Requires-Python')}"
            )
        if set(metadata.get_all("Requires-Dist", [])) != _runtime_requirements(
            repository_root / "requirements.txt"
        ):
            raise ValueError(
                "wheel dependency metadata does not match requirements.txt"
            )

        entry_points = values[entry_point_names[0]].decode("utf-8")
        validate_entry_points(entry_points, repository_root)


def _verify_sdist(sdist_path: Path, repository_root: Path) -> None:
    with tarfile.open(sdist_path, mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        _assert_safe_names(names)
        links = [member.name for member in members if member.issym() or member.islnk()]
        if links:
            raise ValueError(f"source distribution contains archive links: {links}")
        relative_names = {"/".join(PurePosixPath(name).parts[1:]) for name in names}
        reviewed = {
            MODULE_NAME,
            "pyproject.toml",
            "MANIFEST.in",
            "LICENSE",
            "README.md",
        }
        for line in (
            (repository_root / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
        ):
            tokens = shlex.split(line, comments=True)
            if not tokens:
                continue
            if tokens[0] == "include":
                for pattern in tokens[1:]:
                    reviewed.update(
                        path.relative_to(repository_root).as_posix()
                        for path in repository_root.glob(pattern)
                        if path.is_file()
                    )
            elif tokens[0] == "recursive-include" and len(tokens) >= 3:
                for pattern in tokens[2:]:
                    reviewed.update(
                        path.relative_to(repository_root).as_posix()
                        for path in (repository_root / tokens[1]).rglob(pattern)
                        if path.is_file()
                    )
            else:
                raise ValueError("source manifest contains an unsupported directive")
        egg_info = "aws_chaos_engineering_framework.egg-info/"
        generated = {"PKG-INFO", "setup.cfg"} | {
            egg_info + name
            for name in (
                "PKG-INFO",
                "SOURCES.txt",
                "dependency_links.txt",
                "entry_points.txt",
                "requires.txt",
                "top_level.txt",
            )
        }
        for member in members:
            relative = "/".join(PurePosixPath(member.name).parts[1:])
            if member.isdir():
                continue
            if not member.isfile() or relative not in reviewed | generated:
                raise ValueError(
                    f"source distribution contains an unreviewed file: {relative}"
                )
            contents = archive.extractfile(member).read()
            if (
                relative in reviewed
                and contents != (repository_root / relative).read_bytes()
            ):
                raise ValueError(
                    f"source distribution content differs from the repository: {relative}"
                )
            if (
                relative == "setup.cfg"
                and contents.replace(b"\r\n", b"\n").strip()
                != b"[egg_info]\ntag_build = \ntag_date = 0"
            ):
                raise ValueError(
                    "source distribution contains unreviewed setup configuration"
                )
        required = {
            MODULE_NAME,
            "LICENSE",
            "README.md",
            "RELEASING.md",
            "pyproject.toml",
            "requirements.txt",
            "requirements-build.txt",
            "example-config.yaml",
            "scripts/normalize_sdist.py",
            "scripts/normalize_wheel.py",
            "scripts/prepare_release.py",
            "scripts/verify_distribution.py",
            "tests/test_aws_chaos_framework.py",
            "tests/test_normalize_sdist.py",
            "tests/test_normalize_wheel.py",
            "tests/test_release_assets.py",
        }
        missing = sorted(required - relative_names)
        if missing:
            raise ValueError(f"source distribution is missing: {', '.join(missing)}")
        for relative_path in (
            MODULE_NAME,
            "pyproject.toml",
            "requirements.txt",
            "requirements-build.txt",
            "example-config.yaml",
            "scripts/normalize_sdist.py",
            "scripts/normalize_wheel.py",
            "scripts/prepare_release.py",
            "scripts/verify_distribution.py",
            "tests/test_aws_chaos_framework.py",
            "tests/test_normalize_sdist.py",
            "tests/test_normalize_wheel.py",
            "tests/test_release_assets.py",
        ):
            archived_name = next(
                name
                for name in names
                if "/".join(PurePosixPath(name).parts[1:]) == relative_path
            )
            archived_file = archive.extractfile(archived_name)
            if (
                archived_file is None
                or archived_file.read()
                != (repository_root / relative_path).read_bytes()
            ):
                raise ValueError(
                    f"source distribution content differs from the repository: {relative_path}"
                )


def verify_distribution(dist_dir: Path, repository_root: Path) -> tuple[Path, Path]:
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError(
            "dist must contain exactly one wheel and one .tar.gz source distribution"
        )
    version = _project_version(repository_root / "pyproject.toml")
    _verify_wheel(wheels[0], version, repository_root)
    _verify_sdist(sdists[0], repository_root)
    return wheels[0], sdists[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist_dir", type=Path)
    parser.add_argument("--repository-root", type=Path)
    args = parser.parse_args()
    repository_root = (
        args.repository_root or Path(__file__).resolve().parents[1]
    ).resolve()
    wheel, sdist = verify_distribution(args.dist_dir.resolve(), repository_root)
    print(f"Verified {wheel.name}")
    print(f"Verified {sdist.name}")


if __name__ == "__main__":
    main()
