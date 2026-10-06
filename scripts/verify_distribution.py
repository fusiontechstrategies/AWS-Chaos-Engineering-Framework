"""Inspect wheel and source-distribution contents before release."""

from __future__ import annotations

import argparse
import base64
import configparser
import email
import hashlib
import importlib.util
import re
from pathlib import Path, PurePosixPath

_budget_path = Path(__file__).resolve().with_name("archive_budget.py")
_budget_spec = importlib.util.spec_from_file_location(
    "trusted_archive_budget", _budget_path
)
if _budget_spec is None or _budget_spec.loader is None:
    raise ImportError("Trusted archive budget helper is unavailable")
archive_budget = importlib.util.module_from_spec(_budget_spec)
_budget_spec.loader.exec_module(archive_budget)

_source_path = Path(__file__).resolve().with_name("source_files.py")
_source_spec = importlib.util.spec_from_file_location(
    "trusted_source_files", _source_path
)
if _source_spec is None or _source_spec.loader is None:
    raise ImportError("Trusted bounded source reader is unavailable")
source_files = importlib.util.module_from_spec(_source_spec)
_source_spec.loader.exec_module(source_files)

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10; supplied by the pinned build lock.
    import tomli as tomllib

PROJECT_NAME = "aws-chaos-engineering-framework"
MODULE_NAME = "aws_chaos_framework.py"
BLOCKED_SUFFIXES = {".env", ".key", ".p12", ".pem", ".pfx", ".pyc"}


# This policy belongs to the independently trusted verifier, not the selected
# tag's MANIFEST.in or artifact SOURCES.txt. Updating it requires verifier review.
APPROVED_BUILD_SYSTEM = {
    "requires": ["setuptools==84.0.0", "wheel==0.48.0"],
    "build-backend": "setuptools.build_meta",
}
APPROVED_MANIFEST = "include .markdownlint-cli2.yaml\nrecursive-include .github/release-notes *.md\ninclude .github/workflows/release.yml\ninclude .github/workflows/release-promotion.yml\ninclude CHANGELOG.md\ninclude CODE_OF_CONDUCT.md\ninclude CONTRIBUTING.md\ninclude LICENSE\ninclude README.md\ninclude RELEASING.md\ninclude SECURITY.md\ninclude TESTING.md\ninclude example-config.yaml\ninclude requirements.txt\ninclude requirements-dev.txt\ninclude requirements-build.txt\ninclude requirements-build-lock.txt\ninclude requirements-runtime-lock.txt\ninclude docs/security-boundaries.md\ninclude docs/runtime-safety-scope.md\nrecursive-include scripts *.py\nrecursive-include tests *.py"
APPROVED_SOURCE_PATHS = frozenset(
    [
        ".github/workflows/release-promotion.yml",
        ".github/workflows/release.yml",
        ".markdownlint-cli2.yaml",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "MANIFEST.in",
        "README.md",
        "RELEASING.md",
        "SECURITY.md",
        "TESTING.md",
        "aws_chaos_framework.py",
        "docs/runtime-safety-scope.md",
        "docs/security-boundaries.md",
        "example-config.yaml",
        "pyproject.toml",
        "requirements-build-lock.txt",
        "requirements-build.txt",
        "requirements-dev.txt",
        "requirements-runtime-lock.txt",
        "requirements.txt",
        "scripts/archive_budget.py",
        "scripts/download_release_artifact.py",
        "scripts/source_files.py",
        "tests/test_final_five_boundaries.py",
        "scripts/create_verified_draft.py",
        "scripts/normalize_sdist.py",
        "scripts/normalize_wheel.py",
        "scripts/prepare_release.py",
        "scripts/publish_payload.py",
        "scripts/verify_distribution.py",
        "scripts/verify_publish_trust.py",
        "scripts/verify_release_handoff.py",
        "scripts/verify_release_integrity.py",
        "tests/conftest.py",
        "tests/test_archive_budget.py",
        "tests/test_archive_security.py",
        "tests/test_aws_chaos_framework.py",
        "tests/test_final_cloud_c11_planning_only.py",
        "tests/test_final_cloud_c13_regressions.py",
        "tests/test_final_cloud_eight_recovery_controls.py",
        "tests/test_final_cloud_eight_scope_controls.py",
        "tests/test_final_cloud_six_controls.py",
        "tests/test_final_nine_regressions.py",
        "tests/test_route_ebs_planning_only.py",
        "tests/test_final_scan_regressions.py",
        "tests/test_latest_main_four_regressions.py",
        "tests/test_latest_runtime_scan_regressions.py",
        "tests/test_normalize_sdist.py",
        "tests/test_normalize_wheel.py",
        "tests/test_release_assets.py",
        "tests/test_security_regressions.py",
        "tests/test_residual_authorization.py",
        "tests/test_trusted_release_promotion.py",
    ]
)
EGG_INFO = "aws_chaos_engineering_framework.egg-info/"
GENERATED_SDIST_PATHS = frozenset({"PKG-INFO", "setup.cfg"}) | {
    EGG_INFO + name
    for name in (
        "PKG-INFO",
        "SOURCES.txt",
        "dependency_links.txt",
        "entry_points.txt",
        "requires.txt",
        "top_level.txt",
    )
}


def _approved_project(repository_root: Path) -> dict:
    try:
        document = tomllib.loads(
            source_files.read_text(repository_root, "pyproject.toml", 1_048_576)
        )
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid packaging metadata") from exc
    if document.get("build-system") != APPROVED_BUILD_SYSTEM:
        raise ValueError("unreviewed build-system configuration or backend-path")
    tool = document.get("tool", {})
    if (
        tool.get("setuptools") != {"py-modules": ["aws_chaos_framework"]}
        or set(tool) - {"setuptools", "pytest", "ruff"}
        or set(document) != {"build-system", "project", "tool"}
    ):
        raise ValueError("unreviewed setuptools build hooks or configuration")
    project = document.get("project", {})
    if set(project) != {
        "name",
        "version",
        "description",
        "readme",
        "requires-python",
        "license",
        "authors",
        "dependencies",
        "classifiers",
        "urls",
        "scripts",
    } or project.get("scripts") != {"aws-chaos-framework": "aws_chaos_framework:main"}:
        raise ValueError("unreviewed dynamic metadata or project entry points")
    if (
        project.get("name") != PROJECT_NAME
        or project.get("readme") != "README.md"
        or project.get("license") != "Apache-2.0"
        or project.get("requires-python") != ">=3.10,<3.15"
        or not isinstance(project.get("version"), str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", project["version"])
        or any(
            source_files.is_present(repository_root, name)
            for name in ("setup.py", "setup.cfg")
        )
    ):
        raise ValueError("unreviewed static project metadata or legacy build hook")
    return project


def _project_version(pyproject_path: Path) -> str:
    return _approved_project(pyproject_path.parent)["version"]


def _approved_source_files(repository_root: Path) -> set[str]:
    if (
        source_files.read_text(repository_root, "MANIFEST.in", 65_536).strip()
        != APPROVED_MANIFEST
    ):
        raise ValueError("source manifest differs from the trusted packaging policy")
    reviewed = {
        name
        for name in APPROVED_SOURCE_PATHS
        if source_files.is_present(repository_root, name)
    }
    required = {
        MODULE_NAME,
        "pyproject.toml",
        "MANIFEST.in",
        "LICENSE",
        "README.md",
        "RELEASING.md",
        "requirements.txt",
        "requirements-build.txt",
        "example-config.yaml",
    }
    if not required <= reviewed:
        raise ValueError("selected source is missing required packaging inputs")
    # Historical release notes are data. Only one leaf with a canonical version
    # name is permitted; source-controlled patterns never extend executable paths.
    if source_files.is_present(
        repository_root, ".github/release-notes", directory=True
    ):
        for name in source_files.source_names(repository_root, ".github/release-notes"):
            if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+\.md", name):
                raise ValueError("unreviewed release-note filename")
            reviewed.add(".github/release-notes/" + name)
    for name in reviewed:
        source_files.read_bytes(repository_root, name)
    return reviewed


def _normal_text(value: bytes) -> str:
    return value.decode("utf-8").replace("\r\n", "\n").replace("\r", "")


def _pinned_backend_version(name: str) -> str:
    """Return the exact version of a build requirement the verifier pins."""
    for requirement in APPROVED_BUILD_SYSTEM["requires"]:
        package, separator, version = requirement.partition("==")
        if package == name and separator and re.fullmatch(r"[0-9.]+", version):
            return version
    raise ValueError(f"trusted build policy does not pin {name}")


def _expected_package_metadata(project: dict, repository_root: Path) -> str:
    """Derive the exact core metadata the pinned setuptools backend writes.

    One routine serves the sdist PKG-INFO files and the wheel METADATA, so no
    candidate-authored header, ordering or description byte is admitted.
    """
    fields = [
        ("Metadata-Version", "2.4"),
        ("Name", PROJECT_NAME),
        ("Version", project["version"]),
        ("Summary", project["description"]),
        ("Author", ", ".join(author["name"] for author in project["authors"])),
        ("License-Expression", project["license"]),
        *(("Project-URL", f"{key}, {url}") for key, url in project["urls"].items()),
        *(("Classifier", classifier) for classifier in project["classifiers"]),
        ("Requires-Python", "<3.15,>=3.10"),
        ("Description-Content-Type", "text/markdown"),
        ("License-File", "LICENSE"),
        *(("Requires-Dist", requirement) for requirement in project["dependencies"]),
        ("Dynamic", "license-file"),
    ]
    readme = _normal_text(source_files.read_bytes(repository_root, "README.md"))
    if not readme.endswith("\n"):
        readme += "\n"
    return "".join(f"{name}: {value}\n" for name, value in fields) + "\n" + readme


def _expected_entry_points(project: dict) -> str:
    return "[console_scripts]\n" + "".join(
        f"{name} = {target}\n" for name, target in project["scripts"].items()
    )


def _expected_wheel_metadata(project: dict, repository_root: Path) -> dict[str, bytes]:
    """Every wheel metadata member, derived from source and the pinned backend.

    The candidate RECORD proves only self-consistency, never origin, so each
    admitted dist-info member is compared byte for byte with these values.
    """
    return {
        "METADATA": _expected_package_metadata(project, repository_root).encode(
            "utf-8"
        ),
        "WHEEL": (
            "Wheel-Version: 1.0\n"
            f"Generator: setuptools ({_pinned_backend_version('setuptools')})\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n\n"
        ).encode("ascii"),
        "entry_points.txt": _expected_entry_points(project).encode("utf-8"),
        "top_level.txt": (MODULE_NAME.removesuffix(".py") + "\n").encode("ascii"),
        "licenses/LICENSE": source_files.read_bytes(repository_root, "LICENSE"),
    }


def _expected_record(values: dict[str, bytes], record_name: str) -> bytes:
    """The canonical sorted RECORD that normalize_wheel writes for these bytes."""
    lines = []
    for name in sorted(values):
        if name == record_name:
            lines.append(f"{name},,\n")
            continue
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(values[name]).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        lines.append(f"{name},sha256={digest},{len(values[name])}\n")
    return "".join(lines).encode("utf-8")


def _verify_package_metadata(
    value: bytes, project: dict, repository_root: Path
) -> None:
    expected = {
        "metadata-version": ["2.4"],
        "name": [PROJECT_NAME],
        "version": [project["version"]],
        "summary": [project["description"]],
        "author": [", ".join(author["name"] for author in project["authors"])],
        "license-expression": ["Apache-2.0"],
        "project-url": [f"{key}, {url}" for key, url in project["urls"].items()],
        "classifier": project["classifiers"],
        "requires-python": ["<3.15,>=3.10"],
        "description-content-type": ["text/markdown"],
        "license-file": ["LICENSE"],
        "requires-dist": project["dependencies"],
        "dynamic": ["license-file"],
    }
    message = email.message_from_string(_normal_text(value))
    actual = {key.lower(): message.get_all(key) for key in message}
    if message.defects or actual != expected:
        raise ValueError(
            "generated package metadata differs from static project metadata"
        )
    readme = _normal_text(source_files.read_bytes(repository_root, "README.md"))
    if message.get_payload().rstrip("\n") != readme.rstrip("\n"):
        raise ValueError("generated package description differs from static README")
    if _normal_text(value) != _expected_package_metadata(project, repository_root):
        raise ValueError(
            "generated package metadata is not the exact source-derived metadata"
        )
    if set(project["dependencies"]) != _runtime_requirements(
        repository_root / "requirements.txt"
    ):
        raise ValueError("project dependencies differ from the reviewed requirements")


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
        for line in source_files.read_text(
            requirements_path.parent, requirements_path.name, 1_048_576
        ).splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "-r "))
    }


def validate_record(values: dict[str, bytes], record_name: str) -> None:
    """Bind every canonical wheel member to exactly one safe SHA-256 RECORD row."""
    rows = list(archive_budget.record_rows(values[record_name]))
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
    project = source_files.read_text(repository_root, "pyproject.toml", 1_048_576)
    tables = re.findall(r"(?ms)^\[project\.scripts\]\s*\n(.*?)(?=^\[|\Z)", project)
    if (
        len(tables) != 1
        or tables[0].strip() != 'aws-chaos-framework = "aws_chaos_framework:main"'
    ):
        raise ValueError(
            "project.scripts does not contain exactly the reviewed launcher"
        )


def _verify_wheel(wheel_path: Path, version: str, repository_root: Path) -> None:
    project = _approved_project(repository_root)
    with archive_budget.open_zip(wheel_path) as archive:
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
        budget = archive_budget.MemberBudget()
        values = {
            member.filename: archive_budget.read_zip_member(archive, member, budget)
            for member in members
        }
        validate_record(values, info + "RECORD")
        if MODULE_NAME not in names:
            raise ValueError(f"wheel is missing {MODULE_NAME}")
        if values[MODULE_NAME] != source_files.read_bytes(repository_root, MODULE_NAME):
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

        # Protected promotion attests this wheel unchanged, so every admitted
        # member must be source-bound here: the runtime module above, and each
        # metadata member and the RECORD below, byte for byte.
        _verify_package_metadata(values[info + "METADATA"], project, repository_root)
        for name, expected in _expected_wheel_metadata(
            project, repository_root
        ).items():
            if values[info + name] != expected:
                raise ValueError(
                    f"wheel {name} differs from the source-derived trusted value"
                )
        if values[info + "RECORD"] != _expected_record(values, info + "RECORD"):
            raise ValueError("wheel RECORD is not the canonical source-derived RECORD")


def _verify_sdist(sdist_path: Path, repository_root: Path) -> None:
    project = _approved_project(repository_root)
    reviewed = _approved_source_files(repository_root)
    root = f"aws_chaos_engineering_framework-{project['version']}"
    expected_files = reviewed | GENERATED_SDIST_PATHS
    expected_directories = {root}
    for name in expected_files:
        expected_directories.update(
            root + "/" + parent.as_posix()
            for parent in PurePosixPath(name).parents
            if parent.as_posix() != "."
        )
    values = {}
    names = []
    total_size = 0
    with archive_budget.open_tar(sdist_path) as archive:
        budget = archive_budget.MemberBudget()
        for member in archive:
            names.append(member.name)
            if len(names) > 128:
                raise ValueError("source distribution exceeds the member budget")
            canonical = member.name.rstrip("/")
            if canonical != PurePosixPath(canonical).as_posix():
                raise ValueError("source distribution has a noncanonical path")
            if member.isdir():
                if (
                    canonical not in expected_directories
                    or member.size
                    or member.mode != 0o755
                ):
                    raise ValueError("source distribution has an unreviewed directory")
                continue
            if not member.isfile() or not canonical.startswith(root + "/"):
                raise ValueError(
                    "source distribution contains an unreviewed file type or root"
                )
            relative = canonical[len(root) + 1 :]
            if relative not in expected_files:
                raise ValueError(
                    f"source distribution contains an unreviewed file: {relative}"
                )
            if member.mode != 0o644 or not 0 <= member.size <= 8_388_608:
                raise ValueError("source distribution has unsafe mode or size")
            total_size += member.size
            if total_size > 33_554_432 or relative in values:
                raise ValueError(
                    "source distribution exceeds its budget or duplicates a path"
                )
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("source distribution member is unreadable")
            contents = archive_budget.read_member(stream, member.size, budget)
            if len(contents) != member.size:
                raise ValueError("source distribution member size differs from bytes")
            if relative in reviewed and contents != source_files.read_bytes(
                repository_root, relative
            ):
                raise ValueError(
                    f"source distribution content differs from the repository: {relative}"
                )
            values[relative] = contents
    _assert_safe_names(names)
    if set(values) != expected_files:
        raise ValueError("source distribution is missing canonical source or metadata")
    # Protected preparation copies the sdist unchanged, so generated members
    # are compared as raw bytes; line-ending variants are never equivalent.
    expected_metadata = _expected_package_metadata(project, repository_root).encode(
        "utf-8"
    )
    for name in ("PKG-INFO", EGG_INFO + "PKG-INFO"):
        _verify_package_metadata(values[name], project, repository_root)
        if values[name] != expected_metadata:
            raise ValueError(f"generated package metadata bytes are not exact: {name}")
    expected_generated = {
        "setup.cfg": "[egg_info]\ntag_build = \ntag_date = 0\n\n",
        EGG_INFO + "dependency_links.txt": "\n",
        EGG_INFO + "entry_points.txt": _expected_entry_points(project),
        EGG_INFO + "requires.txt": "".join(
            requirement + "\n" for requirement in project["dependencies"]
        ),
        EGG_INFO + "top_level.txt": "aws_chaos_framework\n",
    }
    listed = reviewed | {
        name for name in GENERATED_SDIST_PATHS if name.startswith(EGG_INFO)
    }
    expected_generated[EGG_INFO + "SOURCES.txt"] = "\n".join(
        sorted(listed, key=lambda item: ("/" in item, item))
    )
    for name, expected in expected_generated.items():
        if values[name] != expected.encode("utf-8"):
            raise ValueError(f"unreviewed generated source metadata: {name}")


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
    ).absolute()
    wheel, sdist = verify_distribution(args.dist_dir.resolve(), repository_root)
    print(f"Verified {wheel.name}")
    print(f"Verified {sdist.name}")


if __name__ == "__main__":
    main()
