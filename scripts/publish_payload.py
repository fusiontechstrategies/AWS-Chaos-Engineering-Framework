"""Bind the publish payload to verified public-release bytes without imports from a tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

# Only the protected release-promotion controller on main attests release
# subjects. The publish verify job cannot obtain this signing identity.
SIGNER_WORKFLOW = ".github/workflows/release-promotion.yml"
SIGNER_REF = "refs/heads/main"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
EVIDENCE_NAME = "release-evidence.json"
MAX_EVIDENCE_BYTES = 1_048_576
MAX_ATTESTATION_BYTES = 4_194_304
# Matches the per-distribution limit admitted before download.
MAX_PACKAGE_BYTES = 16 * 1024 * 1024


def expected_names(tag: str) -> set[str]:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Invalid release tag")
    version = tag[1:]
    return {
        f"aws_chaos_engineering_framework-{version}-py3-none-any.whl",
        f"aws_chaos_engineering_framework-{version}.tar.gz",
    }


def digest(path: Path, limit: int | None = None) -> str:
    limit = MAX_PACKAGE_BYTES if limit is None else limit
    if path.is_symlink() or not path.is_file():
        raise ValueError("Publish files must be regular files")
    result = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(min(1_048_576, limit - total + 1)):
            total += len(chunk)
            if total > limit:
                raise ValueError("Publish file exceeds its byte limit")
            result.update(chunk)
    return result.hexdigest()


def capture(release_dir: Path, output_dir: Path, tag: str, source_commit: str) -> None:
    names = expected_names(tag)
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("Invalid source commit")
    # This evidence has already passed the workflow's release and attestation
    # checks. Bind both actual source bytes and actual copied bytes to it again.
    # The read is bounded before JSON parsing, as in the protected job.
    evidence = json.loads(
        _bounded_bytes(release_dir / EVIDENCE_NAME, MAX_EVIDENCE_BYTES)
    )
    if (
        not isinstance(evidence, dict)
        or evidence.get("tag") != tag
        or evidence.get("source_commit") != source_commit
        or not isinstance(evidence.get("artifacts"), list)
    ):
        raise ValueError("Release identity mismatch")
    records: dict[str, dict] = {}
    for item in evidence["artifacts"]:
        if not isinstance(item, dict) or item.get("name") in records:
            raise ValueError("Invalid release evidence")
        records[item.get("name")] = item
    output_dir.mkdir(exist_ok=False)
    packages = output_dir / "packages"
    packages.mkdir()
    manifest = {
        "schema_version": 1,
        "tag": tag,
        "source_commit": source_commit,
        "files": {},
    }
    for name in sorted(names):
        source = release_dir / name
        record = records.get(name)
        if record is None:
            raise ValueError("Public distribution does not match verified evidence")
        if (
            digest(source) != record["sha256"]
            or source.stat().st_size != record["bytes"]
        ):
            raise ValueError("Public distribution does not match verified evidence")
        destination = packages / name
        shutil.copyfile(source, destination)
        if digest(destination) != record["sha256"]:
            raise ValueError("Copied distribution does not match verified evidence")
        manifest["files"][name] = {"sha256": record["sha256"], "bytes": record["bytes"]}
    (output_dir / "publish-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), "utf-8"
    )
    verify(output_dir, tag, source_commit)


def verify(payload_dir: Path, tag: str, source_commit: str) -> None:
    names = expected_names(tag)
    if payload_dir.is_symlink() or {p.name for p in payload_dir.iterdir()} != {
        "packages",
        "publish-manifest.json",
    }:
        raise ValueError("Unexpected publish payload layout")
    path = payload_dir / "publish-manifest.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
        raise ValueError("Invalid publish manifest")
    manifest = json.loads(path.read_text("utf-8"))
    if (
        manifest["schema_version"] != 1
        or manifest["tag"] != tag
        or manifest["source_commit"] != source_commit
    ):
        raise ValueError("Publish identity mismatch")
    packages = payload_dir / "packages"
    if (
        packages.is_symlink()
        or not packages.is_dir()
        or {p.name for p in packages.iterdir()} != names
        or set(manifest["files"]) != names
    ):
        raise ValueError("Unexpected publish distribution set")
    for name in names:
        record = manifest["files"][name]
        source = packages / name
        if (
            digest(source) != record["sha256"]
            or source.stat().st_size != record["bytes"]
        ):
            raise ValueError("Publish distribution digest mismatch")


def signer_identity(repository: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", repository):
        raise ValueError("Invalid repository")
    return f"https://github.com/{repository}/{SIGNER_WORKFLOW}@{SIGNER_REF}"


def _bounded_bytes(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("Invalid trusted verification input")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Invalid trusted verification input")
    return data


def _matches_protected_signer(item: object, repository: str) -> dict | None:
    """Return the statement only for the protected release-promotion signer."""
    if not isinstance(item, dict):
        return None
    result = item.get("verificationResult")
    if not isinstance(result, dict):
        return None
    signature = result.get("signature")
    statement = result.get("statement")
    if not isinstance(signature, dict) or not isinstance(statement, dict):
        return None
    certificate = signature.get("certificate")
    if not isinstance(certificate, dict):
        return None
    if (
        certificate.get("subjectAlternativeName") != signer_identity(repository)
        or certificate.get("issuer") != OIDC_ISSUER
        or certificate.get("sourceRepositoryURI") != f"https://github.com/{repository}"
        or certificate.get("sourceRepositoryRef") != SIGNER_REF
        or certificate.get("runnerEnvironment") != "github-hosted"
        or statement.get("predicateType") != PROVENANCE_PREDICATE
    ):
        return None
    return statement


def require_attested(
    results_path: Path, name: str, sha256: str, repository: str
) -> None:
    """Require a protected-signer statement naming this exact subject digest."""
    results = json.loads(_bounded_bytes(results_path, MAX_ATTESTATION_BYTES))
    if not isinstance(results, list):
        raise ValueError("Invalid attestation verification result")
    for item in results:
        statement = _matches_protected_signer(item, repository)
        subjects = statement.get("subject") if statement else None
        if isinstance(subjects, list) and any(
            isinstance(subject, dict)
            and subject.get("name") == name
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == sha256
            for subject in subjects
        ):
            return
    raise ValueError("No protected release attestation for publish subject")


def authenticate(
    payload_dir: Path,
    tag: str,
    source_commit: str,
    evidence_path: Path,
    attestation_dir: Path,
    repository: str,
) -> None:
    """Authenticate handed-off packages against independently protected subjects.

    The bundled publish manifest is producer-authored integrity metadata only.
    Authority comes from public release evidence and package bytes that each
    carry provenance from the protected release-promotion signer.
    """
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("Invalid source commit")
    names = expected_names(tag)
    verify(payload_dir, tag, source_commit)
    raw_evidence = _bounded_bytes(evidence_path, MAX_EVIDENCE_BYTES)
    require_attested(
        attestation_dir / f"{EVIDENCE_NAME}.json",
        EVIDENCE_NAME,
        hashlib.sha256(raw_evidence).hexdigest(),
        repository,
    )
    evidence = json.loads(raw_evidence)
    if (
        not isinstance(evidence, dict)
        or evidence.get("schema_version") != 1
        or evidence.get("tag") != tag
        or evidence.get("version") != tag[1:]
        or evidence.get("source_commit") != source_commit
        or not isinstance(evidence.get("artifacts"), list)
    ):
        raise ValueError("Protected release evidence identity mismatch")
    records: dict[str, dict] = {}
    for item in evidence["artifacts"]:
        if not isinstance(item, dict) or item.get("name") in records:
            raise ValueError("Invalid protected release evidence")
        records[item.get("name")] = item
    packages = payload_dir / "packages"
    for name in sorted(names):
        record = records.get(name)
        source = packages / name
        actual = digest(source)
        if (
            record is None
            or actual != record.get("sha256")
            or source.stat().st_size != record.get("bytes")
        ):
            raise ValueError("Package does not match protected release evidence")
        require_attested(attestation_dir / f"{name}.json", name, actual, repository)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("capture", "verify"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--trusted-evidence", type=Path)
    parser.add_argument("--attestations", type=Path)
    parser.add_argument("--repository")
    args = parser.parse_args()
    if args.mode == "capture":
        if args.output_dir is None:
            parser.error("capture requires --output-dir")
        capture(args.directory, args.output_dir, args.tag, args.source_commit)
    else:
        if None in (args.trusted_evidence, args.attestations, args.repository):
            parser.error(
                "verify requires --trusted-evidence, --attestations and --repository"
            )
        authenticate(
            args.directory,
            args.tag,
            args.source_commit,
            args.trusted_evidence,
            args.attestations,
            args.repository,
        )


if __name__ == "__main__":
    main()
