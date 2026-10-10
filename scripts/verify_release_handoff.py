"""Reconstruct tagged release data using only independently trusted verifier code."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

MAX_ASSET_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def load_trusted_helper(name):
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("trusted_" + name, path)
    if spec is None or spec.loader is None:
        raise ValueError("Missing trusted release verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


archive_budget = load_trusted_helper("archive_budget")


def preflight_archives(directory):
    """Use the same pre-parser budgets as normalization and trusted verification."""
    for path in directory.iterdir():
        if path.name.endswith(".whl"):
            with archive_budget.open_zip(
                path,
                max_member_bytes=MAX_ASSET_BYTES,
                max_expanded_bytes=MAX_TOTAL_BYTES,
            ) as archive:
                if any(
                    m.compress_type != zipfile.ZIP_STORED for m in archive.infolist()
                ):
                    raise ValueError("Wheel handoff is not stored canonically")
        else:
            with archive_budget.open_tar(
                path, max_stream_bytes=MAX_TOTAL_BYTES, canonical_gzip=True
            ):
                pass


def verify_run_identity(run, artifact_pages, run_id, commit, repository):
    """Bind complete API metadata to one immutable artifact and triggering tag."""
    if (
        run.get("id") != run_id
        or run.get("path") != ".github/workflows/release.yml"
        or run.get("event") != "push"
        or run.get("conclusion") != "success"
        or run.get("head_sha") != commit
        or run.get("head_repository", {}).get("full_name") != repository
    ):
        raise ValueError("Producer run identity mismatch")
    tag = run.get("head_branch")
    if (
        not isinstance(tag, str)
        or len(tag) > 65
        or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag)
    ):
        raise ValueError("Producer run is not a stable version-tag push")
    candidates = [
        artifact
        for page in artifact_pages
        for artifact in page["artifacts"]
        if artifact["name"] == "release-assets" and not artifact["expired"]
    ]
    if len(candidates) != 1:
        raise ValueError("Producer must have exactly one live release candidate")
    artifact_id = candidates[0]["id"]
    if type(artifact_id) is not int or artifact_id <= 0:
        raise ValueError("Producer artifact ID is invalid")
    return {"artifact-id": artifact_id, "source-tag": tag}


def verify_handoff(assets, source, commit, epoch, expected_tag=None):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid authenticated source commit")
    leaves = tuple(assets.iterdir())
    if len(leaves) != 6 or any(p.is_symlink() or not p.is_file() for p in leaves):
        raise ValueError("Release handoff must contain six regular assets")
    sizes = [p.stat().st_size for p in leaves]
    if max(sizes) > MAX_ASSET_BYTES or sum(sizes) > MAX_TOTAL_BYTES:
        raise ValueError("Release handoff exceeds its byte budget")
    evidence_path = assets / "release-evidence.json"
    if evidence_path.stat().st_size > 128 * 1024:
        raise ValueError("Release evidence exceeds its byte budget")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    version = evidence.get("version")
    if (
        not isinstance(version, str)
        or len(version) > 64
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
    ):
        raise ValueError("Invalid stable release version")
    if (
        evidence.get("source_commit") != commit
        or evidence.get("source_date_epoch") != epoch
    ):
        raise ValueError("Producer evidence differs from authenticated source identity")
    tag = "v" + version
    if evidence.get("tag") != tag:
        raise ValueError("Producer tag differs from release version")
    if expected_tag is not None and tag != expected_tag:
        raise ValueError("Candidate tag differs from the authenticated triggering tag")
    prepare = load_trusted_helper("prepare_release")
    integrity = load_trusted_helper("verify_release_integrity")
    with tempfile.TemporaryDirectory(prefix="verified-handoff-") as directory:
        root = Path(directory)
        dist = root / "dist"
        dist.mkdir()
        for name in (
            f"aws_chaos_engineering_framework-{version}-py3-none-any.whl",
            f"aws_chaos_engineering_framework-{version}.tar.gz",
        ):
            (dist / name).write_bytes((assets / name).read_bytes())
        preflight_archives(dist)
        rebuilt = root / "rebuilt"
        # Trusted prepare_release regenerates private wheel and sdist copies
        # with the trusted normalizers and refuses any candidate whose bytes
        # differ, before checksums or evidence are built for attestation.
        prepare.prepare_release(source, dist, rebuilt, version, tag, commit, epoch)
        manifest = integrity.manifest(rebuilt)
        integrity.verify_assets(assets, manifest)
    return {"version": version, "tag": tag, "manifest": manifest}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "identity":
        parser = argparse.ArgumentParser(description=verify_run_identity.__doc__)
        parser.add_argument("run", type=Path)
        parser.add_argument("artifacts", type=Path)
        parser.add_argument("run_id", type=int)
        parser.add_argument("commit")
        parser.add_argument("repository")
        args = parser.parse_args(sys.argv[2:])
        result = verify_run_identity(
            json.loads(args.run.read_text()),
            json.loads(args.artifacts.read_text()),
            args.run_id,
            args.commit,
            args.repository,
        )
        print(json.dumps(result, sort_keys=True))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assets", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("commit")
    parser.add_argument("epoch", type=int)
    parser.add_argument("--expected-manifest")
    parser.add_argument("--expected-tag")
    args = parser.parse_args()
    result = verify_handoff(
        args.assets, args.source, args.commit, args.epoch, args.expected_tag
    )
    if args.expected_manifest and result["manifest"] != json.loads(
        args.expected_manifest
    ):
        raise ValueError(
            "Promotion bytes differ from the independently verified handoff"
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    verifier = load_trusted_helper("verify_distribution")
    raise SystemExit(verifier.run_with_actions_command_guard(main))
