"""Bind the publish payload to verified public-release bytes without imports from a tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


def expected_names(tag: str) -> set[str]:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Invalid release tag")
    version = tag[1:]
    return {
        f"aws_chaos_engineering_framework-{version}-py3-none-any.whl",
        f"aws_chaos_engineering_framework-{version}.tar.gz",
    }


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Publish files must be regular files")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            result.update(chunk)
    return result.hexdigest()


def capture(release_dir: Path, output_dir: Path, tag: str, source_commit: str) -> None:
    names = expected_names(tag)
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("Invalid source commit")
    # This evidence has already passed the workflow's release and attestation
    # checks. Bind both actual source bytes and actual copied bytes to it again.
    evidence = json.loads((release_dir / "release-evidence.json").read_text("utf-8"))
    if evidence["tag"] != tag or evidence["source_commit"] != source_commit:
        raise ValueError("Release identity mismatch")
    records = {item["name"]: item for item in evidence["artifacts"]}
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
        record = records[name]
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("capture", "verify"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    if args.mode == "capture":
        if args.output_dir is None:
            parser.error("capture requires --output-dir")
        capture(args.directory, args.output_dir, args.tag, args.source_commit)
    else:
        verify(args.directory, args.tag, args.source_commit)


if __name__ == "__main__":
    main()
