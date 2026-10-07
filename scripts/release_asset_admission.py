"""Admit public release assets by size before download and verify them as data.

Public release assets and their checksum and evidence manifests are untrusted
until protected provenance is verified. This helper never hands a manifest
name to a generic filesystem consumer: only the six fixed release basenames
are accepted, each is opened as a regular, non-symlink file directly beneath
the asset directory, and every read is bounded. Downloads are admitted from
release metadata by per-file and aggregate size before any byte is fetched,
then streamed under deadlines into new private files while being hashed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PureWindowsPath

PROJECT_SLUG = "AWS-Chaos-Engineering-Framework"
ARCHIVE_NAME = "aws_chaos_engineering_framework"
CHECKSUMS_NAME = "SHA256SUMS.txt"
EVIDENCE_NAME = "release-evidence.json"
TAG = re.compile(r"v([0-9]+\.[0-9]+\.[0-9]+)")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
CHECKSUM_LINE = re.compile(r"([0-9a-f]{64})  ([^\n]+)")
CHUNK_BYTES = 65_536
MAX_NAME_LENGTH = 255
# Per-file limits match the trusted handoff verifier. The aggregate is lower
# than the sum of the per-file limits, so it is an independent admission rule.
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_SBOM_BYTES = 1_048_576
MAX_CHECKSUMS_BYTES = 4096
MAX_EVIDENCE_BYTES = 1_048_576
MAX_RELEASE_BYTES = 32 * 1024 * 1024
METADATA_BYTES = 1_048_576
TOTAL_SECONDS = 300
READ_TIMEOUT_SECONDS = 15


class AdmissionError(ValueError):
    """A release asset, manifest or transport violates the admission contract."""


def expected_assets(tag: str) -> dict[str, int]:
    """Return the exact release basenames, in release order, with byte limits."""
    match = TAG.fullmatch(tag) if isinstance(tag, str) else None
    if match is None:
        raise AdmissionError("Invalid release tag")
    version = match.group(1)
    return {
        f"{PROJECT_SLUG}-v{version}.py": MAX_SOURCE_BYTES,
        f"{ARCHIVE_NAME}-{version}-py3-none-any.whl": MAX_ARCHIVE_BYTES,
        f"{ARCHIVE_NAME}-{version}.tar.gz": MAX_ARCHIVE_BYTES,
        f"{PROJECT_SLUG}-v{version}.spdx.json": MAX_SBOM_BYTES,
        CHECKSUMS_NAME: MAX_CHECKSUMS_BYTES,
        EVIDENCE_NAME: MAX_EVIDENCE_BYTES,
    }


def admit_name(value: object, allowed) -> str:
    """Accept only one exact expected basename; never a path."""
    if not isinstance(value, str) or not 0 < len(value) <= MAX_NAME_LENGTH:
        raise AdmissionError("Release asset name is missing or too long")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        raise AdmissionError("Release asset name contains a control character")
    if (
        value.startswith(("/", "\\"))
        or PureWindowsPath(value).drive
        or PureWindowsPath(value).is_absolute()
        or ":" in value
    ):
        raise AdmissionError("Release asset name is absolute")
    if "/" in value or "\\" in value:
        raise AdmissionError("Release asset name contains a path separator")
    if value in {".", ".."} or value.startswith(".."):
        raise AdmissionError("Release asset name traverses directories")
    if value not in allowed:
        raise AdmissionError("Unexpected release asset name")
    return value


def _strict_json(raw: bytes) -> object:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AdmissionError("Duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionError("Invalid JSON document") from error


def _exact_int(value: object) -> bool:
    return type(value) is int


def _open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _directory_descriptor(directory: Path) -> int | None:
    """Open the asset directory without following links where the OS allows it."""
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_DIRECTORY"):
        return None
    return os.open(
        directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )


def read_regular(
    directory: Path,
    name: str,
    limit: int,
    *,
    keep: bool = False,
    dir_fd: int | None = None,
) -> tuple[int, str, bytes | None]:
    """Hash one regular, non-symlink child with bounded streaming.

    The child is checked with lstat, opened without following links and
    without blocking (beneath the directory descriptor where supported), and
    then bound to the same file identity with fstat. A change in identity,
    type or size during the read is refused.
    """
    target = name if dir_fd is not None else directory / name
    before = os.lstat(target, dir_fd=dir_fd)
    if not stat.S_ISREG(before.st_mode):
        raise AdmissionError("Release asset is not a regular file")
    if before.st_size > limit:
        raise AdmissionError("Release asset exceeds its byte limit")
    descriptor = os.open(target, _open_flags(), dir_fd=dir_fd)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
        ):
            raise AdmissionError("Release asset changed while it was opened")
        digest = hashlib.sha256()
        values = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(CHUNK_BYTES, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise AdmissionError("Release asset exceeds its byte limit")
            digest.update(chunk)
            if keep:
                values.append(chunk)
        after = os.fstat(descriptor)
        if (
            total != opened.st_size
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            raise AdmissionError("Release asset changed while it was read")
    finally:
        os.close(descriptor)
    return total, digest.hexdigest(), b"".join(values) if keep else None


def parse_checksums(raw: bytes, allowed) -> dict[str, str]:
    """Parse the fixed checksum manifest without letting it name local paths."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise AdmissionError("Checksum manifest is not ASCII") from error
    if not text.endswith("\n") or "\r" in text:
        raise AdmissionError("Checksum manifest has an invalid line format")
    result: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise AdmissionError("Checksum manifest has an invalid line format")
        name = admit_name(match.group(2), allowed)
        if name in result:
            raise AdmissionError("Checksum manifest names a subject twice")
        result[name] = match.group(1)
    if set(result) != set(allowed):
        raise AdmissionError("Checksum manifest does not name every subject")
    return result


def parse_evidence(
    raw: bytes, tag: str, source_commit: str, names: tuple[str, ...]
) -> dict[str, dict]:
    """Parse release evidence into fixed subjects; names are only compared."""
    document = _strict_json(raw)
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or document.get("tag") != tag
        or document.get("version") != tag[1:]
        or document.get("source_commit") != source_commit
    ):
        raise AdmissionError("Release evidence identity mismatch")
    listed = document.get("expected_release_assets")
    if not isinstance(listed, list) or len(listed) != len(names):
        raise AdmissionError("Release evidence asset set mismatch")
    seen: set[str] = set()
    for value in listed:
        name = admit_name(value, names)
        if name in seen:
            raise AdmissionError("Release evidence names an asset twice")
        seen.add(name)
    inputs = names[:5]
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(inputs):
        raise AdmissionError("Release evidence subject set mismatch")
    records: dict[str, dict] = {}
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"bytes", "name", "sha256"}:
            raise AdmissionError("Invalid release evidence subject")
        name = admit_name(item["name"], inputs)
        if name in records:
            raise AdmissionError("Release evidence names a subject twice")
        if (
            not _exact_int(item["bytes"])
            or item["bytes"] < 0
            or not isinstance(item["sha256"], str)
            or not SHA256.fullmatch(item["sha256"])
        ):
            raise AdmissionError("Invalid release evidence subject")
        records[name] = {"bytes": item["bytes"], "sha256": item["sha256"]}
    return records


def verify_assets(
    directory: Path, tag: str, source_commit: str, source: Path | None = None
) -> dict[str, dict]:
    """Verify six admitted assets against the fixed checksum and evidence subjects."""
    limits = expected_assets(tag)
    names = tuple(limits)
    if not isinstance(source_commit, str) or not COMMIT.fullmatch(source_commit):
        raise AdmissionError("Invalid source commit")
    directory = Path(directory)
    status = os.lstat(directory)
    if not stat.S_ISDIR(status.st_mode):
        raise AdmissionError("Release asset directory must be a real directory")
    dir_fd = _directory_descriptor(directory)
    try:
        if dir_fd is not None:
            opened = os.fstat(dir_fd)
            if (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino):
                raise AdmissionError("Release asset directory changed")
        entries = os.listdir(directory if dir_fd is None else dir_fd)
        for entry in entries:
            admit_name(entry, names)
        if len(entries) != len(names) or set(entries) != set(names):
            raise AdmissionError(
                "Release asset directory does not hold exactly six assets"
            )
        # Admit every type and size before any asset is opened or hashed.
        declared = 0
        for name in names:
            child = os.lstat(
                name if dir_fd is not None else directory / name, dir_fd=dir_fd
            )
            if not stat.S_ISREG(child.st_mode):
                raise AdmissionError("Release asset is not a regular file")
            if child.st_size > limits[name]:
                raise AdmissionError("Release asset exceeds its byte limit")
            declared += child.st_size
        if declared > MAX_RELEASE_BYTES:
            raise AdmissionError("Release assets exceed the aggregate byte limit")
        computed: dict[str, dict] = {}
        retained: dict[str, bytes] = {}
        for name in names:
            # read_regular refuses any size change after this admission.
            keep = name in {CHECKSUMS_NAME, EVIDENCE_NAME}
            size, digest, data = read_regular(
                directory, name, limits[name], keep=keep, dir_fd=dir_fd
            )
            computed[name] = {"bytes": size, "sha256": digest}
            if data is not None:
                retained[name] = data
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    checksums = parse_checksums(retained[CHECKSUMS_NAME], names[:4])
    evidence = parse_evidence(retained[EVIDENCE_NAME], tag, source_commit, names)
    for name in names[:4]:
        if checksums[name] != computed[name]["sha256"]:
            raise AdmissionError("Release asset differs from its checksum subject")
    for name in names[:5]:
        if evidence[name] != computed[name]:
            raise AdmissionError("Release asset differs from its evidence subject")
    if source is not None:
        source = Path(source)
        _size, digest, _data = read_regular(
            source.parent, source.name, MAX_SOURCE_BYTES
        )
        if digest != computed[names[0]]["sha256"]:
            raise AdmissionError("Standalone release source differs from tagged source")
    return computed


def admit_release_metadata(metadata: object, tag: str) -> dict[str, dict]:
    """Admit exactly the six named, uploaded assets by declared size."""
    limits = expected_assets(tag)
    if (
        not isinstance(metadata, dict)
        or metadata.get("tag_name") != tag
        or metadata.get("draft") is not False
        or metadata.get("prerelease") is not False
    ):
        raise AdmissionError("Release metadata identity mismatch")
    assets = metadata.get("assets")
    if not isinstance(assets, list) or len(assets) != len(limits):
        raise AdmissionError("Release metadata asset set mismatch")
    admitted: dict[str, dict] = {}
    total = 0
    for asset in assets:
        if not isinstance(asset, dict):
            raise AdmissionError("Invalid release asset metadata")
        name = admit_name(asset.get("name"), limits)
        if name in admitted:
            raise AdmissionError("Release metadata names an asset twice")
        identifier, size = asset.get("id"), asset.get("size")
        digest = asset.get("digest")
        if (
            not _exact_int(identifier)
            or identifier <= 0
            or not _exact_int(size)
            or not 0 < size <= limits[name]
            or asset.get("state") != "uploaded"
        ):
            raise AdmissionError("Release asset metadata exceeds its admission limits")
        if digest is not None and (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or not SHA256.fullmatch(digest[7:])
        ):
            raise AdmissionError("Release asset metadata has an invalid digest")
        total += size
        admitted[name] = {
            "id": identifier,
            "size": size,
            "sha256": digest[7:] if digest else None,
        }
    if set(admitted) != set(limits):
        raise AdmissionError("Release metadata asset set mismatch")
    if total > MAX_RELEASE_BYTES:
        raise AdmissionError("Release assets exceed the aggregate byte limit")
    return admitted


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _request(url: str, token: str | None = None, accept: str | None = None):
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.fragment
        or any(ord(character) < 33 for character in url)
    ):
        raise AdmissionError("Release transport requires an absolute HTTPS URL")
    headers = {"X-GitHub-Api-Version": "2022-11-28"}
    if accept is not None:
        headers["Accept"] = accept
    if token is not None:
        if parts.hostname != "api.github.com" or parts.port not in {None, 443}:
            raise AdmissionError("Release API credential is restricted to GitHub")
        headers["Authorization"] = "Bearer " + token
    return urllib.request.Request(url, headers=headers)


def stream(response, limit: int, deadline: float, sink=None, digest=None) -> bytes:
    """Read at most limit bytes before the deadline, hashing as data arrives."""
    declared = response.headers.get("Content-Length")
    if declared is not None and (not declared.isdecimal() or int(declared) > limit):
        raise AdmissionError("Release response exceeds its declared byte limit")
    values = []
    total = 0
    while True:
        if time.monotonic() >= deadline:
            raise AdmissionError("Release response exceeds its read deadline")
        chunk = response.read1(min(CHUNK_BYTES, limit - total + 1))
        if time.monotonic() >= deadline:
            raise AdmissionError("Release response exceeds its read deadline")
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise AdmissionError("Release response exceeds its byte limit")
        if digest is not None:
            digest.update(chunk)
        if sink is None:
            values.append(chunk)
        else:
            sink.write(chunk)
    if declared is not None and total != int(declared):
        raise AdmissionError("Release response length differs from its metadata")
    return b"".join(values)


def _asset_response(opener, url: str, token: str):
    """Return the asset stream; a storage redirect is fetched without credentials."""
    try:
        return opener.open(
            _request(url, token, "application/octet-stream"),
            timeout=READ_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        try:
            if error.code not in {301, 302, 303, 307, 308}:
                raise AdmissionError("Release asset request failed") from None
            location = error.headers.get("Location", "")
        finally:
            error.close()
    return opener.open(_request(location), timeout=READ_TIMEOUT_SECONDS)


def download(
    repository: str, tag: str, output: Path, only: list[str] | None = None
) -> dict[str, dict]:
    """Admit release metadata, then stream selected assets into a new directory."""
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise AdmissionError("Invalid repository")
    limits = expected_assets(tag)
    selected = list(limits) if not only else []
    for value in only or ():
        name = admit_name(value, limits)
        if name in selected:
            raise AdmissionError("Selected asset named twice")
        selected.append(name)
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise AdmissionError("GitHub release read credential is missing")
    output = Path(output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise AdmissionError("Release output must be new inside an existing directory")
    opener = urllib.request.build_opener(NoRedirect())
    deadline = time.monotonic() + TOTAL_SECONDS
    api = f"https://api.github.com/repos/{repository}/releases"
    quoted = urllib.parse.quote(tag, safe="")
    with opener.open(
        _request(f"{api}/tags/{quoted}", token, "application/vnd.github+json"),
        timeout=READ_TIMEOUT_SECONDS,
    ) as response:
        metadata = _strict_json(stream(response, METADATA_BYTES, deadline))
    admitted = admit_release_metadata(metadata, tag)
    private = Path(tempfile.mkdtemp(prefix=".release-assets-", dir=output.parent))
    created: list[Path] = []
    results: dict[str, dict] = {}
    try:
        for name in selected:
            record = admitted[name]
            path = private / name
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_BINARY", 0),
                0o600,
            )
            created.append(path)
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "wb") as sink:
                with _asset_response(
                    opener, f"{api}/assets/{record['id']}", token
                ) as response:
                    stream(response, record["size"], deadline, sink, digest)
                sink.flush()
                os.fsync(sink.fileno())
            size = os.lstat(path).st_size
            if size != record["size"]:
                raise AdmissionError("Release asset length differs from its metadata")
            if record["sha256"] is not None and digest.hexdigest() != record["sha256"]:
                raise AdmissionError("Release asset digest differs from its metadata")
            results[name] = {"bytes": size, "sha256": digest.hexdigest()}
        # The output appears only after every selected asset was admitted.
        output.mkdir(mode=0o700)
        moved: list[Path] = []
        try:
            for path in created:
                os.rename(path, output / path.name)
                moved.append(output / path.name)
        except BaseException:
            for path in moved:
                path.unlink(missing_ok=True)
            output.rmdir()
            raise
        created.clear()
    finally:
        for path in created:
            path.unlink(missing_ok=True)
        private.rmdir()
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    fetch = commands.add_parser("download")
    fetch.add_argument("--repository", required=True)
    fetch.add_argument("--tag", required=True)
    fetch.add_argument("--output", type=Path, required=True)
    fetch.add_argument("--only", action="append")
    check = commands.add_parser("verify")
    check.add_argument("directory", type=Path)
    check.add_argument("--tag", required=True)
    check.add_argument("--source-commit", required=True)
    check.add_argument("--source", type=Path)
    args = parser.parse_args()
    if args.operation == "download":
        result = download(args.repository, args.tag, args.output, args.only)
    else:
        result = verify_assets(
            args.directory, args.tag, args.source_commit, args.source
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
