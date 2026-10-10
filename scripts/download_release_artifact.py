"""Bound the immutable outer Actions artifact before extracting any member."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_path = Path(__file__).resolve().with_name("prepare_release.py")
_spec = importlib.util.spec_from_file_location("trusted_prepare_release", _path)
if _spec is None or _spec.loader is None:
    raise ImportError("Trusted release verifier is unavailable")
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)
archive_budget = release.archive_budget

METADATA_BYTES = 131_072
TOTAL_SECONDS = 120
READ_TIMEOUT_SECONDS = 15
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read(response, limit: int, deadline: float, sink=None) -> bytes:
    values = []
    total = 0
    declared = response.headers.get("Content-Length")
    if declared is not None and (not declared.isdecimal() or int(declared) > limit):
        raise ValueError("artifact response exceeds its declared byte budget")
    while True:
        if time.monotonic() >= deadline:
            raise ValueError("artifact response exceeds its total read deadline")
        # read1 returns currently available transport data instead of waiting to
        # fill a large block. Socket timeout also bounds an individual read.
        value = response.read1(min(65_536, limit - total + 1))
        if time.monotonic() >= deadline:
            raise ValueError("artifact response exceeds its total read deadline")
        if not value:
            break
        total += len(value)
        if total > limit:
            raise ValueError("artifact response exceeds its actual byte budget")
        if sink is None:
            values.append(value)
        else:
            sink.write(value)
    if declared is not None and total != int(declared):
        raise ValueError("artifact response length differs from its metadata")
    return b"".join(values)


def _request(url: str, token: str | None = None):
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.fragment
    ):
        raise ValueError("artifact transport requires an absolute HTTPS URL")
    if any(ord(character) < 33 for character in url):
        raise ValueError("artifact transport URL contains invalid whitespace")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token is not None:
        if parts.hostname != "api.github.com" or parts.port not in {None, 443}:
            raise ValueError("artifact API credential is restricted to GitHub")
        headers["Authorization"] = "Bearer " + token
    return urllib.request.Request(url, headers=headers)


def admit_outer_archive(path: Path) -> dict[str, bytes]:
    """Preflight all six flat regular leaves, then read under shared budgets."""
    with archive_budget.open_zip(path, max_members=6) as archive:
        members = archive.infolist()
        if len(members) != 6:
            raise ValueError("release artifact must contain exactly six leaves")
        names, portable = set(), set()
        for member in members:
            if any(character in member.filename for character in ':<>"|?*'):
                raise ValueError("release artifact leaf is not portable")
            parts = release.archive_parts(member.filename)
            mode = member.external_attr >> 16
            if (
                len(parts) != 1
                or member.is_dir()
                or member.external_attr & 0x10
                or (stat.S_IFMT(mode) not in {0, stat.S_IFREG})
            ):
                raise ValueError(
                    "release artifact contains a nonregular or nested leaf"
                )
            release.record_portable_name(member.filename, names, portable)
        budget = archive_budget.MemberBudget()
        return {
            member.filename: archive_budget.read_zip_member(archive, member, budget)
            for member in members
        }


def download(
    repository: str,
    artifact_id: int,
    run_id: int,
    output: Path,
    expected_digest: str | None = None,
    expected_name: str = "release-assets",
) -> dict:
    if (
        not REPOSITORY.fullmatch(repository)
        or type(artifact_id) is not int
        or artifact_id <= 0
        or type(run_id) is not int
        or run_id <= 0
    ):
        raise ValueError("artifact identity is invalid")
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise ValueError("GitHub artifact read credential is missing")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError(
            "artifact output must be new inside an existing owned directory"
        )
    opener = urllib.request.build_opener(NoRedirect())
    endpoint = (
        f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}"
    )
    deadline = time.monotonic() + TOTAL_SECONDS
    with opener.open(
        _request(endpoint, token), timeout=READ_TIMEOUT_SECONDS
    ) as response:
        metadata = json.loads(_read(response, METADATA_BYTES, deadline))
    if not isinstance(metadata, dict) or not isinstance(
        metadata.get("workflow_run"), dict
    ):
        raise ValueError("artifact metadata has an invalid identity shape")
    digest = metadata.get("digest")
    if (
        type(metadata.get("id")) is not int
        or metadata.get("id") != artifact_id
        or metadata.get("expired") is not False
        or metadata.get("name") != expected_name
        or metadata.get("workflow_run", {}).get("id") != run_id
        or type(metadata.get("size_in_bytes")) is not int
        or not 0 < metadata["size_in_bytes"] <= archive_budget.MAX_ARCHIVE_BYTES
        or not isinstance(digest, str)
        or not DIGEST.fullmatch(digest)
    ):
        raise ValueError(
            "artifact metadata does not bind a bounded immutable run artifact"
        )
    if (
        expected_digest is not None
        and digest != "sha256:" + expected_digest.removeprefix("sha256:")
    ):
        raise ValueError("artifact digest differs from the trusted upload output")
    try:
        with opener.open(
            _request(endpoint + "/zip", token), timeout=READ_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "artifact API did not return the expected storage redirect"
            )
    except urllib.error.HTTPError as error:
        try:
            if error.code != 302:
                raise ValueError("artifact download redirect failed") from None
            location = error.headers.get("Location", "")
        finally:
            error.close()
    # The authenticated API chooses storage. Its credential is never forwarded,
    # and a second redirect is not followed by this opener.
    storage = _request(location)
    with tempfile.TemporaryDirectory(
        prefix=".bounded-artifact-", dir=output.parent
    ) as directory:
        raw = Path(directory) / "artifact.zip"
        with raw.open("xb") as sink:
            with opener.open(storage, timeout=READ_TIMEOUT_SECONDS) as response:
                _read(response, archive_budget.MAX_ARCHIVE_BYTES, deadline, sink)
            sink.flush()
            os.fsync(sink.fileno())
        actual = release.sha256_file(raw)
        if digest != "sha256:" + actual:
            raise ValueError(
                "raw artifact ZIP digest does not match immutable metadata"
            )
        values = admit_outer_archive(raw)
    # No output directory or member is created until all admission/decompression
    # and integrity checks succeed. No-replace creation preserves collisions.
    output.mkdir(mode=0o700)
    created = []
    try:
        for name, value in values.items():
            path = output / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
    except BaseException:
        for path in created:
            path.unlink()
        output.rmdir()
        raise
    return {
        "artifact_id": artifact_id,
        "run_id": run_id,
        "digest": digest,
        "members": sorted(values),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-digest")
    parser.add_argument("--expected-name", default="release-assets")
    args = parser.parse_args()
    print(
        json.dumps(
            download(
                args.repository,
                args.artifact_id,
                args.run_id,
                args.output,
                args.expected_digest,
                args.expected_name,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    raise SystemExit(archive_budget.run_with_actions_command_guard(main))
