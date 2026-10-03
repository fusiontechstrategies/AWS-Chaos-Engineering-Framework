"""Create a verified draft, cleaning up only its returned immutable release ID."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil

# Only a resolved GitHub CLI is invoked, using separate arguments and no shell.
import subprocess  # nosec B404
import tempfile
from pathlib import Path


def load_integrity():
    path = Path(__file__).resolve().with_name("verify_release_integrity.py")
    spec = importlib.util.spec_from_file_location("trusted_release_integrity", path)
    if spec is None or spec.loader is None:
        raise ImportError("Trusted release verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_source_reader():
    path = Path(__file__).resolve().with_name("source_files.py")
    spec = importlib.util.spec_from_file_location("trusted_source_files", path)
    if spec is None or spec.loader is None:
        raise ImportError("Trusted source reader is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gh(arguments):
    executable = shutil.which("gh")
    if executable is None:
        raise RuntimeError("GitHub CLI is unavailable")
    trusted_executable = str(Path(executable).resolve(strict=True))
    # Tagged data cannot supply the executable or a shell command.
    return subprocess.check_output(  # nosec B603
        [trusted_executable, *arguments], text=True, encoding="utf-8", shell=False
    )


def create_draft(assets, notes, repository, tag, commit, manifest):
    integrity = load_integrity()
    integrity.verify_assets(assets, manifest)
    integrity.verify_tag(repository, tag, commit)
    try:
        notes_text = load_source_reader().read_text(notes.parent, notes.name, 65_536)
    except (ValueError, OSError) as error:
        raise ValueError("Release notes must be a bounded regular data file") from error
    release_id = None
    try:
        created = json.loads(
            gh(
                [
                    "api",
                    f"repos/{repository}/releases",
                    "--method",
                    "POST",
                    "-f",
                    "tag_name=" + tag,
                    "-f",
                    "target_commitish=" + commit,
                    "-f",
                    "name=AWS Chaos Engineering Framework " + tag,
                    "-F",
                    "draft=true",
                    "-F",
                    "prerelease=false",
                    "-F",
                    "body=" + notes_text,
                ]
            )
        )
        candidate_id = created.get("id")
        if type(candidate_id) is not int or candidate_id <= 0:
            raise ValueError("New draft did not return an immutable release ID")
        release_id = candidate_id
        if created.get("tag_name") != tag or created.get("draft") is not True:
            raise ValueError("New release identity or draft state differs")
        gh(
            [
                "release",
                "upload",
                tag,
                "--repo",
                repository,
                *[str(assets / name) for name in sorted(manifest)],
            ]
        )
        state = json.loads(gh(["api", f"repos/{repository}/releases/{release_id}"]))
        if (
            state.get("id") != release_id
            or state.get("tag_name") != tag
            or state.get("draft") is not True
            or state.get("prerelease") is not False
            or {item["name"] for item in state["assets"]} != set(manifest)
            or len(state["assets"]) != len(manifest)
        ):
            raise ValueError("Remote draft identity or exact subject set differs")
        with tempfile.TemporaryDirectory(prefix="release-readback-") as directory:
            gh(["release", "download", tag, "--repo", repository, "--dir", directory])
            integrity.verify_assets(Path(directory), manifest)
        integrity.verify_tag(repository, tag, commit)
    except Exception as failure:
        if release_id is not None:
            # Never resolve by tag or remove a release that predated this call.
            try:
                gh(
                    [
                        "api",
                        f"repos/{repository}/releases/{release_id}",
                        "--method",
                        "DELETE",
                    ]
                )
            except Exception as cleanup:
                raise RuntimeError(
                    "New draft verification failed and cleanup requires owner review"
                ) from cleanup
        raise failure
    return release_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assets", type=Path)
    parser.add_argument("notes", type=Path)
    parser.add_argument("repository")
    parser.add_argument("tag")
    parser.add_argument("commit")
    parser.add_argument("manifest")
    args = parser.parse_args()
    print(
        create_draft(
            args.assets,
            args.notes,
            args.repository,
            args.tag,
            args.commit,
            json.loads(args.manifest),
        )
    )


if __name__ == "__main__":
    main()
