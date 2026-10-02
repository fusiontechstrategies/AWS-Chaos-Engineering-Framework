from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import create_verified_draft as draft
from scripts import normalize_sdist, normalize_wheel, prepare_release
from scripts import verify_release_handoff as handoff

ROOT = Path(__file__).resolve().parents[1]
SOURCE = subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
).strip()
EPOCH = 315532800


class TrustedPromotionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.fixture.name).resolve()
        cls.source = cls.directory / "source"
        cls.source.mkdir()
        # Archive the immutable checkout commit, available even in depth-one CI.
        archive = subprocess.check_output(  # noqa: S603
            ["git", "archive", SOURCE], cwd=ROOT
        )
        with tarfile.open(fileobj=io.BytesIO(archive)) as files:
            files.extractall(cls.source, filter="data")
        cls.dist = cls.directory / "dist"
        env = os.environ.copy()
        env["SOURCE_DATE_EPOCH"] = str(EPOCH)
        result = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--wheel",
                "--sdist",
                "--outdir",
                str(cls.dist),
                str(cls.source),
            ],
            capture_output=True,
            env=env,
        )
        if result.returncode:
            raise RuntimeError(result.stdout.decode() + result.stderr.decode())
        normalize_wheel.normalize_wheel(next(cls.dist.glob("*.whl")), EPOCH)
        normalize_sdist.normalize_sdist(next(cls.dist.glob("*.tar.gz")), EPOCH)
        cls.assets = cls.directory / "assets"
        prepare_release.prepare_release(
            cls.source, cls.dist, cls.assets, "2.0.4", "v2.0.4", SOURCE, EPOCH
        )

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def test_exact_frozen_six_asset_handoff(self):
        result = handoff.verify_handoff(self.assets, self.source, SOURCE, EPOCH)
        self.assertEqual(result["tag"], "v2.0.4")
        self.assertEqual(len(result["manifest"]), 6)

    def test_changed_asset_is_rejected_before_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory) / "assets"
            shutil.copytree(self.assets, assets)
            (assets / "SHA256SUMS.txt").write_text("altered", encoding="utf-8")
            with self.assertRaises(ValueError):
                handoff.verify_handoff(assets, self.source, SOURCE, EPOCH)

    def test_source_identity_mismatch_and_extra_asset_are_rejected(self):
        with self.assertRaises(ValueError):
            handoff.verify_handoff(self.assets, self.source, "b" * 40, EPOCH)
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory) / "assets"
            shutil.copytree(self.assets, assets)
            (assets / "unexpected.py").write_text("raise RuntimeError()")
            with self.assertRaises(ValueError):
                handoff.verify_handoff(assets, self.source, SOURCE, EPOCH)

    def test_authenticated_triggering_tag_must_match_candidate_version(self):
        with self.assertRaisesRegex(ValueError, "authenticated triggering tag"):
            handoff.verify_handoff(self.assets, self.source, SOURCE, EPOCH, "v2.0.3")
        handoff.verify_handoff(self.assets, self.source, SOURCE, EPOCH, "v2.0.4")

    def test_run_identity_rejects_branch_and_checks_all_artifact_pages(self):
        run = {
            "id": 123,
            "path": ".github/workflows/release.yml",
            "event": "push",
            "conclusion": "success",
            "head_sha": SOURCE,
            "head_repository": {"full_name": "owner/repository"},
            "head_branch": "v2.0.4",
        }
        pages = [
            {"artifacts": [{"id": 456, "name": "release-assets", "expired": False}]}
        ]
        self.assertEqual(
            handoff.verify_run_identity(run, pages, 123, SOURCE, "owner/repository")[
                "source-tag"
            ],
            "v2.0.4",
        )
        with self.assertRaisesRegex(ValueError, "version-tag push"):
            handoff.verify_run_identity(
                dict(run, head_branch="main"), pages, 123, SOURCE, "owner/repository"
            )
        pages.append(
            {"artifacts": [{"id": 789, "name": "release-assets", "expired": False}]}
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            handoff.verify_run_identity(run, pages, 123, SOURCE, "owner/repository")

    def test_installed_namespace_cannot_shadow_trusted_distribution_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            marker = root / "untrusted-helper.txt"
            (scripts / "__init__.py").write_text("")
            (scripts / "verify_distribution.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n"
            )
            # Simulate another package on an otherwise allowed interpreter path.
            program = (
                "import sys,importlib.util\n"
                f"sys.path.insert(0,{str(root)!r})\n"
                f"spec=importlib.util.spec_from_file_location('trusted_prepare',{str(ROOT / 'scripts/prepare_release.py')!r})\n"
                "module=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\n"
            )
            subprocess.run(
                [sys.executable, "-I", "-c", program], check=True, capture_output=True
            )
            self.assertFalse(marker.exists())

    def test_failed_new_draft_removes_only_its_created_immutable_id(self):
        for failure in ("upload", "readback", "digest", "final_tag"):
            with self.subTest(failure=failure):
                calls = []
                verifier = MagicMock()
                verifier.verify_tag.side_effect = (
                    [None, ValueError("tag moved")] if failure == "final_tag" else None
                )
                verifier.verify_assets.side_effect = (
                    [None, ValueError("digest mismatch")]
                    if failure == "digest"
                    else None
                )

                def fake_gh(arguments, scenario=failure, call_log=calls):
                    call_log.append(arguments)
                    if "POST" in arguments:
                        return json.dumps(
                            {"id": 901, "tag_name": "v2.0.4", "draft": True}
                        )
                    if arguments[:2] == ["release", "upload"] and scenario == "upload":
                        raise RuntimeError("partial upload")
                    if (
                        arguments[:2] == ["release", "download"]
                        and scenario == "readback"
                    ):
                        raise RuntimeError("download failed")
                    if (
                        arguments[:2] == ["api", "repos/owner/repository/releases/901"]
                        and "DELETE" not in arguments
                    ):
                        return json.dumps(
                            {
                                "id": 901,
                                "tag_name": "v2.0.4",
                                "draft": True,
                                "prerelease": False,
                                "assets": [{"name": "asset"}],
                            }
                        )
                    return ""

                with (
                    patch.object(draft, "load_integrity", return_value=verifier),
                    patch.object(draft, "gh", side_effect=fake_gh),
                    self.assertRaises((RuntimeError, ValueError)),
                ):
                    draft.create_draft(
                        self.assets,
                        self.source / ".github/release-notes/v2.0.4.md",
                        "owner/repository",
                        "v2.0.4",
                        SOURCE,
                        {"asset": "digest"},
                    )
                self.assertIn(
                    [
                        "api",
                        "repos/owner/repository/releases/901",
                        "--method",
                        "DELETE",
                    ],
                    calls,
                )
                self.assertFalse(
                    any(
                        "--cleanup-tag" in call or "--clobber" in call for call in calls
                    )
                )

    def test_existing_release_or_ambiguous_creation_is_never_deleted_by_tag(self):
        verifier = MagicMock()
        calls = []

        def fail_create(arguments):
            calls.append(arguments)
            raise RuntimeError("existing release or unknown creation response")

        with (
            patch.object(draft, "load_integrity", return_value=verifier),
            patch.object(draft, "gh", side_effect=fail_create),
            self.assertRaises(RuntimeError),
        ):
            draft.create_draft(
                self.assets,
                self.source / ".github/release-notes/v2.0.4.md",
                "owner/repository",
                "v2.0.4",
                SOURCE,
                {"asset": "digest"},
            )
        self.assertFalse(any("DELETE" in call for call in calls))

    def test_gzip_expansion_is_bounded_before_archive_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.tar.gz").write_bytes(gzip.compress(b"0" * 8192))
            with (
                patch.object(handoff, "MAX_TOTAL_BYTES", 1024),
                self.assertRaisesRegex(ValueError, "decoded archive budget"),
            ):
                handoff.preflight_archives(root)

    def test_cleanup_failure_requires_owner_review(self):
        calls = []

        def fail_upload_and_cleanup(arguments):
            calls.append(arguments)
            if "POST" in arguments:
                return json.dumps({"id": 901, "tag_name": "v2.0.4", "draft": True})
            raise RuntimeError("synthetic remote failure")

        with (
            patch.object(draft, "load_integrity", return_value=MagicMock()),
            patch.object(draft, "gh", side_effect=fail_upload_and_cleanup),
            self.assertRaisesRegex(RuntimeError, "cleanup requires owner review"),
        ):
            draft.create_draft(
                self.assets,
                self.source / ".github/release-notes/v2.0.4.md",
                "owner/repository",
                "v2.0.4",
                SOURCE,
                {"asset": "digest"},
            )
        deletions = [call for call in calls if "DELETE" in call]
        self.assertEqual(
            deletions,
            [["api", "repos/owner/repository/releases/901", "--method", "DELETE"]],
        )

    def test_wrong_created_identity_cleans_only_returned_id(self):
        for change in ({"tag_name": "v2.0.3"}, {"draft": False}):
            with self.subTest(change=change):
                calls = []

                def wrong_identity(arguments, fields=change, call_log=calls):
                    call_log.append(arguments)
                    if "POST" in arguments:
                        return json.dumps(
                            dict(
                                {"id": 901, "tag_name": "v2.0.4", "draft": True},
                                **fields,
                            )
                        )
                    return ""

                with (
                    patch.object(draft, "load_integrity", return_value=MagicMock()),
                    patch.object(draft, "gh", side_effect=wrong_identity),
                    self.assertRaisesRegex(ValueError, "identity or draft state"),
                ):
                    draft.create_draft(
                        self.assets,
                        self.source / ".github/release-notes/v2.0.4.md",
                        "owner/repository",
                        "v2.0.4",
                        SOURCE,
                        {"asset": "digest"},
                    )
                self.assertEqual(
                    [call for call in calls if "DELETE" in call],
                    [
                        [
                            "api",
                            "repos/owner/repository/releases/901",
                            "--method",
                            "DELETE",
                        ]
                    ],
                )
                self.assertFalse(
                    any(call[:2] == ["release", "upload"] for call in calls)
                )

    def test_successful_verified_draft_returns_id_without_cleanup(self):
        calls = []
        verifier = MagicMock()

        def successful_remote(arguments):
            calls.append(arguments)
            if "POST" in arguments:
                return json.dumps({"id": 901, "tag_name": "v2.0.4", "draft": True})
            if arguments[:2] == ["api", "repos/owner/repository/releases/901"]:
                return json.dumps(
                    {
                        "id": 901,
                        "tag_name": "v2.0.4",
                        "draft": True,
                        "prerelease": False,
                        "assets": [{"name": "asset"}],
                    }
                )
            return ""

        with (
            patch.object(draft, "load_integrity", return_value=verifier),
            patch.object(draft, "gh", side_effect=successful_remote),
        ):
            result = draft.create_draft(
                self.assets,
                self.source / ".github/release-notes/v2.0.4.md",
                "owner/repository",
                "v2.0.4",
                SOURCE,
                {"asset": "digest"},
            )
        self.assertEqual(result, 901)
        self.assertEqual(verifier.verify_assets.call_count, 2)
        self.assertEqual(verifier.verify_tag.call_count, 2)
        self.assertFalse(any("DELETE" in call for call in calls))

    def test_oversized_notes_are_rejected_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            notes = Path(directory).resolve() / "notes.md"
            notes.write_bytes(b"a" * (1024 * 1024 + 1))
            with (
                patch.object(draft, "load_integrity", return_value=MagicMock()),
                patch.object(draft, "gh") as remote,
                self.assertRaisesRegex(ValueError, "bounded regular data file"),
            ):
                draft.create_draft(
                    self.assets,
                    notes,
                    "owner/repository",
                    "v2.0.4",
                    SOURCE,
                    {"asset": "digest"},
                )
            remote.assert_not_called()

    def test_symlinked_notes_ancestor_is_rejected_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target"
            target.mkdir()
            (target / "notes.md").write_text("Reviewed notes", encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"Host cannot create test directory symlink: {error}")
            with (
                patch.object(draft, "load_integrity", return_value=MagicMock()),
                patch.object(draft, "gh") as remote,
                self.assertRaisesRegex(ValueError, "bounded regular data file"),
            ):
                draft.create_draft(
                    self.assets,
                    link / "notes.md",
                    "owner/repository",
                    "v2.0.4",
                    SOURCE,
                    {"asset": "digest"},
                )
            remote.assert_not_called()

    def test_tagged_json_and_distribution_modules_never_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)
            marker = cwd / "module-executed.txt"
            payload = f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n"
            (cwd / "json.py").write_text(payload)
            (cwd / "verify_distribution.py").write_text(payload)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(cwd)
            env["GH_TOKEN"] = "synthetic-not-a-credential"
            result = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    "-I",
                    str(ROOT / "scripts/verify_release_handoff.py"),
                    str(self.assets),
                    str(self.source),
                    SOURCE,
                    str(EPOCH),
                ],
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(len(json.loads(result.stdout)["manifest"]), 6)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
