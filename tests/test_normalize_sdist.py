from __future__ import annotations

import hashlib
import io
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import normalize_sdist as normalizer


class DecodedMembers:
    """In-memory parser records; no link or unsafe-path archive is serialized."""

    def __init__(self, member):
        self.member = member

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def __iter__(self):
        return iter([self.member])

    def extractfile(self, _member):
        raise AssertionError("Refused metadata must not reach member data reading")


def decoded_member_parser(member):
    view = SimpleNamespace(**vars(tarfile))
    view.open = lambda *args, **kwargs: DecodedMembers(member)
    return view


class NormalizeSdistTests(unittest.TestCase):
    @staticmethod
    def make_archive(path: Path, mtime: int, file_mode: int = 0o666) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            directory = tarfile.TarInfo("package-1.0")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o777
            directory.mtime = mtime
            archive.addfile(directory)
            value = b"synthetic source\n"
            member = tarfile.TarInfo("package-1.0/source.py")
            member.mode = file_mode
            member.mtime = mtime
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))

    def test_staging_identity_change_fails_before_archive_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdist = root / "synthetic.tar.gz"
            unrelated = root / "unrelated.txt"
            unrelated.write_bytes(b"unchanged")
            self.make_archive(sdist, 100)
            original = sdist.read_bytes()
            real_stage_stat = normalizer.archive_budget.stage_stat

            def substituted_stat(path, owner, private):
                found = real_stage_stat(path, owner, private)
                if path.suffix == ".tmp":
                    return SimpleNamespace(
                        st_mode=stat.S_IFLNK, st_dev=found.st_dev, st_ino=found.st_ino
                    )
                return found

            with (
                patch.object(normalizer.archive_budget, "stage_stat", substituted_stat),
                self.assertRaisesRegex(
                    normalizer.SdistNormalizationError, "staging file changed"
                ),
            ):
                normalizer.normalize_sdist(sdist, 50)
            self.assertEqual(sdist.read_bytes(), original)
            self.assertEqual(unrelated.read_bytes(), b"unchanged")

    def test_retained_staging_descriptor_is_fsynced_before_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            sdist = Path(directory) / "synthetic.tar.gz"
            self.make_archive(sdist, 100)
            real_fsync = os.fsync
            real_replace = normalizer.archive_budget.replace_staged
            events = []

            def fsync(descriptor):
                events.append("fsync")
                return real_fsync(descriptor)

            def replace(source, target, owner, private, identity):
                events.append("replace")
                return real_replace(source, target, owner, private, identity)

            with (
                patch.object(normalizer.os, "fsync", fsync),
                patch.object(normalizer.archive_budget, "replace_staged", replace),
            ):
                normalizer.normalize_sdist(sdist, 50)
            self.assertEqual(events, ["fsync", "replace"])

    def test_staging_substitution_never_writes_an_unrelated_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdist = root / "synthetic.tar.gz"
            unrelated = root / "unrelated.txt"
            unrelated.write_bytes(b"unchanged")
            self.make_archive(sdist, 100)
            original = sdist.read_bytes()
            real_stage = normalizer.archive_budget.pinned_staging
            removed = False

            @contextmanager
            def captured_stage(path):
                nonlocal removed
                with real_stage(path) as state:
                    try:
                        state[1].unlink()
                        removed = True
                        state[1].symlink_to(unrelated)
                    except OSError:
                        pass  # A retained Windows handle may prevent replacement.
                    yield state

            with patch.object(
                normalizer.archive_budget, "pinned_staging", captured_stage
            ):
                try:
                    normalizer.normalize_sdist(sdist, 50)
                    aborted = False
                except (normalizer.SdistNormalizationError, OSError):
                    aborted = True
            if removed:
                self.assertTrue(aborted)
                self.assertEqual(sdist.read_bytes(), original)
            else:
                self.assertFalse(aborted)
            self.assertEqual(unrelated.read_bytes(), b"unchanged")

    def test_post_verification_substitution_never_writes_an_unrelated_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdist = root / "synthetic.tar.gz"
            unrelated = root / "unrelated.txt"
            unrelated.write_bytes(b"unchanged")
            self.make_archive(sdist, 100)
            original = sdist.read_bytes()
            real_stage = normalizer.archive_budget.pinned_staging
            real_digest = normalizer.archive_budget.file_digest
            stage = []
            removed = False

            @contextmanager
            def captured_stage(path):
                with real_stage(path) as state:
                    stage.append(state[1])
                    yield state

            def substitute_after_verification(path):
                nonlocal removed
                digest = real_digest(path)
                try:
                    stage[0].unlink()
                    removed = True
                    stage[0].symlink_to(unrelated)
                except OSError:
                    # Symlinks can be unavailable on this host; the test still verifies the original file.
                    pass
                return digest

            with (
                patch.object(
                    normalizer.archive_budget, "pinned_staging", captured_stage
                ),
                patch.object(
                    normalizer.archive_budget,
                    "file_digest",
                    substitute_after_verification,
                ),
            ):
                try:
                    normalizer.normalize_sdist(sdist, 50)
                    aborted = False
                except (normalizer.SdistNormalizationError, OSError):
                    aborted = True
            if removed:
                self.assertTrue(aborted)
                self.assertEqual(sdist.read_bytes(), original)
            else:
                self.assertFalse(aborted)
            self.assertEqual(unrelated.read_bytes(), b"unchanged")

    def test_parent_rebinding_during_normalization_uses_pinned_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admitted = root / "admitted"
            moved = root / "moved"
            attacker = root / "attacker"
            admitted.mkdir()
            attacker.mkdir()
            archive = admitted / "synthetic.tar.gz"
            unrelated = attacker / archive.name
            unrelated.write_bytes(b"unrelated bytes")
            self.make_archive(archive, 100)
            real_stage = normalizer.archive_budget.pinned_staging
            rebound = False

            @contextmanager
            def rebind_after_stage(path):
                nonlocal rebound
                with real_stage(path) as state:
                    attempt = subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            (
                                "import pathlib,sys; "
                                "pathlib.Path(sys.argv[1]).rename(sys.argv[2]); "
                                "pathlib.Path(sys.argv[1]).symlink_to("
                                "sys.argv[3], target_is_directory=True)"
                            ),
                            str(admitted),
                            str(moved),
                            str(attacker),
                        ],
                        capture_output=True,
                        text=True,
                    )
                    rebound = attempt.returncode == 0
                    if not rebound:
                        self.assertEqual(os.name, "nt")
                        self.assertIn("PermissionError", attempt.stderr)
                    yield state

            try:
                with patch.object(
                    normalizer.archive_budget, "pinned_staging", rebind_after_stage
                ):
                    digest = normalizer.normalize_sdist(archive, 50)
                published = (moved if rebound else admitted) / archive.name
                self.assertEqual(
                    hashlib.sha256(published.read_bytes()).hexdigest(), digest
                )
                self.assertEqual(unrelated.read_bytes(), b"unrelated bytes")
            finally:
                if admitted.is_symlink():
                    admitted.unlink()
                if moved.exists():
                    moved.rename(admitted)

    def test_different_archive_times_and_modes_normalize_to_identical_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"
            self.make_archive(first, 100, 0o644)
            self.make_archive(second, 200, 0o755)
            first_hash = normalizer.normalize_sdist(first, 50)
            second_hash = normalizer.normalize_sdist(second, 50)
            self.assertEqual(first_hash, second_hash)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            normalized = first.read_bytes()
            self.assertEqual(first_hash, normalizer.normalize_sdist(first, 50))
            self.assertEqual(normalized, first.read_bytes())
            with tarfile.open(first, mode="r:gz") as archive:
                members = archive.getmembers()
            self.assertEqual([member.mtime for member in members], [50, 50])
            self.assertEqual([member.mode for member in members], [0o755, 0o644])

    def test_link_member_is_rejected_without_changing_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "linked.tar.gz"
            self.make_archive(path, 100)
            member = tarfile.TarInfo("package-1.0/link")
            member.type = tarfile.SYMTYPE
            # Only a modeled parser record: no TAR/OS link is constructed.
            original = path.read_bytes()
            with (
                patch.object(
                    normalizer.archive_budget, "tarfile", decoded_member_parser(member)
                ),
                self.assertRaisesRegex(
                    normalizer.SdistNormalizationError, "link or device"
                ),
            ):
                normalizer.normalize_sdist(path, 50)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_duplicate_and_case_colliding_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("synthetic", encoding="utf-8")
            duplicate = root / "duplicate.tar.gz"
            with tarfile.open(duplicate, mode="w:gz") as archive:
                archive.add(source, arcname="package-1.0/source.txt")
                archive.add(source, arcname="package-1.0/source.txt")
            with self.assertRaisesRegex(
                normalizer.SdistNormalizationError, "duplicate"
            ):
                normalizer.normalize_sdist(duplicate, 50)

            collision = root / "collision.tar.gz"
            with tarfile.open(collision, mode="w:gz") as archive:
                for name in ("package-1.0/source.py", "package-1.0/SOURCE.py"):
                    value = b"synthetic"
                    member = tarfile.TarInfo(name)
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))
            with self.assertRaisesRegex(
                normalizer.SdistNormalizationError, "non-portable duplicate"
            ):
                normalizer.normalize_sdist(collision, 50)

    def test_invalid_epoch_and_drive_path_preserve_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "epoch.tar.gz"
            self.make_archive(path, 100)
            original = path.read_bytes()
            for epoch, message in ((-1, "negative"), (0x100000000, "gzip")):
                with self.subTest(epoch=epoch):
                    with self.assertRaisesRegex(
                        normalizer.SdistNormalizationError, message
                    ):
                        normalizer.normalize_sdist(path, epoch)
                    self.assertEqual(original, path.read_bytes())

            drive = root / "drive.tar.gz"
            self.make_archive(drive, 100)
            member = tarfile.TarInfo("C:/private.txt")
            member.size = 9
            original_drive = drive.read_bytes()
            with (
                patch.object(
                    normalizer.archive_budget, "tarfile", decoded_member_parser(member)
                ),
                self.assertRaisesRegex(
                    normalizer.SdistNormalizationError, "drive path"
                ),
            ):
                normalizer.normalize_sdist(drive, 50)
            self.assertEqual(original_drive, drive.read_bytes())

    def test_generated_metadata_line_endings_are_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archives = []
            for filename, newline in (
                ("windows.tar.gz", b"\r\n"),
                ("posix.tar.gz", b"\n"),
            ):
                path = root / filename
                with tarfile.open(path, mode="w:gz") as archive:
                    for name in ("package-1.0/PKG-INFO", "package-1.0/setup.cfg"):
                        value = newline.join(
                            (b"Synthetic: value", b"Second: value", b"")
                        )
                        member = tarfile.TarInfo(name)
                        member.size = len(value)
                        archive.addfile(member, io.BytesIO(value))
                    source = b"VALUE = 1\n"
                    member = tarfile.TarInfo("package-1.0/source.py")
                    member.size = len(source)
                    archive.addfile(member, io.BytesIO(source))
                normalizer.normalize_sdist(path, 50)
                archives.append(path)
            self.assertEqual(archives[0].read_bytes(), archives[1].read_bytes())
            with tarfile.open(archives[0], mode="r:gz") as archive:
                metadata = archive.extractfile("package-1.0/PKG-INFO")
                self.assertIsNotNone(metadata)
                value = metadata.read()
            self.assertNotIn(b"\r", value)


if __name__ == "__main__":
    unittest.main()
