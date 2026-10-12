from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import normalize_wheel as normalizer

SOURCE_DATE_EPOCH = 315532800


def record_digest(value: bytes) -> str:
    encoded = (
        base64.urlsafe_b64encode(hashlib.sha256(value).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"sha256={encoded}"


class NormalizeWheelTests(unittest.TestCase):
    @staticmethod
    def make_wheel(
        path: Path, newline: bytes, compression: int, creator_system: int
    ) -> None:
        dist_info = "synthetic-1.0.dist-info"
        record_name = f"{dist_info}/RECORD"
        values = {
            "synthetic.py": b"VALUE = 1\n",
            f"{dist_info}/METADATA": newline.join(
                (b"Metadata-Version: 2.4", b"Name: synthetic", b"Version: 1.0", b"")
            ),
            f"{dist_info}/WHEEL": newline.join(
                (
                    b"Wheel-Version: 1.0",
                    b"Root-Is-Purelib: true",
                    b"Tag: py3-none-any",
                    b"",
                )
            ),
        }
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator=newline.decode("ascii"))
        for name, value in sorted(values.items()):
            writer.writerow((name, record_digest(value), str(len(value))))
        writer.writerow((record_name, "", ""))
        values[record_name] = output.getvalue().encode("utf-8")
        with zipfile.ZipFile(path, mode="w", compression=compression) as archive:
            for name, value in values.items():
                member = zipfile.ZipInfo(name, (2024, 1, 2, 3, 4, 4))
                member.compress_type = compression
                member.create_system = creator_system
                member.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(member, value)

    def test_staging_identity_change_fails_before_archive_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "synthetic.whl"
            unrelated = root / "unrelated.txt"
            unrelated.write_bytes(b"unchanged")
            self.make_wheel(wheel, b"\n", zipfile.ZIP_STORED, 3)
            original = wheel.read_bytes()
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
                    normalizer.WheelNormalizationError, "staging file changed"
                ),
            ):
                normalizer.normalize_wheel(wheel, SOURCE_DATE_EPOCH)
            self.assertEqual(wheel.read_bytes(), original)
            self.assertEqual(unrelated.read_bytes(), b"unchanged")

    def test_retained_staging_descriptor_is_fsynced_before_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "synthetic.whl"
            self.make_wheel(wheel, b"\n", zipfile.ZIP_STORED, 3)
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
                normalizer.normalize_wheel(wheel, SOURCE_DATE_EPOCH)
            self.assertEqual(events, ["fsync", "replace"])

    def test_staging_substitution_never_writes_an_unrelated_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "synthetic.whl"
            unrelated = root / "unrelated.txt"
            unrelated.write_bytes(b"unchanged")
            self.make_wheel(wheel, b"\n", zipfile.ZIP_STORED, 3)
            original = wheel.read_bytes()
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
                    normalizer.normalize_wheel(wheel, SOURCE_DATE_EPOCH)
                    aborted = False
                except (normalizer.WheelNormalizationError, OSError):
                    aborted = True
            if removed:
                self.assertTrue(aborted)
                self.assertEqual(wheel.read_bytes(), original)
            else:
                self.assertFalse(aborted)
            self.assertEqual(unrelated.read_bytes(), b"unchanged")

    def test_post_verification_substitution_never_writes_an_unrelated_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "synthetic.whl"
            unrelated = root / "unrelated.txt"
            unrelated.write_bytes(b"unchanged")
            self.make_wheel(wheel, b"\n", zipfile.ZIP_STORED, 3)
            original = wheel.read_bytes()
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
                    normalizer.normalize_wheel(wheel, SOURCE_DATE_EPOCH)
                    aborted = False
                except (normalizer.WheelNormalizationError, OSError):
                    aborted = True
            if removed:
                self.assertTrue(aborted)
                self.assertEqual(wheel.read_bytes(), original)
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
            wheel = admitted / "synthetic.whl"
            unrelated = attacker / wheel.name
            unrelated.write_bytes(b"unrelated bytes")
            self.make_wheel(wheel, b"\n", zipfile.ZIP_STORED, 3)
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
                    digest = normalizer.normalize_wheel(wheel, SOURCE_DATE_EPOCH)
                published = (moved if rebound else admitted) / wheel.name
                self.assertEqual(
                    hashlib.sha256(published.read_bytes()).hexdigest(), digest
                )
                self.assertEqual(unrelated.read_bytes(), b"unrelated bytes")
            finally:
                if admitted.is_symlink():
                    admitted.unlink()
                if moved.exists():
                    moved.rename(admitted)

    def test_platform_specific_wheels_normalize_to_identical_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.whl"
            second = root / "second.whl"
            self.make_wheel(first, b"\r\n", zipfile.ZIP_DEFLATED, 0)
            self.make_wheel(second, b"\n", zipfile.ZIP_STORED, 3)
            first_hash = normalizer.normalize_wheel(first, SOURCE_DATE_EPOCH)
            second_hash = normalizer.normalize_wheel(second, SOURCE_DATE_EPOCH)
            self.assertEqual(first_hash, second_hash)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            original = first.read_bytes()
            self.assertEqual(
                first_hash, normalizer.normalize_wheel(first, SOURCE_DATE_EPOCH)
            )
            self.assertEqual(original, first.read_bytes())
            with zipfile.ZipFile(first) as archive:
                members = archive.infolist()
                metadata = archive.read("synthetic-1.0.dist-info/METADATA")
            self.assertEqual(
                [member.filename for member in members],
                sorted(member.filename for member in members),
            )
            self.assertNotIn(b"\r", metadata)
            self.assertTrue(
                all(member.compress_type == zipfile.ZIP_STORED for member in members)
            )
            self.assertTrue(all(member.create_system == 3 for member in members))
            self.assertTrue(
                all(
                    stat.S_IMODE(member.external_attr >> 16) == 0o644
                    for member in members
                )
            )

    def test_record_mismatch_is_rejected_without_changing_wheel(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.whl"
            self.make_wheel(path, b"\n", zipfile.ZIP_STORED, 3)
            original = path.read_bytes()
            with zipfile.ZipFile(path) as archive:
                members = [
                    (member, archive.read(member)) for member in archive.infolist()
                ]
            replacement = path.with_suffix(".replacement")
            with zipfile.ZipFile(replacement, mode="w") as archive:
                for member, value in members:
                    archive.writestr(
                        member,
                        b"CHANGED\n" if member.filename == "synthetic.py" else value,
                    )
            replacement.replace(path)
            corrupted = path.read_bytes()
            with self.assertRaisesRegex(
                normalizer.WheelNormalizationError, "hash mismatch"
            ):
                normalizer.normalize_wheel(path, SOURCE_DATE_EPOCH)
            self.assertNotEqual(original, corrupted)
            self.assertEqual(path.read_bytes(), corrupted)

    def test_case_colliding_members_and_invalid_epoch_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collision = root / "collision.whl"
            self.make_wheel(collision, b"\n", zipfile.ZIP_STORED, 3)
            with zipfile.ZipFile(collision, mode="a") as archive:
                archive.writestr("SYNTHETIC.py", b"VALUE = 1\n")
            original = collision.read_bytes()
            with self.assertRaisesRegex(
                normalizer.WheelNormalizationError, "nonportable duplicate"
            ):
                normalizer.normalize_wheel(collision, SOURCE_DATE_EPOCH)
            self.assertEqual(collision.read_bytes(), original)

            valid = root / "valid.whl"
            self.make_wheel(valid, b"\n", zipfile.ZIP_STORED, 3)
            valid_bytes = valid.read_bytes()
            for epoch in (SOURCE_DATE_EPOCH - 1, 0x100000000):
                with self.subTest(epoch=epoch):
                    with self.assertRaisesRegex(
                        normalizer.WheelNormalizationError, "range"
                    ):
                        normalizer.normalize_wheel(valid, epoch)
                    self.assertEqual(valid.read_bytes(), valid_bytes)


if __name__ == "__main__":
    unittest.main()
