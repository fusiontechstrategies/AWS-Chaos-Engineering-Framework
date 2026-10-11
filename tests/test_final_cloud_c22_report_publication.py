"""Offline regressions for descriptor-bound evidence report publication."""

from __future__ import annotations

import json
import logging
import os
import stat
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

import aws_chaos_framework as framework


def assert_private_windows_location(requested: Path, actual: Path) -> None:
    import ctypes

    assert actual != requested
    assert actual.parent.parent == Path.home().absolute()
    handles = framework._open_windows_report_directory(actual.parent, secure=False)
    try:
        framework._windows_private_report_acl(handles[-1])
    finally:
        close_handle = ctypes.WinDLL("kernel32").CloseHandle
        for handle in reversed(handles):
            close_handle(handle)


def test_temporary_entry_swap_cannot_publish_attacker_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    report = tmp_path / "report.json"
    attacker = tmp_path / "attacker.json"
    attacker.write_text('{"attacker": true}\n', encoding="utf-8")
    original = framework._publish_report_link

    def replace_before_link(
        temporary: Path, final: Path, directory_fd: int | None
    ) -> None:
        try:
            os.replace(attacker, temporary)
        except OSError:
            # Windows can forbid replacement while the descriptor is open.
            # Model the same substituted link target at publication instead.
            os.link(attacker, final)
            return
        original(temporary, final, directory_fd)

    monkeypatch.setattr(framework, "_publish_report_link", replace_before_link)
    with caplog.at_level(logging.INFO), pytest.raises(PermissionError):
        framework.atomic_write_json(report, {"trusted": True})
    assert not report.exists()
    if os.name == "nt":
        assert not framework._windows_report_locations[report.absolute()].exists()
    assert "Evidence report saved" not in caplog.text


def test_shared_nonsticky_report_directory_is_rejected_or_secured(
    tmp_path: Path,
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    if os.name == "posix":
        shared.chmod(0o777)
        try:
            with pytest.raises(PermissionError, match="Unsafe shared report directory"):
                framework.atomic_write_json(shared / "report.json", {"trusted": True})
            assert not (shared / "report.json").exists()
        finally:
            shared.chmod(0o700)
    else:
        # Shared write access cannot reach the separate private report namespace.
        granted = subprocess.run(
            ["icacls", str(shared), "/grant", "*S-1-5-11:(OI)(CI)M"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert granted.returncode == 0
        report = shared / "report.json"
        actual = framework.atomic_write_json(report, {"trusted": True})
        assert_private_windows_location(report, actual)
        assert json.loads(actual.read_text(encoding="utf-8")) == {"trusted": True}
        assert not report.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_junction_report_directory_is_rejected_without_touching_existing_report(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    original = target / "report.json"
    original.write_text('{"original": true}\n', encoding="utf-8")
    before = original.read_bytes()
    junction = tmp_path / "junction"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert junction.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    with pytest.raises(PermissionError, match="ordinary directory"):
        framework._open_windows_report_directory(junction, secure=False)
    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        framework.atomic_write_json(junction / "report.json", {"replacement": True})
    assert original.read_bytes() == before
    requested = junction / "new-report.json"
    actual = framework.atomic_write_json(requested, {"trusted": True})
    assert_private_windows_location(requested, actual)
    assert not (target / "new-report.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows file ACL behavior")
def test_windows_shared_temporary_file_acl_prevents_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = framework.tempfile.NamedTemporaryFile

    @contextmanager
    def shared_temporary(*args: object, **kwargs: object):
        with original(*args, **kwargs) as handle:
            subprocess.run(
                ["icacls", handle.name, "/grant", "*S-1-5-11:M"],
                capture_output=True,
                text=True,
                check=True,
            )
            yield handle

    monkeypatch.setattr(framework.tempfile, "NamedTemporaryFile", shared_temporary)
    report = tmp_path / "report.json"
    with pytest.raises(PermissionError, match="Unsafe shared report path ACL"):
        framework.atomic_write_json(report, {"trusted": True})
    assert not report.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory handle sharing")
@pytest.mark.parametrize("requested_access", [0x40000, 0x100])
def test_windows_preexisting_directory_writer_fails_before_report_success(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, requested_access: int
) -> None:
    import ctypes
    from ctypes import wintypes

    output = tmp_path / "shared"
    output.mkdir()
    subprocess.run(
        ["icacls", str(output), "/grant", "*S-1-5-11:(OI)(CI)F"],
        capture_output=True,
        text=True,
        check=True,
    )
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel.CreateFileW.restype = wintypes.HANDLE
    writer = kernel.CreateFileW(
        str(output), requested_access, 0x7, None, 3, 0x02000000, None
    )
    if writer == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        orchestrator = object.__new__(framework.ChaosOrchestrator)
        orchestrator.config = {}
        orchestrator.results = []
        orchestrator.actual_account = None
        orchestrator.caller_arn = None
        orchestrator.vpc_id = None
        orchestrator._sensitive_values_lock = threading.RLock()
        orchestrator._report_sensitive_values = set()
        orchestrator.run_id = "preexisting-writer"
        orchestrator.live = False
        orchestrator.region = "us-gov-west-1"
        orchestrator.seed = None
        orchestrator.expected_account = None
        orchestrator._failed_future_count = 0
        orchestrator.discovered_resources = {}
        orchestrator.output_dir = output
        previous = tmp_path / "previous.json"
        orchestrator.report_path = previous
        with caplog.at_level(logging.INFO):
            actual = orchestrator._generate_report()
        assert orchestrator.report_path == actual
        assert_private_windows_location(
            output / "chaos-report-preexisting-writer.json", actual
        )
        assert not (output / "chaos-report-preexisting-writer.json").exists()
        assert "Evidence report saved" in caplog.text
    finally:
        kernel.CloseHandle(writer)


@pytest.mark.skipif(os.name != "nt", reason="Windows retained ACL handle")
def test_windows_private_snapshot_does_not_reuse_a_previously_shared_directory(
    tmp_path: Path,
) -> None:
    import ctypes
    from ctypes import wintypes

    output = tmp_path / "formerly-shared"
    output.mkdir()
    subprocess.run(
        ["icacls", str(output), "/grant", "*S-1-5-11:(OI)(CI)F"],
        capture_output=True,
        text=True,
        check=True,
    )
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel.CreateFileW.restype = wintypes.HANDLE
    writer = kernel.CreateFileW(str(output), 0x40000, 0x7, None, 3, 0x02000000, None)
    if writer == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        subprocess.run(
            ["icacls", str(output), "/remove", "*S-1-5-11"],
            capture_output=True,
            text=True,
            check=True,
        )
        requested = output / "report.json"
        actual = framework.atomic_write_json(requested, {"trusted": True})
        assert_private_windows_location(requested, actual)
        assert json.loads(actual.read_text(encoding="utf-8")) == {"trusted": True}
        assert not requested.exists()
    finally:
        kernel.CloseHandle(writer)


@pytest.mark.skipif(os.name != "nt", reason="Windows profile publication anchor")
def test_windows_shared_request_cannot_overlap_profile_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setattr(Path, "home", lambda: profile)
    extended_profile = Path("\\\\?\\" + str(profile))
    extended_parent = Path("\\\\?\\" + str(tmp_path))
    for requested in (
        profile / "report.json",
        tmp_path / "report.json",
        extended_profile / "report.json",
        extended_parent / "report.json",
    ):
        monkeypatch.setitem(
            framework._windows_report_locations,
            requested.absolute(),
            profile / "cached.json",
        )
        with pytest.raises(PermissionError, match="profile publication anchor"):
            framework.atomic_write_json(requested, {"trusted": True})
        assert not requested.exists()
    assert not list(profile.glob(".aws-chaos-report-*"))


@pytest.mark.skipif(os.name != "nt", reason="Windows creation-time report ACL")
def test_windows_report_directory_is_private_before_serialization(
    tmp_path: Path,
) -> None:
    requested = (tmp_path / "report.json").absolute()
    actual = framework._windows_private_report_path(requested)
    assert_private_windows_location(requested, actual)
    assert not actual.exists()
    assert framework.atomic_write_json(requested, {"trusted": True}) == actual
    assert json.loads(actual.read_text(encoding="utf-8")) == {"trusted": True}


@pytest.mark.skipif(os.name != "nt", reason="Windows directory ACL behavior")
def test_windows_prior_security_control_grant_is_rejected(tmp_path: Path) -> None:
    output = tmp_path / "shared"
    output.mkdir()
    subprocess.run(
        ["icacls", str(output), "/grant", "*S-1-5-11:(OI)(CI)F"],
        capture_output=True,
        text=True,
        check=True,
    )
    report = output / "report.json"
    actual = framework.atomic_write_json(report, {"trusted": True})
    assert_private_windows_location(report, actual)
    assert json.loads(actual.read_text(encoding="utf-8")) == {"trusted": True}
    assert not report.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory ACL behavior")
def test_windows_read_only_directory_grant_is_not_treated_as_write(
    tmp_path: Path,
) -> None:
    output = tmp_path / "readable"
    output.mkdir()
    subprocess.run(
        ["icacls", str(output), "/grant", "*S-1-5-11:(OI)(CI)RX"],
        capture_output=True,
        text=True,
        check=True,
    )
    report = output / "report.json"
    actual = framework.atomic_write_json(report, {"trusted": True})
    assert_private_windows_location(report, actual)
    assert json.loads(actual.read_text(encoding="utf-8")) == {"trusted": True}


def test_private_report_binds_final_inode_bytes_and_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "posix":
        tmp_path.chmod(0o700)
    report = tmp_path / "report.json"
    observed: dict[str, int] = {}
    original = framework._publish_report_link

    def capture_descriptor_identity(
        temporary: Path, final: Path, directory_fd: int | None
    ) -> None:
        source = framework._report_entry_stat(temporary, directory_fd)
        observed.update(dev=source.st_dev, ino=source.st_ino, size=source.st_size)
        original(temporary, final, directory_fd)

    # Capture the still-open serialized inode at the publication boundary.
    monkeypatch.setattr(framework, "_publish_report_link", capture_descriptor_identity)
    actual = framework.atomic_write_json(report, {"trusted": True})
    published = actual.stat()
    assert (published.st_dev, published.st_ino, published.st_size) == (
        observed["dev"],
        observed["ino"],
        observed["size"],
    )
    expected = json.dumps({"trusted": True}, indent=2, sort_keys=True) + "\n"
    expected = expected.replace("\n", os.linesep).encode()
    assert actual.read_bytes() == expected
    if os.name == "posix":
        assert stat.S_IMODE(published.st_mode) == 0o600
    else:
        assert_private_windows_location(report, actual)


def test_failed_publication_never_sets_or_announces_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    output = tmp_path / "reports"
    output.mkdir()
    attacker = output / "attacker.json"
    attacker.write_text('{"attacker": true}\n', encoding="utf-8")
    orchestrator = object.__new__(framework.ChaosOrchestrator)
    orchestrator.config = {}
    orchestrator.results = []
    orchestrator.actual_account = None
    orchestrator.caller_arn = None
    orchestrator.vpc_id = None
    orchestrator._sensitive_values_lock = threading.RLock()
    orchestrator._report_sensitive_values = set()
    orchestrator.run_id = "failed-publication"
    orchestrator.live = False
    orchestrator.region = "us-gov-west-1"
    orchestrator.seed = None
    orchestrator.expected_account = None
    orchestrator._failed_future_count = 0
    orchestrator.discovered_resources = {}
    orchestrator.output_dir = output
    previous = tmp_path / "previous.json"
    orchestrator.report_path = previous

    def substitute_final(
        _temporary: Path, final: Path, _directory_fd: int | list[int]
    ) -> None:
        os.link(attacker, final)

    monkeypatch.setattr(framework, "_publish_report_link", substitute_final)
    with caplog.at_level(logging.INFO), pytest.raises(PermissionError):
        orchestrator._generate_report()
    assert orchestrator.report_path == previous
    assert not (output / "chaos-report-failed-publication.json").exists()
    assert "Evidence report saved" not in caplog.text


def test_existing_report_is_not_overwritten(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"original": true}\n', encoding="utf-8")
    before = report.read_bytes()
    with pytest.raises(FileExistsError):
        framework.atomic_write_json(report, {"replacement": True})
    assert report.read_bytes() == before
