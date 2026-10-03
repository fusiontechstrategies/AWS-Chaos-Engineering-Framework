"""Read admitted tagged-source data without following links or unbounded reads."""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path, PurePosixPath

MAX_SOURCE_BYTES = 8_388_608
MAX_SOURCE_ENTRIES = 128


def _parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or "\\" in relative or ":" in relative:
        raise ValueError("source input must have a relative portable path")
    parts = tuple(relative.split("/"))
    if PurePosixPath(relative).is_absolute() or any(
        not part or part in {".", ".."} or "\x00" in part for part in parts
    ):
        raise ValueError("source input has an unsafe path")
    return parts


def _metadata(path: Path, directory: bool) -> os.stat_result:
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400:
        raise ValueError("source input or ancestor is a link or reparse point")
    if not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):
        raise ValueError("source input is not a regular file or directory")
    return value


def _root(root: Path) -> Path:
    root = Path(os.path.abspath(root))  # Do not resolve source-controlled links.
    if os.name == "nt" and (
        len(root.drive) != 2 or root.drive[1:] != ":" or root.root != "\\"
    ):
        raise ValueError("source root must be an ordinary local drive path")
    for ancestor in reversed((root, *root.parents)):
        _metadata(ancestor, True)
    return root


def _limit(limit: int) -> int:
    if type(limit) is not int or not 0 <= limit <= MAX_SOURCE_BYTES:
        raise ValueError("source byte budget must be within the trusted limit")
    return limit


@contextlib.contextmanager
def _windows_handle(path: Path, directory: bool):
    import ctypes
    import ctypes.wintypes

    wintypes = ctypes.wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    # No delete or write sharing: retain admitted ancestry throughout the read.
    handle = kernel.CreateFileW(
        str(path),
        0x80000000,
        1,
        None,
        3,
        0x00200000 | (0x02000000 if directory else 0),
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "cannot open admitted source input")
    try:
        attributes = (wintypes.DWORD * 2)()
        if kernel.GetFileType(handle) != 1 or not kernel.GetFileInformationByHandleEx(
            handle, 9, attributes, ctypes.sizeof(attributes)
        ):
            raise ValueError("source handle is not a disk filesystem object")
        if attributes[0] & 0x400 or bool(attributes[0] & 0x10) != directory:
            raise ValueError("source handle is not a regular admitted object")
        yield handle
    finally:
        kernel.CloseHandle(handle)


@contextlib.contextmanager
def _posix_directory(path, *, dir_fd=None):
    """Retain one no-follow directory descriptor with explicit native ownership."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def _file_descriptor(root: Path, parts: tuple[str, ...]):
    if os.name == "nt":
        import msvcrt

        with contextlib.ExitStack() as stack:
            for ancestor in reversed((root, *root.parents)):
                stack.enter_context(_windows_handle(ancestor, True))
            parent = root
            for part in parts[:-1]:
                parent /= part
                _metadata(parent, True)
                stack.enter_context(_windows_handle(parent, True))
            leaf = parent / parts[-1]
            _metadata(leaf, False)
            handle = stack.enter_context(_windows_handle(leaf, False))
            # Duplicate before CRT ownership transfers; the native lease stays held.
            import ctypes
            import ctypes.wintypes

            wintypes = ctypes.wintypes

            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            kernel.DuplicateHandle.argtypes = [
                wintypes.HANDLE,
                wintypes.HANDLE,
                wintypes.HANDLE,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ]
            kernel.DuplicateHandle.restype = wintypes.BOOL
            duplicate = wintypes.HANDLE()
            process = kernel.GetCurrentProcess()
            if not kernel.DuplicateHandle(
                process, handle, process, ctypes.byref(duplicate), 0, False, 2
            ):
                raise OSError(
                    ctypes.get_last_error(), "cannot retain source descriptor"
                )
            try:
                fd = msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                kernel.CloseHandle.restype = wintypes.BOOL
                kernel.CloseHandle(duplicate)
                raise
            try:
                yield fd
            finally:
                os.close(fd)
    else:
        with contextlib.ExitStack() as stack:
            parent_fd = stack.enter_context(_posix_directory(root.anchor))
            for part in (*root.parts[1:], *parts[:-1]):
                parent_fd = stack.enter_context(
                    _posix_directory(part, dir_fd=parent_fd)
                )
            fd = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd
            )
            try:
                yield fd
            finally:
                os.close(fd)


def read_bytes(root: Path, relative: str, max_bytes: int = MAX_SOURCE_BYTES) -> bytes:
    limit = _limit(max_bytes)
    parts = _parts(relative)
    root = _root(root)
    parent = root
    for part in parts[:-1]:
        parent /= part
        _metadata(parent, True)
    before = _metadata(parent / parts[-1], False)
    if before.st_size > limit:
        raise ValueError("source input exceeds its byte budget before opening")
    with _file_descriptor(root, parts) as fd:
        admitted = os.fstat(fd)
        if not stat.S_ISREG(admitted.st_mode) or admitted.st_size > limit:
            raise ValueError("source descriptor is not a bounded regular file")
        chunks = []
        total = 0
        while True:
            value = os.read(fd, min(65_536, limit - total + 1))
            if not value:
                break
            total += len(value)
            if total > limit:
                raise ValueError("source contents exceed their byte budget")
            chunks.append(value)
        if total != admitted.st_size:
            raise ValueError("source contents changed during the bounded read")
        return b"".join(chunks)


def read_text(root: Path, relative: str, max_bytes: int = MAX_SOURCE_BYTES) -> str:
    # Preserve Path.read_text universal-newline semantics after bounded admission.
    value = read_bytes(root, relative, max_bytes).decode("utf-8")
    return value.replace("\r\n", "\n").replace("\r", "\n")


def is_present(root: Path, relative: str, directory: bool = False) -> bool:
    """Optional absence is allowed; untrusted ancestors and objects are not."""
    root = _root(root)
    parts = _parts(relative)
    parent = root
    try:
        for part in parts[:-1]:
            parent /= part
            _metadata(parent, True)
        _metadata(parent / parts[-1], directory)
    except FileNotFoundError:
        return False
    return True


def source_names(root: Path, relative: str) -> list[str]:
    """Enumerate only a pre-admitted bounded source directory, without recursion."""
    root = _root(root)
    directory = root
    for part in _parts(relative):
        directory /= part
        _metadata(directory, True)
    names = []
    with contextlib.ExitStack() as stack:
        if os.name == "nt":
            for ancestor in reversed((directory, *directory.parents)):
                stack.enter_context(_windows_handle(ancestor, True))
            listing = directory
        else:
            listing = stack.enter_context(_posix_directory(directory.anchor))
            for part in directory.parts[1:]:
                listing = stack.enter_context(_posix_directory(part, dir_fd=listing))
        with os.scandir(listing) as entries:
            for entry in entries:
                if len(names) >= MAX_SOURCE_ENTRIES:
                    raise ValueError("source directory exceeds its entry budget")
                names.append(entry.name)
    return names
