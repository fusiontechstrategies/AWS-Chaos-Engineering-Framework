"""Pin an owned release-output parent and publish only through its new child."""

from __future__ import annotations

import os
import secrets
import stat
import sys
from contextlib import contextmanager, suppress
from pathlib import Path


def _reject_darwin_extended_acl(fd: int) -> None:
    """Fail closed if a mode-private directory grants extra ACL authority."""
    import ctypes
    import errno

    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_get_entry.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    )
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_valid.argtypes = (ctypes.c_void_p,)
    libc.acl_valid.restype = ctypes.c_int
    libc.acl_free.argtypes = (ctypes.c_void_p,)
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(fd, 0x100)  # ACL_TYPE_EXTENDED
    if not acl:
        error = ctypes.get_errno()
        # Darwin returns no ACL object when the pinned directory has no
        # extended entries. All other inspection failures remain closed.
        if error in {errno.ENOENT, getattr(errno, "ENOATTR", -1)}:
            return
        raise PermissionError(f"Cannot inspect release-output extended ACL ({error})")
    try:
        if libc.acl_valid(acl) != 0:
            raise PermissionError("Cannot validate release-output extended ACL")
        entry = ctypes.c_void_p()
        result = libc.acl_get_entry(acl, 0, ctypes.byref(entry))  # ACL_FIRST_ENTRY
        if result == 0:
            raise PermissionError("Release output parent has an extended ACL")
    finally:
        libc.acl_free(acl)


def _rename_no_replace(directory_fd: int, source: str, destination: str) -> None:
    """Atomically publish a directory without replacing any existing entry."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        operation = getattr(libc, "renameat2", None)
        flag = 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        operation = getattr(libc, "renameatx_np", None)
        flag = 4  # RENAME_EXCL
    else:
        operation = None
        flag = 0
    if operation is None:
        raise PermissionError("Atomic no-replace directory publication is unavailable")
    operation.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    operation.restype = ctypes.c_int
    result = operation(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        flag,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _windows_api():
    import ctypes
    import ctypes.wintypes as wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    return ctypes, wintypes, kernel, advapi


def _windows_open_relative(
    root: int,
    name: str,
    *,
    directory: bool,
    create: bool,
    write: bool = False,
    readwrite: bool = False,
    security_descriptor: int | None = None,
    share_delete: bool = True,
) -> int:
    """Open one child of a retained Windows directory handle, without reparse."""
    ctypes, wintypes, _, _ = _windows_api()
    ntdll = ctypes.WinDLL("ntdll")

    class UnicodeString(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.USHORT),
            ("maximum_length", wintypes.USHORT),
            ("buffer", wintypes.LPWSTR),
        ]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG),
            ("root", wintypes.HANDLE),
            ("name", ctypes.POINTER(UnicodeString)),
            ("attributes", wintypes.ULONG),
            ("security_descriptor", ctypes.c_void_p),
            ("security_quality", ctypes.c_void_p),
        ]

    class IoStatus(ctypes.Structure):
        _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]

    ntdll.NtCreateFile.argtypes = (
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(ObjectAttributes),
        ctypes.POINTER(IoStatus),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
    )
    ntdll.NtCreateFile.restype = wintypes.LONG
    ntdll.RtlNtStatusToDosError.argtypes = (wintypes.LONG,)
    ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG
    if not name or name in {".", ".."} or "\\" in name or "/" in name:
        raise ValueError("Release output child name must be a single component")
    encoded = name.encode("utf-16-le")
    buffer = ctypes.create_unicode_buffer(name)
    unicode_name = UnicodeString(
        len(encoded), len(encoded) + 2, ctypes.cast(buffer, wintypes.LPWSTR)
    )
    attributes = ObjectAttributes(
        ctypes.sizeof(ObjectAttributes),
        root,
        ctypes.pointer(unicode_name),
        0x40 | 0x1000,  # OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
        security_descriptor,
        None,
    )
    result = wintypes.HANDLE()
    status = IoStatus()
    access = 0x120080 | (0x10000 if directory and create else 0)
    if readwrite:
        access = 0xC0000000 | 0x10000 | 0x100000 | 0x80
    elif write:
        access = 0x40000000 | 0x10000 | 0x100000 | 0x80
    options = (0x1 if directory else 0x40) | 0x200000 | 0x20
    code = ntdll.NtCreateFile(
        ctypes.byref(result),
        access,
        ctypes.byref(attributes),
        ctypes.byref(status),
        None,
        0,
        0x7 if share_delete else 0x3,
        2 if create else 1,
        options,
        None,
        0,
    )
    if code < 0:
        raise ctypes.WinError(ntdll.RtlNtStatusToDosError(code))
    return result.value


@contextmanager
def _windows_private_descriptor(user_sid: str):
    """Create an owner-only DACL before a shared-parent child becomes visible."""
    ctypes, wintypes, kernel, advapi = _windows_api()
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    descriptor = ctypes.c_void_p()
    sddl = f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user_sid})"
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield descriptor.value
    finally:
        kernel.LocalFree(descriptor)


def _windows_token_sid(information_class: int) -> str:
    ctypes, wintypes, kernel, advapi = _windows_api()
    pointer = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(pointer),
    )
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = (
        pointer,
        wintypes.DWORD,
        pointer,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = (pointer, ctypes.POINTER(pointer))
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (pointer,)
    kernel.LocalFree.argtypes = (pointer,)

    token = pointer()
    if not advapi.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(
            token, information_class, None, 0, ctypes.byref(size)
        )
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(
            token, information_class, buffer, size, ctypes.byref(size)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(pointer)).contents.value
        value = pointer()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(value)
        finally:
            kernel.LocalFree(value)
    finally:
        kernel.CloseHandle(token)


def _windows_user_sid() -> str:
    return _windows_token_sid(1)


def _windows_default_owner_sid() -> str:
    return _windows_token_sid(4)


def _windows_owner_is_trusted(
    owner_sid: str, user_sid: str, default_owner_sid: str
) -> bool:
    return owner_sid == user_sid or (owner_sid == default_owner_sid == "S-1-5-32-544")


def _windows_acl_private(handle: int, user_sid: str) -> None:
    """Require token ownership and no untrusted principal's write grant."""
    ctypes, wintypes, kernel, advapi = _windows_api()
    pointer = ctypes.c_void_p
    advapi.GetSecurityInfo.argtypes = (
        pointer,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(pointer),
        pointer,
        ctypes.POINTER(pointer),
        pointer,
        ctypes.POINTER(pointer),
    )
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    advapi.GetAce.argtypes = (pointer, wintypes.DWORD, ctypes.POINTER(pointer))
    advapi.GetAce.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = (pointer, ctypes.POINTER(pointer))
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = (pointer,)

    class Acl(ctypes.Structure):
        _fields_ = [
            ("revision", ctypes.c_ubyte),
            ("reserved", ctypes.c_ubyte),
            ("size", wintypes.WORD),
            ("count", wintypes.WORD),
            ("reserved2", wintypes.WORD),
        ]

    def sid_string(sid: int) -> str:
        allocated = pointer()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(allocated)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(allocated)
        finally:
            kernel.LocalFree(allocated)

    owner = pointer()
    dacl = pointer()
    descriptor = pointer()
    result = advapi.GetSecurityInfo(
        handle,
        1,
        0x00000005,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise OSError(result, "Cannot inspect release-output ACL")
    try:
        default_owner = _windows_default_owner_sid()
        if (
            not _windows_owner_is_trusted(sid_string(owner), user_sid, default_owner)
            or not dacl
        ):
            raise PermissionError(
                "Release output must be current-token-owned and private"
            )
        allowed = {user_sid, "S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"}
        writable = 0xD0000 | 0x10000000 | 0x40000000 | 0x00000156
        acl = ctypes.cast(dacl, ctypes.POINTER(Acl)).contents
        for index in range(acl.count):
            ace = pointer()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            kind = ctypes.c_ubyte.from_address(ace.value).value
            if kind == 1:
                continue
            if kind != 0:
                raise PermissionError("Unsupported release-output ACL entry")
            mask = wintypes.DWORD.from_address(ace.value + 4).value
            if sid_string(ace.value + 8) not in allowed and mask & writable:
                raise PermissionError("Shared release-output parent is writable")
    finally:
        kernel.LocalFree(descriptor)


def _windows_directory_identity(handle: int) -> tuple[int, int]:
    """Identify the retained directory and reject a reparse-point object."""
    ctypes, wintypes, kernel, _ = _windows_api()
    kernel.GetFileInformationByHandle.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL

    class FileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation", wintypes.FILETIME),
            ("access", wintypes.FILETIME),
            ("write", wintypes.FILETIME),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    info = FileInformation()
    if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not info.attributes & 0x10 or info.attributes & 0x400:
        raise PermissionError("Release output path contains a reparse point")
    return info.volume, (info.index_high << 32) | info.index_low


def _windows_open_directory(path: Path) -> tuple[int, tuple[int, int]]:
    """Open and identify a directory without following a reparse point."""
    ctypes, wintypes, kernel, _ = _windows_api()
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
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)

    handle = kernel.CreateFileW(str(path), 0x20080, 0x3, None, 3, 0x02200000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return handle, _windows_directory_identity(handle)
    except BaseException:
        kernel.CloseHandle(handle)
        raise


def _windows_close(handle: int) -> None:
    _, wintypes, kernel, _ = _windows_api()
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    if not kernel.CloseHandle(handle):
        raise OSError("Could not close release-output directory handle")


def _windows_rename_relative(
    handle: int, parent: int, destination: str, *, replace: bool = False
) -> None:
    """Rename an open object relative to its pinned parent."""
    ctypes, wintypes, _, _ = _windows_api()
    ntdll = ctypes.WinDLL("ntdll")

    class RenameInfo(ctypes.Structure):
        _fields_ = [
            ("replace", wintypes.DWORD),
            ("root", wintypes.HANDLE),
            ("length", wintypes.DWORD),
            ("name", wintypes.WCHAR * 1),
        ]

    class IoStatus(ctypes.Structure):
        _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]

    ntdll.NtSetInformationFile.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(IoStatus),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
    )
    ntdll.NtSetInformationFile.restype = wintypes.LONG
    ntdll.RtlNtStatusToDosError.argtypes = (wintypes.LONG,)
    ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG
    encoded = destination.encode("utf-16-le")
    size = RenameInfo.name.offset + len(encoded) + 2
    buffer = ctypes.create_string_buffer(size)
    info = ctypes.cast(buffer, ctypes.POINTER(RenameInfo)).contents
    info.replace = int(replace)
    info.root = parent
    info.length = len(encoded)
    ctypes.memmove(
        ctypes.addressof(buffer) + RenameInfo.name.offset, encoded, len(encoded)
    )
    status = IoStatus()
    code = ntdll.NtSetInformationFile(handle, ctypes.byref(status), buffer, size, 10)
    if code < 0:
        error = ntdll.RtlNtStatusToDosError(code)
        if error in {80, 183}:
            raise FileExistsError(error, "Release output must be new", destination)
        raise ctypes.WinError(error)


def _windows_mark_delete(handle: int) -> None:
    ctypes, wintypes, kernel, _ = _windows_api()
    kernel.SetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    flag = wintypes.BOOL(1)
    if not kernel.SetFileInformationByHandle(
        handle, 4, ctypes.byref(flag), ctypes.sizeof(flag)
    ):
        raise ctypes.WinError(ctypes.get_last_error())


class OwnedOutput:
    """Retain the owned parent through private staging and publication."""

    def __init__(self, path: Path):
        self.path = Path(path).absolute()
        self.parent_fd: int | None = None
        self.private_fds: dict[str, int] = {}
        self.parent_handles: list[int] = []
        self.private_handles: dict[str, int] = {}
        self.user_sid: str | None = None

    def __enter__(self):
        if os.name == "posix":
            self._pin_posix_parent()
        elif os.name == "nt":
            self._pin_windows_parent()
        else:
            raise PermissionError("Release output cannot be pinned on this platform")
        if self.path.exists() or self.path.is_symlink():
            self.__exit__(None, None, None)
            raise FileExistsError("Release output must be new")
        return self

    def _pin_posix_parent(self) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent = self.path.parent
        current = os.open(parent.anchor, flags)
        try:
            parts = parent.parts[1:]
            for index, part in enumerate(parts):
                next_fd = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = next_fd
                info = os.fstat(current)
                if info.st_uid not in {0, os.geteuid()}:
                    raise PermissionError("Release output ancestor has an unsafe owner")
                if index == len(parts) - 1:
                    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                        raise PermissionError(
                            "Release output parent must be owned and private"
                        )
                elif info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                    raise PermissionError("Release output ancestor permits renaming")
            if not parts:
                info = os.fstat(current)
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise PermissionError(
                        "Release output parent must be owned and private"
                    )
            if sys.platform == "darwin":
                _reject_darwin_extended_acl(current)
            self.parent_fd = current
        except BaseException:
            os.close(current)
            raise

    def _pin_windows_parent(self) -> None:
        self.user_sid = _windows_user_sid()
        try:
            root, _ = _windows_open_directory(Path(self.path.anchor))
            self.parent_handles.append(root)
            for component in self.path.parent.parts[1:]:
                handle = _windows_open_relative(
                    self.parent_handles[-1],
                    component,
                    directory=True,
                    create=False,
                    share_delete=False,
                )
                self.parent_handles.append(handle)
                _windows_directory_identity(handle)
            _windows_acl_private(self.parent_handles[-1], self.user_sid)
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def create_private(self, prefix: str, *, restricted: bool = False) -> Path:
        """Create a new private sibling under the pinned parent."""
        if os.name == "posix":
            if self.parent_fd is None:
                raise PermissionError("Release output parent is not pinned")
            for _ in range(8):
                name = prefix + secrets.token_hex(12)
                try:
                    os.mkdir(name, 0o700, dir_fd=self.parent_fd)
                except FileExistsError:
                    continue
                try:
                    fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=self.parent_fd,
                    )
                    retained = None
                    try:
                        opened = os.fstat(fd)
                        named = os.stat(
                            name, dir_fd=self.parent_fd, follow_symlinks=False
                        )
                        if (
                            not stat.S_ISDIR(opened.st_mode)
                            or opened.st_uid != os.geteuid()
                            or opened.st_mode & 0o077
                            or (opened.st_dev, opened.st_ino)
                            != (named.st_dev, named.st_ino)
                        ):
                            raise PermissionError("Private release directory changed")
                        private = self.path.parent / name
                        # Register the publication descriptor before closing
                        # the validation descriptor, so either close failure
                        # still has an explicit owner and cleanup path.
                        retained = os.dup(fd)
                        self.private_fds[name] = retained
                        return private
                    except BaseException:
                        if retained is not None:
                            self.private_fds.pop(name, None)
                            to_close, retained = retained, None
                            os.close(to_close)
                        raise
                    finally:
                        try:
                            os.close(fd)
                        except BaseException:
                            if retained is not None:
                                self.private_fds.pop(name, None)
                                os.close(retained)
                            raise
                except BaseException:
                    os.rmdir(name, dir_fd=self.parent_fd)
                    raise
            raise FileExistsError("Could not allocate private release directory")
        if not self.parent_handles or self.user_sid is None:
            raise PermissionError("Release output parent is not pinned")
        for _ in range(8):
            name = prefix + secrets.token_hex(12)
            try:
                if restricted:
                    with _windows_private_descriptor(self.user_sid) as descriptor:
                        handle = _windows_open_relative(
                            self.parent_handles[-1],
                            name,
                            directory=True,
                            create=True,
                            security_descriptor=descriptor,
                            share_delete=False,
                        )
                else:
                    handle = _windows_open_relative(
                        self.parent_handles[-1], name, directory=True, create=True
                    )
            except FileExistsError:
                continue
            try:
                _windows_directory_identity(handle)
                _windows_acl_private(handle, self.user_sid)
            except BaseException:
                try:
                    _windows_mark_delete(handle)
                finally:
                    _windows_close(handle)
                raise
            self.private_handles[name] = handle
            return self.path.parent / name
        raise FileExistsError("Could not allocate private release directory")

    def open_member(self, private: Path, name: str, *, readwrite: bool = False) -> int:
        """Create a fixed-name member relative to the retained stage handle."""
        if os.name == "nt":
            import msvcrt

            handle = self.private_handles[private.name]
            child = _windows_open_relative(
                handle,
                name,
                directory=False,
                create=True,
                write=not readwrite,
                readwrite=readwrite,
            )
            try:
                mode = os.O_RDWR if readwrite else os.O_WRONLY
                return msvcrt.open_osfhandle(child, mode | os.O_BINARY)
            except BaseException:
                _windows_close(child)
                raise
        return os.open(
            name,
            (os.O_RDWR if readwrite else os.O_WRONLY)
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
            0o600,
            dir_fd=self.private_fds[private.name],
        )

    def stat_member(self, private: Path, name: str):
        """Read member identity relative to the retained Windows stage handle."""
        import msvcrt

        handle = _windows_open_relative(
            self.private_handles[private.name],
            name,
            directory=False,
            create=False,
        )
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            _windows_close(handle)
            raise
        try:
            return os.fstat(descriptor)
        finally:
            os.close(descriptor)

    def replace_member(
        self, private: Path, name: str, destination: str, identity: tuple[int, int]
    ) -> None:
        """Publish the checked stage file through retained Windows directory handles."""
        import msvcrt

        handle = _windows_open_relative(
            self.private_handles[private.name],
            name,
            directory=False,
            create=False,
            write=True,
            share_delete=False,
        )
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
        except BaseException:
            _windows_close(handle)
            raise
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != identity
            ):
                raise PermissionError("Private release member changed")
            _windows_rename_relative(
                msvcrt.get_osfhandle(descriptor),
                self.parent_handles[-1],
                destination,
                replace=True,
            )
            published = _windows_open_relative(
                self.parent_handles[-1],
                destination,
                directory=False,
                create=False,
            )
            try:
                published_descriptor = msvcrt.open_osfhandle(
                    published, os.O_RDONLY | os.O_BINARY
                )
            except BaseException:
                _windows_close(published)
                raise
            try:
                actual = os.fstat(published_descriptor)
                if (
                    not stat.S_ISREG(actual.st_mode)
                    or (actual.st_dev, actual.st_ino) != identity
                ):
                    raise PermissionError("Published release member changed")
            finally:
                os.close(published_descriptor)
        finally:
            os.close(descriptor)

    def cleanup_private(self, private: Path, names: list[str]) -> None:
        """Remove only members of the retained, still-private stage."""
        if os.name == "nt":
            handle = self.private_handles.pop(private.name, None)
            if handle is None:
                return
            failure = None
            try:
                for name in names:
                    try:
                        with suppress(FileNotFoundError):
                            child = _windows_open_relative(
                                handle, name, directory=False, create=False, write=True
                            )
                            try:
                                _windows_mark_delete(child)
                            finally:
                                _windows_close(child)
                    except BaseException as error:
                        if failure is None:
                            failure = error
                try:
                    _windows_mark_delete(handle)
                except BaseException as error:
                    if failure is None:
                        failure = error
            finally:
                _windows_close(handle)
            if failure is not None:
                raise failure
            return
        fd = self.private_fds.pop(private.name, None)
        if fd is None:
            return
        try:
            for name in names:
                with suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=fd)
            if self.parent_fd is None:
                raise PermissionError("Release output parent is not pinned")
            os.rmdir(private.name, dir_fd=self.parent_fd)
        finally:
            os.close(fd)

    def publish_private(self, private: Path) -> None:
        """Publish an entirely populated private sibling with no later writes."""
        private = Path(private).absolute()
        if private.parent != self.path.parent or private.name == self.path.name:
            raise ValueError("Private release directory is outside the pinned parent")
        if os.name == "posix" and os.path.lexists(self.path):
            raise FileExistsError("Release output must be new")
        if os.name == "posix":
            if self.parent_fd is None:
                raise PermissionError("Release output parent is not pinned")
            fd = self.private_fds[private.name]
            renamed = False
            try:
                opened = os.fstat(fd)
                named = os.stat(
                    private.name, dir_fd=self.parent_fd, follow_symlinks=False
                )
                identity = (opened.st_dev, opened.st_ino)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or opened.st_mode & 0o077
                    or identity != (named.st_dev, named.st_ino)
                ):
                    raise PermissionError("Private release directory changed")
                _rename_no_replace(self.parent_fd, private.name, self.path.name)
                self.private_fds.pop(private.name)
                renamed = True
                published = os.stat(
                    self.path.name, dir_fd=self.parent_fd, follow_symlinks=False
                )
                if (
                    not stat.S_ISDIR(published.st_mode)
                    or (published.st_dev, published.st_ino) != identity
                ):
                    raise PermissionError("Published release directory changed")
            finally:
                if renamed:
                    os.close(fd)
        else:
            if self.user_sid is None:
                raise PermissionError("Release output parent is not pinned")
            stage = self.private_handles[private.name]
            identity = _windows_directory_identity(stage)
            _windows_acl_private(stage, self.user_sid)
            _windows_rename_relative(stage, self.parent_handles[-1], self.path.name)
            self.private_handles.pop(private.name)
            _windows_close(stage)
            published = _windows_open_relative(
                self.parent_handles[-1], self.path.name, directory=True, create=False
            )
            try:
                actual = _windows_directory_identity(published)
                if actual != identity:
                    raise PermissionError("Published release directory changed")
                _windows_acl_private(published, self.user_sid)
            finally:
                _windows_close(published)

    def __exit__(self, exc_type, exc, traceback):
        failure = None

        def release(close, value):
            nonlocal failure
            try:
                close(value)
            except BaseException as error:
                if failure is None:
                    failure = error

        for fd in self.private_fds.values():
            release(os.close, fd)
        self.private_fds.clear()
        for handle in self.private_handles.values():
            release(_windows_close, handle)
        self.private_handles.clear()
        if self.parent_fd is not None:
            release(os.close, self.parent_fd)
            self.parent_fd = None
        for handle in reversed(self.parent_handles):
            release(_windows_close, handle)
        self.parent_handles.clear()
        if failure is not None and exc_type is None:
            raise failure
