"""Bound archive bytes and metadata before stdlib parsers allocate member state."""

from __future__ import annotations

import csv
import io
import os
import secrets
import stat
import struct
import sys
import tarfile
import tempfile
import traceback
import zipfile
import zlib
from contextlib import contextmanager

CHUNK_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_EXPANDED_BYTES = 32 * 1024 * 1024
MAX_STREAM_BYTES = 40 * 1024 * 1024
MAX_MEMBERS = 128
MAX_HEADERS = 384
MAX_METADATA_BYTES = 64 * 1024
MAX_METADATA_TOTAL = 1024 * 1024
MAX_NAME_BYTES = 4096
MAX_RATIO = 200


class ArchiveBudgetError(ValueError):
    """An archive exceeds the reviewed resource or format boundary."""


def run_with_actions_command_guard(run):
    """Keep archive CLI output inside a suspended Actions command channel."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return run()
    sys.stdout.flush()
    token = secrets.token_hex(32)
    print(f"::stop-commands::{token}", file=sys.stderr, flush=True)
    try:
        try:
            return run()
        except SystemExit as error:
            if isinstance(error.code, str):
                print(error.code, file=sys.stderr, flush=True)
                return 1
            return error.code or 0
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return 1
    finally:
        sys.stdout.flush()
        print(f"::{token}::", file=sys.stderr, flush=True)


def require(condition, message):
    if not condition:
        raise ArchiveBudgetError(message)


def _limit(value, maximum):
    if value is None:
        return maximum
    require(
        type(value) is int and value >= 0,
        "Archive budget override must be a nonnegative integer",
    )
    return min(maximum, value)


def bounded_size(handle):
    info = os.fstat(handle.fileno())
    require(stat.S_ISREG(info.st_mode), "Archive input must be a regular file")
    size = info.st_size
    require(
        0 <= size <= MAX_ARCHIVE_BYTES, "Compressed archive exceeds its byte budget"
    )
    return size


@contextmanager
def snapshot(path):
    """Pin captured bytes so input edits cannot replace admitted parser metadata."""
    require(stat.S_ISREG(path.lstat().st_mode), "Archive input must be a regular file")
    with path.open("rb") as source, tempfile.TemporaryFile() as captured:
        expected = bounded_size(source)
        total = 0
        while chunk := source.read(min(CHUNK_BYTES, MAX_ARCHIVE_BYTES - total + 1)):
            total += len(chunk)
            require(
                total <= MAX_ARCHIVE_BYTES, "Compressed archive exceeds its byte budget"
            )
            captured.write(chunk)
        require(total == expected, "Archive size changed during bounded capture")
        captured.seek(0)
        yield captured, total


def _exact(handle, count):
    require(
        0 <= count <= MAX_METADATA_BYTES, "Archive metadata exceeds its byte budget"
    )
    value = handle.read(count)
    require(len(value) == count, "Archive metadata is truncated")
    return value


ZIP_COVERAGE_ERROR = (
    "ZIP local records do not contiguously cover the bytes before the central directory"
)


def _assert_no_unicode_path_extra(extra):
    """Refuse path rewriting before ZipFile sanitizes a Unicode Path value."""
    offset = 0
    while offset < len(extra):
        require(offset + 4 <= len(extra), "ZIP extra metadata is malformed")
        kind, length = struct.unpack_from("<HH", extra, offset)
        offset += 4
        require(offset + length <= len(extra), "ZIP extra metadata is malformed")
        require(kind != 0x7075, "ZIP Unicode Path metadata is unsupported")
        offset += length


def zip_preflight(
    handle, size, max_member_bytes=None, max_expanded_bytes=None, max_members=None
):
    """Inspect bounded raw central records before ZipFile builds its object list."""
    tail_size = min(size, 65557)
    handle.seek(size - tail_size)
    tail = handle.read(tail_size)
    offset = tail.rfind(b"PK\x05\x06")
    require(offset >= 0 and offset + 22 <= len(tail), "ZIP end record is missing")
    end = struct.unpack("<4s4H2IH", tail[offset : offset + 22])
    _, disk, central_disk, disk_count, count, central_size, central_offset, comment = (
        end
    )
    require(
        disk == central_disk == 0 and disk_count == count,
        "Multipart ZIP archives are unsupported",
    )
    require(
        count != 0xFFFF and central_size != 0xFFFFFFFF and central_offset != 0xFFFFFFFF,
        "ZIP64 archives are outside the reviewed archive budget",
    )
    require(
        count <= _limit(max_members, MAX_MEMBERS), "ZIP exceeds the member count budget"
    )
    require(
        central_size <= MAX_METADATA_TOTAL
        and central_offset + central_size == size - tail_size + offset
        and offset + 22 + comment == len(tail),
        "ZIP central metadata is oversized or inconsistent",
    )
    # ZipFile detects ZIP64 locators even without ordinary EOCD sentinels.
    eocd_offset = size - tail_size + offset
    if eocd_offset >= 20:
        handle.seek(eocd_offset - 20)
        require(
            handle.read(4) != b"PK\x06\x07",
            "ZIP64 footer is outside the reviewed archive budget",
        )
    handle.seek(central_offset)
    member_limit = _limit(max_member_bytes, MAX_MEMBER_BYTES)
    total_limit = _limit(max_expanded_bytes, MAX_EXPANDED_BYTES)
    total = 0
    spans = []
    for _ in range(count):
        position = handle.tell()
        require(
            position + 46 <= central_offset + central_size,
            "ZIP central record is truncated",
        )
        record = struct.unpack("<4s6H3I5H2I", _exact(handle, 46))
        require(record[0] == b"PK\x01\x02", "ZIP central record is malformed")
        flags, method, checksum = record[3], record[4], record[7]
        compressed, expanded = record[8], record[9]
        name_size, extra_size, comment_size, member_disk, local_offset = record[
            10:14
        ] + (record[16],)
        require(
            flags & 0x61 == 0 and method in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
            "ZIP uses encryption or unsupported compression",
        )
        require(
            member_disk == 0
            and expanded != 0xFFFFFFFF
            and compressed != 0xFFFFFFFF
            and local_offset != 0xFFFFFFFF,
            "ZIP64 or multipart members are unsupported",
        )
        require(
            expanded <= member_limit and compressed <= MAX_ARCHIVE_BYTES,
            "ZIP member exceeds its expanded byte budget",
        )
        total += expanded
        require(
            total <= total_limit,
            "ZIP exceeds the aggregate expanded byte budget",
        )
        require(
            expanded <= max(1, compressed) * MAX_RATIO,
            "ZIP member exceeds the compression ratio budget",
        )
        require(
            0 < name_size <= MAX_NAME_BYTES
            and extra_size <= MAX_METADATA_BYTES
            and comment_size <= MAX_METADATA_BYTES,
            "ZIP member metadata exceeds its byte budget",
        )
        next_record = position + 46 + name_size + extra_size + comment_size
        require(
            next_record <= central_offset + central_size,
            "ZIP central metadata is truncated",
        )
        # Check the bytes before ZipFile can truncate at NUL or apply a
        # Unicode-path extra field to its public filename.
        handle.seek(position + 46)
        central_name = _exact(handle, name_size)
        require(
            not any(byte < 32 or byte == 127 for byte in central_name),
            "ZIP member name contains a control character",
        )
        _assert_no_unicode_path_extra(_exact(handle, extra_size))
        handle.seek(local_offset)
        local = struct.unpack("<4s5H3I2H", _exact(handle, 30))
        require(local[0] == b"PK\x03\x04", "ZIP local record is malformed")
        local_end = local_offset + 30 + local[9] + local[10] + compressed
        require(
            local[9] <= MAX_NAME_BYTES
            and local[10] <= MAX_METADATA_BYTES
            and local_end <= central_offset,
            "ZIP local metadata or compressed range exceeds its budget",
        )
        local_name = _exact(handle, local[9])
        require(
            local_name == central_name,
            "ZIP local member name differs from its central record",
        )
        _assert_no_unicode_path_extra(_exact(handle, local[10]))
        if flags & 0x08:
            local_end += _data_descriptor(
                handle, local_end, central_offset, (checksum, compressed, expanded)
            )
        spans.append((local_offset, local_end))
        handle.seek(next_record)
    require(
        handle.tell() == central_offset + central_size,
        "ZIP member count differs from central metadata",
    )
    # Every raw byte before the central directory must belong to exactly one
    # admitted local record, so no unparsed gap can carry unreviewed bytes.
    position = 0
    for start, end in sorted(spans):
        require(start == position, ZIP_COVERAGE_ERROR)
        position = end
    require(position == central_offset, ZIP_COVERAGE_ERROR)
    handle.seek(0)


def _data_descriptor(handle, offset, central_offset, expected):
    """Return the length of a data descriptor that repeats the central values."""
    handle.seek(offset)
    available = min(16, central_offset - offset)
    require(available >= 12, "ZIP data descriptor is missing or truncated")
    value = _exact(handle, available)
    if available == 16 and struct.unpack("<4s3I", value) == (
        b"PK\x07\x08",
        *expected,
    ):
        return 16
    require(
        struct.unpack("<3I", value[:12]) == expected,
        "ZIP data descriptor differs from its central record",
    )
    return 12


@contextmanager
def open_zip(
    path,
    error_type=ArchiveBudgetError,
    *,
    max_member_bytes=None,
    max_expanded_bytes=None,
    max_members=None,
):
    try:
        with snapshot(path) as (raw, size):
            zip_preflight(raw, size, max_member_bytes, max_expanded_bytes, max_members)
            with zipfile.ZipFile(raw) as archive:
                yield archive
    except ArchiveBudgetError as error:
        if error_type is ArchiveBudgetError:
            raise
        raise error_type(str(error)) from error
    except (
        OSError,
        EOFError,
        UnicodeError,
        zipfile.BadZipFile,
        zlib.error,
        OverflowError,
    ) as error:
        raise error_type("ZIP input is malformed or unreadable") from error


class MemberBudget:
    def __init__(self):
        self.count = 0
        self.total = 0

    def admit(self, size):
        require(
            0 <= size <= MAX_MEMBER_BYTES,
            "Archive member exceeds its expanded byte budget",
        )
        self.count += 1
        self.total += size
        require(self.count <= MAX_MEMBERS, "Archive exceeds the member count budget")
        require(
            self.total <= MAX_EXPANDED_BYTES,
            "Archive exceeds the aggregate expanded byte budget",
        )


def read_member(handle, size, budget):
    """Read at most the admitted bytes plus one overflow sentinel, in small chunks."""
    budget.admit(size)
    chunks = []
    actual = 0
    while True:
        chunk = handle.read(min(CHUNK_BYTES, size - actual + 1))
        if not chunk:
            break
        actual += len(chunk)
        require(actual <= size, "Archive member bytes exceed its declared size")
        chunks.append(chunk)
    require(actual == size, "Archive member is truncated")
    return b"".join(chunks)


def read_zip_member(archive, member, budget):
    with archive.open(member) as handle:
        return read_member(handle, member.file_size, budget)


def record_rows(value, error_type=ArchiveBudgetError):
    try:
        require(len(value) <= MAX_MEMBER_BYTES, "Wheel RECORD exceeds its byte budget")
        reader = csv.reader(io.StringIO(value.decode("utf-8"), newline=""), strict=True)
        for count, row in enumerate(reader, 1):
            require(count <= MAX_MEMBERS, "Wheel RECORD exceeds its row count budget")
            require(len(row) == 3, "Wheel RECORD contains a malformed row")
            yield row
    except (UnicodeDecodeError, csv.Error, ArchiveBudgetError) as error:
        raise error_type("Wheel RECORD is malformed or exceeds its budget") from error


def _pax_fields(value):
    fields = {}
    position = 0
    records = 0
    while position < len(value):
        records += 1
        require(records <= MAX_MEMBERS, "PAX metadata exceeds its record count budget")
        space = value.find(b" ", position, position + 9)
        require(space > position, "PAX metadata has an invalid record length")
        digits = value[position:space]
        require(digits.isdigit(), "PAX metadata has an invalid record length")
        length = int(digits)
        require(
            length > space - position + 2 and position + length <= len(value),
            "PAX metadata is truncated",
        )
        record = value[space + 1 : position + length]
        require(record.endswith(b"\n") and b"=" in record, "PAX metadata is malformed")
        key, data = record[:-1].split(b"=", 1)
        require(not key.startswith(b"GNU.sparse"), "Sparse TAR members are unsupported")
        if key == b"size":
            require(
                data.isdigit() and len(data) <= 10, "PAX size is invalid or oversized"
            )
            size = int(data)
            require(size <= MAX_MEMBER_BYTES, "PAX size exceeds the member byte budget")
            fields[key] = size
        if key in {b"path", b"linkpath"}:
            require(len(data) <= MAX_NAME_BYTES, "PAX path exceeds its byte budget")
        position += length
    return fields


def tar_preflight(raw, stream_size):
    """Bound physical/PAX headers before tarfile performs recursive metadata parsing."""
    raw.seek(0)
    budget = MemberBudget()
    headers = metadata_total = chain = 0
    global_fields = {}
    local_fields = {}
    while True:
        block = raw.read(512)
        require(len(block) == 512, "TAR end record is missing or truncated")
        if block == bytes(512):
            require(raw.read(512) == bytes(512), "TAR end record is incomplete")
            while chunk := raw.read(CHUNK_BYTES):
                require(not any(chunk), "TAR has nonzero trailing bytes")
            break
        headers += 1
        require(headers <= MAX_HEADERS, "TAR exceeds its physical header count budget")
        member = tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")
        require(member.size >= 0, "TAR member has a negative size")
        if member.type in {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME}:
            chain += 1
            require(chain <= 8, "TAR metadata chain exceeds its count budget")
            metadata_total += member.size
            require(
                member.size <= MAX_METADATA_BYTES
                and metadata_total <= MAX_METADATA_TOTAL,
                "TAR metadata exceeds its byte budget",
            )
            value = _exact(raw, member.size)
            if member.type == tarfile.GNUTYPE_LONGNAME:
                require(
                    len(value.rstrip(b"\x00")) <= MAX_NAME_BYTES,
                    "TAR long name exceeds its byte budget",
                )
            else:
                fields = _pax_fields(value)
                if member.type == tarfile.XGLTYPE:
                    global_fields.update(fields)
                else:
                    local_fields.update(fields)
        else:
            require(
                member.type
                in {
                    tarfile.REGTYPE,
                    tarfile.AREGTYPE,
                    tarfile.CONTTYPE,
                    tarfile.DIRTYPE,
                },
                "TAR contains a link or device or sparse member",
            )
            require(
                not member.isdir() or member.size == 0, "TAR directory has nonzero data"
            )
            fields = {**global_fields, **local_fields}
            require(
                fields.get(b"size", member.size) == member.size,
                "PAX size differs from the physical member size",
            )
            budget.admit(member.size)
            local_fields.clear()
            chain = 0
            require(
                raw.tell() + member.size <= stream_size, "TAR member data is truncated"
            )
            raw.seek(member.size, 1)
        padding = -member.size % 512
        require(raw.tell() + padding <= stream_size, "TAR member padding is truncated")
        raw.seek(padding, 1)
    require(chain == 0, "TAR metadata has no following member")
    raw.seek(0)


GZIP_MAGIC = b"\x1f\x8b\x08"
GZIP_FHCRC, GZIP_FEXTRA, GZIP_FNAME, GZIP_FCOMMENT = 0x02, 0x04, 0x08, 0x10
STORED_BLOCK_BYTES = 0xFFFF
CANONICAL_GZIP_ERROR = "Gzip stream is not the canonical stored-block serialization"


def _gzip_bytes(handle, count):
    """Read a gzip framing field whose length the format itself bounds."""
    value = handle.read(count)
    require(len(value) == count, "Gzip member is truncated")
    return value


def _gzip_string(handle, header):
    """Read one bounded zero-terminated gzip header field."""
    for _ in range(MAX_NAME_BYTES + 1):
        value = _gzip_bytes(handle, 1)
        header.append(value)
        if value == b"\x00":
            return
    raise ArchiveBudgetError("Gzip header field exceeds its byte budget")


def _gzip_header(handle):
    """Parse one RFC 1952 member header; return its fixed ten bytes."""
    fixed = _gzip_bytes(handle, 10)
    require(
        fixed[:3] == GZIP_MAGIC and fixed[3] & 0xE0 == 0,
        "Gzip header is malformed or uses reserved flags",
    )
    flags = fixed[3]
    header = [fixed]
    if flags & GZIP_FEXTRA:
        size = _gzip_bytes(handle, 2)
        header += [size, _gzip_bytes(handle, struct.unpack("<H", size)[0])]
    for flag in (GZIP_FNAME, GZIP_FCOMMENT):
        if flags & flag:
            _gzip_string(handle, header)
    if flags & GZIP_FHCRC:
        require(
            struct.unpack("<H", _gzip_bytes(handle, 2))[0]
            == zlib.crc32(b"".join(header)) & 0xFFFF,
            "Gzip header checksum is invalid",
        )
    return fixed


def _gunzip_one_member(compressed, raw, limit):
    """Decode exactly one gzip member; refuse concatenated or trailing bytes."""
    fixed = _gzip_header(compressed)
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    pending = b""
    total = crc = 0
    while not decoder.eof:
        if not pending:
            pending = compressed.read(CHUNK_BYTES)
            require(pending, "Gzip member is truncated")
        chunk = decoder.decompress(pending, CHUNK_BYTES)
        pending = decoder.unconsumed_tail
        total += len(chunk)
        require(
            total <= limit,
            "TAR stream exceeds decoded archive budget (expanded bytes or compression ratio)",
        )
        crc = zlib.crc32(chunk, crc)
        raw.write(chunk)
    # unused_data plus at most nine more bytes: exactly eight means the member
    # trailer ends the file, with no further gzip member or trailing data.
    trailer = decoder.unused_data + compressed.read(9)
    require(
        len(trailer) == 8,
        "Gzip input must be exactly one member with no trailing bytes",
    )
    require(
        struct.unpack("<2I", trailer) == (crc & 0xFFFFFFFF, total & 0xFFFFFFFF),
        "Gzip member checksum or size is invalid",
    )
    return fixed, total


def _require_canonical_gzip(fixed, compressed, size, raw):
    """Require the normalizer's exact header and stored-block serialization."""
    require(
        fixed[3] == 0 and fixed[8:] == b"\x00\xff",
        "Gzip header is not canonical",
    )
    compressed.seek(10)
    raw.seek(0)
    block = raw.read(STORED_BLOCK_BYTES)
    if not block:
        require(
            _gzip_bytes(compressed, 5) == b"\x01\x00\x00\xff\xff", CANONICAL_GZIP_ERROR
        )
    while block:
        following = raw.read(STORED_BLOCK_BYTES)
        expected = (
            (0 if following else 1).to_bytes(1, "little")
            + len(block).to_bytes(2, "little")
            + (len(block) ^ 0xFFFF).to_bytes(2, "little")
            + block
        )
        require(compressed.read(len(expected)) == expected, CANONICAL_GZIP_ERROR)
        block = following
    require(compressed.tell() == size - 8, CANONICAL_GZIP_ERROR)
    raw.seek(0)


@contextmanager
def open_tar(
    path,
    error_type=ArchiveBudgetError,
    *,
    max_stream_bytes=None,
    canonical_gzip=False,
):
    """Admit one gzip member, then bounded TAR metadata, before tarfile parsing.

    With ``canonical_gzip`` the raw gzip bytes must also be exactly the
    trusted normalizer's header and stored-block serialization.
    """
    try:
        with snapshot(path) as (compressed, size), tempfile.TemporaryFile() as raw:
            limit = min(
                _limit(max_stream_bytes, MAX_STREAM_BYTES), max(1, size) * MAX_RATIO
            )
            fixed, total = _gunzip_one_member(compressed, raw, limit)
            tar_preflight(raw, total)
            if canonical_gzip:
                _require_canonical_gzip(fixed, compressed, size, raw)
            with tarfile.open(fileobj=raw, mode="r:") as archive:
                yield archive
    except ArchiveBudgetError as error:
        if error_type is ArchiveBudgetError:
            raise
        raise error_type(str(error)) from error
    except (OSError, EOFError, tarfile.TarError, zlib.error, OverflowError) as error:
        raise error_type("TAR input is malformed or unreadable") from error


def file_digest(path):
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        bounded_size(handle)
        total = 0
        while chunk := handle.read(CHUNK_BYTES):
            total += len(chunk)
            require(total <= MAX_ARCHIVE_BYTES, "Archive hash exceeds its byte budget")
            digest.update(chunk)
    return digest.hexdigest()
