"""Small native archive attacks refuse before parsing, rewriting or publication."""

import base64
import csv
import gzip
import hashlib
import io
import struct
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import normalize_sdist, normalize_wheel, prepare_release
from scripts import verify_distribution as verifier
from scripts import verify_release_handoff as handoff

ROOT = Path(__file__).resolve().parents[1]
EPOCH = 315532800


def make_wheel(path, value=b"synthetic source\n", extra=None):
    values = {
        "synthetic.py": value,
        "synthetic-1.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: synthetic\nVersion: 1.0\n",
        "synthetic-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
        **(extra or {}),
    }
    record = "synthetic-1.0.dist-info/RECORD"
    text = io.StringIO(newline="")
    writer = csv.writer(text, lineterminator="\n")
    for name, data in values.items():
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .rstrip(b"=")
            .decode()
        )
        writer.writerow((name, "sha256=" + digest, str(len(data))))
    writer.writerow((record, "", ""))
    values[record] = text.getvalue().encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in values.items():
            archive.writestr(name, data)


def make_tar(
    path, value=b"synthetic source\n", count=1, pax=None, format=tarfile.PAX_FORMAT
):
    with tarfile.open(path, "w:gz", format=format) as archive:
        for index in range(count):
            member = tarfile.TarInfo(f"synthetic-1.0/source{index}.py")
            member.size = len(value)
            member.pax_headers = pax or {}
            archive.addfile(member, io.BytesIO(value))
    encoded = bytearray(gzip.compress(gzip.decompress(path.read_bytes()), mtime=EPOCH))
    encoded[8:10] = b"\x00\xff"
    path.write_bytes(encoded)


def target(kind, entrypoint, path):
    module = normalize_wheel if kind == "wheel" else normalize_sdist
    if entrypoint == "normalizer":
        return module.archive_budget, lambda: getattr(module, "normalize_" + kind)(
            path, EPOCH
        )
    if entrypoint == "reader":
        name = "read_values" if kind == "wheel" else "read_members"
        return module.archive_budget, lambda: getattr(module, name)(path)
    if entrypoint == "inventory":
        if kind == "wheel":
            return (
                prepare_release.archive_budget,
                lambda: prepare_release.wheel_inventory(path, EPOCH),
            )
        return prepare_release.archive_budget, lambda: prepare_release.sdist_inventory(
            path, "1.0", EPOCH
        )
    if entrypoint == "verifier":
        if kind == "wheel":
            return verifier.archive_budget, lambda: verifier._verify_wheel(
                path, "1.0", ROOT
            )
        return verifier.archive_budget, lambda: verifier._verify_sdist(path, ROOT)
    return handoff.archive_budget, lambda: handoff.preflight_archives(path.parent)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize(
    "entrypoint", ["normalizer", "reader", "inventory", "verifier", "handoff"]
)
def test_high_ratio_native_archives_fail_every_admission_path(
    tmp_path, kind, entrypoint
):
    path = tmp_path / ("attack.whl" if kind == "wheel" else "attack.tar.gz")
    (make_wheel if kind == "wheel" else make_tar)(path, b"0" * 65536)
    original = path.read_bytes()
    _, call = target(kind, entrypoint, path)
    with pytest.raises((ValueError, RuntimeError), match="ratio"):
        call()
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("attack", ["compressed", "member", "aggregate", "count"])
def test_small_native_resource_limits_fail_without_replacing(
    tmp_path, monkeypatch, kind, attack
):
    path = tmp_path / ("attack.whl" if kind == "wheel" else "attack.tar.gz")
    value = bytes(range(256)) * 2
    if kind == "wheel":
        make_wheel(path, value, {"second.py": value})
    else:
        make_tar(path, value, count=3)
    original = path.read_bytes()
    budget, call = target(kind, "normalizer", path)
    constant, limit = {
        "compressed": ("MAX_ARCHIVE_BYTES", len(original) - 1),
        "member": ("MAX_MEMBER_BYTES", 511),
        "aggregate": ("MAX_EXPANDED_BYTES", 1024),
        "count": ("MAX_MEMBERS", 2),
    }[attack]
    monkeypatch.setattr(budget, constant, limit)
    with pytest.raises((ValueError, RuntimeError), match="budget"):
        call()
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize(
    "attack",
    [
        "size",
        "count",
        "metadata",
        "zip64",
        "method",
        "strong_encryption",
        "patched_data",
    ],
)
def test_zip_declared_metadata_refuses_before_zip_parser(tmp_path, monkeypatch, attack):
    path = tmp_path / "declared.whl"
    make_wheel(path)
    raw = bytearray(path.read_bytes())
    central = raw.index(b"PK\x01\x02")
    end = raw.rindex(b"PK\x05\x06")
    if attack == "size":
        struct.pack_into("<I", raw, central + 24, 8 * 1024 * 1024 + 1)
    elif attack == "count":
        struct.pack_into("<H", raw, end + 8, 129)
        struct.pack_into("<H", raw, end + 10, 129)
    elif attack == "metadata":
        struct.pack_into("<H", raw, central + 28, 65535)
    elif attack == "zip64":
        struct.pack_into("<I", raw, central + 24, 0xFFFFFFFF)
    elif attack == "strong_encryption":
        struct.pack_into("<H", raw, central + 8, 0x40)
    elif attack == "patched_data":
        struct.pack_into("<H", raw, central + 8, 0x20)
    else:
        struct.pack_into("<H", raw, central + 10, zipfile.ZIP_LZMA)
    path.write_bytes(raw)
    original = path.read_bytes()
    monkeypatch.setattr(
        zipfile,
        "ZipFile",
        lambda *a, **k: pytest.fail("ZIP parser reached before admission"),
    )
    with pytest.raises(normalize_wheel.WheelNormalizationError):
        normalize_wheel.normalize_wheel(path, EPOCH)
    assert path.read_bytes() == original


@pytest.mark.parametrize("attack", ["crc", "truncated"])
def test_zip_actual_malformed_stream_preserves_input(tmp_path, attack):
    path = tmp_path / "actual.whl"
    make_wheel(path)
    raw = bytearray(path.read_bytes())
    if attack == "crc":
        central = raw.index(b"PK\x01\x02")
        struct.pack_into("<I", raw, central + 16, 0)
    else:
        raw = raw[:-7]
    path.write_bytes(raw)
    with pytest.raises(normalize_wheel.WheelNormalizationError):
        normalize_wheel.normalize_wheel(path, EPOCH)
    assert path.read_bytes() == raw


def raw_tar(path, header):
    path.write_bytes(gzip.compress(header + bytes(1024), mtime=0))


@pytest.mark.parametrize("size", [8 * 1024 * 1024 + 1, 2**70, -1])
def test_tar_declared_size_refuses_before_tar_parser(tmp_path, monkeypatch, size):
    path = tmp_path / "declared.tar.gz"
    member = tarfile.TarInfo("synthetic-1.0/source.py")
    member.size = size
    raw_tar(path, member.tobuf(format=tarfile.GNU_FORMAT))
    original = path.read_bytes()
    monkeypatch.setattr(
        tarfile,
        "open",
        lambda *a, **k: pytest.fail("TAR parser reached before admission"),
    )
    with pytest.raises(normalize_sdist.SdistNormalizationError):
        normalize_sdist.normalize_sdist(path, EPOCH)
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "attack", ["metadata", "pax_size", "pax_digits", "sparse", "chain"]
)
def test_pax_metadata_is_bounded_before_tarfile_parsing(tmp_path, monkeypatch, attack):
    path = tmp_path / "pax.tar.gz"
    if attack == "metadata":
        make_tar(path, pax={"comment": "x" * 256})
        monkeypatch.setattr(normalize_sdist.archive_budget, "MAX_METADATA_BYTES", 128)
    elif attack == "pax_size":
        make_tar(path, pax={"size": str(8 * 1024 * 1024 + 1)})
    elif attack == "pax_digits":
        make_tar(path, pax={"size": "9" * 100})
    elif attack == "sparse":
        make_tar(path, pax={"GNU.sparse.size": "100"})
    else:
        extension = tarfile.TarInfo("pax")
        extension.type = tarfile.XHDTYPE
        value = b"13 comment=x\n"
        extension.size = len(value)
        payload = (extension.tobuf() + value + bytes(512 - len(value))) * 9
        raw_tar(path, payload)
    original = path.read_bytes()
    monkeypatch.setattr(
        tarfile,
        "open",
        lambda *a, **k: pytest.fail("TAR parser reached before admission"),
    )
    with pytest.raises(normalize_sdist.SdistNormalizationError):
        normalize_sdist.normalize_sdist(path, EPOCH)
    assert path.read_bytes() == original


@pytest.mark.parametrize("declared, actual", [(3, b"four"), (3, b"ab"), (3, b"abc")])
def test_chunked_reader_checks_actual_size_and_sentinel(declared, actual):
    helper = normalize_wheel.archive_budget

    class Observed(io.BytesIO):
        def read(self, size=-1):
            assert 0 < size <= helper.CHUNK_BYTES
            return super().read(size)

    if len(actual) == declared:
        assert (
            helper.read_member(Observed(actual), declared, helper.MemberBudget())
            == actual
        )
    else:
        with pytest.raises(ValueError, match="declared|truncated"):
            helper.read_member(Observed(actual), declared, helper.MemberBudget())


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_valid_canonical_output_is_deterministic_and_inventory_safe(tmp_path, kind):
    path = tmp_path / ("valid.whl" if kind == "wheel" else "valid.tar.gz")
    (make_wheel if kind == "wheel" else make_tar)(path)
    _, call = target(kind, "normalizer", path)
    digest = call()
    canonical = path.read_bytes()
    assert call() == digest and path.read_bytes() == canonical
    handoff.preflight_archives(tmp_path)
    if kind == "wheel":
        records, values = prepare_release.wheel_inventory(path, EPOCH)
        assert records and values["synthetic.py"] == b"synthetic source\n"
    else:
        assert normalize_sdist.read_members(path)[0][1] == b"synthetic source\n"


def test_bounded_pax_size_and_long_name_remain_supported(tmp_path):
    path = tmp_path / "valid.tar.gz"
    make_tar(
        path, b"synthetic", pax={"size": "9", "path": "synthetic-1.0/" + "p" * 120}
    )
    normalize_sdist.normalize_sdist(path, EPOCH)
    members = normalize_sdist.read_members(path)
    assert members[0][0].name == "synthetic-1.0/" + "p" * 120
    assert members[0][1] == b"synthetic"


def test_pax_record_count_and_size_mismatch_refuse_before_parser(tmp_path, monkeypatch):
    for case, pax in (
        ("count", {f"comment{index}": "x" for index in range(129)}),
        ("mismatch", {"size": "10"}),
    ):
        path = tmp_path / (case + ".tar.gz")
        make_tar(path, b"synthetic", pax=pax)
        original = path.read_bytes()
        with monkeypatch.context() as patch:
            patch.setattr(
                tarfile, "open", lambda *a, **k: pytest.fail("TAR parser reached")
            )
            with pytest.raises(
                normalize_sdist.SdistNormalizationError, match="count|physical"
            ):
                normalize_sdist.normalize_sdist(path, EPOCH)
        assert path.read_bytes() == original


def test_record_row_count_is_bounded_before_eager_csv_retention(tmp_path):
    path = tmp_path / "rows.whl"
    record = "synthetic-1.0.dist-info/RECORD"
    make_wheel(path)
    values = normalize_wheel.read_values(path)
    values[record] = b"".join(f"file{i},digest,1\n".encode() for i in range(129))
    for call in (
        lambda: normalize_wheel.validate_record(values, record),
        lambda: verifier.validate_record(values, record),
        lambda: prepare_release.validate_wheel_record(values),
    ):
        with pytest.raises((ValueError, RuntimeError), match="budget"):
            call()


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_parser_reads_captured_bytes_after_source_mutation(tmp_path, monkeypatch, kind):
    path = tmp_path / ("snapshot.whl" if kind == "wheel" else "snapshot.tar.gz")
    (make_wheel if kind == "wheel" else make_tar)(path)
    module = normalize_wheel if kind == "wheel" else normalize_sdist
    helper = module.archive_budget
    function = "zip_preflight" if kind == "wheel" else "tar_preflight"
    previous = getattr(helper, function)
    mutation = []

    def change_original(*args):
        try:
            path.write_bytes(b"changed original input")
            mutation.append("changed")
        except PermissionError:
            mutation.append("native handle refused writer")
        return previous(*args)

    monkeypatch.setattr(helper, function, change_original)
    if kind == "wheel":
        assert module.read_values(path)["synthetic.py"] == b"synthetic source\n"
    else:
        assert module.read_members(path)[0][1] == b"synthetic source\n"
    assert mutation


def test_compressed_input_actual_growth_is_bounded_during_capture(
    tmp_path, monkeypatch
):
    path = tmp_path / "growth.whl"
    make_wheel(path)
    original = path.read_bytes()
    helper = normalize_wheel.archive_budget
    prior = helper.bounded_size
    monkeypatch.setattr(helper, "MAX_ARCHIVE_BYTES", len(original) + 8)

    def append_after_stat(handle):
        size = prior(handle)
        with path.open("ab") as writer:
            writer.write(b"x" * 16)
        return size

    monkeypatch.setattr(helper, "bounded_size", append_after_stat)
    with pytest.raises(normalize_wheel.WheelNormalizationError, match="byte budget"):
        normalize_wheel.normalize_wheel(path, EPOCH)
    assert path.read_bytes() == original + b"x" * 16
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("limit", [0, -1, True, 0.5])
def test_stricter_caller_budgets_are_never_treated_as_defaults(tmp_path, kind, limit):
    path = tmp_path / ("limit.whl" if kind == "wheel" else "limit.tar.gz")
    (make_wheel if kind == "wheel" else make_tar)(path)
    original = path.read_bytes()
    helper = (
        normalize_wheel.archive_budget
        if kind == "wheel"
        else normalize_sdist.archive_budget
    )
    with pytest.raises(ValueError, match="budget"):
        if kind == "wheel":
            with helper.open_zip(path, max_member_bytes=limit):
                pytest.fail("Nonempty ZIP was admitted under an invalid/zero budget")
        else:
            with helper.open_tar(path, max_stream_bytes=limit):
                pytest.fail("Nonempty TAR was admitted under an invalid/zero budget")
    assert path.read_bytes() == original


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_actual_cli_refuses_ratio_and_ignores_shadow_helper(tmp_path, kind):
    path = tmp_path / ("attack.whl" if kind == "wheel" else "attack.tar.gz")
    (make_wheel if kind == "wheel" else make_tar)(path, b"0" * 65536)
    original = path.read_bytes()
    marker = tmp_path / "shadow-executed"
    (tmp_path / "archive_budget.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts" / f"normalize_{kind}.py"),
            str(path),
            "--source-date-epoch",
            str(EPOCH),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0 and "ratio" in result.stderr
    assert path.read_bytes() == original and not marker.exists()


def central(name: bytes, offset: int) -> bytes:
    return (
        struct.pack(
            "<4s6H3I5H2I",
            b"PK\x01\x02",
            20,
            20,
            0,
            zipfile.ZIP_STORED,
            0,
            0,
            0,
            0,
            0,
            len(name),
            0,
            0,
            0,
            0,
            0,
            offset,
        )
        + name
    )


def zip64_polyglot(path, member_count: int = 129) -> None:
    """Normal EOCD admits one record; hidden ZIP64 metadata selects many records."""
    locals_ = bytearray()
    entries = []
    for index in range(member_count):
        name = f"f{index:03d}.txt".encode("ascii")
        offset = len(locals_)
        locals_ += struct.pack(
            "<4s5H3I2H",
            b"PK\x03\x04",
            20,
            0,
            zipfile.ZIP_STORED,
            0,
            0,
            0,
            0,
            0,
            len(name),
            0,
        )
        locals_ += name
        entries.append(central(name, offset))
    hidden = b"".join(entries)
    outer_name = b"outer"
    outer_offset = len(locals_)
    hidden_offset = outer_offset + 46 + len(outer_name)
    zip64_end = struct.pack(
        "<4sQ2H2I4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        member_count,
        member_count,
        len(hidden),
        hidden_offset,
    )
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, hidden_offset + len(hidden), 1)
    outer_comment = hidden + zip64_end + locator
    outer = bytearray(central(outer_name, 0))
    struct.pack_into("<H", outer, 32, len(outer_comment))
    outer += outer_comment
    eocd = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        1,
        1,
        len(outer),
        outer_offset,
        0,
    )
    path.write_bytes(bytes(locals_) + bytes(outer) + eocd)


def tar_checksum(block: bytearray) -> None:
    block[148:156] = b"        "
    block[148:156] = f"{sum(block):06o}\0 ".encode("ascii")


def sparse_tar(path, extended=False):
    member = tarfile.TarInfo("synthetic-1.0/sparse.bin")
    member.type = tarfile.GNUTYPE_SPARSE
    member.size = 0
    header = bytearray(member.tobuf(format=tarfile.GNU_FORMAT))
    header[482] = int(extended)
    header[483:495] = b"00000000001\0"
    tar_checksum(header)
    raw = bytes(header) + (bytes(512) if extended else b"") + bytes(1024)
    encoded = bytearray(gzip.compress(raw, mtime=EPOCH))
    encoded[8:10] = b"\x00\xff"
    path.write_bytes(encoded)


@pytest.mark.parametrize(
    "entrypoint", ["normalizer", "reader", "inventory", "verifier", "handoff"]
)
@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_alternate_parser_views_refuse_without_replacement(tmp_path, kind, entrypoint):
    path = tmp_path / ("bad.whl" if kind == "wheel" else "bad.tar.gz")
    if kind == "wheel":
        zip64_polyglot(path)
        with zipfile.ZipFile(path) as archive:
            assert len(archive.infolist()) == 129
        message = "ZIP64 footer"
    else:
        sparse_tar(path)
        with tarfile.open(path, "r:gz") as archive:
            member = archive.next()
            assert member.type == tarfile.GNUTYPE_SPARSE and member.isfile()
            assert member.size == 1
        message = "sparse member"
    original = path.read_bytes()
    _, invoke = target(kind, entrypoint, path)
    with pytest.raises((ValueError, RuntimeError), match=message):
        invoke()
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("extended", [False, True])
def test_old_gnu_sparse_refuses_before_tar_parser(tmp_path, monkeypatch, extended):
    path = tmp_path / "sparse.tar.gz"
    sparse_tar(path, extended)
    helper = normalize_sdist.archive_budget
    monkeypatch.setattr(
        tarfile, "open", lambda *a, **k: pytest.fail("TAR parser constructed")
    )
    with pytest.raises(ValueError, match="sparse member"), helper.open_tar(path):
        pytest.fail("Unsupported sparse format admitted")


def test_hidden_zip64_refuses_before_zip_parser(tmp_path, monkeypatch):
    path = tmp_path / "hidden.whl"
    zip64_polyglot(path)
    helper = normalize_wheel.archive_budget
    monkeypatch.setattr(
        zipfile, "ZipFile", lambda *a, **k: pytest.fail("ZIP parser constructed")
    )
    with pytest.raises(ValueError, match="ZIP64 footer"), helper.open_zip(path):
        pytest.fail("Alternate central directory admitted")


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_alternate_parser_cli_refuses_without_replacement(tmp_path, kind):
    path = tmp_path / ("bad.whl" if kind == "wheel" else "bad.tar.gz")
    zip64_polyglot(path) if kind == "wheel" else sparse_tar(path)
    original = path.read_bytes()
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts" / ("normalize_" + kind + ".py")),
            str(path),
            "--source-date-epoch",
            str(EPOCH),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert ("ZIP64 footer" if kind == "wheel" else "sparse member") in result.stderr
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]
