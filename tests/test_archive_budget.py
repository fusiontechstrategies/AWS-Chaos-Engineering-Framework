"""Current admission controls using regular archives and modeled decoder data.

Historical test names remain. Corruption, alternate parsers, links, hostile
helpers and source mutation are not reproduced by this methodology.
"""

import base64
import copy
import csv
import gzip
import hashlib
import io
import stat
import subprocess
import sys
import tarfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

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


def make_tar(path, value=b"synthetic source\n", count=1, pax=None):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for index in range(count):
            member = tarfile.TarInfo(f"synthetic-1.0/source{index}.py")
            member.size = len(value)
            member.pax_headers = pax or {}
            archive.addfile(member, io.BytesIO(value))
    # A regular gzip encoder emits the exact admitted header; no byte patching.
    with (
        path.open("wb") as output,
        gzip.GzipFile(
            filename="", fileobj=output, mode="wb", compresslevel=6, mtime=EPOCH
        ) as encoder,
    ):
        encoder.write(raw.getvalue())


def target(kind, entrypoint, path):
    module = normalize_wheel if kind == "wheel" else normalize_sdist
    if entrypoint == "normalizer":
        return module.archive_budget, lambda: getattr(module, "normalize_" + kind)(
            path, EPOCH
        )
    if entrypoint == "reader":
        return module.archive_budget, lambda: getattr(
            module, "read_values" if kind == "wheel" else "read_members"
        )(path)
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


def regular_fixture(tmp_path, kind, name="regular"):
    path = tmp_path / (name + (".whl" if kind == "wheel" else ".tar.gz"))
    (make_wheel if kind == "wheel" else make_tar)(path)
    return path


def unchanged(path, original):
    assert path.read_bytes() == original
    assert list(path.parent.iterdir()) == [path]


def refuse_parser(monkeypatch, helper, kind):
    original = helper.zipfile if kind == "wheel" else helper.tarfile
    view = SimpleNamespace(**vars(original))
    setattr(
        view,
        "ZipFile" if kind == "wheel" else "open",
        lambda *a, **k: pytest.fail("Archive parser reached before admission"),
    )
    monkeypatch.setattr(helper, "zipfile" if kind == "wheel" else "tarfile", view)


def model_zip_record(monkeypatch, helper, changes, *, end=False):
    unpack = helper.struct.unpack

    def decoded(format_, data):
        fields = list(unpack(format_, data))
        if format_ == ("<4s4H2IH" if end else "<4s6H3I5H2I"):
            for index, value in changes.items():
                fields[index] = value
        return tuple(fields)

    monkeypatch.setattr(helper, "struct", SimpleNamespace(unpack=decoded))


def model_zip64_footer(monkeypatch, helper, path):
    """Model the signature read, never an alternate ZIP byte representation."""
    original = helper.snapshot
    position = path.read_bytes().rfind(b"PK\x05\x06") - 20
    observed = []

    class FooterRead:
        def __init__(self, raw):
            self.raw = raw

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def read(self, count=-1):
            current = self.raw.tell()
            value = self.raw.read(count)
            if current == position and count == 4:
                observed.append(current)
                return b"PK\x06\x07"
            return value

    @contextmanager
    def captured(candidate):
        with original(candidate) as (raw, size):
            yield FooterRead(raw), size

    monkeypatch.setattr(helper, "snapshot", captured)
    return observed


def pax_record(key, value):
    body = key.encode() + b"=" + value.encode() + b"\n"
    length = len(body) + 2
    while length != len(str(length)) + 1 + len(body):
        length = len(str(length)) + 1 + len(body)
    return str(length).encode() + b" " + body


def modeled_member(size=0, type_=tarfile.REGTYPE):
    member = tarfile.TarInfo("synthetic-1.0/source.py")
    member.size, member.type = size, type_
    return member


def model_tar_records(monkeypatch, helper, path, records):
    """Real preflight decisions consume typed header/metadata read responses.

    Disk input and underlying decoded bytes are regular and unchanged. The
    modeled read view is never given to a native archive parser.
    """
    header = gzip.decompress(path.read_bytes())[:512]
    temporary = helper.tempfile.TemporaryFile
    state = {"record": None, "index": 0, "files": 0}
    observed = []

    class MetadataRead(io.BytesIO):
        def read(self, count=-1):
            if count == 512 and state["index"] < len(records):
                member, value = records[state["index"]]
                state["index"] += 1
                state["record"] = member
                self.pending = value
                self.seek(512, 1)
                observed.append(member.type)
                return header
            if getattr(self, "pending", None) is not None:
                value, self.pending = self.pending, None
                assert count == len(value)
                self.seek(count, 1)
                return value
            return super().read(count)

    def captured_file():
        state["files"] += 1
        return temporary() if state["files"] == 1 else MetadataRead()

    def decoded(_block, _encoding, _errors):
        assert state["record"] is not None
        return copy.copy(state["record"])

    view = SimpleNamespace(**vars(helper.tarfile))
    view.TarInfo = SimpleNamespace(frombuf=decoded)
    view.open = lambda *a, **k: pytest.fail("TAR parser reached before admission")
    monkeypatch.setattr(helper, "tarfile", view)
    monkeypatch.setattr(
        helper, "tempfile", SimpleNamespace(TemporaryFile=captured_file)
    )
    return observed


def model_alternate_metadata(monkeypatch, helper, path, kind):
    if kind == "wheel":
        observed = model_zip64_footer(monkeypatch, helper, path)
        refuse_parser(monkeypatch, helper, kind)
        return "ZIP64 footer", observed
    observed = model_tar_records(
        monkeypatch,
        helper,
        path,
        [(modeled_member(type_=tarfile.GNUTYPE_SPARSE), None)],
    )
    return "sparse member", observed


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize(
    "entrypoint", ["normalizer", "reader", "inventory", "verifier", "handoff"]
)
def test_high_ratio_native_archives_fail_every_admission_path(
    tmp_path, monkeypatch, kind, entrypoint
):
    path = regular_fixture(tmp_path, kind)
    original = path.read_bytes()
    helper, call = target(kind, entrypoint, path)
    monkeypatch.setattr(helper, "MAX_RATIO", 1)
    with pytest.raises((ValueError, RuntimeError), match="ratio"):
        call()
    unchanged(path, original)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("attack", ["compressed", "member", "aggregate", "count"])
def test_small_native_resource_limits_fail_without_replacing(
    tmp_path, monkeypatch, kind, attack
):
    path = tmp_path / ("regular.whl" if kind == "wheel" else "regular.tar.gz")
    value = bytes(range(16))
    make_wheel(path, value, {"second.py": value}) if kind == "wheel" else make_tar(
        path, value, count=3
    )
    original = path.read_bytes()
    helper, call = target(kind, "normalizer", path)
    constant, limit = {
        "compressed": ("MAX_ARCHIVE_BYTES", len(original) - 1),
        "member": ("MAX_MEMBER_BYTES", 15),
        "aggregate": ("MAX_EXPANDED_BYTES", 20),
        "count": ("MAX_MEMBERS", 2),
    }[attack]
    monkeypatch.setattr(helper, constant, limit)
    with pytest.raises((ValueError, RuntimeError), match="budget"):
        call()
    unchanged(path, original)


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
    path = regular_fixture(tmp_path, "wheel")
    original = path.read_bytes()
    helper = normalize_wheel.archive_budget
    if attack == "size":
        monkeypatch.setattr(helper, "MAX_MEMBER_BYTES", 8)
        model_zip_record(monkeypatch, helper, {9: 9})
    elif attack == "count":
        monkeypatch.setattr(helper, "MAX_MEMBERS", 2)
        model_zip_record(monkeypatch, helper, {3: 3, 4: 3}, end=True)
    elif attack == "metadata":
        monkeypatch.setattr(helper, "MAX_NAME_BYTES", 8)
        model_zip_record(monkeypatch, helper, {10: 9})
    else:
        model_zip_record(
            monkeypatch,
            helper,
            {
                "zip64": {9: 0xFFFFFFFF},
                "method": {4: zipfile.ZIP_LZMA},
                "strong_encryption": {3: 0x40},
                "patched_data": {3: 0x20},
            }[attack],
        )
    refuse_parser(monkeypatch, helper, "wheel")
    with pytest.raises(normalize_wheel.WheelNormalizationError):
        normalize_wheel.normalize_wheel(path, EPOCH)
    unchanged(path, original)


@pytest.mark.parametrize("attack", ["crc", "truncated"])
def test_zip_actual_malformed_stream_preserves_input(tmp_path, monkeypatch, attack):
    path = regular_fixture(tmp_path, "wheel")
    original = path.read_bytes()
    helper = normalize_wheel.archive_budget
    native = helper.zipfile.ZipFile
    error = (
        zipfile.BadZipFile("modeled checksum failure")
        if attack == "crc"
        else EOFError("modeled completion failure")
    )

    class ErrorRead(io.BytesIO):
        def read(self, _count=-1):
            raise error

    class DecodedArchive:
        def __init__(self, *args, **kwargs):
            self.archive = native(*args, **kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.archive.close()

        def infolist(self):
            return self.archive.infolist()

        def open(self, _member):
            return ErrorRead()

    view = SimpleNamespace(**vars(helper.zipfile))
    view.ZipFile = DecodedArchive
    monkeypatch.setattr(helper, "zipfile", view)
    with pytest.raises(
        normalize_wheel.WheelNormalizationError, match="malformed or unreadable"
    ) as raised:
        normalize_wheel.normalize_wheel(path, EPOCH)
    assert raised.value.__cause__ is error
    unchanged(path, original)


@pytest.mark.parametrize("size", [8 * 1024 * 1024 + 1, 2**70, -1])
def test_tar_declared_size_refuses_before_tar_parser(tmp_path, monkeypatch, size):
    path = regular_fixture(tmp_path, "sdist")
    original = path.read_bytes()
    model_tar_records(
        monkeypatch,
        normalize_sdist.archive_budget,
        path,
        [(modeled_member(size), None)],
    )
    with pytest.raises(normalize_sdist.SdistNormalizationError, match="size|budget"):
        normalize_sdist.normalize_sdist(path, EPOCH)
    unchanged(path, original)


@pytest.mark.parametrize(
    "attack", ["metadata", "pax_size", "pax_digits", "sparse", "chain"]
)
def test_pax_metadata_is_bounded_before_tarfile_parsing(tmp_path, monkeypatch, attack):
    path = regular_fixture(tmp_path, "sdist")
    original = path.read_bytes()
    helper = normalize_sdist.archive_budget
    value = pax_record("comment", "x")
    if attack == "metadata":
        monkeypatch.setattr(helper, "MAX_METADATA_BYTES", 8)
    elif attack == "pax_size":
        monkeypatch.setattr(helper, "MAX_MEMBER_BYTES", 8)
        value = pax_record("size", "9")
    elif attack == "pax_digits":
        value = pax_record("size", "12345678901")
    elif attack == "sparse":
        value = pax_record("GNU.sparse.size", "1")
    records = [(modeled_member(len(value), tarfile.XHDTYPE), value)] * (
        9 if attack == "chain" else 1
    )
    observed = model_tar_records(monkeypatch, helper, path, records)
    with pytest.raises(normalize_sdist.SdistNormalizationError):
        normalize_sdist.normalize_sdist(path, EPOCH)
    assert observed
    unchanged(path, original)


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
    path = regular_fixture(tmp_path, kind, "valid")
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
    for case in ("count", "mismatch"):
        case_root = tmp_path / case
        case_root.mkdir()
        path = regular_fixture(case_root, "sdist")
        original = path.read_bytes()
        with monkeypatch.context() as patch:
            helper = normalize_sdist.archive_budget
            if case == "count":
                patch.setattr(helper, "MAX_MEMBERS", 2)
                value = b"".join(
                    pax_record(f"comment{index}", "x") for index in range(3)
                )
            else:
                value = pax_record("size", "10")
            model_tar_records(
                patch,
                helper,
                path,
                [
                    (modeled_member(len(value), tarfile.XHDTYPE), value),
                    (modeled_member(9), None),
                ],
            )
            with pytest.raises(
                normalize_sdist.SdistNormalizationError, match="count|physical"
            ):
                normalize_sdist.normalize_sdist(path, EPOCH)
        unchanged(path, original)


def test_record_row_count_is_bounded_before_eager_csv_retention(tmp_path, monkeypatch):
    path = regular_fixture(tmp_path, "wheel", "rows")
    record = "synthetic-1.0.dist-info/RECORD"
    values = normalize_wheel.read_values(path)
    values[record] = b"".join(f"file{i},digest,1\n".encode() for i in range(3))
    for module in (normalize_wheel, verifier, prepare_release):
        monkeypatch.setattr(module.archive_budget, "MAX_MEMBERS", 2)
    for call in (
        lambda: normalize_wheel.validate_record(values, record),
        lambda: verifier.validate_record(values, record),
        lambda: prepare_release.validate_wheel_record(values),
    ):
        with pytest.raises((ValueError, RuntimeError), match="budget"):
            call()


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_parser_reads_captured_bytes_after_source_mutation(tmp_path, monkeypatch, kind):
    """Captured-handle identity is checked without modifying an input file."""
    path = regular_fixture(tmp_path, kind, "snapshot")
    original = path.read_bytes()
    module = normalize_wheel if kind == "wheel" else normalize_sdist
    helper = module.archive_budget
    function = "zip_preflight" if kind == "wheel" else "tar_preflight"
    previous = getattr(helper, function)
    admitted, observed = [], []

    def observe_preflight(raw, *args):
        admitted.append(raw)
        return previous(raw, *args)

    monkeypatch.setattr(helper, function, observe_preflight)
    native_module = helper.zipfile if kind == "wheel" else helper.tarfile
    parser = native_module.ZipFile if kind == "wheel" else native_module.open
    view = SimpleNamespace(**vars(native_module))

    def observe_parser(*args, **kwargs):
        raw = args[0] if kind == "wheel" else kwargs["fileobj"]
        assert raw is admitted[-1] and not isinstance(raw, (str, Path))
        observed.append(raw)
        return parser(*args, **kwargs)

    setattr(view, "ZipFile" if kind == "wheel" else "open", observe_parser)
    monkeypatch.setattr(helper, "zipfile" if kind == "wheel" else "tarfile", view)
    if kind == "wheel":
        assert module.read_values(path)["synthetic.py"] == b"synthetic source\n"
    else:
        assert module.read_members(path)[0][1] == b"synthetic source\n"
    assert admitted == observed
    unchanged(path, original)


def test_compressed_input_actual_growth_is_bounded_during_capture(
    tmp_path, monkeypatch
):
    """Tiny modeled reads exceed admitted size without growing a real file."""
    path = regular_fixture(tmp_path, "wheel", "growth")
    original = path.read_bytes()
    helper, previous_open, requested = normalize_wheel.archive_budget, Path.open, []

    class ModeledRead(io.BytesIO):
        def fileno(self):
            return 0

        def read(self, count=-1):
            requested.append(count)
            assert 0 < count <= 11
            return super().read(count)

    def open_reader(candidate, mode="r", *args, **kwargs):
        if candidate == path and mode == "rb":
            return ModeledRead(b"abcdefghijk")
        return previous_open(candidate, mode, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(helper, "MAX_ARCHIVE_BYTES", 10)
        view = SimpleNamespace(**vars(helper.os))
        view.fstat = lambda _fd: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644, st_size=8
        )
        patch.setattr(helper, "os", view)
        patch.setattr(Path, "open", open_reader)
        with pytest.raises(
            normalize_wheel.WheelNormalizationError, match="byte budget"
        ):
            normalize_wheel.normalize_wheel(path, EPOCH)
    assert requested == [11]
    unchanged(path, original)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("limit", [0, -1, True, 0.5])
def test_stricter_caller_budgets_are_never_treated_as_defaults(tmp_path, kind, limit):
    path = regular_fixture(tmp_path, kind, "limit")
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
    unchanged(path, original)


def current_cli_error(path, kind):
    """Only current trusted CLI, regular archive and invalid scalar epoch."""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts" / f"normalize_{kind}.py"),
            str(path),
            "--source-date-epoch",
            "-1",
        ],
        cwd=path.parent,
        capture_output=True,
        text=True,
        timeout=15,
    )
    expected = "outside wheel range" if kind == "wheel" else "negative"
    assert result.returncode == 1 and expected in result.stderr
    assert "Normalized " not in result.stdout


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_actual_cli_refuses_ratio_and_ignores_shadow_helper(
    tmp_path, monkeypatch, capsys, kind
):
    path = regular_fixture(tmp_path, kind)
    original = path.read_bytes()
    module = normalize_wheel if kind == "wheel" else normalize_sdist
    assert (
        Path(module.archive_budget.__file__).resolve()
        == ROOT / "scripts" / "archive_budget.py"
    )
    with monkeypatch.context() as patch:
        patch.setattr(module.archive_budget, "MAX_RATIO", 1)
        patch.setattr(
            sys, "argv", ["normalizer", str(path), "--source-date-epoch", str(EPOCH)]
        )
        with pytest.raises((ValueError, RuntimeError), match="ratio"):
            module.main()
    assert "Normalized " not in capsys.readouterr().out
    current_cli_error(path, kind)
    unchanged(path, original)


@pytest.mark.parametrize(
    "entrypoint", ["normalizer", "reader", "inventory", "verifier", "handoff"]
)
@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_alternate_parser_views_refuse_without_replacement(
    tmp_path, monkeypatch, kind, entrypoint
):
    path = regular_fixture(tmp_path, kind)
    original = path.read_bytes()
    helper, invoke = target(kind, entrypoint, path)
    message, observed = model_alternate_metadata(monkeypatch, helper, path, kind)
    with pytest.raises((ValueError, RuntimeError), match=message):
        invoke()
    assert observed
    unchanged(path, original)


@pytest.mark.parametrize("extended", [False, True])
def test_old_gnu_sparse_refuses_before_tar_parser(tmp_path, monkeypatch, extended):
    path = regular_fixture(tmp_path, "sdist")
    original = path.read_bytes()
    helper = normalize_sdist.archive_budget
    member = modeled_member(type_=tarfile.GNUTYPE_SPARSE)
    member.sparse = [] if extended else None
    observed = model_tar_records(monkeypatch, helper, path, [(member, None)])
    with pytest.raises(ValueError, match="sparse member"), helper.open_tar(path):
        pytest.fail("Unsupported sparse metadata admitted")
    assert observed == [tarfile.GNUTYPE_SPARSE]
    unchanged(path, original)


def test_hidden_zip64_refuses_before_zip_parser(tmp_path, monkeypatch):
    path = regular_fixture(tmp_path, "wheel")
    original = path.read_bytes()
    helper = normalize_wheel.archive_budget
    observed = model_zip64_footer(monkeypatch, helper, path)
    refuse_parser(monkeypatch, helper, "wheel")
    with pytest.raises(ValueError, match="ZIP64 footer"), helper.open_zip(path):
        pytest.fail("Alternate central-directory metadata admitted")
    assert observed
    unchanged(path, original)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_alternate_parser_cli_refuses_without_replacement(
    tmp_path, monkeypatch, capsys, kind
):
    path = regular_fixture(tmp_path, kind)
    original = path.read_bytes()
    module = normalize_wheel if kind == "wheel" else normalize_sdist
    message, observed = model_alternate_metadata(
        monkeypatch, module.archive_budget, path, kind
    )
    monkeypatch.setattr(
        sys, "argv", ["normalizer", str(path), "--source-date-epoch", str(EPOCH)]
    )
    with pytest.raises((ValueError, RuntimeError), match=message):
        module.main()
    assert observed and "Normalized " not in capsys.readouterr().out
    current_cli_error(path, kind)
    unchanged(path, original)
