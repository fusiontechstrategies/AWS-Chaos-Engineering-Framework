# Testing

All repository and release tests are offline. They use synthetic identifiers,
ordinary fake clients, actual botocore service models and Stubber, and small
regular package fixtures. Public CI must never require credentials or contact
an AWS account. Supported live simulations acquire authority through the actual
public orchestrator, reviewed configuration and confirmation token. Direct live
construction, premature/reentrant recovery and raw effectful calls assert early refusal; ordinary approved
handler dispatch and owned recovery retain positive coverage.

The final scan regression suite covers dual irreversible approval, absence of
implicit EC2 volume copies, failed recovery latching, sequential recovery timing,
scoped target redaction, control-character output and all eight report-disclosure
combinations. Two historical method names remain for their defensive invariants:
`test_actual_tag_verifier_replacement_cannot_survive_publish_digest_check` now
uses a small ordinary copied-payload byte mismatch and the real current digest
verifier; `test_publish_checker_is_isolated_from_tag_imports_and_binds_source_identity`
now uses the real current isolated CLI from an empty directory, a static workflow
launch assertion, and the original source-identity and exact member-set refusals.
These methods do not execute generated replacement helpers or hostile shadow
modules. Earlier runtime-v3 success is historical execution evidence and does not
clear this final methodology.

`tests/test_latest_main_four_regressions.py` retains exact static sdist
backend/member/metadata policy refusals without running selected helpers.
Actual botocore models validate owner-bound S3 reads, deletion and 403 refusal.
Deterministic mocked lifecycle ordering and same-thread signals exercise stop
admission, latch activation, in-flight completion and continued owned recovery.
The old repeated Barrier race keeps its test name but uses deterministic
lifecycle controls. Additional ordinary provider callbacks assert that public
recovery refuses during forward work and nested recovery; successful and
ambiguous-failure forward handlers then retain actual sequential owned recovery
and separate phase accounting. These controls do not reproduce a thread race. Effectful read-like raw operations assert admission refusal;
actual approved EC2 handler dispatch supplies the supported tracking counterpart.
Reviewed identity/safety reads and narrow EC2 inventory paginators remain usable
after stop. SDK protocol checks retain `hasattr`, `getattr` defaults, unknown
attributes and call-time unsupported-method refusal.

`tests/test_trusted_release_promotion.py` copies and builds the exact current
tracked corrected source. Its preserved historical import test names check the
real current verifier/helper origins and run the current isolated handoff CLI
from an empty directory. No tagged or shadow modules execute. Its decoder budget
case uses tiny valid regular TAR data and a small decode limit; the positive
six-asset handoff, actual identity/member/digest refusals and draft cleanup gates
remain. The final signed package gate separately binds the actual signed commit.
Historical old-HEAD build and shadow-module setup evidence does not clear these
current methods.

Archive tests retain their named defensive invariants using small valid regular
archives, deterministic small size/count limits and modeled decoder, member-type
and metadata failures. They do not construct corrupt decoder streams, link or
special-file archives, alternate-parser probes, source growth, shadow helpers or
exhaustion demonstrations. These controls establish exercised current admission
and refusal decisions. Native exploit, corrupt-stream, hostile-import, link and
race behavior is outside this evidence; deployed AWS permissions and service
behavior are not established.

## 2.0.3 release-readiness gate

The 2.0.3 candidate must pass:

- the complete framework regression suite on Python 3.10 through 3.14
- Python 3.12 platform tests on Windows and macOS
- plan-mode coverage for every advertised executable experiment with zero AWS writes
- live-path simulations using deterministic fake clients for rollback, conflict, alarm, identity, target, FIS, IAM, reporting, and API-model controls
- source compilation, Ruff formatting and linting, and Bandit analysis
- runtime, development, and build dependency audits
- CodeQL, Semgrep, Trivy, Gitleaks, and dependency review
- two independent normalized distribution builds with byte-identical release assets
- isolated wheel and source-distribution installation checks
- exact runtime version, help, and read-only experiment-catalog smoke checks
- SPDX, checksum, archive membership, and release-evidence validation

This evidence demonstrates exercised safeguards and known regression coverage. It does not authorize live testing, prove that every AWS service state is recoverable, or replace account-specific architecture and rollback review.

### Local candidate results

The candidate tree was validated on August 28, 2026, without AWS credentials or AWS network activity.

- Python 3.10.21, 3.12.10, and 3.14.7 each passed 101 tests plus 4 parameterized subtests.
- Coverage was 52.59% against the enforced 50% gate on each Python boundary.
- All 60 executable experiment modes passed deterministic plan-mode and safety-metadata coverage.
- Ruff formatting and linting, Bandit, bytecode compilation, and dependency consistency passed on all three Python versions.
- Runtime, development, and build dependency audits reported no known vulnerabilities at test time.
- Two Python 3.12 builds produced the same exact six release files byte for byte.
- Two Windows builds, a mounted WSL build, and a native Linux clone build produced the same six filenames and bytes after regular source-archive modes were canonicalized.
- Independent Python 3.10, 3.12, and 3.14 builds produced the same exact six release files byte for byte.
- Twine, archive safety, package metadata, exact source identity, wheel RECORD, SPDX, checksum, and release-evidence checks passed.
- The wheel and source distribution installed in separate clean environments, reported 2.0.3, exposed 79 catalog entries with exactly 60 executable modes, and contained runtime bytes identical to source.
- Actionlint, YAML parsing, markdownlint, relative-link checks, and repository ASCII-punctuation checks passed.
- Release payload scanning found no private local path, maintainer workstation name, or forbidden Unicode dash.

Independent hosted Linux, Windows, macOS, CodeQL, Semgrep, Trivy, dependency-review, and full-history secret-scanning gates must pass on the exact pull-request and protected-main commits before release approval.

## Local commands

```powershell
$env:AWS_EC2_METADATA_DISABLED = "true"
python -m pip install --require-hashes --only-binary :all: -r requirements-pip-lock.txt
python -m pip install --require-hashes --only-binary :all: -r requirements-dev-lock.txt -r requirements-build-lock.txt
python -m ruff format --check .
python -m ruff check .
python -m pytest -q --cov=aws_chaos_framework --cov-report=term --cov-fail-under=50
python -m bandit -q -r aws_chaos_framework.py scripts
python -m pip_audit -r requirements-runtime-lock.txt --require-hashes --disable-pip --progress-spinner off
python -m pip_audit -r requirements-dev-lock.txt --require-hashes --disable-pip --progress-spinner off
python -m pip_audit -r requirements-build-lock.txt --require-hashes --disable-pip --progress-spinner off
```
