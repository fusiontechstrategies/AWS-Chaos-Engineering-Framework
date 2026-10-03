# Testing

The final scan regression suite uses only synthetic resources. It covers both
irreversible approval gates, absence of implicit EC2 volume copies, a staggered
SQS rollback race across two real worker lifecycles, short and scoped target
redaction, control-character output, all eight report-disclosure combinations,
and actual post-verification package replacement and isolated-import probes.
These offline checks do not establish deployed AWS permissions or service behavior.

All repository and release tests are offline. They use deterministic fake AWS clients, synthetic identifiers, and generated package fixtures. Public CI must never require credentials or contact an AWS account.

`tests/test_latest_main_four_regressions.py` covers the approved static sdist
backend/member policy and generated metadata tampering without executing hostile
build hooks. Real botocore service models and Stubber validate S3 owner-bound
request shapes and 403 refusal without network calls. Deterministic threaded and
same-thread signal simulations exercise stop admission, latch activation,
in-flight completion and continued recovery. Redaction cases include complete
registered account-prefixed targets and longer unregistered ARN controls.
Actual SDK Stubber controls also cover effectful StepFunctions TestState,
ElastiCache TestFailover, CodeCommit TestRepositoryTriggers and STS
GetSessionToken before/after stop, without an owner, in plan/recovery mode, and
with tracked live admission. Reviewed safety/identity reads remain available
after stop; only reviewed EC2 inventory paginator operations can return delegates.

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
python -m pip install -r requirements-dev.txt
python -m ruff format --check .
python -m ruff check .
python -m pytest -q --cov=aws_chaos_framework --cov-report=term --cov-fail-under=50
python -m bandit -q -r aws_chaos_framework.py scripts
python -m pip_audit -r requirements.txt --progress-spinner off
python -m pip_audit -r requirements-dev.txt --progress-spinner off
python -m pip_audit -r requirements-build.txt --progress-spinner off
```
