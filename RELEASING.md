# Release process

AWS Chaos Engineering Framework releases come from a reviewed, fully tested commit on protected `main`. The runtime, package metadata, changelog, release notes, tag, checksums, SBOM, and release evidence must identify the same stable version.

Tag creation and release publication are separate maintainer decisions. The tag workflow builds a read-only candidate. A separate protected-main controller verifies that candidate and, after the required release-environment review, attests it and creates a draft. Neither workflow publishes a release or uploads to a package registry.

## Exact asset contract

For version `X.Y.Z`, the release contains exactly:

1. `AWS-Chaos-Engineering-Framework-vX.Y.Z.py`
2. `aws_chaos_engineering_framework-X.Y.Z-py3-none-any.whl`
3. `aws_chaos_engineering_framework-X.Y.Z.tar.gz`
4. `AWS-Chaos-Engineering-Framework-vX.Y.Z.spdx.json`
5. `SHA256SUMS.txt`
6. `release-evidence.json`

The standalone asset is byte-identical to `aws_chaos_framework.py` in the tagged commit. The wheel and source distribution use canonical metadata, archive ordering, timestamps, ownership, permissions, and line endings. The SPDX 2.3 document lists the exact pinned direct runtime dependencies. Release evidence binds every asset and archive member to the source commit.

Existing release assets are never replaced.

## Candidate gate

1. Start from current protected `main`.
2. Confirm `pyproject.toml`, `__version__`, the changelog, and versioned release notes agree.
3. Run every offline test on supported Python versions and the Windows and macOS platform gates.
4. Run Ruff, Bandit, dependency audits, CodeQL, Semgrep, Trivy, Gitleaks, and dependency review.
5. Build and normalize the wheel and source distribution twice from the same commit timestamp.
6. Require the complete six-asset result to be byte-identical across both builds.
7. Install the wheel and source distribution in separate clean environments.
8. Exercise `--version`, `--help`, and the read-only catalog command from each installation.
9. Inspect the SBOM, checksums, archive membership, and release evidence.

The release gate is offline. It must set `AWS_EC2_METADATA_DISABLED=true` and must not use AWS credentials or contact an AWS account.

## Candidate commands

Use new empty output directories and the exact 40-character candidate commit:

```powershell
$candidateCommit = git rev-parse HEAD
$candidateEpoch = git show -s --format=%ct HEAD
$env:SOURCE_DATE_EPOCH = $candidateEpoch
$env:AWS_EC2_METADATA_DISABLED = "true"
python -m pip install --require-hashes -r requirements-build-lock.txt
python -m build --no-isolation --wheel --sdist --outdir package-dist
python scripts\normalize_wheel.py --source-date-epoch $candidateEpoch package-dist\aws_chaos_engineering_framework-2.0.4-py3-none-any.whl
python scripts\normalize_sdist.py --source-date-epoch $candidateEpoch package-dist\aws_chaos_engineering_framework-2.0.4.tar.gz
python -m twine check package-dist\*
python scripts\verify_distribution.py package-dist
python scripts\prepare_release.py --version 2.0.4 --tag v2.0.4 --source-commit $candidateCommit --source-date-epoch $candidateEpoch --dist-directory package-dist --output-directory release-assets
```

The builder rejects mismatched versions or tags, malformed commit IDs, missing release notes, unpinned runtime dependencies, unexpected distributions, unsafe archive members, incomplete wheel records, existing output directories, and unexpected final assets.

## Draft and publication review

A `vX.Y.Z` tag must point to the approved GitHub-verified commit on protected `main`. The tag workflow rebuilds and compares every byte with read-only permissions. The default-branch `release-promotion.yml` controller authenticates the producer run, signed source commit, protected-main verifier, immutable artifact ID, and exact six-asset digest map. It reconstructs the release with trusted-main helpers and reads tagged files only as data. Both privileged jobs repeat this verification after `release` environment approval; the draft job downloads and compares the remote asset bytes too. All Python verification runs in isolated mode from the trusted checkout, including the final draft state check.

Before publication, download the draft assets into a clean directory, recompute checksums, verify provenance, inspect the archives and evidence, install both package formats independently, rerun the offline smoke commands, and confirm there are no unresolved security alerts. Publishing the draft remains a manual maintainer decision.

## Separate PyPI publication

The manually dispatched `.github/workflows/publish.yml` workflow accepts an existing public, stable GitHub release tag. It checks the tagged commit and exact six-asset set, release hashes and evidence, distribution contents, and GitHub provenance before uploading only the verified wheel and source distribution. The upload job uses the protected `pypi` environment and a short-lived OpenID Connect credential. No PyPI API token is stored in the repository.

Before the first PyPI publication, recheck that the normalized project name is available, secure the PyPI maintainer account with two-factor authentication, register the exact GitHub repository, `publish.yml`, and `pypi` environment as a pending trusted publisher, require maintainer approval on the environment, and allowlist the pinned PyPA publishing Action. A pending publisher does not reserve a project name.

After separately deciding to publish the reviewed GitHub release on PyPI, dispatch `publish.yml` from protected `main` with the exact public release tag. Review the verification job before approving the `pypi` deployment. Confirm PyPI lists the same version and file hashes, install the exact version in a clean environment, and run offline smoke commands before announcing the registry package.

## External release controls

The `release` environment accepts only the protected `main` branch and requires the account owner to review privileged jobs. Version-tag creation is restricted to that owner. A separate no-bypass ruleset prevents subsequent version-tag updates and deletion. These controls are part of the trust boundary; trusted repository administrators can change settings and must review those changes. No approval is implied by a successful candidate build.

The repository currently has one write-capable account: its trusted owner.
Outside contributions use forks. GitHub release-management and historical-run
rerun rights accompany repository write access and are not restricted by an
environment gate. Adding a write-capable collaborator therefore requires a new
authority review or a role that excludes release management and unsafe reruns.
Historical version tags retain their historical workflow definitions; the new
controller does not retroactively rewrite them. The owner remains trusted for
settings, draft editing, publication, and historical rerun decisions. Main
requires signed commits, the configured CI gates, conversation resolution, and
linear history; force pushes and deletion are prohibited. Environment review
is a single-owner decision, not a two-person control.

The controller binds the producer's authenticated triggering tag to the
reconstructed version and examines all artifact pages. Trusted helpers load
their verification dependencies by exact sibling path. Failed verification or
partial upload attempts remove only the new draft's returned release ID. If
creation returns no trustworthy ID or cleanup itself fails, the workflow fails
and the owner must inspect drafts; it never guesses an existing release by tag
or deletes a tag. No failed verification authorizes publication.

## PyPI dispatch trust boundary

The external `pypi` environment permits exactly the `main` branch, not tags or
wildcards, requires the repository owner to approve, and disables administrator
bypass. These restrictions are external to branch-selected YAML, so a modified
branch workflow cannot grant itself the deployment identity. Both jobs reject
non-main dispatches. Verification tools come from the exact workflow commit,
whose GitHub signature and protected-main ancestry are checked. Each job reads
and validates the current environment policy, owner reviewer, protected-main CI
status policy and workflow signature before its work. Read permissions are
limited to contents and Actions; no administration token is added to the workflow.
Full signature enforcement, CI, no-force-push and no-deletion branch settings
also require maintainer audit because the job token cannot read administrative
branch-protection details. Settings-changing administrators remain trusted.

PyPI must register exactly this repository, `publish.yml`, and `pypi` environment.
The prior successful trusted publication is historical identity evidence, not a
fresh inspection of the PyPI maintainer account. Recheck current registration
before authorizing any future publication; code changes and successful CI do not
authorize a dispatch or prove that external PyPI account state is unchanged.
