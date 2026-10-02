# Release process

AWS Chaos Engineering Framework releases come from a reviewed, fully tested commit on protected `main`. The runtime, package metadata, changelog, release notes, tag, checksums, SBOM, and release evidence must identify the same stable version.

Tag creation and release publication are separate maintainer decisions. The tag workflow creates only a draft GitHub release. It has no publication command and no package-registry upload step.

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

A `vX.Y.Z` tag must point to the approved GitHub-verified commit on protected `main`. The tag workflow rebuilds and compares every byte, attests every asset, and creates a non-prerelease draft with exactly the six approved files.

Before publication, download the draft assets into a clean directory, recompute checksums, verify provenance, inspect the archives and evidence, install both package formats independently, rerun the offline smoke commands, and confirm there are no unresolved security alerts. Publishing the draft remains a manual maintainer decision.

## Separate PyPI publication

The manually dispatched `.github/workflows/publish.yml` workflow accepts an existing public, stable GitHub release tag. It checks the tagged commit and exact six-asset set, release hashes and evidence, distribution contents, and GitHub provenance before uploading only the verified wheel and source distribution. The upload job uses the protected `pypi` environment and a short-lived OpenID Connect credential. No PyPI API token is stored in the repository.

Before the first PyPI publication, recheck that the normalized project name is available, secure the PyPI maintainer account with two-factor authentication, register the exact GitHub repository, `publish.yml`, and `pypi` environment as a pending trusted publisher, require maintainer approval on the environment, and allowlist the pinned PyPA publishing Action. A pending publisher does not reserve a project name.

After separately deciding to publish the reviewed GitHub release on PyPI, dispatch `publish.yml` from protected `main` with the exact public release tag. Review the verification job before approving the `pypi` deployment. Confirm PyPI lists the same version and file hashes, install the exact version in a clean environment, and run offline smoke commands before announcing the registry package.
