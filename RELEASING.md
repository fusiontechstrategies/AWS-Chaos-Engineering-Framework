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
python -m pip install -r requirements-build.txt
python -m build --no-isolation --wheel --sdist --outdir package-dist
python scripts\normalize_wheel.py --source-date-epoch $candidateEpoch package-dist\aws_chaos_engineering_framework-2.0.2-py3-none-any.whl
python scripts\normalize_sdist.py --source-date-epoch $candidateEpoch package-dist\aws_chaos_engineering_framework-2.0.2.tar.gz
python -m twine check package-dist\*
python scripts\verify_distribution.py package-dist
python scripts\prepare_release.py --version 2.0.2 --tag v2.0.2 --source-commit $candidateCommit --source-date-epoch $candidateEpoch --dist-directory package-dist --output-directory release-assets
```

The builder rejects mismatched versions or tags, malformed commit IDs, missing release notes, unpinned runtime dependencies, unexpected distributions, unsafe archive members, incomplete wheel records, existing output directories, and unexpected final assets.

## Draft and publication review

A `vX.Y.Z` tag must point to the approved GitHub-verified commit on protected `main`. The tag workflow rebuilds and compares every byte, attests every asset, and creates a non-prerelease draft with exactly the six approved files.

Before publication, download the draft assets into a clean directory, recompute checksums, verify provenance, inspect the archives and evidence, install both package formats independently, rerun the offline smoke commands, and confirm there are no unresolved security alerts. Publishing the draft remains a manual maintainer decision.
