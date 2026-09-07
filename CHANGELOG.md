# Changelog

All notable changes to this project are documented here.

## 2.0.3 - 2026-08-28

### Fixed

- included the active versioned release notes and tag workflow in the source distribution so its bundled release-construction tests pass from an extracted package
- added an archive-membership regression that verifies both release inputs before any candidate is accepted
- canonicalized regular source-archive member modes so mounted and native build filesystems produce identical bytes

### Changed

- advanced the recovery candidate to 2.0.3 because the existing public `v2.0.2` tag remains fixed and its draft release was not published
- replaced the hard-coded current-version manifest entry with a generic release-notes rule so later patch versions inherit the same self-test contract

## 2.0.2 - 2026-08-28

### Added

- reproducible wheel, source archive, standalone script, SPDX SBOM, checksums, and release evidence
- tag-only release automation that creates a draft release for human review
- offline package validation on Linux, Windows, and macOS

### Changed

- pinned runtime, development, and build dependencies for auditable release inputs
- declared Botocore as a direct runtime dependency because the application imports it directly
- constrained supported Python versions to the tested 3.10 through 3.14 range

### Security

- release assembly now rejects unsafe archive paths and validates exact package contents
- distribution builds are normalized and compared byte for byte before release assets are accepted

## 2.0.1 - 2026-08-12

### Fixed

- initialized rollback metadata explicitly for every supported experiment path
- removed unnecessary test-double variable deletion flagged by CodeQL
- added a regression test for complete experiment safety metadata

## 2.0.0 - 2026-08-12

### Added

- guarded orchestration for existing AWS FIS experiment templates
- fail-closed account, partition, credential, alarm, target, and blast-radius controls
- exact live confirmation tokens and dual approval for irreversible actions
- tag-scoped VPC discovery and exact target allowlisting
- cooperative emergency stops and runtime safety monitoring
- mutation-attempt and rollback-attempt evidence
- atomic, privacy-conscious JSON reports
- CLI commands for sample configuration, validation, catalog inspection, and token display
- deterministic offline tests for every advertised executable experiment mode

### Changed

- plan mode is now the default and live mode is CLI-only
- automatic rollback reports failure when recovery cannot be verified
- resource-policy faults preserve existing policy statements and exempt the active break-glass principal
- unsupported or non-credible actions are explicitly gated
- logs redact credentials, ARNs, account IDs, and registered target identifiers

### Fixed

- AWS SDK service and request-model errors across AppStream, WAF, VPC routing, and other service extensions
- fail-open safety checks and missing-alarm handling
- IAM self-lockout paths involving the active role or access key
- suite failures that could previously be reported as successful
- unsafe report overwrite and non-atomic report output
