# Changelog

All notable changes to this project are documented here.

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
