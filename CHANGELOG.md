# Changelog

## Unreleased security follow-ups

### Planning-only SQS purge and RDS reboot, failover and retention

- Withdraw live support for `sqs_queue_purge`. `PurgeQueue` deletes whatever the
  queue holds when AWS processes it and cannot be conditioned on an exact,
  immutable message set, so the approved blast radius could not bound the
  messages destroyed.
- Withdraw live support for `rds_failover`, `rds_reboot` and
  `rds_backup_retention_modify`. AWS offers no conditional generation or
  exclusive lease for these requests, so a write could activate changes queued
  after admission, and failover could restart cluster members outside the
  approved target count. The queued-change, cluster-member and ARN checks
  remain in place and still run in plan mode.
- All four types now report `live_supported: false` (`LIVE no` in
  `--list-experiments`). Live tokens, live suites, execution grants, historical
  recovery and the `PurgeQueue`, `RebootDBInstance`, `FailoverDBCluster` and
  `ModifyDBInstance` SDK requests are refused; dry-run plans are unchanged. This
  is a compatibility change: existing live configurations for these types can
  still produce plans but can no longer obtain a live token.

- Pin live sessions to one verified credential snapshot, keeping the selected
  profile's non-credential configuration, so a refreshable profile cannot later
  sign as another account, and require name-only RDS and Kinesis
  reads to return the reviewed account-bearing ARN before mutation.
- Make S3 lifecycle expiration planning only (no conditional lifecycle revision);
  plans require a canonical nonempty `prefix`, keep unrelated rules, report a
  privacy-filtered `lifecycle_plan` and reject any key outside the lifecycle
  schema before token generation.
- Require `original_nacl_id` for `vpc_subnet_acl_modify`; it is bound into the
  token, allowlist, execution grant and `--vpc-id` scope, and both the forward
  handler and recovery refuse a different observed or recorded original NACL.
- Name FIS template targets by ordinal in guardrail diagnostics, and record ECS
  task stops one task at a time so a partial failure keeps confirmed evidence.
- Require irreversible approval for RDS retention and S3 lifecycle changes and
  refuse claims that deleted data was recovered.
- Remove unapproved implicit EC2 termination snapshots and serialize complete live
  experiment lifecycles, including recovery.
- Remove implicit EBS detach snapshots, block later live execution after any
  unverified recovery, and reject disabled live automatic recovery.
- Scope exact target redaction per run, escape console controls, and keep report
  identity filtering independent of resource disclosure.
- Verify distributions with trusted workflow-source tools and bind the final
  publish payload to a digest manifest rechecked in the protected publish job.
- Authenticate PyPI uploads inside the protected `pypi` job against public
  release evidence and GitHub provenance from the protected
  `release-promotion.yml` signer, so the lower-privilege verify job can no
  longer forge a self-consistent package and manifest handoff.
- Require live targets under `--vpc-id` to belong to the discovered, exactly
  tagged inventory of that VPC, verify each pre-mutation response, and refuse
  VPC-addressable types whose membership cannot be verified.
- Bind live S3 lifecycle writes to the reviewed region with an owner-bound
  bucket location check and refuse SDK region redirects for S3 writes.
- Bind WAF and Lambda recovery to the LockToken or RevisionId issued by the
  forward update itself. A different or later generation is refused even with
  identical values. Recovery is single use and revokes the execution grant
  after it ends.
- Refuse WAF rule, rate-limit and IP-set requests already satisfied by current
  state before dispatch, without ownership or a recovery claim.

### Queued-change, unreadable-state and plan-parity follow-ups

- Refuse RDS backup-retention changes (`ApplyImmediately`), reboots and cluster
  failovers unless the target is available with no pending modifications and
  every DB parameter group (and option group, or cluster-member parameter
  group) is `in-sync`; the reason is recorded as `queued_change_refusal`.
- Check the parent cluster of a clustered-instance reboot (availability,
  pending modifications and the member's cluster parameter group), and require
  every failover member instance to pass the instance checks; unreadable
  clusters or members are refused.
- Refuse Lambda environment experiments and their recovery when
  `Environment.Error` is present or `Environment` lacks `Variables`; unreadable
  variables are never treated as an empty environment, and a restored empty map
  verifies even when `Environment` is omitted.
- Compute WAF IP-set ownership against canonical CIDRs, write only canonically
  new addresses and remove only owned canonical entries during recovery.
- Apply every structural FIS guardrail in plan mode; only the live alarm-state
  read is skipped, so a plan reports the violations live checks would raise.
- Refuse execution grants for experiment types without a reviewed live
  implementation, deny their S3 encryption, Kinesis, ECS and CloudFront writes
  at the SDK proxy, and delete a Directory Service trust only when exactly the approved
  `TrustId` is returned.

All notable changes to this project are documented here.

## 2.0.4 - 2026-09-29

### Corrected

- Removed the unsupported Beta development-status classifier from package metadata. Runtime behavior and live-execution safety gates are unchanged from 2.0.3.

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
