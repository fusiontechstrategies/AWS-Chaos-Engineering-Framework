# Changelog

## Unreleased security follow-ups

### Planning-only Kinesis retention and SES deletion, terminal log redaction and release-asset admission

- Withdraw live support for `kinesis_retention_modify` and
  `ses_configuration_set_delete`. `DecreaseStreamRetentionPeriod` and
  `DeleteConfigurationSet` address a reusable name and accept no stable
  generation, provider-enforced condition or exclusive lease, so another
  same-account principal could change or replace the stream or configuration
  set after approval and the pre-read and the irreversible write would land on
  that new state. Both types now report `live_supported: false` (`LIVE no`);
  live tokens, live suites, execution grants, direct live construction and the
  `kinesis.decrease_stream_retention_period` and
  `ses.delete_configuration_set` SDK requests are refused. Dry-run plans are
  unchanged. The Kinesis `StreamARN` check is retained in the live branch as
  defence in depth. Compatibility: existing live configurations for these two
  types can still produce plans but can no longer obtain a live token.
- Keep exact-value log redaction active until terminal logging finishes. Run,
  worker and handler scopes now attach an immutable snapshot of their
  protected values to any exception that escapes them. The CLI logs a
  propagated error, its debug traceback and chained causes under that snapshot
  plus the identifiers in the loaded configuration, and the suite loop logs a
  failed worker under the worker's snapshot, so a missing-alarm violation or an
  AWS error naming a target no longer reaches the console unredacted.
- Make privacy-safe logging part of the library contract. Every public handler
  call, plan or live, direct or orchestrated, and `run_rollback()` install a
  scope from all targets bound by the experiment configuration and the call
  arguments. Targets supplied only as handler arguments are kept in the
  instance's append-only protected-value set, so later recovery, rollback, run
  and metrics calls on that instance (and their errors) stay redacted; other
  instances never inherit the set. The `aws_chaos_framework` logger carries a filter that renders and
  redacts each record (message, traceback and stack information) in the
  caller's context before any handler runs, so an embedding application with a
  basic `StreamHandler` receives no raw identifiers and does not need the CLI.
  Compatibility: framework log records reach handlers with `args` empty and
  `exc_info` cleared; the redacted traceback is in `exc_text`, with control
  characters escaped onto one line.
- Add `scripts/release_asset_admission.py`, a trusted helper for public release
  assets. `verify` accepts only the six fixed release basenames, never joins a
  checksum or evidence name to a path, rejects absolute, separated, traversing,
  control-character, duplicate and unexpected names, admits every file's type
  and size before opening any, opens only regular non-symlink children (beneath
  a directory descriptor where the platform supports it), hashes with bounded
  streaming and refuses files that change while they are read. `download`
  admits release metadata by per-file and aggregate size before any asset is
  requested, then streams each asset under its declared size and a deadline
  into a new private file while hashing it. `publish_payload.py capture` now
  bounds the evidence read before JSON parsing, refuses duplicate evidence
  records, and every package digest is size-bounded.
- Route every public release download and manifest check in
  `.github/workflows/publish.yml` through the helper (owner-approved workflow
  change). The verify job replaces `gh release download`,
  `sha256sum --check` and its inline evidence check with
  `release_asset_admission.py download` into a new `release-assets` directory
  and `release_asset_admission.py verify` with the dispatched tag, the
  verified source commit and the tagged standalone source, before
  distribution checks, provenance and payload capture. The protected `pypi`
  job replaces its `gh release download` with
  `release_asset_admission.py download --only release-evidence.json` into a
  new `trusted-release` directory, so the complete release metadata is still
  size-admitted before the evidence is fetched and before attestation. Both
  helpers run from the trusted workflow commit in Python isolated mode.
  Triggers, permissions, the environment, job structure, action pins and the
  provenance, attestation and OIDC checks are unchanged.

### Canonical AWS endpoint origin and source-bound wheel metadata

- Bind every SDK client to a canonical AWS origin. Live admission trusted
  `GetCallerIdentity` from a client whose endpoint could come from the selected
  profile or the environment, so a host-trusted responder could claim the
  configured account while the pinned credentials authorized another one.
  Framework clients (the pre-role STS client, the pinned STS client and every
  service client, in live and plan mode) come from one factory, and each
  session is hardened before any credential is resolved, so botocore's own
  credential-provider clients (assume-role and web-identity STS, SSO
  `GetRoleCredentials`, SSO-OIDC token refresh and login) are bound the same
  way for their actual service and region. Every client sets
  `ignore_configured_endpoint_urls`, pins dual-stack, S3 accelerate and
  account-ID-based endpoints off, and pins the profile or environment
  `use_fips_endpoint` choice. Each request is checked before it is sent: its
  host must be exactly one canonical host that botocore's packaged partition
  data and endpoint ruleset designate for the partition, service, region and
  FIPS choice, and any explicit `Host` header must name that same host. Hosts
  must lie under the partition's packaged `dnsSuffix` or a reviewed
  per-service domain; the only reachable service whose packaged rules need one
  is AWS Sign-In (login token refresh), admitted exactly as
  `signin.aws.amazon.com`, `signin.amazonaws.cn`,
  `signin.amazonaws-us-gov.com` and `signin-fips.amazonaws-us-gov.com`.
  Customer data paths (`AWS_DATA_PATH`, `~/.aws/models`) are never consulted
  for that decision. Unknown regions, partitions or services, and FIPS
  requests a ruleset cannot satisfy, fail closed. Response-owner checks are
  unchanged. The check runs at the client's generic `before-send` stage;
  in-process hooks registered later are trusted code outside this boundary.
- Live runs apply an explicit address policy to the IMDS and container
  credential transports, which are plain HTTP outside the SDK client stack: a
  configured IMDS endpoint must be botocore's default (`169.254.169.254` or
  `[fd00:ec2::254]`), and a container credential URL must target
  `169.254.170.2`, `169.254.170.23`, `fd00:ec2::23` or loopback, without user
  information. Other values fail live initialization before any credential
  request.
- Compatibility: profile `endpoint_url`, `services` sections and
  `AWS_ENDPOINT_URL[_<SERVICE>]` are now ignored rather than honored, for
  credential providers as well as service calls, so this tool can no longer be
  pointed at local emulators or endpoint-specific `vpce-...` DNS names
  (interface endpoints with private DNS keep the canonical names and still
  work). Dual-stack, accelerate and account-ID endpoint settings no longer
  apply. A customer endpoint ruleset that redirects a service makes that
  service fail closed. Live runs refuse a custom IMDS endpoint and HTTPS
  container credential URLs on arbitrary hosts, which botocore itself would
  accept. A session must be hardened before credentials are resolved from it;
  library callers that pass their own boto3 session to `pin_session_credentials`
  must call `harden_session_origin` first. China endpoints are bound
  canonically, but live China admission remains refused by the existing
  partition checks.
- Source-bind every admitted wheel member before protected promotion. The
  verifier previously checked RECORD self-consistency, the runtime module and
  selected metadata fields, so a candidate could change other `METADATA`
  fields, `WHEEL`, `top_level.txt` or the bundled license, recompute RECORD and
  obtain protected provenance. The exact source-derived metadata check now
  applies to the wheel `METADATA`; `WHEEL` must name the pinned setuptools
  backend, purelib root and `py3-none-any` tag; `top_level.txt`,
  `entry_points.txt` and `licenses/LICENSE` must equal source-derived bytes; and
  RECORD must be the canonical normalized manifest. Generated sdist members
  (both `PKG-INFO` files, `setup.cfg` and the egg-info files) are now compared
  as raw bytes with their source-derived values, so carriage-return or other
  line-ending variants are refused rather than normalized away. Workflows are
  unchanged; `prepare_release.py` and the protected handoff already run this
  verifier.

### Planning-only SQS purge and RDS reboot, failover and retention

- Withdraw live support for `sqs_queue_purge`. `PurgeQueue` deletes whatever the
  queue holds when AWS processes it and cannot be conditioned on an exact,
  immutable message set, so the approved blast radius could not bound the
  messages destroyed.
- Withdraw live support for `rds_failover`, `rds_reboot` and
  `rds_backup_retention_modify`. AWS offers no conditional generation or
  exclusive lease for these requests, so a write could activate changes queued
  after admission, and failover could restart cluster members outside the
  approved target count. The queued-change and cluster-member checks still run
  in plan mode. The response-ARN and transition-completion checks are retained
  but apply only to live dispatch, which is now refused, so a successful plan
  does not establish them.
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
- Install routine CI tooling only from reviewed hash locks with
  `--require-hashes --only-binary :all:`. A hashed `requirements-pip-lock.txt`
  replaces the runtime `pip install --upgrade pip`; the new complete,
  cross-platform `requirements-dev-lock.txt` is installed with the release
  `requirements-build-lock.txt`. Smoke environments install the hashed runtime
  or build lock before adding the local wheel or sdist with `--no-deps`, and
  `pip-audit` audits the hashed locks with `--disable-pip` instead of resolving
  unhashed requirements. The sandboxed candidate runtime also installs its
  hashed runtime lock wheel-only, as do the three hash-locked installs in the
  tag-triggered release workflow. The workflow regression tests enforce this
  contract for every lock install, reject unreviewed installer lines and pin
  the exact bytes of both workflow files to a reviewed digest, so any workflow
  change (including action bumps) must be reviewed and the digest updated.

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
