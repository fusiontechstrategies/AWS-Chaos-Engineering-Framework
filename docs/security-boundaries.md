# Live experiment security boundaries

Live execution requires exact authorization for both parent resources and child
selectors. WAF rule names, shard IDs, repository image digests, route
destinations, and S3 prefixes must appear in `safety.target_allowlist` alongside
their parent resources. Unknown nested selectors fail closed.

ARN-valued targets must match the reviewed AWS partition, service, account and
region before offline approval and live dispatch. IAM and CloudFront use explicit
global-region exceptions; AWS-managed IAM policy ARNs are allowed only in policy
fields. S3 bucket ARNs omit region and account and retain the independent
ExpectedBucketOwner check. Direct SDK mutations and recovery enforce the same
identity boundary; a matching literal allowlist entry cannot approve a foreign
ARN. Cross-account target resources are unsupported.

The mutation proxy checks the actual SDK client's region metadata as well as
literal ARNs. IAM uses its partition-specific global endpoint; CloudFront uses
the commercial global endpoint. A global ARN exception does not establish
service availability in GovCloud. AWS documents that [CloudFront operates in
the commercial partition](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/setting-up-cloudfront.html).
WAF `CLOUDFRONT` scope requires a separately reviewed `us-east-1` configuration.
Nested request inspection refuses cycles, repeated containers, depths above 16
and traversals above 20,000 nodes before recording a mutation attempt. Request
string values and serialized protected requests each have a 1 MiB aggregate
budget. Reviewed cross-service references are classified by operation and exact
SDK field path. ELB Cognito authentication references must match the same owner,
partition and region before a fault is introduced or recovery is attempted.
Lambda environment variable values are application strings, not target ARNs;
the function identity and execution-role ARN still require identity admission.
SNS Firehose subscriptions admit the IAM role only in the documented
`Attributes.SubscriptionRoleArn` field for that protocol. The role and endpoint
must match the reviewed owner and partition. The role's final name and optional
path must also satisfy the [IAM role name and path constraints](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html),
including their separate 64-character and 512-character limits. Before deleting a subscription, its
saved topic, protocol, endpoint and mandatory Firehose role are checked against
the same admission rules and copied for attempted recreation. Deletion remains
an irreversible operation: recreation does not prove restoration of the original
subscription ARN, delivery history or every subscription attribute. See the
[SNS subscription API](https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html).

Every AWS mutation requires immutable execution authority issued by the confirmed
public orchestrator after caller identity, suite token, target scope, safety and
irreversible approvals. Direct experiment construction is planning only. A live
handler must match the approved type and complete argument list, and consumes its
authority once. Mutation dispatch is admitted only inside that handler's current
thread or its `run_rollback()` recovery envelope after the owned forward handler
has completely returned. Each live object holds one lifecycle lock through the full
handler and recovery envelope. Premature, overlapping or reentrant recovery is
refused. Recovery safety exemptions, stop-barrier decisions and write accounting
are derived from the current thread's admitted authority phase. The legacy
`_in_rollback` flag is diagnostic and grants no exemption or authority.
Raw client mutations and direct calls to `rollback()` cannot acquire this authority.
Rejected live handlers return failed result data; constructors and raw proxy
mutations raise `SafetyViolation`. An approved object whose configuration or
reviewed identity changes loses mutation authority.

KMS grant revocation, ECR digest deletion, CloudFront invalidation and WAF IP-set
updates additionally require a one-use dispatch context created by their public
experiment handlers. It binds a detached canonical request to the exact reviewed targets
and selectors before the proxy records or sends it. Raw calls to those four SDK
operations are refused, even with an allowlisted parent or during recovery.
WAF recovery can remove only confirmed owned additions, and only while the IP set
remains at the generation its forward update created. These internal controls protect the supported APIs; they are
not a Python sandbox against code that changes private framework objects.

Live KMS grant revocation requires the complete immutable key ARN in both the
configuration and exact allowlist, together with the grant ID. Bare key IDs and
aliases are planning only. The grant lookup must return exactly that key ARN and
grant ID. This follows the [KMS key identity contract](https://docs.aws.amazon.com/kms/latest/APIReference/API_RevokeGrant.html)
without resolving a movable alias before deletion.

ECR image deletion is planning only. `BatchDeleteImage` by digest also removes
every tag alias attached to that digest, including aliases attached after review,
and the request accepts no condition over the alias set, so no approval can bind
what is destroyed. No approval combination issues a live token, and live suites,
execution grants and the `BatchDeleteImage` SDK request are refused. Plans still
read the reviewed repository and digests. The digest controls below are retained
as defence in depth and run only on live dispatch, which is refused.
Live ECR image deletion would require unique explicit `imageDigest` values in the
reviewed configuration and target allowlist. Tag selectors remain planning only.
No live handler resolves a tag and then deletes its current occupant. Digest
deletion removes the image and all its tags, so operators must review that
distinct operation deliberately. The SDK proxy binds the registry account and
rejects tags even for direct library calls.
Both the describe and delete requests specify the reviewed registry account.
Describe responses must identify exactly the approved repository, registry and
digests. Delete responses must prove exactly the approved digest set with no
reported failures. A digest can have several returned tag entries, as the
[ECR API example](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchDeleteImage.html)
shows. Missing or foreign response evidence is a failed result even if AWS may
already have performed the irreversible deletion; mutation records are retained.

Throttle experiments only reduce existing capacity. EFS throughput changes require
an existing provisioned mode and a smaller positive provisioned throughput. Lambda
functions without reserved concurrency can only be paused at zero. ECS desired
count must decrease. Scale-up is not supported by these experiments.

FIS template inspection is read-only. Live starts and live confirmation tokens
are disabled because StartExperiment takes a mutable template ID with no
conditional version or digest. A second read does not close the final-read/start
race, and configuration assertions do not prove an immutable IAM/SCP boundary.
Re-enabling this capability requires an enforceable, independently verified
immutable-template trust boundary or conditional AWS start support. Recovery
authority is unavailable through the current public API for already-running
experiments from older versions. Those experiments require operator reconciliation
through separately approved AWS procedures. The six legacy EC2 SSM shell fault
handlers are disabled in both modes; they no longer generate or dispatch shell
programs.

Emergency stop is shared by every controller, including controllers created
after a stop. A request immediately blocks new forward-call admission and wakes
forward waits. Stop activation and forward SDK calls share a dispatch barrier:
the latch activates after an already accepted call returns, and no forward SDK
call begins after that activation. A request arriving after the final admission
check can precede the start of that accepted call; the latch remains inactive
until it returns. Signals on the dispatching thread defer activation to that
same return boundary. SDK requests are not cancelled, and stop activation may
wait for their configured timeouts and retries. Only supported recovery writes remain available.
Unknown FIS start outcomes require operator reconciliation.
Terminal FIS status alone does not prove resource recovery. ECS recovery requires
restored running capacity, no pending tasks or failed deployments, and one stable
deployment. Failed recovery remains a failed result.

Supported rollback restores verified pre-state rather than supplied YAML. WAF
rule/rate rollback requires a successful forward return and uniquely verified
post-state, patches only the selected field, refuses conflicting changes and
writes only under the confirmed post-forward LockToken. A later generation, even
with the identical value, is refused. Ambiguous writes require manual
reconciliation. Requests already satisfied by current WAF state fail before any
write and claim no ownership or recovery.
ELB recovery retains port and availability-zone identity. NACL recovery resolves
the subnet's current association ID. Security-group ingress removal and recovery
are planning only because their APIs cannot prove conditional write ownership.

Release verification rejects unexpected archive members, including startup hooks,
unreviewed build scripts, native binaries, and executable wheel data directories.
Source files must match reviewed repository contents. The independently trusted
verifier fixes the source member list, exact static setuptools backend and build
requirements, manifest, module and console entry point. Selected source cannot
add `setup.py`, custom backend paths, setuptools hooks or dynamic metadata.
Generated source metadata is reconstructed from static project data; the
artifact's `SOURCES.txt` never defines accepted members. Source archives require
regular files with mode 0644 and directories with mode 0755. Adding a new packaged
script or changing build policy requires a trusted verifier review.
Install release build tools
with `--require-hashes` using `requirements-build-lock.txt`. Regenerate this lock
with `uv pip compile requirements-build.txt --generate-hashes --universal` when
updating build tools, then review the changes before release.

Routine CI installs Python tooling only from reviewed hash locks with
`--require-hashes --only-binary :all:`; pip itself is installed only as a
reviewed hashed pin, never as an unpinned upgrade. The release workflow's
build and runtime lock installs are likewise wheel-only, so no source fallback
can install unhashed build requirements. The regression tests pin the
exact bytes of both workflow files to a reviewed SHA-256 digest
(`REVIEWED_WORKFLOW_DIGESTS`), so any change, however it is spelled and
including Dependabot action bumps, comments and formatting, fails until it has
been reviewed against this contract and the digest is updated deliberately.
`.gitattributes` checks the workflow files out with LF line endings on every
platform.
`requirements-pip-lock.txt` pins the pip bootstrap, `requirements-dev-lock.txt`
holds the complete test, lint and audit closure (including the runtime pins),
and it is installed together with `requirements-build-lock.txt`. Smoke
environments install `requirements-runtime-lock.txt` (and the build lock for the
source distribution) before adding the local artifact with `--no-deps`.
`pip-audit` reads the hashed locks with `--require-hashes --disable-pip`. The
human-readable `requirements-pip.txt`, `requirements.txt`,
`requirements-dev.txt` and `requirements-build.txt` stay the reviewed inputs;
after changing any of them, regenerate every affected lock from the repository
root and review the complete diff:

```text
uv pip compile requirements.txt --generate-hashes --universal --python-version 3.10 --output-file requirements-runtime-lock.txt
uv pip compile requirements-build.txt --generate-hashes --universal --output-file requirements-build-lock.txt --python-version 3.10
uv pip compile requirements-pip.txt --generate-hashes --universal --python-version 3.10 --output-file requirements-pip-lock.txt
uv pip compile requirements-dev.txt --constraint requirements-runtime-lock.txt --constraint requirements-build-lock.txt --generate-hashes --universal --python-version 3.10 --output-file requirements-dev-lock.txt
```

Compile the development lock last: its constraints keep shared packages
identical to the runtime and build locks so both CI locks install in one
`pip` invocation. Keep the pip pin in `requirements-pip.txt` equal to the pip
version the development lock resolves for `pip-api`. Before merging, install
the locks with the exact CI commands on each supported Python version and
platform, run `python -m pip check`, and let the hosted Linux, Windows and
macOS jobs confirm the result.

## Reviewed plan and exact selectors

The live confirmation token includes SHA-256 of the complete reviewed configuration,
including experiment parameters, target allowlist, alarms, duration and safety
limits. Editing any of these invalidates the token. Runtime-only approval flags
are excluded because they are supplied by the CLI independently.

SG rules, NACL rule/protocol/CIDR/direction, RDS parameter arrays, Lambda environment
changes, ELB descriptors, CloudFront invalidation paths and WAF IP-set scope/CIDRs
are approved using canonical selector digests in
`safety.target_allowlist`. Print them offline with
`python aws_chaos_framework.py --config example-config.yaml --suite <suite> --show-target-selectors`.
Include each `selector:<type>:<sha256>` value alongside the parent resources.
CloudFront literal paths are sorted and deduplicated without decoding or changing
their characters. WAF CIDRs use canonical network notation, sorted without
duplicates. Parent identity and WAF scope are included in their digests. Both
actions count one parent plus every unique child path or CIDR toward blast radius,
require these approvals for confirmed orchestrator handlers, and include the approved digest
in affected-resource evidence. An omitted CloudFront path list approves `/*`;
an explicitly empty list is refused.
For live ELB removal, provide `target_descriptors` with exact Id, Port and returned
AvailabilityZone. An ID alone cannot distinguish multiple registrations.
S3 object deletion requires a non-empty reviewed prefix; whole-bucket deletion is
not supported by that action.
All supported experiment bucket reads, writes, verification and recovery calls
carry `ExpectedBucketOwner` equal to the captured global approved AWS account.
AWS refuses an owner mismatch. Per-experiment account overrides are rejected;
editing the global account invalidates the confirmation token. Cross-account
S3 experiments are unsupported. Direct library callers must supply an experiment
owner and the reviewed twelve-digit account through their controller or
experiment configuration for planning reads. Live writes additionally require the
confirmed orchestrator authority described above. Controller-only clients permit safety and identity
reads, but refuse every mutation and all supported S3 bucket calls, including
bucket reads. A missing or invalid account refuses owned bucket calls before
dispatch. The controller's captured account alone does not grant an ownerless
client experiment approval or recovery authority.
Owned plan-mode clients permit reads but refuse direct mutation dispatch,
including calls marked as recovery. Planning never grants write authority.
The S3 proxy accepts only the thirteen direct bucket operations used by the
supported experiments. Raw SDK paginators, waiters, presigned URL/post helpers
and other bucket methods are refused because they can retain an unwrapped SDK
client or omit the approved owner. SDK reads are classified by an exact reviewed
per-service operation list, not `get_`, `test_` or other name prefixes. Effectful
TestState, TestFailover and TestRepositoryTriggers calls and credential-issuing
GetSessionToken calls receive normal owner, plan, stop and tracking checks, plus
active handler authority. They have no supported standalone live handler. Raw
non-S3 waiter/presign helpers and non-EC2 paginators are disabled. EC2 paginator
requests accept only the seven reviewed VPC inventory operations. Known unsupported SDK methods remain callable on attribute lookup, but their
replacement refuses invocation without exposing the raw SDK method. Unknown
attributes retain ordinary `AttributeError` and `getattr` default behavior.
EC2's read-only approval-inventory paginator
remains supported.

## Concurrent changes and recovery evidence

Recovery for EFS throughput, RDS parameters, S3 versioning/encryption
and Lambda fields checks current state against original or
experiment-owned state before restoring. Conflicting operator state observed by
those checks is refused. These reads alone do not prevent later external writes.
Lambda writes also use RevisionId and preserve unrelated environment variables.
Lambda ownership is the `RevisionId` returned by the update itself; a settled read
of any other revision is not adopted. Recovery writes require the current
revision to equal it. An update whose SDK invocation began but returned no
response may still be accepted and become visible later, so a read of the
original values never verifies its recovery: recovery stays unverified, the
process-wide live block is set and the function must be reconciled. A
response without a new `RevisionId` is handled the same way. When the update
returned a new revision, recovery without a write is verified only when the
recovery read reports that revision with an explicit `LastUpdateStatus` of
`Successful`; a missing or unknown status is never treated as success, here or
in the configuration waiter. A restoration write is sent only from an
explicitly `Successful` read of the owned revision, its response must issue a
new revision, and it is verified only from one read that reports that new
revision, an explicit `Successful` status and the restored values together;
otherwise recovery fails and the process-wide live block is set. Only an
attempt the client proxy explicitly recorded as never dispatched may otherwise
verify recovery without a write; WAF and Lambda recovery is single use and revokes the
execution grant after verification or failure.
S3/SNS whole-policy changes, EBS IOPS changes, OpenSearch node-count changes and
security-group ingress changes retain planning and dry runs only. Live tokens,
direct SDK dispatch and legacy recovery refuse these operations. Matching values,
statement identifiers, a local lock or a declared exclusive window do not prove
AWS-side ownership, and no configuration assertion grants an exception. Dry-run
recovery changes no resource and cannot establish live restoration. Live FIS
execution also remains disabled rather than trusting an unverified assertion.
Other read-before-write checks are not AWS compare-and-swap operations; only
actual service revision conditions provide that conditional boundary.

All live experiments are serialized from pre-state capture through verified
recovery, including direct worker calls and separate orchestrators in the same
process. Plan mode may still use configured concurrency. Separate processes and
external operators must honor the exclusive change window; this lock is not a
distributed AWS resource lock. Failed or unverified recovery latches a process-wide
stop regardless of failure_policy. Reconcile the resource before starting a new
process. Live automatic recovery cannot be disabled, and the configured delay
between live experiments starts after the preceding experiment finishes recovery.

RDS backup-retention changes and S3 lifecycle expiration are irreversible actions.
Both are planning only: no approval combination issues a live token for them, and
their plans cannot claim automatic recovery. The S3 lifecycle plan is prefix
scoped and never whole-bucket. Kinesis retention decreases and SES
configuration-set deletion are planning only as well, because both writes are
addressed by a reusable name without a generation, condition or lease. ECR
digest deletion and VPC endpoint deletion are planning only because each delete
also removes a provider-derived child set (tag aliases, or endpoint network
interfaces and gateway routes) that no request condition can bind. The
remaining irreversible live types, such as KMS grant revocation, require both
irreversible approvals and the LIVE-IRREVERSIBLE confirmation.
Restoring settings cannot recover backups or objects already deleted. EC2 termination and EBS detach create no implicit
snapshots. Arrange and approve any required backups separately before approving
these actions; neither action creates persistent data copies.

A recovery API attempt never counts as verified recovery. Automatic or managed
recovery must set rollback_verified only after a state read proves the intended
restoration. A handler without such evidence reports unsuccessful recovery rather
than claiming a successful run. Even a completed FIS experiment must independently
show every selected instance running. Do not use the suite as a production
recovery controller, and reconcile failed recovery before another experiment.

## Candidate execution isolation

Runtime imports in release jobs are pinned with hashes in
requirements-runtime-lock.txt. Candidate smoke checks run with network and process
isolation and a read-only host filesystem. Artifact hashes are captured before
execution and checked afterward. Isolation failure blocks publication. CI exercises
this exact Linux boundary; mocked AWS tests do not demonstrate deployed AWS IAM,
alarm or recovery behavior.


Live approval requires concrete resource IDs in YAML and in the exact target
allowlist. Discovery placeholders are planning aids and cannot authorize a live
write. The full approval digest binds the configuration, CLI profile, selected
role, VPC scope and random seed. Generate the token with the same options used
for execution. Discovered resources do not become implicitly approved targets.
Managed FIS recovery checks run even when auto_rollback is false.

All extension recovery handlers read back the intended original state before
claiming verified recovery. These are control-plane observations and do not
prove application health. Eventual consistency or a failed read may require
manual reconciliation. The exact standalone smoke runtime comes from a new
virtual environment populated only from the reviewed, hashed runtime lock.


WAF IP-set recovery removes only addresses introduced by a confirmed successful experiment update. A rejected or transport-ambiguous forward update does not establish ownership; automatic cleanup is refused and recovery remains unverified until operator reconciliation. This conservative behavior can leave an experiment addition in place after a lost success response, but never authorizes deleting an operator-owned address based on an attempted write. Ownership is bound to the update's `NextLockToken`; an address removed and re-added in any later generation is preserved and recovery is refused. A request whose addresses are all canonically present is refused before dispatch.

## Console privacy and publish payloads

### Archive resource admission

Normalization, package verification, release inventory and handoff share the
independently trusted `scripts/archive_budget.py` reader. It is loaded from its
exact sibling path, including under isolated Python; installed packages and the
working directory cannot select an alternate helper. Input bytes are captured
once into an owned temporary descriptor, so a changed input cannot substitute
metadata after admission.

Compressed input is capped at 64 MiB. Expanded file data is capped at 8 MiB per
member and 32 MiB in aggregate, with at most 128 files/directories. ZIP central
records are checked before constructing `ZipFile`; only stored and DEFLATE
compression are supported, and multipart/ZIP64 archives are refused. Each ZIP
member also has a 200:1 expansion limit.

Gzip decoding writes at most 40 MiB to a seekable temporary stream and enforces
the same 200:1 archive ratio. Before `tarfile` reads metadata, physical TAR headers
are capped at 384, metadata chains at eight, individual extension metadata at
64 KiB and aggregate metadata at 1 MiB. PAX records are bounded to 128 per
extension, names to 4 KiB, and sparse formats are refused. A bounded PAX size must
equal the physical header's size. Ordinary PAX metadata and long names remain
supported. The decompressed stream includes headers, padding and end records in
its budget. Wheel RECORD parsing is separately capped at 128 rows.

Raw representation bytes are admitted too, not only decoded member views.
Every byte before a ZIP central directory must belong to exactly one local
record (its header, data and any data descriptor that repeats the central CRC
and sizes), so gaps between records or before the central directory are
refused. Gzip input must be exactly one member followed by nothing else;
concatenated members, including empty members whose optional header fields
carry data, and trailing bytes are refused, and the member CRC and size are
checked. Release inventory and protected handoff admission further require
the normalizer's exact gzip header and stored-block serialization.

Before any checksum, release evidence or asset is written, `prepare_release.py`
captures each wheel and sdist exactly once; semantic validation, inventory,
regeneration and asset output all use those captured bytes. It regenerates a
private copy with the trusted `normalize_wheel.py` and `normalize_sdist.py`,
and refuses a candidate whose bytes differ from that regeneration. The
protected promotion verifier runs this trusted copy of `prepare_release.py`, so
only bytes equal to their trusted canonical regeneration can become attested
release subjects. Because earlier provenance may predate this gate, the
protected PyPI job's trusted `publish_payload.py verify` repeats it on a single
capture of each package, using the attested evidence's `source_date_epoch`,
before the publish action can add PyPI attestations.

Member reads use bounded chunks and verify actual bytes against the admitted
size. Normalized TAR and gzip output are streamed rather than assembled as a
second full TAR buffer. Existing canonical content, hash, source-provenance and
atomic replacement checks remain; failed admission or verification does not
replace the input. These are fixed resource bounds, not an execution sandbox or
a claim about arbitrary filesystems. See Python's [ZIP](https://docs.python.org/3/library/zipfile.html),
[TAR](https://docs.python.org/3/library/tarfile.html) and [gzip](https://docs.python.org/3/library/gzip.html)
interfaces.

Console target registries are scoped to a run and worker, bounded to 4,096 values,
and include identifiers of every length. Exact identifier boundaries preserve
unrelated words. CR, LF, tabs, terminal escapes, and Unicode control characters
are displayed as visible escapes in operator messages.

A scope that an exception leaves attaches an immutable snapshot of its protected
values to that exception. The CLI logs a propagated error, its debug traceback
and chained causes under that snapshot and the identifiers of the loaded
configuration, and the suite loop does the same for a failed worker. Every
public handler call and `run_rollback()`, including direct imported use, adds the
targets bound by its configuration and arguments to the active registry. A
filter on the `aws_chaos_framework` logger renders and redacts every record in
the caller's context before any handler runs, so a host's own basic handler
receives only redacted text. Redaction covers registered exact values and the
generic ARN, account and access-key patterns; other identifiers that appear only
in AWS responses are not registered.

Report disclosure flags apply to typed fields: include_resource_ids exposes the
affected-resource list, and include_identity exposes run identity. ARN/account
identity inside resource fields still requires include_identity. Errors and
diagnostics retain identity and resource filtering under every flag combination;
credential fields are always redacted.

FIS template target aliases are AWS response keys that no sensitive-value
registry covers, so guardrail messages name targets only by template ordinal
(`FIS target #2`) and never echo an invalid selection mode. ECS task stops are
recorded one task at a time after AWS confirms that task's ARN; a later failure
keeps the confirmed subset in affected resources and ordinal per-task outcomes
in diagnostics, without task ARNs.

The publish workflow executes verification tools from the immutable workflow
commit with Python isolated mode, never from the release tag. Verified public
distribution bytes are copied into a fresh payload with a tag, source commit,
size, and SHA-256 manifest. That manifest comes from the same lower-privilege job
as the bytes, so it is integrity metadata, not authentication. Before publishing,
the protected `pypi` job independently resolves the tag commit, downloads the
public release evidence and verifies GitHub provenance for that evidence and for
the exact handed-off wheel and source distribution. Only the protected
`release-promotion.yml@refs/heads/main` signer on a GitHub-hosted runner is
accepted. The attested evidence must name the dispatched tag, version and commit
and match both package digests and sizes. Tag and commit strings alone never
authenticate package bytes. No tag-controlled code executes after the verified
payload is captured.

`scripts/release_asset_admission.py` is the trusted parser for unauthenticated
release manifests and the bounded downloader for public release assets. It
accepts only the six fixed basenames and compares checksum and evidence names
instead of opening them, opens only regular non-symlink files beneath the asset
directory, and admits per-file and aggregate sizes from release metadata before
any download. The publish workflow calls it from the trusted workflow commit
for every release download and manifest check: the verify job downloads the six
assets into a new directory and runs `verify` (tag, verified source commit and
tagged standalone source) before distribution checks, provenance and payload
capture, and the protected job downloads only `release-evidence.json`, after
admitting the whole release by size, before attestation. No `gh release
download`, `sha256sum --check` or inline evidence parsing remains in the
workflow. The helper creates each output directory and refuses an existing one.

## Destructive-call and transition evidence

VPC deletion requires an explicitly successful service result, followed by exact
target absence (including the matching not-found error) or the authoritative
`deleted` peering tombstone. EC2 may retain deleted peering records temporarily.
A rejection, unknown result or bounded read-back timeout is a failed result.
RDS failover, RDS reboot and RDS backup-retention changes are planning only.
AWS offers no conditional generation or exclusive lease for these requests, so a
change queued after admission could be activated by the write, and a failover
can restart cluster members outside the approved target count. The completion
checks below are retained as defence in depth but run only after a live
transition, which is now refused; plans never issue the transition and do not
evaluate them: RDS failover completion requires a different exact writer and available cluster state, and
RDS reboot completion requires an observed rebooting state followed by
available. An API acceptance or an unchanged available response alone does not
prove completion.

`ApplyImmediately` also applies every pending modification. A reboot applies
`pending-reboot` DB parameter-group changes and, for a cluster member, static
cluster parameters awaiting the next instance restart. Backup-retention changes
and reboots therefore require an available instance with no
`PendingModifiedValues`, at least one DB parameter group, every group
`in-sync` and every option-group membership `in-sync`. A reboot of an instance
that reports a `DBClusterIdentifier` also reads that exact cluster and requires
it to be available, with no cluster `PendingModifiedValues`, and the instance
to appear exactly once in its members with an `in-sync` cluster parameter
group; an unreadable cluster or a missing member is refused.

Failover can restart cluster members. Whether a given failover activates queued
parameters is engine specific and not stated by the AWS API model, so failover
is refused conservatively unless both parameter domains are clean: no cluster
`PendingModifiedValues`, every member's cluster parameter group `in-sync`, and
every member instance (at most 16, each read once) passing the same instance
checks as a reboot. The checks use reads taken immediately before the write and
apply in plan mode too. Every refusal from these checks, including an
unavailable instance or cluster, records `queued_change_refusal`. They are not
conditional writes: a change queued after those reads is outside this boundary,
which is why live reboot, failover and retention changes are withdrawn.

Lambda environment handlers read variables only when `Environment.Variables` is
present and `Environment.Error` is absent; a missing `Environment` means no
variables. Unreadable environments (for example a denied KMS decrypt) refuse
forward work and recovery instead of writing or verifying an empty map;
recovery verification compares readable variables, so a restored empty map
verifies whether AWS returns empty `Variables` or omits `Environment`. Execution
grants for types without a reviewed live implementation are refused, and the
writes used only by those types, including S3 encryption deletion, are also
denied at the SDK proxy. Directory
Service trust deletion requires exactly one returned trust with the approved
`TrustId`.

SQS queue purge is planning only. `PurgeQueue` cannot be conditioned on an exact,
immutable message set, so neither the approved blast radius nor an owner check
bounds the messages it deletes. Live tokens and execution grants are refused and
the SDK proxy rejects `PurgeQueue`. Purge configuration still requires
`queue_arn` as well as `queue_url`. The reviewed ARN must exactly match the
configured partition, region and account, and the native HTTPS queue URL must
name the same account and queue; foreign or missing owners are rejected during
token generation before the planning-only refusal. No token generator performs
an AWS lookup.

Enabled GuardDuty checks consider all non-archived high/critical findings across
all detectors, without a last-update cutoff. Enabled Security Hub checks block
ACTIVE CRITICAL findings in NEW or NOTIFIED, while RESOLVED and SUPPRESSED do not
block. Both exhaust bounded result pages and reject pagination ambiguity or
exhaustion. Failed reads still fail closed.

Live suite/worker preflight failures and exceptions from safety reads latch the
same process stop as a signal. Safety and terminal-state reads recheck stop after
returning; the final SQS owner lookup rechecks stop immediately before dispatch.
This cannot cancel an AWS request already in flight or make a Python check and
remote RPC atomic. Recovery waits remain exempt from forward safety polling.

Wheel verification requires the complete canonical member set and exactly one
RECORD row per member, with SHA-256 and byte size matching the actual contents;
RECORD leaves its own hash/size empty. Unknown, duplicate, unsafe or missing rows
and missing metadata fail closed. Expanded wheel members also have per-member
and aggregate byte budgets before their contents are retained.

A self-consistent RECORD proves only that the candidate agrees with itself, not
that its bytes came from reviewed source. Because protected promotion copies and
attests the candidate wheel unchanged, the verifier source-binds every admitted
member byte for byte before `prepare_release.py` accepts it: the runtime module
must equal the repository file; `METADATA` must equal the core metadata derived
from static `pyproject.toml` and `README.md` (the field-level comparison still
runs, and the same routine derives the sdist `PKG-INFO` files); `WHEEL` must name
exactly the setuptools version pinned by the trusted build policy, a purelib
root and the single `py3-none-any` tag; `top_level.txt`, `entry_points.txt` and
`licenses/LICENSE` must equal their source-derived values or the repository
`LICENSE` bytes; and RECORD must be the canonical sorted manifest that
`normalize_wheel.py` writes for those bytes. Any other header, field, ordering or
license byte fails closed even when RECORD was recomputed. Changing the pinned
backend or the metadata layout therefore requires a trusted verifier review.

The sdist is also copied unchanged, so its generated members (both `PKG-INFO`
files, `setup.cfg`, `SOURCES.txt`, `requires.txt`, `entry_points.txt`,
`top_level.txt` and `dependency_links.txt`) are compared as raw bytes with their
source-derived values, not after line-ending normalization. A carriage-return
variant that a parser might read differently is refused.


## Live credential and response identity

Live mode freezes the resolved credentials into a fixed, non-refreshing session
before the STS identity check, so every later client signs as the verified
account, partition and principal. The pinned session keeps the selected
`--profile` (or ambient profile), so its non-credential shared configuration,
such as `ca_bundle` and `use_fips_endpoint`, still applies; only the credential
source is replaced by the explicit static snapshot. Endpoint routing is not
inherited: see the next section. A refreshable profile cannot rotate to
another identity mid-run; the snapshot can only expire, which fails closed, so
temporary credentials must outlive the run. The name-only Kinesis `StreamARN`
check and the equivalent `DBInstanceArn` and `DBClusterArn` checks remain in the
live branches of the planning-only Kinesis retention and RDS reboot, failover
and retention handlers; dry-run plans skip them, so a plan does not establish
them.

## Canonical AWS endpoint origin

The STS answer is the account decision, so it is trusted only from AWS. Every
SDK client involved in a run, in live and plan mode, is origin-bound:

- Framework clients come from one factory (`origin_bound_client`): the pre-role
  STS client used for `AssumeRole` and its ExternalId, the pinned STS client
  used for live admission, and every service client, including ones first
  created after admission.
- Credential-provider clients are bound too. Botocore's credential chain
  creates its own clients from the session that resolves credentials:
  assume-role and web-identity STS, the SSO `GetRoleCredentials` client that
  carries the bearer token, the SSO-OIDC token-refresh client and the login
  client. All of them call that session's `create_client`, so the framework
  replaces it on each session instance (`harden_session_origin`) immediately
  after constructing the session and before any credential or token is
  resolved. Each nested client then receives the same settings and request
  check for its actual service and region (explicit `region_name`, else its
  config's `region_name`, else the session region, as botocore resolves it);
  an explicit `endpoint_url` is refused. The settings below are also set
  session-wide. Credentials are frozen only from a hardened session.
- Direct-library session contract. A caller-supplied session must already be
  hardened: create it, pass it to `harden_session_origin` before botocore
  initializes its credential or token providers, then hand it to
  `SafetyController`. Construction
  refuses a boto3 session with a botocore core that is not marked
  origin-hardened, before the session is stored or any credential or token is
  resolved, so an assume-role (including its ExternalId), web-identity, SSO,
  SSO-OIDC or login provider request never honours a configured endpoint.
  `origin_bound_client`, which creates every framework client, applies the
  same check before creating a client or running the credential transport
  policy, and every experiment constructor checks its controller's session,
  so a direct factory call or a session replaced after construction is
  refused the same way. `harden_session_origin` refuses a session whose
  credential resolver or token provider was already built: SSO and login
  providers can capture an unwrapped `create_client`, while the token provider
  can cache an unwrapped SSO-OIDC client. Such a session cannot be hardened in
  place, and a new one must be created. A session object
  without a botocore core (a test double) has no provider chain and is still
  accepted; its clients are bound by `origin_bound_client`.
- Configured endpoint URLs are ignored (`ignore_configured_endpoint_urls`):
  profile `endpoint_url`, `services` sections, `AWS_ENDPOINT_URL` and
  `AWS_ENDPOINT_URL_<SERVICE>`. Dual-stack, S3 accelerate and S3 dual-stack are
  pinned off. Account-ID-based endpoints are disabled
  (`account_id_endpoint_mode = disabled`): role, SSO and pinned credentials
  carry an account ID, and botocore's default `preferred` mode would otherwise
  send, for example, Kinesis control calls to account-qualified hosts. The
  profile or environment `use_fips_endpoint` choice is read once per session
  and pinned in each client's configuration.
- Canonical hosts are derived, not hand-listed. The framework reads only
  botocore's packaged data (never `~/.aws/models` or `AWS_DATA_PATH`, which can
  replace endpoint rules without any `endpoint_url`). The region must be listed
  explicitly by a bundled partition (`aws`, `aws-us-gov` and `aws-cn` are the
  partitions the region syntax admits), and the service's bundled endpoint
  ruleset is evaluated with that region, no custom endpoint, no dual-stack,
  account endpoints disabled and exactly the approved FIPS choice. Both answers
  of the legacy global-endpoint switches for STS and S3 are admitted. Every host
  must lie under an approved parent domain: the partition's packaged
  `dnsSuffix`, plus a reviewed per-service, per-partition domain where the
  packaged rules use one. An unknown region, partition or service, or a FIPS
  request a ruleset cannot satisfy, fails closed when the client is built.
- Reviewed parent domains (`REVIEWED_SERVICE_DOMAINS`). An enumeration of the
  packaged rules for all 434 services with endpoint rules, every packaged region
  and both FIPS choices (dual-stack off, account endpoints disabled) found 396
  service/partition families with hosts outside the partition `dnsSuffix`,
  mostly `api.aws` names. Among the services the framework or a credential
  provider can create, only AWS Sign-In, the login provider's token-refresh
  client, is one of them. Its exact parent domains are admitted for Sign-In
  only: `signin.aws.amazon.com` (`aws`), `signin.amazonaws.cn` (`aws-cn`) and
  `signin.amazonaws-us-gov.com` and `signin-fips.amazonaws-us-gov.com`
  (`aws-us-gov`). Sign-In parents for partitions whose regions the framework
  refuses are not admitted, and no broad Amazon or dual-stack suffix is. The
  request check stays exact, so for example only
  `us-east-1.signin.aws.amazon.com` is reachable from `us-east-1`. A regression
  test re-enumerates the packaged rules for every reachable service and requires
  the table to equal exactly what they emit; the other families belong to
  services the framework never creates and fail closed if one ever were.
- FIPS is an approved variant, not a different owner: with FIPS selected only
  the canonical FIPS hosts are accepted (for example
  `sts-fips.us-east-1.amazonaws.com`, or the GovCloud regional hosts the
  ruleset designates), and without it a FIPS host is refused.
- The client's descriptive `meta.endpoint_url` must be HTTPS on the default
  port, without credentials or path, under the same approved parent domains
  for that service and partition. With
  endpoint rulesets the request URL is resolved per call, so the binding check
  is a `before-send` handler: every request, including retries, must be HTTPS
  on the default port to exactly one canonical host (S3 also admits a bucket
  label below its canonical host), and any explicit `Host` header must name
  that same authority. An AWS-domain host that customers control, such as an
  API Gateway `execute-api` name, is refused. A refused request is never sent,
  so a forged identity or ownership answer can never be received.
- Scope of the request check: the handler is registered first among the
  client's generic `before-send` handlers, and botocore runs service- and
  operation-specific `before-send.<service>.<operation>` handlers before it, so
  their changes are checked. A handler registered later in the same Python
  process could still change a request after the check. Arbitrary in-process
  hooks are trusted code and outside this boundary; the framework registers
  none that alter requests.

### Credential transports outside the SDK client stack

The EC2 instance metadata (IMDS) and container credential providers use their
own plain HTTP transports, so they cannot be canonical-origin bound. Plan and
live runs both resolve credentials (role assumption and the STS identity read),
so an explicit address policy is applied in both modes. The orchestrator
applies it immediately after the session is origin-hardened and before any role
assumption, credential resolution, client creation or STS request. It is also
applied before every framework SDK client is created (so direct
`SafetyController` and planning-experiment construction with a caller-supplied
session are covered) and before `pin_session_credentials` resolves
credentials:

- A configured IMDS endpoint (`AWS_EC2_METADATA_SERVICE_ENDPOINT` or the
  profile `ec2_metadata_service_endpoint`) is admitted only when it is
  botocore's default, `http://169.254.169.254` or `http://[fd00:ec2::254]`
  (a trailing slash is tolerated; no port, path or other host is).
  Selecting IPv6 with `ec2_metadata_service_endpoint_mode` remains allowed.
- The container credential URL (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` joined
  to `169.254.170.2`, or `AWS_CONTAINER_CREDENTIALS_FULL_URI`) must use HTTP or
  HTTPS without user information, a valid port, and one of the documented
  ECS/EKS link-local hosts `169.254.170.2`, `169.254.170.23` and
  `fd00:ec2::23`, or a normalized numeric loopback literal: an IPv4 address in
  `127.0.0.0/8` or exactly `::1`. Host names, including `localhost`, are
  refused over HTTP and HTTPS, because the provider transport would resolve
  the name without pinning the connection to a loopback address and a hostile
  resolver could direct the request, and any configured container
  authorization token, elsewhere. Noncanonical, scoped and IPv4-mapped
  spellings are refused too. Botocore itself admits `localhost` and loopback
  for plain HTTP and any host for HTTPS; the framework refuses names and
  arbitrary HTTPS hosts.
- Any other value is refused at those points before any provider or SDK
  request, so a malicious provider endpoint receives no request or configured
  container authorization token through them. Credentials a caller resolves
  directly from its own session, outside the framework, are outside this
  boundary.

These transports are unauthenticated plain HTTP on the instance or task. An
environment that can intercept link-local traffic can still supply arbitrary
credentials; the canonical STS check then reports the account those
credentials actually belong to, so they cannot claim the reviewed account.

Response-owner checks (STS account and partition, `StreamARN`, S3
`ExpectedBucketOwner` and the rest) remain as defence in depth. This control does
not defend against a host that is already compromised enough to trust a hostile
CA bundle and redirect DNS for genuine AWS names: TLS to the canonical name is
the remaining authentication. A profile `credential_process` runs a local
command by design and is outside this boundary. Plan mode uses the same
clients, so a plan's identity warning also comes only from canonical STS. China
(`aws-cn`) clients bind to their canonical `amazonaws.com.cn` hosts, but this
change does not add China live support: live ARN and identity checks still
expect `aws` or `aws-us-gov`, so an `aws-cn` identity is refused at admission
as before.

## Denied-target policy migration

The legacy regex key `safety.denied_target_patterns` is rejected even when an
individual spelling could also be a glob. Every existing regex configuration
requires manual migration to the new `safety.denied_target_globs` key. A key rename
alone can weaken denial: `.*critical.*` has literal dots under glob syntax.
Review each intended target set, for example deliberately replacing `^test-.*$`
with `test-*`. Matching is case insensitive over the whole target; `*` matches a
sequence, `?` one character, and all other accepted characters are literal.
Regex brackets, escapes, alternation, anchors, grouping and quantifier `+` are
unsupported. The list requires 1 through 32 nonempty ASCII globs of at most 128
characters. Target admission permits at most 1,024 targets of 2,048 characters
and an aggregate pattern-length times target-length budget of 1,048,576.
Exceeding a bound refuses admission. The matcher uses bounded dynamic programming.

The fixed `prod` and `production` name-token rule remains active independently of
these globs, with `-`, `_` and `/` as separators. It cannot be removed by changing
the configured list. Defaults are `prod` and `production`.

## Selected VPC scope

With `--vpc-id`, the exact target allowlist is necessary but not sufficient.
Each VPC-addressable live target must also be in the matching discovered
inventory for that VPC, which includes only resources with the required safety
tags. Live `ec2_reboot` instances and `vpc_subnet_acl_modify` subnets and
replacement NACLs must appear in the corresponding discovered instance, subnet
or NACL set. Before mutating, each handler checks the exact describe response:
the instance `VpcId` or the current subnet NACL association's `VpcId`.
`vpc_endpoint_delete` is planning only, so it is refused before discovery; its
endpoint inventory and `VpcId` checks remain as defence in depth. The reviewed `original_nacl_id` must also be in the discovered NACL
set and equal the subnet's current NACL, because recovery re-associates the
subnet with it. An
`efs_mount_target_delete` target is admitted only when the exact mount-target
response reports the selected `VpcId` and a discovered subnet; that relationship
is only known when the handler reads the mount target, so it is enforced there,
before the deletion, rather than at suite start.
`vpc_peering_delete` needs both endpoints in the selected VPC. Reviewed
endpoints must be distinct VPCs, so peering deletion is always refused under
`--vpc-id`. Other live types that do not address a VPC resource, such as
CloudFront, WAF and KMS, are unaffected. All remaining live
types are refused under `--vpc-id`, including RDS, Lambda, ECS and Directory
Service, because this tool does not verify their VPC placement and tags. A live
suite whose configured target contradicts the selected VPC fails with a
configuration error after discovery and before any experiment starts, except for
the EFS relationship above. Required tags come from the discovery snapshot taken
when the suite starts; a tag removed later is not re-read before a write. Without
`--vpc-id`, admission is unchanged. Separately, every live S3 write first reads
the bucket location, so it needs the `s3:GetBucketLocation` permission; with S3
lifecycle expiration now planning only, no supported live type issues one.

## VPC peering endpoint approval

`vpc_peering_delete` requires `peering_endpoints` with exact `requester` and
`accepter` mappings. Each contains `owner_id`, `region` and `vpc_id`. Both owners
and regions must equal the reviewed global account and region, and the VPC IDs
must differ. Cross-account and cross-region peering deletion is unsupported.

```yaml
peering_endpoints:
  requester:
    owner_id: '123456789012'
    region: us-gov-west-1
    vpc_id: vpc-0123456789abcdef0
  accepter:
    owner_id: '123456789012'
    region: us-gov-west-1
    vpc_id: vpc-0123456789abcdef1
```

The allowlist must contain the peering ID, both VPC IDs and the canonical
`selector:vpc_peering_delete:<sha256>` endpoint-tuple digest printed by
`--show-target-selectors`. All appear in affected-resource evidence. Blast radius
counts three resources: the connection and both endpoints. Immediately before
deleting, the describe response must select exactly the approved connection and
return the complete matching owner/region/VPC tuple. This preflight is not an AWS
conditional-write guarantee against later changes by another operator.

Draft release notes are passed to GitHub as raw literal field data and compared
byte-for-byte as text against both creation and final release readback. Body
mismatch refuses handoff and triggers cleanup only for the immutable draft ID
returned by that creation request.
