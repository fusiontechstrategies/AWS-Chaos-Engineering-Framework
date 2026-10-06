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

Live ECR image deletion requires unique explicit `imageDigest` values in the
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
revision to equal it; WAF and Lambda recovery is single use and revokes the
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
Live retention changes require both irreversible approvals and the
LIVE-IRREVERSIBLE confirmation, and cannot claim automatic recovery. S3 lifecycle
expiration is planning only; its plan is prefix scoped and never whole-bucket.
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
size, and SHA-256 manifest. The protected publish job independently checks that
manifest and the exact distribution set immediately before publishing. No
tag-controlled code executes after the verified payload is captured.

## Destructive-call and transition evidence

VPC deletion requires an explicitly successful service result, followed by exact
target absence (including the matching not-found error) or the authoritative
`deleted` peering tombstone. EC2 may retain deleted peering records temporarily.
A rejection, unknown result or bounded read-back timeout is a failed result.
RDS failover requires a different exact writer and available cluster state.
RDS reboot requires an observed rebooting state followed by available. An API
acceptance or an unchanged available response alone does not prove completion.

SQS purge configuration requires `queue_arn` as well as `queue_url`. The reviewed
ARN must exactly match the configured partition, region and account, and the
native HTTPS queue URL must name the same account and queue. Operators obtain
QueueArn through a read-only lookup before reviewing the configuration. The
offline token binds that explicit owner identity; live code resolves and compares
it again through the final SDK dispatch. Foreign, missing or changed owners fail
closed before PurgeQueue. No token generator performs an AWS lookup.

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


## Live credential and response identity

Live mode freezes the resolved credentials into a fixed, non-refreshing session
before the STS identity check, so every later client signs as the verified
account, partition and principal. The pinned session keeps the selected
`--profile` (or ambient profile), so its non-credential shared configuration,
such as `ca_bundle` and `use_fips_endpoint`, still applies; only the credential
source is replaced by the explicit static snapshot. A refreshable profile cannot rotate to
another identity mid-run; the snapshot can only expire, which fails closed, so
temporary credentials must outlive the run. Name-only RDS and Kinesis reads must
also return a `DBInstanceArn`, `DBClusterArn` or `StreamARN` with the reviewed
partition, region, account and resource name before a reboot, failover,
retention change or stream retention decrease.

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
tags. Live `ec2_reboot` instances, `vpc_subnet_acl_modify` subnets and
replacement NACLs, and `vpc_endpoint_delete` endpoints must appear in the
corresponding discovered instance, subnet, NACL or endpoint set. Before
mutating, each handler checks the exact describe response: the instance
`VpcId`, the current subnet NACL association's `VpcId`, or the endpoint
`VpcId`. The reviewed `original_nacl_id` must also be in the discovered NACL
set and equal the subnet's current NACL, because recovery re-associates the
subnet with it. An
`efs_mount_target_delete` target is admitted only when the exact mount-target
response reports the selected `VpcId` and a discovered subnet; that relationship
is only known when the handler reads the mount target, so it is enforced there,
before the deletion, rather than at suite start.
`vpc_peering_delete` needs both endpoints in the selected VPC. Reviewed
endpoints must be distinct VPCs, so peering deletion is always refused under
`--vpc-id`. Other live types that do not address a VPC resource, such as S3, SQS,
Kinesis, CloudFront, WAF, KMS, ECR and SES, are unaffected. All remaining live
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
