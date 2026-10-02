# Live experiment security boundaries

Live execution requires exact authorization for both parent resources and child
selectors. WAF rule names, shard IDs, repository image digests/tags, route
destinations, and S3 prefixes must appear in `safety.target_allowlist` alongside
their parent resources. Unknown nested selectors fail closed.

Throttle experiments only reduce existing capacity. EFS throughput changes require
an existing provisioned mode and a smaller positive provisioned throughput. Lambda
functions without reserved concurrency can only be paused at zero. ECS desired
count must decrease. Scale-up is not supported by these experiments.

Live FIS templates support only reviewed EC2 reboot actions and stop actions with
automatic restart between one and 59 minutes. Other actions remain available for
planning but cannot run live. Targets must be explicit local EC2 instance ARNs,
already running, and exactly allowlisted. The aggregate target bound must fit
`max_blast_radius`. A stop alarm must belong to the expected partition, region,
and account, exist in an OK state, and be named in `safety.safety_alarms`.
The template is read again before starting and a changed template is rejected.
Restrict FIS template modification permissions during execution, since AWS starts
templates by ID and does not provide a conditional version parameter.

Emergency stop prevents new forward writes at the SDK boundary. Recovery writes
remain available. Unknown FIS start outcomes require operator reconciliation.
Terminal FIS status alone does not prove resource recovery. ECS recovery requires
restored running capacity, no pending tasks or failed deployments, and one stable
deployment. Failed recovery remains a failed result.

Rollback restores verified pre-state rather than supplied YAML. WAF rollback
patches only the experiment-owned field and refuses conflicting changes. ELB
recovery retains port and availability-zone identity. NACL recovery resolves the
subnet's current association ID. Security-group recovery only restores an actual
permission observed before the experiment and confirmed absent after revocation.

Release verification rejects unexpected archive members, including startup hooks,
unreviewed build scripts, native binaries, and executable wheel data directories.
Source files must match reviewed repository contents. Install release build tools
with `--require-hashes` using `requirements-build-lock.txt`. Regenerate this lock
with `uv pip compile requirements-build.txt --generate-hashes --universal` when
updating build tools, then review the changes before release.

## Reviewed plan and exact selectors

The live confirmation token includes SHA-256 of the complete reviewed configuration,
including experiment parameters, target allowlist, alarms, duration and safety
limits. Editing any of these invalidates the token. Runtime-only approval flags
are excluded because they are supplied by the CLI independently.

SG rules, NACL rule/protocol/CIDR/direction, RDS parameter arrays, Lambda environment
changes and ELB descriptors are approved using canonical selector digests in
`safety.target_allowlist`. Print them offline with
`python aws_chaos_framework.py --config example-config.yaml --suite <suite> --show-target-selectors`.
Include each `selector:<type>:<sha256>` value alongside the parent resources.
For live ELB removal, provide `target_descriptors` with exact Id, Port and returned
AvailabilityZone. An ID alone cannot distinguish multiple registrations.
S3 object deletion requires a non-empty reviewed prefix; whole-bucket deletion is
not supported by that action.

## Concurrent changes and recovery evidence

Recovery for EFS throughput, RDS retention/parameters, S3 versioning/encryption/
lifecycle and Lambda fields checks current state against original or
experiment-owned state before restoring. Conflicting operator changes fail closed.
Lambda writes also use RevisionId and preserve unrelated environment variables.
S3/SNS policy recovery removes only the exact experiment-owned statement and keeps
unrelated concurrent statements. API operations without a conditional revision
parameter still require an exclusive change window: read-before-write checks do
not make those AWS APIs atomic. FIS template modification must remain denied to
other principals throughout validation, start and execution. The second read
narrows the race but cannot replace that IAM deployment prerequisite.

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
