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
