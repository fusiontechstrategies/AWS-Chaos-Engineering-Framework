# Runtime approval and recovery boundaries

## Explicit EC2 plans and EBS relationships

Review read-only AWS inventory and record the complete relationship in the
configuration. EBS detach plans bind the attachment fields; live detach and
restoration are unavailable because their requests cannot condition on the
mutable single-attachment capability. EC2 termination retains read-only
planning but cannot produce a live token. Missing, duplicate, unexpected, or
changed resources are refused in the corresponding inventory checks.

For EC2 termination, list every selected instance as a key in
`delete_on_termination_volumes`, including an empty list when no attached EBS
volume has `DeleteOnTermination: true`:

```yaml
type: ec2_terminate
instance_ids: [i-0123456789abcdef0]
delete_on_termination_volumes:
  i-0123456789abcdef0: [vol-0123456789abcdef0]
```

Both the instance and every listed volume must appear in
`safety.target_allowlist`. `max_blast_radius` counts their combined unique IDs;
the example accounts for two. These fields provide planning evidence and never
authorize live termination. Plan evidence includes the observed deletion map and all materially affected
IDs. The framework creates no implicit backup or snapshot. AWS permanently
deletes attached EBS volumes whose deletion flag is true; instance-store data
also disappears. See the [AWS termination API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TerminateInstances.html).

For EBS detach, record exactly one instance/device attachment:

```yaml
type: ebs_detach_volume
volume_id: vol-0123456789abcdef0
attachment:
  instance_id: i-0123456789abcdef0
  device: /dev/xvdf
```

The computed scope contains the volume ID, the instance ID, and
`attachment:i-0123456789abcdef0:/dev/xvdf`. The blast radius is two resources.
Current plans compute and capture this scope; they do not establish allowlist
authorization. An exact allowlist containing all three values and a radius
allowance of at least two would be configuration requirements for any future,
separately reviewed live contract. The current live capability is withdrawn.
Root volumes, multiple attachments, and changed attachment state are refused.
Read-only selection requires observed `MultiAttachEnabled: false`; an absent or
unknown capability does not establish single-attachment behavior. The retained
read-only terminal predicate requires the exact single instance/device tuple
with `State: attached` while the volume is `in-use`. An `attaching` tuple or
aggregate state alone cannot satisfy it; additional attachments are refused.
`ModifyVolume` can change `MultiAttachEnabled`, and `AttachVolume`/`DetachVolume`
have no condition for that capability or its revision. Supplying the exact
`VolumeId`, `InstanceId` and `Device` does not make the capability immutable. Live
approval, forward detach, direct/historical recovery and SDK detach/attach are
therefore refused. These predicates remain planning evidence, not live recovery. See the [AWS detach API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DetachVolume.html).

The termination API has no child-resource revision condition. A final read or a
local process lock cannot prevent another AWS principal from attaching a volume
or changing its deletion flag before termination. Live confirmation, handler and
SDK dispatch are therefore disabled, including direct and recovery calls. No
configuration assertion grants an exception. Re-enabling live termination needs
an independently enforceable AWS-side boundary that prevents those concurrent
changes, or conditional termination support from AWS.

## Continuous forward safety checks

Every extension transition helper polls CloudWatch, GuardDuty, Security Hub,
allowed days/hours, and resource-limit conditions before reading transition state
and while waiting. Sleeps wake no later than `monitor_interval_seconds`; SDK
request time is additional. A violation or failed safety evaluation requests a
process-wide emergency stop and prevents new forward-call admission. An accepted
SDK call holds the dispatch barrier through its return. The stop latch activates
only after that call exits; no forward call begins after activation. A request
after the final admission check can still precede the accepted call's start.
Signals on that thread defer activation without deadlocking. Stop activation
does not cancel an in-flight SDK request and can await its timeouts and retries.
Recovery waits and permitted
rollback writes continue after a stop request.

S3 bucket operations bind `ExpectedBucketOwner` to the captured approved global
account on reads, forward writes and recovery. Missing accounts, differing
explicit owners and per-experiment account overrides are refused. Cross-account
bucket targets are unsupported; changes to the approved global account require
a new configuration confirmation token.
Immediately before a live S3 write, an owner-bound `GetBucketLocation` must
report the reviewed global region. An empty or absent legacy constraint means
`us-east-1` and `EU` means `eu-west-1`; any other mismatch, unrecognized value or
read error refuses the write. Botocore can redirect a request and sign it again
for the bucket's actual region. A signing-time hook on each framework S3 client
refuses any S3 write signed for a region other than the client's reviewed
region, so such a redirect cannot reach another region.
`ExpectedBucketOwner` remains a separate control.
Every SDK client, including the STS clients that decide live account binding
and the clients botocore's credential providers create (assume-role, web
identity, SSO and SSO-OIDC refresh), ignores configured endpoint URLs from the
profile or environment and
refuses, before sending, any request whose host is not botocore's bundled
canonical host for the client's partition, service, region and approved FIPS
choice. A profile that sets `endpoint_url` therefore still talks to canonical
AWS, and a customer endpoint-rules override (`AWS_DATA_PATH` or
`~/.aws/models`) that redirects a service makes that service's calls fail
closed. Account-ID-based endpoints are disabled, so account-bearing role or
SSO credentials keep Kinesis and other services on their regional hosts. Plan
and live runs, framework client creation (including direct `SafetyController`
and planning-experiment construction) and `pin_session_credentials` also
refuse a non-default IMDS endpoint or a container credential URL outside the
documented link-local addresses and numeric loopback literals (host names such
as `localhost` are refused), before any provider or SDK request. See
[Canonical AWS endpoint origin](security-boundaries.md#canonical-aws-endpoint-origin).
Controller-only clients without an experiment owner support safety and identity
reads; they refuse all mutations and account-bound S3 bucket reads. They cannot
claim the recovery exception or bypass the process stop through an ownerless
write.
S3 proxy calls are limited to the thirteen direct owner-bound operations used by
the supported experiments; raw SDK delegates and unreviewed S3 methods refuse.
Other SDK reads also use exact reviewed per-service operation names. Effectful
`test_*` calls and unreviewed `get_*` calls do not bypass mutation checks. Raw SDK
waiter/presign delegates and non-EC2 paginators are disabled; EC2 pagination is
restricted to the seven reviewed VPC inventory operations.

EC2 recovery requires the exact selected instance set on every read. Empty,
partial, duplicated, or extra responses cannot establish recovery. An unverified
recovery sets the process-wide live-execution latch and blocks later live work.

## Planning-only operations without conditional ownership proof

The following types support dry-run planning and advertise `live_supported: false`:

- `s3_bucket_policy_deny`, `sns_topic_policy_restrict`, `sns_subscription_delete`
- `ebs_throttle_iops`, `ebs_detach_volume`, `opensearch_cluster_config_modify`
- `vpc_route_table_modify`
- `vpc_security_group_modify`, `vpc_nacl_block_traffic`
- `ec2_terminate` (immutable child authorization cannot be proven)
- `s3_lifecycle_modify` (whole-document lifecycle replacement)
- `sqs_queue_policy_restrict`, `sqs_message_delay`, `sqs_visibility_timeout`
- `kms_key_disable`, `kms_key_policy_restrict`
- `iam_policy_detach`, `iam_role_modify`, `iam_user_access_key_deactivate`
- `ecr_repository_policy_restrict`
- `codecommit_trigger_delete`
- `ec2_stop`, `efs_throttle_throughput`, `rds_parameter_group_modify`
- `lambda_throttle`, `s3_object_delete`, `s3_bucket_versioning_suspend`
- `elb_remove_targets`, `elb_modify_attributes`, `elb_listener_rule_modify`,
  `elb_health_check_modify`
- `ecs_service_update`, `ecs_container_instance_drain`
- `appstream_fleet_stop`, `appstream_stack_disassociate`
- `ds_conditional_forwarder_delete`
- `sqs_queue_purge` (the destroyed message set cannot be bounded)
- `rds_failover`, `rds_reboot`, `rds_backup_retention_modify` (no conditional
  generation or exclusive lease against changes queued after admission)

These APIs cannot atomically prove that the state being reversed still belongs
to this execution. A local lock, successful forward response, unchanged scalar,
or immediate reread cannot distinguish another principal's identical change or
prevent a race before a whole-document/list replacement. Live tokens and dispatch
are refused. The SDK proxy also rejects the unsafe forward and rollback API
operations, including direct class calls and legacy cleanup state, before an AWS
mutation attempt. No configuration option bypasses this restriction.

### Additional service capability limits

These restrictions are compatibility changes. Existing configurations can still
produce plans, but cannot obtain live approval for the listed actions. Historical
recovery of these operations needs separate operator reconciliation. The public
approval, admitted handler lifecycle, direct recovery entry and SDK write boundary
all refuse the affected operations; a previous grant does not restore support.

| Service / action | Ownership or authorization limit |
| --- | --- |
| EC2 stop/start | Requests contain instance IDs, with no caller-owned state revision for restoration. |
| Route deletion/restoration | `DeleteRoute` binds a destination, not the captured target or generation. Create-only active restoration cannot identify a newer target removed during forward deletion. Both live APIs are refused. |
| EBS detach/attach | The tuple identifies an attachment, but neither request conditions on the mutable `MultiAttachEnabled` capability or revision. A local lock, reread or post-write terminal check does not establish that boundary. Both live APIs are refused. |
| EFS throughput | `UpdateFileSystem` accepts mode and throughput, with no conditional revision. |
| RDS parameter group | Modification has no revision condition. A group name is also insufficient authorization for every DB instance or cluster that consumes the shared group. Plans do not claim that a one-resource radius accounts for those consumers. |
| Lambda reserved concurrency | Put/delete concurrency has no `RevisionId`. A reread of the same integer cannot prove ownership of a later write. |
| S3 object deletion | The current plan and approval bind keys, not immutable object versions or conditional object identity. Key-only deletion cannot be live-approved, including with irreversible approval. AWS's optional version/conditional request fields are not an implemented approval contract here. |
| S3 bucket versioning | The current `PutBucketVersioning` request has no caller-owned revision for restoration. |
| S3 lifecycle expiration | `PutBucketLifecycleConfiguration` replaces the whole rule document with no revision condition, so neither a prefix-scoped rule nor preserved unrelated rules can be made exclusive. Plans require a canonical nonempty `prefix` (the exact `Filter.Prefix`), list unrelated rules unchanged, refuse an existing chaos rule ID and reject every key outside `bucket_name`, `prefix`, `expire_days` and common metadata (`type`, `name`, `description`, `duration_seconds`, `auto_rollback`, `state_timeout_seconds`). Diagnostics include `lifecycle_plan`: preserved rules by ordinal, status, action names and SHA-256 of the unchanged rule, plus the chaos rule's prefix and expiration. |
| ELB targets, attributes, listener actions and health settings | The current registration and modification requests have no caller-owned revision; preserving an earlier list or rereading a scalar does not authorize replacement. |
| ECS service count and container instance state | Current update requests do not condition restoration on an owned revision. A matching desired count is insufficient. |
| AppStream fleet state and association | Current start/stop and associate/disassociate requests have no caller-owned revision. A service concurrent-modification error is not such a condition. |
| Directory Service conditional forwarder | Name-based deletion cannot bind the selected forwarder's generation. Recreating a saved address list does not establish that the name still belongs to this execution. |
| SQS queue purge | `PurgeQueue` deletes whatever the queue holds when AWS processes the request. It cannot be conditioned on an exact, immutable message set, so no approved blast radius or owner check bounds the messages destroyed. `PurgeQueue` is refused at the SDK proxy. |
| RDS reboot, cluster failover and backup retention | `RebootDBInstance`, `FailoverDBCluster` and `ModifyDBInstance` with `ApplyImmediately` accept no conditional generation or exclusive lease. A reboot, failover or immediate modification can also activate parameter, option-group or instance changes another principal queues after the plan's reads, and a failover can restart cluster members that are not counted as approved targets. All three requests are refused at the SDK proxy. |
| Kinesis retention decrease and SES configuration-set deletion | `DecreaseStreamRetentionPeriod` and `DeleteConfigurationSet` address a reusable stream or set name and accept no stable generation, provider-enforced condition or exclusive lease. Another principal can change or replace the named resource after approval and the pre-read, and the irreversible write would then apply to that new state. Both requests are refused at the SDK proxy. |
| ECR digest deletion and VPC endpoint deletion | `BatchDeleteImage` by digest also removes every tag alias attached to that digest, and `DeleteVpcEndpoints` also removes the endpoint's network interfaces and gateway routes across its subnets and route tables. Neither request accepts a condition over that derived child set, so aliases or associations present or added after approval would be destroyed without review. Both requests are refused at the SDK proxy. |

The SDK operation inventory is evaluated against the pinned Botocore model;
unconditional retries or additional reads do not supply absent service conditions.
See the request contracts for
[EFS](https://docs.aws.amazon.com/efs/latest/APIReference/API_UpdateFileSystem.html),
[RDS](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBParameterGroup.html),
[RDS reboot](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RebootDBInstance.html),
[SQS purge](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html),
[Lambda concurrency](https://docs.aws.amazon.com/lambda/latest/api/API_PutFunctionConcurrency.html),
[S3 deletion](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html),
[ECS](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html),
[ELB](https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ModifyTargetGroup.html)
and [AppStream](https://docs.aws.amazon.com/appstream2/latest/APIReference/API_StartFleet.html).

SNS subscription deletion now retains read-only planning for an exact subscription
ARN; its live irreversible deletion contract is withdrawn. `Unsubscribe` and
`Subscribe` SDK mutations are both refused, including historical automatic
recovery. The subscription request cannot condition recreation on a caller-owned
revision, and an irreversible approval does not restore live support. Pure
account, partition, region and Firehose IAM role validators remain available as
identity checks; they do not grant execution authority. Operators must reconcile
historical subscription outcomes separately.
SES configuration-set deletion likewise keeps its declared irreversible scope
for planning only; live deletion and legacy configuration-set recreation are
both refused. Previously unsupported S3
encryption restoration is also refused at SDK dispatch. These paths cannot be
used to recover old executions automatically.
SQS queue purge and RDS reboot, cluster failover and backup-retention changes
are likewise planning only. Their plans still read the reviewed queue or DB
resources and apply the RDS queued-change and cluster-member checks. The
resolved queue-owner comparison, RDS response-ARN checks and transition
completion checks are retained as defence in depth but run only on live
dispatch, which is refused, so a successful plan does not establish them. Live tokens, live suites, execution
grants (including recovery of a historical execution) and the `PurgeQueue`,
`RebootDBInstance`, `FailoverDBCluster` and `ModifyDBInstance` SDK requests are
refused, and `--list-experiments` reports `LIVE no` for all four types. A larger
`max_blast_radius` or irreversible approval does not restore live support.
Kinesis retention decreases and SES configuration-set deletion are planning only
on the same terms. Their plans still read the named stream or set. The Kinesis
`StreamARN` check runs only on live dispatch, which is refused. Live tokens,
live suites, execution grants, direct live construction and the
`DecreaseStreamRetentionPeriod` and `DeleteConfigurationSet` SDK requests are
refused, and `--list-experiments` reports `LIVE no` for both types.
ECR digest deletion and VPC endpoint deletion are planning only on the same
terms. Their plans still read the reviewed repository digests or endpoint. The
ECR digest, registry and response checks and the endpoint selected-VPC and
deletion read-back checks run only on live dispatch, which is refused. Live
tokens (even with every alias, route table, subnet, group and interface in the
allowlist), live suites, execution grants, direct live construction and the
`BatchDeleteImage` and `DeleteVpcEndpoints` SDK requests are refused, and
`--list-experiments` reports `LIVE no` for both types.

### Exact Lambda identity and terminal recovery state

Lambda accepts only a local unqualified function name or a full unqualified ARN
with the reviewed partition, region and account. Account-bearing partial ARNs,
aliases, version qualifiers, wildcards and a separate SDK `Qualifier` are refused
before SDK calls, in planning as well as dispatch. SDK calls require a reviewed
twelve-digit account and the exact reviewed endpoint. Live configuration reads
must return the exact canonical `FunctionArn` before their revision data is used.
Conditional configuration updates retain `RevisionId`; concurrency operations
remain planning only. This deliberately narrows AWS's broader identifier syntax.
See [GetFunctionConfiguration](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunctionConfiguration.html).

A configuration fault owns only the `RevisionId` returned by its own successful
conditional update. A missing, empty or unchanged response revision establishes
no ownership. Confirmation must then read that same revision, settled and
carrying the requested values. The API model gives no lineage from the update to
any other revision. A settled read reporting another revision is therefore never
adopted, even with identical values: the forward fails, ownership is withheld,
the reason is recorded and manual reconciliation is required. If an emergency
stop interrupts the settle wait, the update's own revision remains the only
owner. A recovery write requires the current revision to equal the owned one. A
later revision is refused even when it carries the identical chaos value, and an
ambiguous forward with no owned revision cannot write. Recovery that needs no write only reads back the original
values, and only when every forward update either returned a new revision or
was explicitly recorded by the client proxy as never dispatched. An update
whose SDK invocation began without a returned response, or whose response
carried no new `RevisionId`, may have been accepted and can become visible
after a read of the original values, so its recovery is never verified: it
fails, the process-wide live block is set and manual reconciliation is
required. When the update returned revision R, a no-write recovery claim also
requires the recovery read to report R itself with an explicit
`LastUpdateStatus` of `Successful`. A stale or other-generation read of
original values, or a read whose status is missing or unknown, fails recovery
the same way. The configuration waiter likewise accepts only an explicit
`Successful` status. A restoration write is sent only after a read of R with an
explicit `Successful` status. Its response must issue a new revision R2, and
recovery is verified only from one read that carries R2, an explicit
`Successful` status and the restored values together. A read still showing R
is waited out. Any other revision, a missing or unknown status, a timeout or
mismatched values fail recovery with the process-wide live block. Live WAF and Lambda recovery is single use: the first `run_rollback`
consumes it under the lifecycle lock. Verified or failed, that attempt clears
owned markers and revokes the execution grant, so a later call cannot mint
another write. Failed recovery requires operator reconciliation.

The retained read-only route predicate checks exactly one selected route table
and destination, the captured target, and `State: active`. A matching `blackhole`
route fails; missing or nonterminal state reaches a bounded timeout. The former
create-only restoration cannot repair destination-only deletion of a changed
captured target, so both live deletion and restoration are withdrawn. EBS retains
the exact attached-tuple predicate described above. Ordinary mocked checks of
these predicates do not authorize writes or establish live network/storage
recovery. Historical route or attachment outcomes require separate operator
reconciliation.

Subnet NACL association changes use the AWS association ID as a conditional
identity. Recovery requires a confirmed owned replacement ID and matching NACL,
then passes that exact ID to AWS; changed or unconfirmed associations are refused.
`vpc_subnet_acl_modify` requires `original_nacl_id`, the NACL that recovery
re-associates. It is a target key, so it must be in the exact allowlist, and it
is bound into the token, execution grant and `--vpc-id` inventory check. The
handler refuses before any write when the subnet's observed NACL differs, and
recovery refuses a recorded original that is not the granted reviewed value.

## Honest results and unambiguous configuration

Subnet, target-group, and listener-rule lookups require exactly one matching
resource and required child association/actions. A live `completed` result must
include a mutation attempt and affected-resource evidence. Missing resources
cannot produce a successful no-write experiment.

Configuration YAML rejects duplicate keys at every depth, non-string mapping
keys, merge keys, and aliases. Parser diagnostics report only numeric line/column
coordinates. Source lines, arbitrary parser problem text, and source buffers are
never emitted, including malformed password, token, external-ID, or secret-key
lines.

Remediation regressions use deterministic fake AWS clients, actual offline
botocore operation models with Stubber, and temporary local inputs. They
establish local control-flow, SDK validation and request-shape behavior;
they do not establish outcomes from a live AWS experiment.

## Policy, scalar and ambiguous-forward limits

S3/SNS whole-policy replacements, EBS IOPS changes, OpenSearch node-count changes,
and security-group ingress removal/restoration are planning and dry-run operations
only. Their service APIs do not provide the conditional revision/ownership proof
needed for safe shared-resource recovery. A local process lock, named policy
statement, matching scalar, immediate reread or declared maintenance window does
not close that AWS-side boundary. No configuration assertion grants live support.
Eligibility, live tokens, direct SDK writes and legacy recovery paths refuse them.
Dry-run recovery performs no SDK changes and is not evidence of live restoration.

See the actual request contracts for [S3 policy](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html),
[SNS attributes](https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html),
[EBS modification](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVolume.html)
and [OpenSearch configuration](https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_UpdateDomainConfig.html).

WAF rule/rate updates retain the service's required
[LockToken](https://docs.aws.amazon.com/waf/latest/APIReference/API_UpdateWebACL.html).
Recovery additionally requires a successful forward return and a unique matching
post-state. An exception or unconfirmed post-state requires manual reconciliation;
an absent/changed value is never used to infer that this execution owned a write.
The marker resets before each new attempt. The forward write's `NextLockToken` is
the confirmed generation. For rules, the confirmation read must report it too.
Recovery proceeds only while the Web ACL or IP set is still at that scope, name,
ID and LockToken. Any later generation is refused for manual reconciliation, even
one carrying the identical action, limit or a re-added address. Recovery preserves
unrelated fields and refuses conflicting selected values. An optimistic-lock
failure remains a failure, not permission to retry an unconditional overwrite.

A WAF request that is already satisfied is refused before dispatch as a failed
result, with no write, ownership marker or recovery claim. This covers the
current rule action type, the current rate limit, or an IP-set request without a
CIDR that is canonically new. One canonically new address is required.
Ownership is computed against canonical CIDRs: an operator entry that is the
same network in another textual form is pre-existing state, is not written again
and is never owned. Recovery removes only entries whose canonical form is an
owned addition, at the confirmed generation.

## Plan parity and queued service changes

FIS plans apply every structural guardrail that live validation applies (action
recovery, alarm stop condition from `safety_alarms`, selection bounds, target
allowlist, exact instance ARNs and required tags). Plan mode skips only the live
CloudWatch alarm-state read, so a template with a structural violation is
reported as failed with the same `guardrail_violations`, never as planned. This
is structural parity only: alarm state is not checked, and live FIS starts stay
disabled regardless of the plan result. RDS
queued-change refusals, Lambda unreadable-environment refusals and the exact
Directory Service trust match are evaluated in plan mode as well; see
[security boundaries](security-boundaries.md#destructive-call-and-transition-evidence).
