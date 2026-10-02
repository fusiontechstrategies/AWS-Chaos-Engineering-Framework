# Runtime approval and recovery boundaries

## Explicit EC2 and EBS relationships

Before generating a live token, review read-only AWS inventory and record the
complete relationship in the configuration. The token includes these fields;
changing any relationship changes the token. Token generation remains offline.
The framework resolves the relationships again immediately before a mutation and
refuses missing, duplicate, unexpected, or changed resources.

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
the example requires at least two. Both irreversible approval gates still apply.
Result evidence includes the observed deletion map and all materially affected
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

The exact allowlist must contain the volume ID, the instance ID, and
`attachment:i-0123456789abcdef0:/dev/xvdf`. The blast radius is two resources.
Root volumes, multiple attachments, and changed attachment state are refused.
The final AWS request includes `VolumeId`, `InstanceId`, and `Device`, which binds
the write to the approved attachment. See the [AWS detach API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DetachVolume.html).

The termination API has no child-resource revision condition. Maintain an
exclusive change window for EC2 attachment/deletion flags through termination;
the final read does not provide a distributed lock against another AWS writer.

## Continuous forward safety checks

Every extension transition helper polls CloudWatch, GuardDuty, Security Hub,
allowed days/hours, and resource-limit conditions before reading transition state
and while waiting. Sleeps wake no later than `monitor_interval_seconds`; SDK
request time is additional. A violation or failed safety evaluation sets the
emergency stop and prevents later forward writes. Recovery waits and permitted
rollback writes continue after a stop request.

EC2 recovery requires the exact selected instance set on every read. Empty,
partial, duplicated, or extra responses cannot establish recovery. An unverified
recovery sets the process-wide live-execution latch and blocks later live work.

## Planning-only operations without conditional ownership proof

The following types support dry-run planning and advertise `live_supported: false`:

- `vpc_nacl_block_traffic`
- `sqs_queue_policy_restrict`, `sqs_message_delay`, `sqs_visibility_timeout`
- `kms_key_disable`, `kms_key_policy_restrict`
- `iam_policy_detach`, `iam_role_modify`, `iam_user_access_key_deactivate`
- `ecr_repository_policy_restrict`
- `codecommit_trigger_delete`

These APIs cannot atomically prove that the state being reversed still belongs
to this execution. A local lock, successful forward response, unchanged scalar,
or immediate reread cannot distinguish another principal's identical change or
prevent a race before a whole-document/list replacement. Live tokens and dispatch
are refused. The SDK proxy also rejects the unsafe forward and rollback API
operations, including direct class calls and legacy cleanup state, before an AWS
mutation attempt. No configuration option bypasses this restriction.

Subnet NACL association changes use the AWS association ID as a conditional
identity. Recovery requires a confirmed owned replacement ID and matching NACL,
then passes that exact ID to AWS; changed or unconfirmed associations are refused.

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

All remediation regressions use deterministic fake AWS clients and temporary
local inputs. They establish local control-flow and request-shape behavior;
they do not establish outcomes from a live AWS experiment.
