# Plan-only game-day walkthrough

Use this walkthrough to review an AWS chaos experiment without authorizing a mutation. Plan mode can still call AWS read APIs, so use a dedicated, least-privilege role in an isolated test account or explicitly approved test environment.

This is a rehearsal and evidence review, not proof that a live fault or rollback will succeed.

## Before the meeting

- Name the experiment owner, application owner, incident contact, and stop authority.
- Select one account, region, suite, VPC, and exact set of candidate targets.
- Confirm that the role permits only the read operations needed for planning.
- Prepare CloudWatch safety alarms and verify their dimensions, region, and ownership.
- Decide where the redacted plan evidence may be stored and who may receive it.
- Define the expected blast radius, observable effect, abort condition, recovery owner, and success criteria in plain language.

## Build and validate the planner

Follow the repository's hash-locked [quick start](../README.md#quick-start), then create and validate a starter configuration:

```powershell
aws-chaos-framework --create-sample-config chaos.yaml
aws-chaos-framework --validate-config chaos.yaml
aws-chaos-framework --list-experiments
```

Replace every placeholder. Leave `--live` absent, optionally pass the explicit `--dry-run` CLI flag, and do not request a confirmation token. Do not add the obsolete `global.dry_run` configuration key; plan versus live execution is a command-line decision.

## Generate the plan

Use the same account, region, profile, suite, VPC, and seed that a later reviewed run would use:

```powershell
python .\aws_chaos_framework.py `
  --config .\chaos.yaml `
  --suite tagged_ec2_recovery `
  --vpc-id vpc-0123456789abcdef0 `
  --seed 20261030 `
  --dry-run `
  --profile chaos-test
```

The command must remain in plan mode. A successful exit means the plan passed the implemented checks; it does not grant approval for live execution.

## Review the evidence

Record the answer to each question:

| Review question | Required evidence |
| --- | --- |
| Who is calling AWS? | The expected account, partition, region, and caller identity match the approved test boundary. |
| What can be affected? | Every discovered placeholder is resolved to an exact reviewed target, and the aggregate target count remains within the approved blast radius. |
| What stops the run? | Alarm names, dimensions, state, region, and ownership are reviewed; missing or ambiguous alarms are blocking. |
| What is the expected effect? | The experiment's observable outcome and maximum duration are explicit. |
| How is recovery authorized? | The extension declares a supported rollback contract, the recovery owner is present, and unsupported recovery remains a blocker. |
| What remains private? | The report is redacted by default and stored only in an approved location. |
| What remains unproven? | Live dispatch, AWS-side timing, service behavior, alarm transition, and rollback have not been exercised. |

## Stop here by default

Archive the reviewed plan according to the team's evidence policy and close the rehearsal with one of three outcomes:

- **Rejected:** scope, identity, alarm, target, recovery, or evidence handling is unsafe or unclear.
- **Revise and re-plan:** a configuration or ownership decision changed; generate a new plan and review it from the beginning.
- **Eligible for a separate live-authorization process:** every plan question is answered, but no live permission is implied.

Do not paste a live confirmation token into tickets, chat, source control, or this document. Any configuration, target, identity, safety, or plan change invalidates the prior review. Live AWS FIS starts remain disabled by this project; reconcile any experiment started outside it through separately approved AWS procedures.
