# Security Policy

## Supported versions

Security fixes are provided for the latest `2.x` release. Users should upgrade to the newest release before reporting a vulnerability.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use the repository's **Security** tab and select **Report a vulnerability** to open a private GitHub Security Advisory. Include:

- the affected version or commit
- the security impact
- a minimal reproduction that does not contain credentials or real AWS identifiers
- the expected safe behavior
- any suggested mitigation

You should receive an initial acknowledgment within seven days. Disclosure timing will be coordinated after the issue is understood and a fix is available.

## Scope

Particularly important reports include:

- a path that mutates AWS resources without explicit live approval
- a target-scope, account-binding, or confirmation-token bypass
- an operation that can affect resources outside the configured allowlist
- credential, identity, target, or report-data disclosure
- rollback behavior that reports success without recovery
- command, YAML, policy, ARN, or log injection
- a vulnerable dependency or GitHub Actions supply-chain issue

Reports that require attacking systems without authorization are out of scope.

## Safe research

Use only isolated environments that you own or are explicitly authorized to test. Never include live credentials, account IDs, ARNs, resource names, report files, or customer information in a report. Offline reproductions and mocked AWS clients are strongly preferred.
