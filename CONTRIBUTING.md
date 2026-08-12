# Contributing

Thank you for helping improve the AWS Chaos Engineering Framework.

## Ground rules

- Keep the runtime application in the single `aws_chaos_framework.py` file.
- Keep plan mode free of mutating AWS calls.
- Prefer AWS FIS when it supplies a managed fault.
- Fail closed when identity, target scope, alarms, or recovery state is uncertain.
- Never add credentials, account IDs, ARNs, internal resource names, or generated reports.
- Do not test a pull request against an AWS account as part of the public test suite.
- Use ASCII punctuation and do not introduce em dashes.

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Run the release checks:

```powershell
python -m ruff format --check .
python -m ruff check .
python -m pytest -q
python -m bandit -q -r .\aws_chaos_framework.py
python -m pip_audit -r .\requirements.txt
```

## Adding or changing an experiment

Every executable experiment must provide:

1. explicit support and risk metadata
2. strict configuration validation
3. bounded target selection
4. a read-only plan path
5. mutation-attempt tracking
6. an honest rollback classification
7. deterministic offline tests for success and failure paths
8. Botocore-model-valid operation and request names

If exact recovery cannot be implemented, classify the action as irreversible or unsupported. Do not label best-effort recreation as automatic rollback.

## Pull requests

Keep pull requests focused. Explain the safety impact, test coverage, configuration changes, and documentation changes. New behavior should include tests that fail before the fix and pass after it.

All contributions are licensed under the Apache License 2.0.
