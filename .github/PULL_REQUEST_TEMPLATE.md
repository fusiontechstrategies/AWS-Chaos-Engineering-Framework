## Summary

Describe the change and the problem it solves.

## Safety impact

- [ ] Plan mode remains free of AWS mutations.
- [ ] Account, target, alarm, and blast-radius controls remain fail closed.
- [ ] Rollback behavior is exact or the action is classified as irreversible.
- [ ] No credentials, account IDs, ARNs, resource names, or reports are included.

## Validation

- [ ] Offline tests added or updated.
- [ ] `python -m ruff format --check .`
- [ ] `python -m ruff check .`
- [ ] `python -m pytest -q`
- [ ] `python -m bandit -q -r aws_chaos_framework.py`

## Documentation

- [ ] README, example configuration, and changelog updated if needed.
