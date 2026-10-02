"""Verify external GitHub controls before a PyPI deployment can consume OIDC."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def verify_controls(
    environment: dict,
    policies: dict,
    protection: dict,
    repository: dict,
    workflow_commit: dict,
    ref: str,
    sha: str,
) -> None:
    if ref != "refs/heads/main" or repository.get("default_branch") != "main":
        raise ValueError("PyPI dispatch must use protected main")
    if (
        not re.fullmatch(r"[a-f0-9]{40}", sha)
        or workflow_commit.get("sha") != sha
        or workflow_commit.get("commit", {}).get("verification", {}).get("verified")
        is not True
    ):
        raise ValueError("Workflow commit must have a verified signature")
    if (
        environment.get("name") != "pypi"
        or environment.get("can_admins_bypass") is not False
        or environment.get("deployment_branch_policy")
        != {"protected_branches": False, "custom_branch_policies": True}
    ):
        raise ValueError(
            "PyPI environment must prohibit bypass and use exact branch restrictions"
        )
    branches = policies.get("branch_policies")
    if (
        policies.get("total_count") != 1
        or not isinstance(branches, list)
        or len(branches) != 1
        or branches[0].get("name") != "main"
        or branches[0].get("type") != "branch"
    ):
        raise ValueError(
            "PyPI environment must accept only the main branch, never tags or globs"
        )
    reviews = [
        rule
        for rule in environment.get("protection_rules", [])
        if rule.get("type") == "required_reviewers"
    ]
    reviewers = reviews[0].get("reviewers", []) if len(reviews) == 1 else []
    if (
        len(reviewers) != 1
        or reviewers[0].get("type") != "User"
        or reviewers[0].get("reviewer", {}).get("login")
        != repository.get("owner", {}).get("login")
    ):
        raise ValueError("PyPI environment requires only account-owner approval")
    if (
        protection.get("name") != "main"
        or protection.get("protected") is not True
        or not protection.get("protection", {})
        .get("required_status_checks", {})
        .get("contexts")
    ):
        raise ValueError("Workflow must be bound to main with enforced CI protection")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    args = parser.parse_args()
    values = [
        json.loads((args.directory / (name + ".json")).read_text(encoding="utf-8"))
        for name in (
            "environment",
            "policies",
            "protection",
            "repository",
            "workflow-commit",
        )
    ]
    verify_controls(*values, args.ref, args.workflow_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
