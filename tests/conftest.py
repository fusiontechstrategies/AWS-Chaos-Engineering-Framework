"""Independent offline simulations each represent a fresh process boundary."""

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import aws_chaos_framework as framework  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_simulated_live_process(monkeypatch):
    # Production never resets its latch. Deliberate failure cases in independent
    # offline tests must not share one simulated process with unrelated tests.
    monkeypatch.setattr(framework, "_LIVE_RECOVERY_BLOCKED", threading.Event())
    monkeypatch.setattr(
        framework, "_PROCESS_EMERGENCY_STOP", framework.EmergencyStopLatch()
    )
