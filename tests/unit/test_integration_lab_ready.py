"""Lab-free tests for the integration-suite readiness gate.

The gate exists because the lab's Check Point management server can take a
minute or two to answer after idling. Without it every test in a bucket fails
the same way and the log never says why. The gate polls a cheap, unauthenticated
API command until the server answers or a wall-clock budget runs out, then
either reports how long the server took or refuses to start the run.

`wait_until_ready` takes an injected probe and a `sleep`/`clock` pair so a
three-minute wait runs in milliseconds here.
"""

from __future__ import annotations

import pytest

from tests.integration.lab_ready import LabNotReady, answered_by_api, wait_until_ready


class FakeClock:
    """Monotonic clock advanced only by the fake sleep, so tests are instant."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class FlakyProbe:
    """Probe that fails `failures` times, then answers; counts every call."""

    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls = 0

    async def __call__(self) -> None:
        self.calls += 1
        if self.calls <= self.failures:
            raise ConnectionError(f"attempt {self.calls}: connection refused")


async def test_server_answering_at_once_returns_zero_wait_and_never_sleeps():
    """A responsive server costs one probe and no waiting."""
    clock = FakeClock()
    probe = FlakyProbe(failures=0)

    waited = await wait_until_ready(probe=probe, budget=180, interval=10, sleep=clock.sleep, clock=clock)

    assert waited == 0.0
    assert probe.calls == 1
    assert clock.slept == []


async def test_server_answering_on_third_probe_reports_how_long_it_took():
    """Two refused probes then an answer: the gate waits the interval between probes and reports the total."""
    clock = FakeClock()
    probe = FlakyProbe(failures=2)

    waited = await wait_until_ready(probe=probe, budget=180, interval=10, sleep=clock.sleep, clock=clock)

    assert probe.calls == 3
    assert clock.slept == [10, 10]
    assert waited == 20.0


async def test_server_never_answering_raises_after_budget_with_last_error():
    """When the budget runs out the gate raises, naming the budget and the last error the probe raised."""
    clock = FakeClock()
    probe = FlakyProbe(failures=10_000)

    with pytest.raises(LabNotReady, match=r"180 s.*attempt 19: connection refused"):
        await wait_until_ready(probe=probe, budget=180, interval=10, sleep=clock.sleep, clock=clock)

    # Probes at t=0,10,...,180 inclusive: the budget is a deadline for the last probe, not a hard stop before it.
    assert probe.calls == 19
    assert clock.now == 180.0


async def test_zero_budget_means_a_single_probe():
    """Budget 0 is fail-fast: one probe, no sleep, then the verdict."""
    clock = FakeClock()
    probe = FlakyProbe(failures=1)

    with pytest.raises(LabNotReady):
        await wait_until_ready(probe=probe, budget=0, interval=10, sleep=clock.sleep, clock=clock)

    assert probe.calls == 1
    assert clock.slept == []


async def test_probe_failure_is_chained_onto_the_raised_error():
    """The original exception stays reachable for anyone reading a traceback."""
    clock = FakeClock()
    probe = FlakyProbe(failures=1)

    with pytest.raises(LabNotReady) as excinfo:
        await wait_until_ready(probe=probe, budget=0, interval=10, sleep=clock.sleep, clock=clock)

    assert isinstance(excinfo.value.__cause__, ConnectionError)


async def test_error_without_text_is_still_named_in_the_verdict():
    """A bare TimeoutError has an empty str(); the verdict must still say what failed."""
    clock = FakeClock()

    async def timing_out_probe() -> None:
        raise TimeoutError

    with pytest.raises(LabNotReady, match=r"last error: TimeoutError"):
        await wait_until_ready(probe=timing_out_probe, budget=0, interval=10, sleep=clock.sleep, clock=clock)


# ---------------------------------------------------------------------------
# answered_by_api: what counts as "the API server is up"
# ---------------------------------------------------------------------------
#
# The lab refuses `show-api-versions` without a session, so the probe cannot
# expect success. What it can expect is a Check Point JSON error body -- that
# comes from the API server itself, so receiving one proves it is up. An HTML
# page (nginx answering for a CPM that is down) proves only that the gateway
# is up, which is exactly the state we want to keep waiting through.


def test_successful_answer_means_ready():
    assert answered_by_api({"success": True, "data": {"api-versions": ["1.9"]}, "message": "", "code": ""})


def test_checkpoint_json_error_means_the_api_server_is_up():
    """The lab's real answer to an unauthenticated show-api-versions."""
    response = {
        "success": False,
        "data": {"code": "generic_err_missing_required_header", "message": "Missing header: [X-chkp-sid]"},
        "message": "Missing header: [X-chkp-sid]",
        "code": "generic_err_missing_required_header",
    }
    assert answered_by_api(response)


def test_html_gateway_error_means_not_ready():
    """cpapi wraps a non-JSON body as {"errors": [{"message": <raw html>}]}: no CP code, so not ready."""
    html = "<html><head><title>502 Bad Gateway</title></head><body><p>nginx</p></body></html>"
    response = {
        "success": False,
        "data": {"errors": [{"message": html}]},
        "message": "502 Bad Gateway: nginx",
        "code": "502",
    }
    assert not answered_by_api(response)


def test_answer_without_data_means_not_ready():
    assert not answered_by_api({"success": False, "data": None, "message": "Unknown error", "code": "error"})
