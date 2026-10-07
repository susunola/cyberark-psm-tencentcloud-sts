"""Measure the issuance admission queue over real sockets.

The burst that motivated the queue was measured before it existed: ten concurrent logins
against a half-second STS produced eight refusals, and PSM's form submission does not retry by
itself. This reproduces that measurement as often as needed, so the queue can be checked after
any change to it, and it fails when the behaviour it documents stops holding.

    python scripts/load_check.py            # the deployed shape: 3 slots and a 5-second wait
    python scripts/load_check.py --wait 0   # the pre-queue behaviour, for the comparison

Each caller uses its own identity, which is the documented deployment prerequisite. Ten logins
sharing one identity measure something else entirely - the per-identity pending-token bound
refuses all but three of them long before admission is reached - so a shared identity here
would look like a failure of the queue rather than the bound working as intended.

The exit status is non-zero when a caller received a server error, or when a run that should
have queued callers refused them instead.
"""
from __future__ import annotations

import argparse
import re
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import DEFAULT_ISSUANCE_SLOTS, DEFAULT_ISSUANCE_WAIT_SECONDS, create_app
from runtime import make_server

PROXY_KEY = 'p' * 32
SESSION_KEY = 's' * 32
SECRET_ID = 'AKIDloadcheck0000001'
SETTINGS: dict[str, Any] = {
    'profiles': {
        'readonly': {
            'role_arn': 'qcs::cam::uin/123456789012:roleName/PSMLoadCheck',
            'allowed_secret_ids': [SECRET_ID],
            'destination': 'https://console.tencentcloud.com/',
            'duration_seconds': 300,
            'region': 'ap-guangzhou',
        }
    }
}
HEADERS = {'X-PSM-Bridge-Key': PROXY_KEY, 'X-PSM-Authenticated-User': 'load-check'}


class SlowSts:
    """A stand-in for the STS round trip, which is the latency the slots exist to bound."""

    def __init__(self, milliseconds: int) -> None:
        self.milliseconds = milliseconds

    def __call__(self, *_args: object) -> dict[str, str]:
        time.sleep(self.milliseconds / 1000)
        return {'TmpSecretId': 'AKID-TEMP', 'TmpSecretKey': 'fake-temp-key', 'Token': 'fake-token'}


def login(base_url: str, identity: str, timeout: float = 30.0) -> tuple[int, float]:
    """One complete login over real sockets; returns its status and how long it took."""
    started = time.monotonic()
    headers = {**HEADERS, 'X-PSM-Authenticated-User': identity}
    form = requests.get(base_url + '/', headers=headers, timeout=timeout)
    csrf = re.search(r'name="csrf" value="([^"]+)"', form.text)
    if csrf is None:
        return form.status_code, time.monotonic() - started
    # Secure cookies are never sent over plain HTTP, so the TLS-terminating proxy is emulated
    # by forwarding the cookie header explicitly, exactly as the test suite does.
    cookie = form.cookies.get('session')
    response = requests.post(
        base_url + '/connect',
        headers={**headers, 'Cookie': f'session={cookie}'},
        timeout=timeout,
        allow_redirects=False,
        data={'csrf': csrf.group(1), 'profile': 'readonly', 'secret_id': SECRET_ID,
              'secret_key': 'fake-broker-key', 'audit_label': 'load-check'},
    )
    return response.status_code, time.monotonic() - started


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(fraction * (len(ordered) - 1)))]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--callers', type=int, default=10, help='concurrent logins to attempt')
    parser.add_argument('--sts-ms', type=int, default=500, dest='sts_ms', help='simulated STS duration')
    parser.add_argument('--slots', type=int, default=DEFAULT_ISSUANCE_SLOTS, help='concurrent issuance slots')
    parser.add_argument('--wait', type=float, default=DEFAULT_ISSUANCE_WAIT_SECONDS, help='admission wait in seconds')
    args = parser.parse_args()
    if args.callers < 1 or args.slots < 1 or args.sts_ms < 0:
        raise SystemExit('Use a positive caller count and slot count, and a non-negative STS duration')

    app = create_app(SETTINGS, proxy_key=PROXY_KEY, session_key=SESSION_KEY, sts=SlowSts(args.sts_ms),
                     issuance_slots=args.slots, issuance_wait=args.wait)
    server = make_server(app, port=0)
    base_url = f'http://127.0.0.1:{server.effective_port}'
    stopping = threading.Event()
    failures: list[BaseException] = []

    def serve() -> None:
        try:
            while not stopping.is_set():
                server.asyncore.loop(timeout=0.1, map=server._map, count=1)
        except Exception as error:  # noqa: BLE001 - reported below rather than forwarded
            failures.append(error)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=args.callers) as pool:
            futures = [pool.submit(login, base_url, f'load-check-{index}') for index in range(args.callers)]
            results = [future.result() for future in futures]
    finally:
        wall = time.monotonic() - started
        stopping.set()
        thread.join(timeout=5)
        server.task_dispatcher.shutdown()
        server.close()

    counts: dict[int, int] = {}
    for status, _elapsed in results:
        counts[status] = counts.get(status, 0) + 1
    served = sorted(elapsed for status, elapsed in results if status == 303)
    print(f'callers={args.callers} slots={args.slots} wait={args.wait}s sts={args.sts_ms}ms: {wall:.2f}s wall clock')
    print('status counts: ' + ', '.join(f'{status} x{count}' for status, count in sorted(counts.items())))
    if served:
        print(f'login latency: min {served[0]:.3f}s median {statistics.median(served):.3f}s '
              f'p95 {percentile(served, 0.95):.3f}s max {served[-1]:.3f}s')
    if failures:
        print(f'server error: {failures[0]!r}', file=sys.stderr)
        return 1
    # 503 is the documented admission refusal with Retry-After, not a failure; anything else
    # in the 5xx range is a server error, which PSM's form submission cannot recover from.
    unexpected = sorted({status for status, _elapsed in results if status >= 500 and status != 503})
    if unexpected:
        print(f'Unexpected server status: {unexpected}.', file=sys.stderr)
        return 1
    if args.wait > 0 and counts.get(303, 0) != args.callers:
        print(f'Callers were refused although the wait could have queued them; expected {args.callers} logins.',
              file=sys.stderr)
        return 1
    if args.wait <= 0 and not counts.get(503):
        print('A zero wait refused nobody, so this run cannot show what the queue changes.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
