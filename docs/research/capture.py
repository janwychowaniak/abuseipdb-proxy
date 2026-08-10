#!/usr/bin/env python3
"""Capture raw AbuseIPDB CHECK responses as research material / future fixtures.

One invocation = one API call = one JSON file in docs/research/captures/.
The API key is read from the repo-root .env and is never written to disk.

Usage (from repo root, no project env needed yet):
    uv run --no-project --with requests python docs/research/capture.py \
        --name bad-ip-default --ip 185.220.101.34
    ... --max-age 365            # explicit maxAgeInDays
    ... --verbose                # ask upstream to attach individual reports
    ... --raw "not-an-ip"        # send an arbitrary string as ipAddress (422 probe)
    ... --bad-key                # use a deliberately invalid key (401 probe)
"""

import argparse
import datetime
import json
import pathlib
import sys

import requests

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 5  # seconds — the project rule: every upstream call has an explicit timeout
HEADERS_TO_KEEP = {
    "content-type",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
}


def load_key() -> str:
    env_path = pathlib.Path(__file__).resolve().parents[2] / ".env"
    for line in env_path.read_text().splitlines():
        if line.startswith("ABUSEIPDB_API_KEY="):
            return line.split("=", 1)[1].strip()
    sys.exit("ABUSEIPDB_API_KEY not found in .env")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="capture file basename")
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--ip", help="IP address to check")
    target.add_argument("--raw", help="arbitrary string to send as ipAddress")
    ap.add_argument("--max-age", type=int, help="maxAgeInDays (omit = upstream default)")
    ap.add_argument("--verbose", action="store_true", help="request per-report details")
    ap.add_argument("--bad-key", action="store_true", help="probe with an invalid key")
    args = ap.parse_args()

    params: dict[str, str | int] = {"ipAddress": args.ip or args.raw}
    if args.max_age is not None:
        params["maxAgeInDays"] = args.max_age
    if args.verbose:
        params["verbose"] = ""

    key = "deliberately-invalid-key" if args.bad_key else load_key()
    resp = requests.get(
        CHECK_URL,
        headers={"Key": key, "Accept": "application/json"},
        params=params,
        timeout=TIMEOUT,
    )
    try:
        body = resp.json()
    except ValueError:
        body = {"_non_json_body": resp.text[:2000]}

    capture = {
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "request": {
            "method": "GET",
            "url": CHECK_URL,
            "params": params,
            "auth": "invalid key (401 probe)" if args.bad_key else "valid key (redacted)",
        },
        "response": {
            "status": resp.status_code,
            "headers": {k: v for k, v in resp.headers.items() if k.lower() in HEADERS_TO_KEEP},
            "body": body,
        },
    }

    out = pathlib.Path(__file__).parent / "captures" / f"{args.name}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(capture, indent=2) + "\n")

    data = body.get("data", {}) if isinstance(body, dict) else {}
    triage = {
        k: data.get(k)
        for k in ("abuseConfidenceScore", "totalReports", "isWhitelisted", "isPublic", "lastReportedAt")
        if k in data
    }
    print(f"{args.name}: HTTP {resp.status_code} {triage or body} -> {out.relative_to(pathlib.Path.cwd())}")


if __name__ == "__main__":
    main()
