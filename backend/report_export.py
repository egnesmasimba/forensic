"""Download a saved report as NDJSON using an explicitly supplied session.

Set REPORT_SESSION to a current zanaq_session cookie. Existing roles and privacy
controls apply to every page. No credentials are written to the output.
"""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import httpx


def export_report(client, definition_id, output):
    after, count = 0, 0
    while True:
        response = client.get(f"/api/reports/definitions/{definition_id}/data",
                              params={"after_id": after, "limit": 500})
        response.raise_for_status()
        page = response.json()
        if page.get("schema_version") != 1:
            raise ValueError("Unsupported report schema")
        for row in page["rows"]:
            output.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
        next_id = page["next_after_id"]
        if next_id is None:
            return count
        if not isinstance(next_id, int) or next_id <= after:
            raise ValueError("Invalid report pagination cursor")
        after = next_id


def main():
    parser = argparse.ArgumentParser(description="Export a saved case report for external tools")
    parser.add_argument("--server", required=True)
    parser.add_argument("--definition", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    url = urlsplit(args.server)
    if (url.username or url.password or url.query or url.fragment or url.path not in ('', '/')
            or not url.hostname or (url.scheme != 'https' and not
                (url.scheme == 'http' and url.hostname in ('localhost', '127.0.0.1', '::1')))):
        parser.error("Use an HTTPS server origin (HTTP is accepted only on loopback)")
    if args.definition < 1:
        parser.error("Definition must be a positive report ID")
    token = os.environ.get('REPORT_SESSION', '')
    if not token or any(char in token for char in '\r\n;'):
        parser.error("Set REPORT_SESSION to a current application session cookie")
    partial = args.output.with_name(args.output.name + '.partial')
    if args.output.exists():
        parser.error("Output already exists; choose a new filename")
    try:
        with httpx.Client(base_url=args.server.rstrip('/'), timeout=30, follow_redirects=False,
                          cookies={'zanaq_session': token}) as client:
            with partial.open('x', encoding='utf-8') as output:
                count = export_report(client, args.definition, output)
        # Exclusive publication also prevents replacing a concurrently created file.
        os.link(partial, args.output)
        partial.unlink()
    except (httpx.HTTPError, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Export incomplete ({type(error).__name__}); check access and the .partial file")
    print(f"Exported {count} cases to {args.output}")


if __name__ == '__main__':
    main()
