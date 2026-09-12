#!/usr/bin/env python3
"""Kabuki browser smoke test (real Chromium via Playwright).

Requirements:
    - Kabuki running locally: ./kabuki.sh local (backend :8040, UI :4240)
    - Playwright with Chromium available in the interpreter used to run this
      script (e.g. samurai/backend/.venv/bin/python).

Usage:
    samurai/backend/.venv/bin/python kabuki/e2e/browser_smoke.py [--frontend URL]
"""

from __future__ import annotations

import argparse
import functools
import http.server
import socketserver
import threading

from playwright.sync_api import sync_playwright

FIXTURE_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>XWA Kabuki Fixture</title><link rel="stylesheet" href="/style.css"></head>
<body><h1>Fixture</h1><p>local target</p></body></html>"""


def start_fixture(port: int) -> socketserver.TCPServer:
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # silence
            pass

    fixture_dir = "/tmp/opencode/kabuki-fixture"
    import os

    os.makedirs(fixture_dir, exist_ok=True)
    with open(os.path.join(fixture_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(FIXTURE_HTML)
    handler = functools.partial(Handler, directory=fixture_dir)
    httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frontend", default="http://localhost:4240")
    parser.add_argument("--fixture-port", type=int, default=8108)
    parser.add_argument("--headed", action="store_true")
    args = parser.parse_args()

    fixture = start_fixture(args.fixture_port)
    target = f"http://127.0.0.1:{args.fixture_port}"
    checks: list[tuple[str, bool]] = []
    console_errors: list[str] = []
    page_errors: list[str] = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not args.headed)
            page = browser.new_page()
            page.on(
                "console",
                lambda m: console_errors.append(m.text) if m.type == "error" else None,
            )
            page.on("pageerror", lambda e: page_errors.append(str(e)))

            page.goto(args.frontend, wait_until="networkidle")
            page.wait_for_timeout(2500)
            body = page.inner_text("body")
            checks.append(("shell: backend online without interaction", "[BACKEND ONLINE]" in body))

            page.locator("input").first.fill(target)
            page.locator("button:has-text('ANALYZE')").first.click()
            completed = False
            for _ in range(30):
                page.wait_for_timeout(1000)
                text = page.inner_text("body")
                if "COMPLETED" in text or "[ERROR" in text:
                    completed = "COMPLETED" in text
                    break
            checks.append(("analyzer: REST analysis completes via UI", completed))

            page.goto(args.frontend + "/history", wait_until="networkidle")
            page.wait_for_timeout(2500)
            rows = page.locator(".history-item").count()
            checks.append(("history: rows rendered without clicks", rows > 0))
            checks.append(("history: no stuck loading", "[ LOADING... ]" not in page.inner_text("body")))

            if rows:
                first_target = page.locator(".history-target").first.inner_text()
                checks.append(("history: shows the scanned target", target in first_target))

            page.locator("button", has_text="EN").first.click()
            page.wait_for_timeout(900)
            rows_es = page.locator(".history-item").count()
            es_ok = "HISTORIAL" in page.inner_text("body")
            page.locator("button", has_text="ES").first.click()
            page.wait_for_timeout(900)
            rows_en = page.locator(".history-item").count()
            checks.append(("i18n: ES toggle keeps data", es_ok and rows_es == rows))
            checks.append(("i18n: back to EN keeps data", rows_en == rows))

            page.goto(args.frontend + "/analysis/1", wait_until="networkidle")
            page.wait_for_timeout(2500)
            detail = page.inner_text("body")
            checks.append(("results: detail renders without clicks", "ANALYSIS #1" in detail and "WAF" in detail))

            browser.close()
    finally:
        fixture.shutdown()

    print("=== KABUKI BROWSER SMOKE ===")
    passed = 0
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        passed += int(ok)
    print(f"checks: {len(checks)} | passed: {passed} | failed: {len(checks) - passed}")
    print(f"console errors: {len(console_errors)} | page errors: {len(page_errors)}")
    if console_errors:
        print("console:", console_errors[:5])
    if page_errors:
        print("page:", page_errors[:5])
    ok = passed == len(checks) and not console_errors and not page_errors
    print("RESULT:", "OK" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
