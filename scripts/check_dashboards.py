#!/usr/bin/env python3
"""
Run every PromQL expression in every provisioned dashboard against the live
Prometheus and report which ones return no data.

A panel that renders nothing is worse than no panel: it reads as "zero" when it
actually means "wrong metric name". Run this after editing gen_dashboards.py.

Exit code = number of expressions returning no series.
"""
import json
import pathlib
import sys
import urllib.parse
import urllib.request

PROM = "http://localhost:9090"
DASH = pathlib.Path(__file__).resolve().parent.parent / "infra" / "grafana" / "dashboards"

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def query(expr):
    url = f"{PROM}/api/v1/query?" + urllib.parse.urlencode({"query": expr})
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            body = json.load(r)
    except Exception as e:  # noqa: BLE001
        return None, str(e)
    if body.get("status") != "success":
        return None, body.get("error", "query failed")
    return len(body["data"]["result"]), None


def walk(panels):
    for p in panels:
        yield p
        yield from walk(p.get("panels", []))


def main():
    empty = 0
    total = 0
    for f in sorted(DASH.glob("*.json")):
        print(f"\n{f.name}")
        d = json.loads(f.read_text())
        for panel in walk(d.get("panels", [])):
            for t in panel.get("targets", []):
                expr = t.get("expr")
                # Tempo-backed panels have no Prometheus series until traces flow.
                if not expr:
                    continue
                total += 1
                n, err = query(expr)
                label = f"{panel['title'][:42]:44s}"
                if err:
                    print(f"  {RED}ERR {RESET} {label} {err}")
                    empty += 1
                elif n == 0:
                    print(f"  {YELLOW}NODATA{RESET} {label} {expr[:80]}")
                    empty += 1
                else:
                    print(f"  {GREEN}OK{RESET}   {label} {n} series")
    print(f"\n{total - empty}/{total} expressions returning data")
    return empty


if __name__ == "__main__":
    sys.exit(min(main(), 120))
