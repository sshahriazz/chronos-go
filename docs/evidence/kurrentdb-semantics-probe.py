#!/usr/bin/env python3
"""Verify the KurrentDB semantics the architecture depends on."""
import json, os, urllib.request, urllib.error, uuid

BASE = f"http://localhost:{os.environ.get('KURRENTDB_PORT', '2113')}"
G, R, Y, X = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
EV_JSON = "application/vnd.eventstore.events+json"


def req(method, path, body=None, headers=None, accept=None):
    h = dict(headers or {})
    if accept:
        h["Accept"] = accept
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", EV_JSON)
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw.strip() and accept else raw)
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200]


def ev(etype, data, eid=None):
    return [{"eventId": eid or str(uuid.uuid4()), "eventType": etype, "data": data}]


def expect(label, got, want):
    ok = got == want
    print(f"  {G+'PASS'+X if ok else R+'FAIL'+X}  {label:56s} got={got} want={want}")
    return 0 if ok else 1


fails = 0
sid = uuid.uuid4().hex[:8]

print("=== 1. optimistic concurrency (the aggregate consistency boundary) ===")
s = f"organization-{sid}"
code, _ = req("POST", f"/streams/{s}", ev("OrganizationCreated", {"n": 1}),
              {"ES-ExpectedVersion": "-1"})          # -1 = NoStream
fails += expect("append to new stream with ExpectedVersion=NoStream", code, 201)
code, _ = req("POST", f"/streams/{s}", ev("OrganizationRenamed", {"n": 2}),
              {"ES-ExpectedVersion": "-1"})          # stale — stream now exists
fails += expect("STALE expected version is REJECTED", code, 400)
code, _ = req("POST", f"/streams/{s}", ev("OrganizationRenamed", {"n": 2}),
              {"ES-ExpectedVersion": "0"})           # correct
fails += expect("correct expected version succeeds", code, 201)

print("\n=== 2. idempotency: same eventId + same expected version ===")
dup = str(uuid.uuid4())
req("POST", f"/streams/{s}", ev("PolicyChanged", {"x": 1}, dup), {"ES-ExpectedVersion": "1"})
code, _ = req("POST", f"/streams/{s}", ev("PolicyChanged", {"x": 1}, dup), {"ES-ExpectedVersion": "1"})
fails += expect("replayed append is accepted, not duplicated", code, 201)
_, head = req("GET", f"/streams/{s}/head/backward/20", accept="application/vnd.eventstore.atom+json")
n = len(head["entries"])
fails += expect("stream still has exactly 3 events (no dup)", n, 3)

print("\n=== 3. uniqueness reservation (event stores have no unique index) ===")
email = f"user-{sid}@example.com"
res = f"reservation_email-{email}"
code, _ = req("POST", f"/streams/{res}", ev("EmailReserved", {"by": "usr_a"}),
              {"ES-ExpectedVersion": "-1"})
fails += expect("first claim of an email wins", code, 201)
code, _ = req("POST", f"/streams/{res}", ev("EmailReserved", {"by": "usr_b"}),
              {"ES-ExpectedVersion": "-1"})
fails += expect("second claim is REJECTED atomically", code, 400)

print("\n=== 4. category streams need $by_category (projections are OFF) ===")
code, _ = req("GET", f"/streams/$ce-organization/head/backward/1",
              accept="application/vnd.eventstore.atom+json")
fails += expect("$ce-organization is unavailable", code, 404)
code, body = req("GET", "/info", accept="application/json")
print(f"  {Y}note{X}  /info features: {body.get('features')}")

print("\n=== 5. stream metadata: $maxCount (snapshot-stream pattern) ===")
meta = f"/streams/{s}/metadata"
code, _ = req("POST", meta, [{"eventId": str(uuid.uuid4()), "eventType": "$metadata",
                              "data": {"$maxCount": 1}}])
fails += expect("stream metadata accepted", code, 201)

print("\n=== 6. $all is globally ordered (single projector ordering guarantee) ===")
code, allb = req("GET", "/streams/%24all/head/backward/5",
                 accept="application/vnd.eventstore.atom+json")
fails += expect("$all is readable", code, 200)
if code == 200:
    print(f"  {Y}note{X}  newest $all entries: {[e['title'] for e in allb['entries'][:3]]}")

    sysev = [e['title'] for e in allb['entries'] if '@$' in e['title'] or e['title'].startswith('0@$$')]
    print(f"  {Y}note{X}  $all CARRIES system/metadata events -> projectors must filter: {bool(sysev)}")

print("\n=== 7. soft delete then recreate ===")
code, _ = req("DELETE", f"/streams/{s}")
fails += expect("soft delete succeeds", code, 204)
code, _ = req("POST", f"/streams/{s}", ev("OrganizationReopened", {}),
              {"ES-ExpectedVersion": "-2"})          # -2 = Any
fails += expect("soft-deleted stream can be reopened", code, 201)

print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILURES'}")
raise SystemExit(1 if fails else 0)
