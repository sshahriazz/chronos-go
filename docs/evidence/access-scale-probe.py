#!/usr/bin/env python3
"""Stress the access topology: depth limits, cycles, wide teams, BatchCheck, ListObjects."""
import json, os, statistics, time, urllib.request, urllib.error

BASE, KEY = "http://localhost:8080", os.environ.get("OPENFGA_PRESHARED_KEY", "chronos_dev_openfga_key")
G, R, Y, X = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def call(path, body=None, method="POST"):
    d = json.dumps(body).encode() if body is not None else None
    rq = urllib.request.Request(BASE + path, data=d, method=method,
                                headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(rq, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        return {"__error": e.code, "__body": e.read().decode()[:300]}


THIS, U = {"this": {}}, [{"type": "user"}]
UT = [{"type": "user"}, {"type": "team", "relation": "member"}]
ttu = lambda via, rel: {"tupleToUserset": {"tupleset": {"relation": via}, "computedUserset": {"relation": rel}}}
MODEL = {"schema_version": "1.1", "type_definitions": [
    {"type": "user"},
    {"type": "team", "relations": {"member": THIS},
     "metadata": {"relations": {"member": {"directly_related_user_types": U}}}},
    {"type": "folder", "relations": {
        "parent": THIS, "viewer": {"union": {"child": [THIS, ttu("parent", "viewer")]}}},
     "metadata": {"relations": {"parent": {"directly_related_user_types": [{"type": "folder"}]},
                                "viewer": {"directly_related_user_types": UT}}}},
]}

store = call("/stores", {"name": "access-scale-probe"})["id"]
model = call(f"/stores/{store}/authorization-models", MODEL)["authorization_model_id"]
W, C = f"/stores/{store}/write", f"/stores/{store}/check"
t = lambda u, r, o: {"user": u, "relation": r, "object": o}


def write(tuples):
    for i in range(0, len(tuples), 100):
        res = call(W, {"authorization_model_id": model, "writes": {"tuple_keys": tuples[i:i + 100]}})
        if "__error" in res:
            return res
    return {}


def check(u, r, o, ctx=None, mode="HIGHER_CONSISTENCY"):
    b = {"tuple_key": t(u, r, o), "authorization_model_id": model, "consistency": mode}
    if ctx:
        b["contextual_tuples"] = {"tuple_keys": ctx}
    return call(C, b)


def timed(fn, n=15):
    ts = []
    for _ in range(n):
        s = time.perf_counter(); fn(); ts.append((time.perf_counter() - s) * 1000)
    ts.sort()
    return statistics.median(ts), ts[int(len(ts) * 0.95)]


print("=== 1. DEPTH: how deep can inheritance go before it breaks? ===")
write([t("user:deep", "viewer", "folder:d0")])
depth_limit = None
for d in range(1, 41):
    write([t(f"folder:d{d-1}", "parent", f"folder:d{d}")])
    if d in (1, 5, 10, 15, 20, 25, 30, 35, 40):
        r = check("user:deep", "viewer", f"folder:d{d}")
        if "__error" in r or not r.get("allowed"):
            err = r.get("__body", "not allowed")[:90]
            print(f"  {R}depth {d:>2}: FAILS{X}  {err}")
            depth_limit = depth_limit or d
        else:
            med, p95 = timed(lambda dd=d: check("user:deep", "viewer", f"folder:d{dd}"))
            print(f"  {G}depth {d:>2}: allow{X}   p50={med:6.2f}ms  p95={p95:6.2f}ms")
print(f"  {Y}==> first failing depth: {depth_limit or 'none up to 40'}{X}")

print("\n=== 2. CYCLE: what does OpenFGA do with a self-referential parent? ===")
write([t("folder:cyc_a", "parent", "folder:cyc_b"), t("folder:cyc_b", "parent", "folder:cyc_a")])
s = time.perf_counter()
r = check("user:nobody", "viewer", "folder:cyc_a")
el = (time.perf_counter() - s) * 1000
print(f"  result={r.get('allowed', r.get('__body','?'))[:80] if isinstance(r.get('allowed', ''), str) else r.get('allowed')}  in {el:.1f}ms")
print(f"  {Y}==> cycles do not hang; they resolve/err — but produce wrong-shaped graphs{X}")

print("\n=== 3. WIDE TEAM: 1000 members, one grant ===")
write([t(f"user:w{i}", "member", "team:wide") for i in range(1000)])
write([t("team:wide#member", "viewer", "folder:wideroot"),
       t("folder:wideroot", "parent", "folder:widechild")])
med, p95 = timed(lambda: check("user:w500", "viewer", "folder:widechild"))
print(f"  {G}Check via 1000-member team{X}  p50={med:6.2f}ms  p95={p95:6.2f}ms")
s = time.perf_counter()
lu = call(f"/stores/{store}/list-users", {"authorization_model_id": model,
          "object": {"type": "folder", "id": "widechild"}, "relation": "viewer",
          "user_filters": [{"type": "user"}]})
el = (time.perf_counter() - s) * 1000
print(f"  {Y}ListUsers -> {len(lu.get('users', []))} users in {el:.0f}ms  (expands the whole team){X}")

print("\n=== 4. BatchCheck vs N sequential Checks (a 50-item page) ===")
write([t("folder:wideroot", "parent", f"folder:page{i}") for i in range(50)])
s = time.perf_counter()
for i in range(50):
    check("user:w500", "viewer", f"folder:page{i}", mode="MINIMIZE_LATENCY")
seq = (time.perf_counter() - s) * 1000
items = [{"tuple_key": t("user:w500", "viewer", f"folder:page{i}"), "correlation_id": f"c{i}"} for i in range(50)]
s = time.perf_counter()
bc = call(f"/stores/{store}/batch-check", {"authorization_model_id": model, "checks": items,
                                           "consistency": "MINIMIZE_LATENCY"})
batch = (time.perf_counter() - s) * 1000
ok = len(bc.get("result", {})) if "__error" not in bc else bc.get("__body", "")[:80]
print(f"  50 sequential Checks : {seq:7.0f} ms")
print(f"  1 BatchCheck         : {batch:7.0f} ms   -> {ok} results")
if isinstance(ok, int) and ok:
    print(f"  {G}==> BatchCheck is {seq/batch:.1f}x faster for a page{X}")

print("\n=== 5. ListObjects at scale ===")
for mode in ("MINIMIZE_LATENCY", "HIGHER_CONSISTENCY"):
    s = time.perf_counter()
    lo = call(f"/stores/{store}/list-objects", {"authorization_model_id": model, "type": "folder",
              "relation": "viewer", "user": "user:w500", "consistency": mode})
    el = (time.perf_counter() - s) * 1000
    print(f"  {mode:20s} -> {len(lo.get('objects', []))} objects in {el:7.0f} ms")

print("\n=== 6. Contextual tuples (read-your-writes cost) ===")
ctx = [t("user:fresh", "viewer", "folder:wideroot")]
med0, _ = timed(lambda: check("user:w500", "viewer", "folder:widechild"))
med1, _ = timed(lambda: check("user:fresh", "viewer", "folder:widechild", ctx=ctx))
print(f"  without contextual: p50={med0:6.2f}ms")
print(f"  with 1 contextual : p50={med1:6.2f}ms   (grant visible immediately: "
      f"{check('user:fresh','viewer','folder:widechild',ctx=ctx).get('allowed')})")

call(f"/stores/{store}", method="DELETE")
print("\n(store deleted)")
