#!/usr/bin/env python3
"""Prove the Drive-shaped access topology against the running OpenFGA."""
import json, os, time, urllib.request, urllib.error

BASE = "http://localhost:8080"
KEY = os.environ.get("OPENFGA_PRESHARED_KEY", "chronos_dev_openfga_key")
G, R, Y, X = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def call(path, body=None, method="POST"):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {KEY}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{path} -> {e.code} {e.read().decode()[:500]}")


def direct(t):  # shorthand for directly_related_user_types
    return {"directly_related_user_types": t}


U = [{"type": "user"}]
UT = [{"type": "user"}, {"type": "team", "relation": "member"}]


def ttu(via, rel):
    return {"tupleToUserset": {"tupleset": {"relation": via},
                               "computedUserset": {"relation": rel}}}


def union(*children):
    return {"union": {"child": list(children)}}


THIS = {"this": {}}
MODEL = {
    "schema_version": "1.1",
    "type_definitions": [
        {"type": "user"},
        {"type": "team",
         "relations": {"member": THIS},
         "metadata": {"relations": {"member": direct(U)}}},
        # container: nests into itself -> arbitrary depth
        {"type": "folder",
         "relations": {
             "parent": THIS,
             "owner": THIS,
             "editor": union(THIS, ttu("parent", "editor")),
             "viewer": union(THIS, {"computedUserset": {"relation": "editor"}},
                             ttu("parent", "viewer")),
         },
         "metadata": {"relations": {
             "parent": direct([{"type": "folder"}]),
             "owner": direct(U), "editor": direct(UT), "viewer": direct(UT)}}},
        # leaf
        {"type": "file",
         "relations": {
             "parent": THIS,
             "editor": union(THIS, ttu("parent", "editor")),
             "viewer": union(THIS, {"computedUserset": {"relation": "editor"}},
                             ttu("parent", "viewer")),
         },
         "metadata": {"relations": {
             "parent": direct([{"type": "folder"}]),
             "editor": direct(UT), "viewer": direct(UT)}}},
    ],
}

store = call("/stores", {"name": "access-topology-probe"})["id"]
model = call(f"/stores/{store}/authorization-models", MODEL)["authorization_model_id"]
print(f"store={store}\nmodel={model}\n")


def write(tuples=None, deletes=None):
    body = {"authorization_model_id": model}
    if tuples:
        body["writes"] = {"tuple_keys": tuples}
    if deletes:
        body["deletes"] = {"tuple_keys": deletes}
    return call(f"/stores/{store}/write", body)


def t(user, relation, obj):
    return {"user": user, "relation": relation, "object": obj}


def parent(p, c):
    """In OpenFGA the OBJECT is the child: 'p is the parent of c'."""
    return t(p, "parent", c)


def check(user, relation, obj, consistency="HIGHER_CONSISTENCY"):
    r = call(f"/stores/{store}/check",
             {"tuple_key": t(user, relation, obj),
              "authorization_model_id": model, "consistency": consistency})
    return r.get("allowed", False)


def expect(label, got, want):
    ok = got == want
    print(f"  {G+'PASS'+X if ok else R+'FAIL'+X}  {label:58s} got={got} want={want}")
    return 0 if ok else 1


fails = 0
print("=== 1. team grant on a folder, 3 levels deep, ONE tuple ===")
write([
    t("user:alice", "member", "team:eng"),
    t("user:bob", "member", "team:eng"),
    t("team:eng#member", "editor", "folder:root"),      # <-- the only grant
    parent("folder:root", "folder:projects"),
    parent("folder:projects", "folder:q3"),
    parent("folder:q3", "file:spec"),
])
fails += expect("alice (via team) can edit deeply nested file", check("user:alice", "editor", "file:spec"), True)
fails += expect("bob   (via team) can view deeply nested file", check("user:bob", "viewer", "file:spec"), True)
fails += expect("carol (no team)  cannot view it", check("user:carol", "viewer", "file:spec"), False)

print("\n=== 2. FUTURE resources inherit with no new grant ===")
write([parent("folder:q3", "file:created_later")])
fails += expect("file created AFTER the grant is inherited", check("user:alice", "editor", "file:created_later"), True)
write([parent("folder:q3", "folder:deeper"), parent("folder:deeper", "file:deepest")])
fails += expect("new subtree created AFTER the grant inherits", check("user:alice", "editor", "file:deepest"), True)

print("\n=== 3. scale: 100 individual members vs 1 team tuple ===")
big = [t(f"user:m{i}", "viewer", "folder:root") for i in range(100)]
for i in range(0, 100, 50):
    write(big[i:i + 50])
fails += expect("individually-granted member reaches nested file", check("user:m73", "viewer", "file:spec"), True)
print(f"  {Y}note{X}  100 members = 100 tuples individually, 1 tuple via team")

print("\n=== 4. break inheritance (remove the permission edge) ===")
write(deletes=[parent("folder:projects", "folder:q3")])
fails += expect("alice loses inherited access to restricted subtree", check("user:alice", "editor", "file:spec"), False)
write([t("user:alice", "viewer", "folder:q3")])
fails += expect("direct grant still works inside restricted subtree", check("user:alice", "viewer", "file:spec"), True)
fails += expect("bob still excluded from restricted subtree", check("user:bob", "viewer", "file:spec"), False)
write([parent("folder:projects", "folder:q3")])
fails += expect("restoring the edge restores inherited access", check("user:bob", "viewer", "file:spec"), True)

print("\n=== 5. realtime revocation ===")
write(deletes=[t("user:alice", "member", "team:eng")])
fails += expect("removing team membership revokes everywhere", check("user:alice", "editor", "file:created_later"), False)
write([t("user:alice", "member", "team:eng")])
fails += expect("re-adding restores access immediately", check("user:alice", "editor", "file:created_later"), True)

print("\n=== 6. stale-read window (MINIMIZE_LATENCY vs HIGHER_CONSISTENCY) ===")
write(deletes=[t("user:bob", "member", "team:eng")])
lo = check("user:bob", "editor", "file:created_later", "MINIMIZE_LATENCY")
hi = check("user:bob", "editor", "file:created_later", "HIGHER_CONSISTENCY")
print(f"  MINIMIZE_LATENCY={lo}  HIGHER_CONSISTENCY={hi}")
fails += expect("HIGHER_CONSISTENCY reflects the revoke", hi, False)

print("\n=== 7. latency (warm) ===")
for mode in ("MINIMIZE_LATENCY", "HIGHER_CONSISTENCY"):
    s = time.time()
    for _ in range(20):
        check("user:m73", "viewer", "file:deepest", mode)
    print(f"  {mode:20s} {(time.time()-s)/20*1000:6.2f} ms/check (depth 4)")

print("\n=== 8. ListObjects / ListUsers ===")
lo = call(f"/stores/{store}/list-objects",
          {"authorization_model_id": model, "type": "file",
           "relation": "viewer", "user": "user:m73"})
print(f"  ListObjects(m73, viewer, file) -> {sorted(lo.get('objects', []))}")
lu = call(f"/stores/{store}/list-users",
          {"authorization_model_id": model,
           "object": {"type": "file", "id": "created_later"},
           "relation": "viewer", "user_filters": [{"type": "user"}]})
users = [u.get("object", {}).get("id") for u in lu.get("users", [])]
print(f"  ListUsers(file:created_later, viewer) -> {len(users)} users")

call(f"/stores/{store}", method="DELETE")
print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILURES'} (store deleted)")
raise SystemExit(1 if fails else 0)
