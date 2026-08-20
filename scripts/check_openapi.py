#!/usr/bin/env python3
"""
Validate the generated OpenAPI spec.

This exists because a generator misconfiguration once produced a spec with
`paths: {}` — structurally valid YAML, completely useless, and silent. A
published API document that is quietly empty is worse than none, because
consumers trust it.

It also cross-checks the document against the .proto it is generated from. The
OpenAPI generator reads gnostic annotations and knows nothing of
`chronos.options.v1`, so an RPC's `public` option and its published `security`
are two statements of one fact — and the SECOND one is the one clients read
while the FIRST is the one the authentication interceptor enforces. When the
paths were hand-written they had already diverged: `ResendEmailVerification` is
`public = true` and was published as requiring a bearer token. That is a
documented lie about an authentication boundary, and it is the class of bug this
file exists to make impossible, so it is checked here rather than trusted.

Exits non-zero on any problem.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "api" / "chronos-openapi.yaml"
PROTO_DIR = ROOT / "proto" / "chronos"
G, R, Y, X = "\033[32m", "\033[31m", "\033[33m", "\033[0m"

try:
    import yaml
except ImportError:
    # FAIL, not skip. This used to `sys.exit(0)`, which made the OpenAPI gate in
    # `make check` pass by doing nothing on any machine without PyYAML — including
    # CI, whose workflow calls this script and never installs it. The spec could
    # have been `paths: {}` and the build would have stayed green, which is the
    # exact failure this script was written to catch after it happened once.
    #
    # A gate that cannot run has not been satisfied. Say so and stop.
    print(
        f"{R}FAIL{X}  PyYAML is not installed, so the OpenAPI spec was NOT checked.\n"
        f"      This is a failure and not a skip: an unrun gate proves nothing, and\n"
        f"      treating it as a pass is how an empty spec ships.\n"
        f"      Install it:  pip install pyyaml   (or: python3 -m venv .venv && "
        f".venv/bin/pip install pyyaml)"
    )
    sys.exit(1)

problems: list[str] = []


def check(ok: bool, msg: str) -> bool:
    if ok:
        print(f"  {G}OK{X}    {msg}")
    else:
        print(f"  {R}FAIL{X}  {msg}")
        problems.append(msg)
    return ok


if not SPEC.exists():
    sys.exit(f"{R}missing{X} {SPEC} — run `make api-docs`")

spec = yaml.safe_load(SPEC.read_text())

print("openapi spec validation\n")

check(str(spec.get("openapi", "")).startswith("3."), "declares OpenAPI 3.x")

info = spec.get("info") or {}
check(bool(info.get("title")), "info.title is set")
check(bool(info.get("version")), "info.version is set")
check(len(info.get("description") or "") > 200,
      "info.description is substantive, not a placeholder")
check(bool(spec.get("servers")), "servers are declared")
check(bool(spec.get("externalDocs")), "externalDocs links the error catalogue")

schemes = ((spec.get("components") or {}).get("securitySchemes") or {})
check(bool(schemes), "security schemes are documented")

paths = spec.get("paths") or {}
# The regression this file exists to catch.
check(len(paths) > 0, f"paths is NOT empty ({len(paths)} documented)")

ops = 0
seen_ids: dict[str, str] = {}
for path, item in paths.items():
    for verb, op in (item or {}).items():
        if verb not in {"get", "post", "put", "patch", "delete"}:
            continue
        ops += 1
        where = f"{verb.upper()} {path}"
        op_id = op.get("operationId")
        if not op_id:
            problems.append(f"{where}: no operationId (generated clients need it)")
        elif op_id in seen_ids:
            # operationId must be unique document-wide. A method exposed as both
            # GET and POST is the case that breaks it: one shared id makes every
            # generated client emit two methods with one name.
            problems.append(
                f"{where}: operationId {op_id!r} is already used by {seen_ids[op_id]}")
        else:
            seen_ids[op_id] = where
        if not op.get("responses"):
            problems.append(f"{where}: no responses documented")
        # Descriptions come from proto comments; an empty one means the comment
        # lint was bypassed or the generator dropped it.
        if not (op.get("summary") or op.get("description")):
            problems.append(f"{where}: no summary or description — is the RPC documented?")

check(ops > 0, f"operations are documented ({ops})")
check(len(seen_ids) == ops, f"every operationId is unique ({len(seen_ids)} of {ops})")


# --- the published document vs the schema it claims to be generated from ------
#
# Parsed with a regex rather than a descriptor set on purpose: the check must run
# in CI with nothing installed but Python, and it is comparing two TEXTS that are
# meant to agree. A descriptor set would be a third artifact to keep in step.
RPC_RE = re.compile(r"\brpc\s+(\w+)\s*\([^)]*\)\s*returns\s*\([^)]*\)\s*(\{.*?\n  \}|;)", re.S)


def public_rpc_paths() -> tuple[set[str], int]:
    """Every /<package>.<Service>/<Method> whose RPC declares public = true."""
    public: set[str] = set()
    total = 0
    for proto in sorted(PROTO_DIR.rglob("*.proto")):
        src = proto.read_text()
        pkg = re.search(r"^package\s+([\w.]+)\s*;", src, re.M)
        if not pkg:
            continue
        for svc in re.finditer(r"^service\s+(\w+)\s*\{", src, re.M):
            # The service body: from its opening brace to the closing brace in
            # column 0.
            start = svc.end()
            end = src.find("\n}", start)
            body = src[start:end if end != -1 else len(src)]
            for rpc in RPC_RE.finditer(body):
                total += 1
                route = f"/{pkg.group(1)}.{svc.group(1)}/{rpc.group(1)}"
                if re.search(r"\(chronos\.options\.v1\.public\)\s*=\s*true", rpc.group(2)):
                    public.add(route)
    return public, total


public, declared = public_rpc_paths()
check(declared > 0, f"the .proto sources were parsed ({declared} RPCs found)")

mismatched: list[str] = []
for path, item in paths.items():
    for verb, op in (item or {}).items():
        if verb not in {"get", "post", "put", "patch", "delete"}:
            continue
        sec = op.get("security")
        where = f"{verb.upper()} {path}"
        if path in public:
            # An empty requirement overrides the document default. `[]` cannot be
            # produced from a proto annotation (an empty repeated field is
            # indistinguishable from an unset one), so `[{}]` — "satisfiable with
            # nothing" — is the form used, and it is what is checked for.
            if sec != [{}]:
                mismatched.append(
                    f"{where}: declares public = true but publishes security {sec!r}")
        elif sec is not None:
            mismatched.append(
                f"{where}: is NOT public but overrides the document security default "
                f"with {sec!r}")
problems.extend(mismatched)
check(not mismatched,
      f"published security matches (chronos.options.v1.public) on all {ops} operations")

missing = sorted(p for p in public if p not in paths)
check(not missing, "every public RPC appears in the document"
      + ("" if not missing else f" — missing: {missing}"))
problems.extend(f"{p}: public RPC is absent from the document" for p in missing)

# Every $ref must resolve, or a client generator produces broken code.
text = SPEC.read_text()
refs = set(re.findall(r"\$ref:\s*'?\"?(#/[^'\"\s]+)", text))
dangling = []
for ref in refs:
    node = spec
    for part in ref.lstrip("#/").split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            dangling.append(ref)
            break
check(not dangling, f"all {len(refs)} $refs resolve"
      + ("" if not dangling else f" — dangling: {dangling[:3]}"))

# Nothing unreachable may be published — this is what `trim-unused-types` is for,
# and the leak it was turned on to stop was annotation machinery from
# `chronos.options.v1` arriving in `components.schemas` because the generator was
# handed options.proto.
#
# The check used to be `"chronos.options.v1" not in <whole file>`, and it was
# WRONG in both directions. It fired on `chronos.options.v1.AssuranceLevel`,
# which three response messages carry as an ordinary field type and which
# therefore belongs in the document; and it fired on prose in `info.description`
# that names the `public` option, which is the document correctly telling a
# reader where `security` comes from. Meanwhile it would have said nothing about
# an unused type from any other package.
#
# So the property is stated directly instead: every published schema is reachable
# from something. `Authz` and friends are unreachable the moment they are not a
# field type, and are caught by that without being named.
#
# One schema is unreachable ON PURPOSE and is named here rather than tolerated by
# a looser rule: `chronos.errors.v1.ErrorDetail` is injected by
# internal/tools/gendocs as `override=`, and it reaches a client inside
# `connect.error.details`, whose items are `google.protobuf.Any`. OpenAPI cannot
# express "an Any that is really this message", so there is no $ref to find and
# the generator's own trimming would drop it. Published deliberately, unreachable
# unavoidably.
INTENTIONALLY_UNREFERENCED = {"chronos.errors.v1.ErrorDetail"}

schemas = ((spec.get("components") or {}).get("schemas") or {})
referenced = {r.rsplit("/", 1)[-1] for r in refs if r.startswith("#/components/schemas/")}
orphans = sorted(name for name in schemas
                 if name.replace("~", "~0").replace("/", "~1") not in referenced
                 and name not in INTENTIONALLY_UNREFERENCED)
# The exemption must not outlive the thing it exempts.
for name in sorted(INTENTIONALLY_UNREFERENCED - set(schemas)):
    problems.append(f"{name} is exempted from the reachability check but is not "
                    f"published at all — drop the exemption")
check(not orphans, f"all {len(schemas)} published schemas are reachable"
      + ("" if not orphans else f" — unreferenced: {orphans[:5]}"))
problems.extend(f"components.schemas.{name}: published but referenced by nothing"
                for name in orphans)

print()
if problems:
    print(f"{R}{len(problems)} problem(s){X}")
    for p in problems:
        print(f"  - {p}")
    sys.exit(1)
print(f"{G}spec is valid and non-empty{X}")
