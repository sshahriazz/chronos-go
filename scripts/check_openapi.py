#!/usr/bin/env python3
"""
Validate the generated OpenAPI spec.

This exists because a generator misconfiguration once produced a spec with
`paths: {}` — structurally valid YAML, completely useless, and silent. A
published API document that is quietly empty is worse than none, because
consumers trust it.

Exits non-zero on any problem.
"""
import re
import sys
from pathlib import Path

SPEC = Path(__file__).resolve().parent.parent / "docs" / "api" / "chronos-openapi.yaml"
G, R, Y, X = "\033[32m", "\033[31m", "\033[33m", "\033[0m"

try:
    import yaml
except ImportError:
    print(f"{Y}skip{X}  PyYAML not installed (pip install pyyaml)")
    sys.exit(0)

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
for path, item in paths.items():
    for verb, op in (item or {}).items():
        if verb not in {"get", "post", "put", "patch", "delete"}:
            continue
        ops += 1
        where = f"{verb.upper()} {path}"
        if not op.get("operationId"):
            problems.append(f"{where}: no operationId (generated clients need it)")
        if not op.get("responses"):
            problems.append(f"{where}: no responses documented")
        # Descriptions come from proto comments; an empty one means the comment
        # lint was bypassed or the generator dropped it.
        if not (op.get("summary") or op.get("description")):
            problems.append(f"{where}: no summary or description — is the RPC documented?")

check(ops > 0, f"operations are documented ({ops})")

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

# Annotation-only packages must not leak into the published surface.
check("chronos.options.v1" not in text,
      "annotation-only types are trimmed from the public spec")

print()
if problems:
    print(f"{R}{len(problems)} problem(s){X}")
    for p in problems:
        print(f"  - {p}")
    sys.exit(1)
print(f"{G}spec is valid and non-empty{X}")
