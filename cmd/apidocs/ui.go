package main

import "fmt"

// The documentation site publishes ONE reference: REST.
//
// It previously published two — a Scalar-rendered OpenAPI surface and a
// protoc-gen-doc gRPC surface — on the reasoning that the two audiences are
// different. They are, but a gRPC audience is served better by the .proto
// sources and by reflection than by a second prose document, and a second
// document is a second thing that can go stale, a second thing to review, and a
// second place a reader has to check before believing the first.
//
// gRPC has NOT been removed from the product. The server still carries it on the
// same port, still answers reflection, and the schema it is generated from is
// served under /proto/. What was removed is a duplicate rendering of that schema.

const navHTML = `<nav class="chrono-nav">
  <a class="brand" href="/">Chronos API</a>
  <a href="/reference"%s>REST reference</a>
  <a href="/errors.md">Errors</a>
  <a href="/proto/">Protos</a>
</nav>`

const navCSS = `
.chrono-nav{position:sticky;top:0;z-index:9999;display:flex;gap:.25rem;align-items:center;
  padding:.55rem 1rem;background:#111827;color:#e5e7eb;font:14px/1 system-ui,sans-serif;
  border-bottom:1px solid #374151}
.chrono-nav a{color:#9ca3af;text-decoration:none;padding:.4rem .7rem;border-radius:.35rem}
.chrono-nav a:hover{color:#fff;background:#1f2937}
.chrono-nav a[aria-current]{color:#fff;background:#2563eb}
.chrono-nav .brand{font-weight:600;color:#fff;margin-right:.75rem;padding-left:0}
`

// nav renders the shared header, marking the active surface.
func nav(active string) string {
	mark := func(name string) string {
		if name == active {
			return ` aria-current="page"`
		}
		return ""
	}
	return fmt.Sprintf(navHTML, mark("reference"))
}

func indexHTML(apiPort, docsPort string) string {
	return `<!doctype html>
<meta charset="utf-8">
<title>Chronos API</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 :root{color-scheme:light dark}
 *{box-sizing:border-box}
 body{margin:0;font:16px/1.65 system-ui,sans-serif}
 ` + navCSS + `
 main{max-width:62rem;margin:0 auto;padding:2.5rem 1.5rem 5rem}
 h1{margin:0 0 .2rem;font-size:1.9rem}
 .sub{opacity:.7;margin:0 0 2.5rem}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(21rem,1fr));gap:1.25rem}
 .card{border:1px solid color-mix(in srgb,currentColor 18%,transparent);
   border-radius:.7rem;padding:1.25rem 1.35rem}
 .card h2{margin:0 0 .1rem;font-size:1.15rem}
 .card .tag{font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;opacity:.55}
 .card p{margin:.6rem 0 1rem;opacity:.85;font-size:.95rem}
 .btn{display:inline-block;padding:.45rem .9rem;border-radius:.4rem;background:#2563eb;
   color:#fff;text-decoration:none;font-size:.9rem;font-weight:500}
 .btn.ghost{background:transparent;color:inherit;
   border:1px solid color-mix(in srgb,currentColor 30%,transparent)}
 ul{padding-left:1.1rem;margin:.5rem 0} li{margin:.3rem 0;font-size:.93rem}
 a{color:inherit}
 pre{background:color-mix(in srgb,currentColor 7%,transparent);padding:.8rem 1rem;
   border-radius:.45rem;overflow-x:auto;font-size:.83rem;margin:.6rem 0 0}
 code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
 .note{margin-top:2.5rem;padding:1rem 1.25rem;border-left:3px solid #2563eb;
   background:color-mix(in srgb,#2563eb 8%,transparent);border-radius:0 .4rem .4rem 0;font-size:.93rem}
</style>
` + nav("") + `
<main>
  <h1>Chronos API</h1>
  <p class="sub">One schema, published as one REST reference.</p>

  <div class="grid">
    <div class="card">
      <div class="tag">HTTP / JSON</div>
      <h2>REST reference</h2>
      <p>Every endpoint, with its types, headers, validation rules and worked
         examples — and a console to call it from the page. Generated from the
         OpenAPI 3.1 spec, which is generated from the schema the server runs.</p>
      <a class="btn" href="/reference">Open REST reference</a>
      <a class="btn ghost" href="/openapi.yaml">openapi.yaml</a>
      <pre><code>curl -X POST http://localhost:` + apiPort + `/chronos.system.v1.SystemService/GetStatus \
  -H 'Content-Type: application/json' -d '{}'</code></pre>
    </div>

    <div class="card">
      <div class="tag">Contract</div>
      <h2>Errors</h2>
      <p>Clients branch on <code>reason</code>, never on the HTTP status or the
         message.</p>
      <ul>
        <li><code>ACCESS_DENIED</code> → ask an admin</li>
        <li><code>PLAN_UPGRADE_REQUIRED</code> → offer an upgrade</li>
        <li><code>VALIDATION_FAILED</code> → the response names the field</li>
      </ul>
      <a class="btn ghost" href="/errors.md">Full catalogue</a>
    </div>
  </div>

  <div class="grid" style="margin-top:1.25rem">
    <div class="card">
      <div class="tag">Code generation</div>
      <h2>Build a client</h2>
      <p>Generate a typed client in any language from the schema itself — the
         same <code>.proto</code> files the running server was built from.</p>
      <ul>
        <li><a href="/proto/">Proto sources</a> — for <code>buf</code> or <code>protoc</code></li>
        <li><a href="/openapi.yaml">OpenAPI 3.1</a> — for an HTTP client generator</li>
      </ul>
      <pre><code>curl -O http://localhost:` + docsPort + `/openapi.yaml</code></pre>
    </div>
  </div>

  <div class="note">
    <strong>REST is the published surface.</strong> The server also speaks gRPC
    and gRPC-Web on the same port and answers reflection, so a gRPC client
    explores the live server or generates from the
    <a href="/proto/">proto sources</a> above. There is deliberately no second
    reference document: one generated from the schema cannot drift, two can
    disagree with each other. Doc comments are enforced by <code>buf lint</code>,
    validation rules are enforced by an interceptor, and breaking changes fail
    the build.
  </div>
</main>
`
}

// referenceHTML renders the OpenAPI spec with Scalar from an embedded bundle.
//
// No CDN: the binary must work on an air-gapped host, and documentation that
// silently degrades when a third party is unreachable is worse than none.
// Refresh with `make vendor-refresh`.
//
// Scalar over Redoc/Swagger UI: native OpenAPI 3.1 (what we emit) and a built-in
// request console, which matters because our HTTP surface is RPC-shaped POSTs
// that are awkward to hand-craft. It costs ~3x Redoc's bundle — irrelevant for
// an embedded internal tool.
func referenceHTML() string {
	return `<!doctype html>
<meta charset="utf-8">
<title>Chronos API — REST reference</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{margin:0}` + navCSS + `</style>
` + nav("reference") + `
<script id="api-reference" data-url="/openapi.yaml"></script>
<script src="/vendor/scalar.js"></script>
`
}
