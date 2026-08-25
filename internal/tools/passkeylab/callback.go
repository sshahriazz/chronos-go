package main

// callbackPage completes a federated ceremony from the browser.
//
// # Why the ceremony finishes here and not in the Go handler
//
// This tool holds no credentials and must not: exchanging the code needs the
// client secret and the PKCE verifier, both of which live in cmd/api. The
// browser lands here with a code and a state, posts them through the same proxy
// every other call uses, and shows what came back.
//
// It is also where the ONE outcome that is not a session gets rendered honestly.
// A refused auto-link is identity.md §7 rule 2 working, not a failure, and a
// harness that showed it as an error would misrepresent the flow it exists to
// test.
const callbackPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Federated callback</title>
<style>
  :root {
    --bg: #fbfbfa; --panel: #fff; --ink: #17181c; --muted: #6b6f76;
    --line: #e3e4e8; --accent: #2f5bd7; --ok: #1a7f4b; --bad: #a4262c;
    --mono: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #16171a; --panel: #1e1f24; --ink: #e9eaee; --muted: #9aa0a8;
      --line: #2e3038; --accent: #7d9bf0; --ok: #4ec27f; --bad: #ef8b90;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 20px; background: var(--bg); color: var(--ink);
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, sans-serif;
  }
  main { max-width: 680px; margin: 0 auto; }
  h1 { font-size: 19px; margin: 0 0 6px; letter-spacing: -0.01em; }
  p.lede { margin: 0 0 18px; color: var(--muted); font-size: 14px; }
  section {
    background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; padding: 16px 18px; margin-bottom: 14px;
  }
  pre {
    margin: 0; padding: 12px; background: var(--bg); border: 1px solid var(--line);
    border-radius: 6px; font: 12px/1.5 var(--mono); white-space: pre-wrap;
    word-break: break-word; max-height: 340px; overflow: auto;
  }
  a { color: var(--accent); }
  .ok { color: var(--ok); } .bad { color: var(--bad); }
  .verdict { font-size: 15px; font-weight: 500; margin: 0 0 10px; }
</style>
</head>
<body>
<main>
  <h1>Federated callback</h1>
  <p class="lede">
    The provider sent the browser back here. The code is exchanged server-side —
    this page holds no credentials and never sees the client secret or the PKCE
    verifier.
  </p>
  <section>
    <p class="verdict" id="verdict">Working…</p>
    <pre id="out">—</pre>
  </section>
  <p class="lede"><a href="/">← back to the lab</a></p>
</main>

<script>
const show = (verdict, body, bad) => {
  const v = document.getElementById('verdict');
  v.textContent = verdict;
  v.className = 'verdict ' + (bad ? 'bad' : 'ok');
  document.getElementById('out').textContent =
    typeof body === 'string' ? body : JSON.stringify(body, null, 2);
};

async function rpc(method, body) {
  const headers = {
    'Content-Type': 'application/json',
    'Idempotency-Key': 'idem_lab_' + crypto.randomUUID().replace(/-/g, '').slice(0, 26).toUpperCase(),
  };
  // A LINK is performed by an authenticated caller; a sign-in is not. The lab
  // stores the bearer so a link started from the main page can finish here.
  const bearer = sessionStorage.getItem('chronos_bearer');
  if (bearer && method === 'FinishFederatedLink') headers['Authorization'] = 'Bearer ' + bearer;

  const res = await fetch('/chronos.identity.v1.IdentityService/' + method, {
    method: 'POST', headers, body: JSON.stringify(body),
  });
  const text = await res.text();
  let parsed;
  try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = { raw: text }; }
  if (!res.ok) {
    const err = new Error(parsed.message || res.statusText);
    err.detail = { status: res.status, ...parsed };
    throw err;
  }
  return parsed;
}

(async () => {
  const q = new URLSearchParams(location.search);
  const code = q.get('code');
  const state = q.get('state');
  // RFC 9207. Passed through verbatim: when the provider sends it the server
  // compares it, and when it does not the field is simply absent.
  const iss = q.get('iss') || '';
  const provider = sessionStorage.getItem('chronos_provider') || 'google';
  const mode = sessionStorage.getItem('chronos_fed_mode') || 'signin';

  if (q.get('error')) {
    show('The provider refused', {
      error: q.get('error'),
      description: q.get('error_description') || '',
      note: 'This came from the provider, not from Chronos. Nothing was exchanged.',
    }, true);
    return;
  }
  if (!code || !state) {
    show('Nothing to complete', 'The callback carried no code and no state.', true);
    return;
  }

  try {
    if (mode === 'link') {
      await rpc('FinishFederatedLink', { provider, code, state, iss });
      show('Linked', {
        provider,
        note: 'The provider is attached to your account. Nothing about the ' +
              'auto-link rules was consulted — you had already proven the ' +
              'account, which is exactly what those rules substitute for.',
      });
      return;
    }

    const out = await rpc('FinishFederatedSignIn', { provider, code, state, iss });

    if (out.linkRefused) {
      // NOT an error. identity.md §7 rule 2.
      show('Signed in, and deliberately NOT linked', {
        linkRefused: true,
        accountExists: out.accountExists || false,
        why: out.accountExists
          ? 'An account already claims that address, and the conditions for an ' +
            'automatic link were not all met. Sign in with an existing method ' +
            'and link this provider from settings — auto-linking on an email ' +
            'match alone is the account takeover §7 exists to refuse.'
          : 'No account claims that address, so there was nothing to link to.',
      });
      return;
    }

    if (out.token) sessionStorage.setItem('chronos_bearer', out.token);
    show('Signed in', {
      sessionId: out.sessionId,
      assuranceLevel: out.assuranceLevel,
      note: 'AAL1 is expected: identity.md §2 puts a federated link alone on ' +
            'that row, because the provider may have required its own second ' +
            'factor and this system has no way to know that it did. Anything ' +
            'sensitive will ask for step-up.',
    });
  } catch (e) {
    show('Refused', e.detail || String(e), true);
  }
})();
</script>
</body>
</html>`
