package main

// callbackPage is what Google redirects the browser to after consent.
//
// It does three things and then hands over to the console: reads the code and
// state off the query string, posts them to CompleteSignIn with the ceremony id
// the console stored before the redirect, and keeps the PENDING token in
// sessionStorage.
//
// # Why the ceremony id is in sessionStorage rather than in the URL
//
// It is the handle to server-side state holding the PKCE verifier and the
// nonce. Round-tripping it through the provider would mean the browser carried
// it across an origin we do not control, and a value that travels through the
// redirect is a value an attacker who can influence the redirect can substitute
// — which is the whole reason `state` is separate from it.
//
// sessionStorage rather than localStorage: it dies with the tab, which is the
// right lifetime for a five-minute ceremony.
const callbackPage = `<!doctype html>
<meta charset="utf-8">
<title>operator sign-in — callback</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace;
         margin: 0; padding: 2.5rem; max-width: 62rem; }
  h1 { font-size: 1.05rem; margin: 0 0 1.2rem; letter-spacing: .02em; }
  pre { background: rgba(127,127,127,.10); padding: .85rem 1rem; border-radius: 6px;
        white-space: pre-wrap; word-break: break-all; margin: 0 0 1rem; }
  .ok  { color: #128a3e; }
  .bad { color: #c2341d; }
  a { color: inherit; }
</style>
<h1>operator sign-in — step 1 of 2 (SSO)</h1>
<pre id="out">exchanging the authorization code…</pre>
<p id="next"></p>

<script>
const out  = document.getElementById('out');
const next = document.getElementById('next');

function show(text, cls) {
  out.textContent = text;
  out.className = cls || '';
}

async function rpc(method, body, headers) {
  const res = await fetch('/chronos.operator.v1.OperatorService/' + method, {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}),
    body: JSON.stringify(body || {}),
  });
  const text = await res.text();
  let parsed;
  try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = { raw: text }; }
  if (!res.ok) {
    const err = new Error(parsed.message || ('HTTP ' + res.status));
    err.code = parsed.code;
    throw err;
  }
  return parsed;
}

(async () => {
  const params = new URLSearchParams(location.search);

  // The provider's own refusal comes back on the query string, and it is more
  // useful than anything we could infer from a missing code.
  if (params.get('error')) {
    show('the provider refused this sign-in:\n\n  ' + params.get('error') +
         (params.get('error_description') ? '\n  ' + params.get('error_description') : ''), 'bad');
    return;
  }

  const code  = params.get('code');
  const state = params.get('state');
  const iss   = params.get('iss') || '';
  const ceremony = sessionStorage.getItem('operator.ceremony');

  if (!code || !state) {
    show('no code or state on the callback URL — nothing to exchange', 'bad');
    return;
  }
  if (!ceremony) {
    show('no ceremony id in this tab.\n\n' +
         'The console stores it before redirecting, so it is missing when the ' +
         'redirect landed in a different tab or the tab was reopened. Start ' +
         'again from the console.', 'bad');
    next.innerHTML = '<a href="/">back to the console</a>';
    return;
  }

  try {
    const res = await rpc('CompleteSignIn', { code, state, iss },
                          { 'Operator-Ceremony': ceremony });

    sessionStorage.setItem('operator.pending', res.pendingToken);
    sessionStorage.setItem('operator.enrolled', res.credentialEnrolled ? '1' : '');
    sessionStorage.removeItem('operator.ceremony');

    show('SSO complete.\n\n' +
         '  pending token   ' + res.pendingToken.slice(0, 12) + '…\n' +
         '  authenticator   ' + (res.credentialEnrolled ? 'enrolled' : 'NOT YET — first sign-in will enrol one') + '\n' +
         '  expires         ' + res.expiresAt + '\n\n' +
         'This token authorizes exactly one thing: the WebAuthn pair. ' +
         'It is not a session.', 'ok');
    next.innerHTML = '<a href="/#second-factor">continue to the second factor →</a>';
    setTimeout(() => { location.href = '/#second-factor'; }, 1500);
  } catch (e) {
    show('CompleteSignIn was refused: ' + e.message +
         (e.code ? '\n\ncode: ' + e.code : '') +
         '\n\nOne answer covers an unknown operator, a disabled one, and a ' +
         'ceremony that did not verify — deliberately. The plane logs which ' +
         'it was; check its output.', 'bad');
    next.innerHTML = '<a href="/">back to the console</a>';
  }
})();
</script>
`
