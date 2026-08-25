package main

// page is the harness itself.
//
// Kept as one string rather than an embedded directory because it is a single
// file with no assets, and because the whole point of a harness is that somebody
// can read the request it is about to send in the same place they read the
// button that sends it.
const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chronos passkey lab</title>
<style>
  :root {
    --bg: #fbfbfa; --panel: #fff; --ink: #17181c; --muted: #6b6f76;
    --line: #e3e4e8; --accent: #2f5bd7; --ok: #1a7f4b; --bad: #a4262c;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #16171a; --panel: #1e1f24; --ink: #e9eaee; --muted: #9aa0a8;
      --line: #2e3038; --accent: #7d9bf0; --ok: #4ec27f; --bad: #ef8b90;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 28px 20px 60px; background: var(--bg); color: var(--ink);
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  main { max-width: 780px; margin: 0 auto; display: flex; flex-direction: column; gap: 18px; }
  h1 { font-size: 20px; margin: 0; letter-spacing: -0.01em; }
  h2 { font-size: 14px; margin: 0 0 10px; text-transform: uppercase;
       letter-spacing: 0.06em; color: var(--muted); }
  p.lede { margin: 0; color: var(--muted); font-size: 14px; }
  section {
    background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px;
  }
  label { display: block; font-size: 13px; color: var(--muted); margin: 10px 0 4px; }
  input {
    width: 100%; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px;
    background: var(--bg); color: var(--ink); font: 13px/1.4 var(--mono);
  }
  .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: flex-end; }
  .row > div { flex: 1 1 200px; }
  button {
    margin-top: 12px; padding: 9px 16px; border: 0; border-radius: 6px;
    background: var(--accent); color: #fff; font-size: 14px; font-weight: 500; cursor: pointer;
  }
  button.ghost { background: transparent; color: var(--accent); border: 1px solid var(--line); }
  button:disabled { opacity: .5; cursor: not-allowed; }
  pre {
    margin: 12px 0 0; padding: 12px; background: var(--bg); border: 1px solid var(--line);
    border-radius: 6px; font: 12px/1.5 var(--mono); white-space: pre-wrap;
    word-break: break-word; max-height: 320px; overflow: auto;
  }
  .ok { color: var(--ok); } .bad { color: var(--bad); }
  .pill { display: inline-block; padding: 1px 7px; border-radius: 20px;
          border: 1px solid var(--line); font-size: 11px; color: var(--muted); }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); }
  th { color: var(--muted); font-weight: 500; font-size: 12px; }
  td.mono { font-family: var(--mono); font-size: 11px; word-break: break-all; }
</style>
</head>
<body>
<main>
  <header>
    <h1>Chronos passkey lab</h1>
    <p class="lede">
      Drives the real RPCs against the real server. A WebAuthn signature can only
      come from an authenticator, so this is the one part of the flow no Go test
      can reach.
    </p>
  </header>

  <section>
    <h2>0 · Create an account</h2>
    <p class="lede">
      Registers, reads the verification link out of Mailpit — the dev mailbox —
      and completes it. There is deliberately no RPC that hands out a
      verification token, so the harness does what a person does and reads the
      mail.
      <br><br>
      <strong>Three processes besides this one:</strong> <code>cmd/api</code>,
      <code>cmd/worker</code> (sends the mail — the API only appends the event)
      and <code>cmd/projector</code> (builds the account projection
      <code>VerifyEmail</code> reads). Without the projector, verification fails
      with &ldquo;this link is no longer valid&rdquo; while the token is
      perfectly good — the lookup that failed is the account, not the token.
    </p>
    <div class="row">
      <div><label for="new-email">Email</label><input id="new-email"></div>
      <div><label for="new-username">Username</label><input id="new-username"></div>
      <div><label for="new-password">Password</label><input id="new-password" type="password"></div>
    </div>
    <button id="signup">Create account</button>
    <button id="fill" class="ghost">Fill with a fresh test identity</button>
    <pre id="out-signup">—</pre>
  </section>

  <section>
    <h2>1 · Bearer token</h2>
    <p class="lede">
      Registration needs an authenticated caller. Sign in with a password, or
      paste a token you already have.
    </p>
    <div class="row">
      <div><label for="email">Email</label><input id="email" autocomplete="username"></div>
      <div><label for="password">Password</label><input id="password" type="password" autocomplete="current-password"></div>
      <div><label for="code">TOTP code (if enrolled)</label><input id="code" inputmode="numeric"></div>
    </div>
    <button id="signin">Sign in</button>
    <label for="token">Bearer token</label>
    <input id="token" placeholder="set by signing in, or paste one">
    <pre id="out-signin">—</pre>
  </section>

  <section>
    <h2>2 · Register a passkey</h2>
    <p class="lede">
      Two calls. <code>BeginPasskeyRegistration</code> returns the options; the
      authenticator signs them; <code>FinishPasskeyRegistration</code> verifies.
      On your FIRST passkey the response also carries recovery codes, once.
    </p>
    <label for="label">Label for this device</label>
    <input id="label" value="Test device" maxlength="64">
    <button id="register">Create passkey</button>
    <pre id="out-register">—</pre>
  </section>

  <section>
    <h2>2b · TOTP, the other second factor</h2>
    <p class="lede">
      Enrols an authenticator secret and proves it with a live code. The code is
      computed here with Web Crypto — RFC 6238 over HMAC-SHA-1 — so this is the
      real algorithm an authenticator app runs, not a stub the server would
      accept either way.
    </p>
    <button id="totp-enrol">Enrol TOTP</button>
    <button id="totp-confirm" class="ghost">Confirm with a live code</button>
    <button id="totp-signin" class="ghost">Sign in with password + code</button>
    <pre id="out-totp">—</pre>
  </section>

  <section>
    <h2>3 · Sign in with the passkey</h2>
    <p class="lede">
      Usernameless: nothing identifies the account, the authenticator does. This
      needs no bearer token — it produces one.
    </p>
    <button id="login">Sign in with passkey</button>
    <pre id="out-login">—</pre>
  </section>

  <section>
    <h2>3b · Federated sign-in (identity.md §7)</h2>
    <p class="lede">
      Redirects to the provider. The code is exchanged server-side with the PKCE
      verifier the browser never saw.
      <br><br>
      <strong>A refused link is the flow working.</strong> Auto-linking on an
      email match alone is the account takeover §7 exists to refuse, so unless
      the provider is on the trusted list AND both sides verified the address,
      the sign-in succeeds and creates no link — you then link explicitly below.
    </p>
    <div id="providers" class="lede">Loading providers…</div>
    <button id="fed-signin">Sign in with provider</button>
    <button id="fed-link" class="ghost">Link to my account</button>
    <pre id="out-fed">—</pre>
  </section>

  <section>
    <h2>4 · Enrolled passkeys</h2>
    <button id="list" class="ghost">List</button>
    <div id="passkeys"></div>
    <pre id="out-list">—</pre>
  </section>
</main>

<script>
// ---------------------------------------------------------------------------
// base64url, both directions
//
// WebAuthn speaks ArrayBuffers and its JSON encoding is base64url WITHOUT
// padding. Hand-rolled rather than relying on the newer
// PublicKeyCredential.toJSON(), which Safari and older Chrome do not have — and
// a harness that only works in one browser cannot test what a browser does.
// ---------------------------------------------------------------------------
const b64uToBytes = (s) => {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(pad + '='.repeat((4 - pad.length % 4) % 4));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
};
const bytesToB64u = (buf) => {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const show = (id, value, bad) => {
  const el = document.getElementById(id);
  el.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  el.className = bad ? 'bad' : '';
};

// One place that speaks Connect. Every RPC is a POST of JSON to the
// fully-qualified method name, and errors come back as {code, message}.
async function rpc(method, body, bearer) {
  const headers = {
    'Content-Type': 'application/json',
    // Every mutating RPC requires one. A fresh key per call, because these are
    // distinct requests and not retries of one.
    'Idempotency-Key': 'idem_lab_' + crypto.randomUUID().replace(/-/g, '').slice(0, 26).toUpperCase(),
  };
  if (bearer) headers['Authorization'] = 'Bearer ' + bearer;

  const res = await fetch('/chronos.identity.v1.IdentityService/' + method, {
    method: 'POST', headers, body: JSON.stringify(body || {}),
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

const tokenBox = document.getElementById('token');

// --- 0. create an account ---------------------------------------------------
//
// Register, then read the token out of the dev mailbox. Polling rather than a
// single read because the mail is sent by a REACTOR: the API appends an event
// and returns, and the worker picks it up a moment later. A single read would
// race that and report a missing mailbox instead of a slow one.
document.getElementById('fill').onclick = () => {
  const tag = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  document.getElementById('new-email').value = 'lab-' + tag + '@example.test';
  document.getElementById('new-username').value = 'lab_' + tag;
  document.getElementById('new-password').value = 'correct-horse-battery-' + tag;
};

async function verificationToken(email, since) {
  for (let i = 0; i < 40; i++) {
    const res = await fetch('/mailpit/api/v1/search?query=' + encodeURIComponent('to:' + email));
    if (res.ok) {
      const found = await res.json();
      for (const m of found.messages || []) {
        if (new Date(m.Created).getTime() < since) continue;
        const body = await fetch('/mailpit/api/v1/message/' + m.ID).then(r => r.json());
        // The link is built by the template from the token, so the token is
        // whatever follows the query parameter — read from the TEXT part,
        // which carries the same URL as the HTML one without the markup.
        const hit = /[?&]token=([A-Za-z0-9._~-]+)/.exec((body.Text || '') + (body.HTML || ''));
        if (hit) return hit[1];
      }
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(
    'no verification mail arrived within 20s. Two processes have to be running ' +
    'besides the API, and neither reports anything when it is absent:\n\n' +
    '  cmd/worker     sends the mail. The API only appends the event.\n' +
    '  cmd/projector  builds user_view, which VerifyEmail reads to resolve the\n' +
    '                 account. Without it, verification fails with "this link is\n' +
    '                 no longer valid" even though the token is perfectly good.\n\n' +
    'Also check SMTP_HOST: "mailpit" only resolves inside the compose network, ' +
    'so a worker on the host needs "localhost".');
}

document.getElementById('signup').onclick = async () => {
  const email = document.getElementById('new-email').value.trim();
  const username = document.getElementById('new-username').value.trim();
  const password = document.getElementById('new-password').value;
  if (!email || !username || !password) {
    show('out-signup', 'Email, username and password are all required.', true);
    return;
  }
  const since = Date.now() - 5000;
  try {
    show('out-signup', 'registering…');
    await rpc('Register', { email });

    show('out-signup', 'waiting for the verification mail…');
    const token = await verificationToken(email, since);

    show('out-signup', 'verifying…');
    await rpc('VerifyEmail', { token, password, username });

    // Sign in immediately. With no second factor this is a BOOTSTRAP session at
    // AAL1 — the one authentication that legitimately stops below AAL2, because
    // it exists so somebody can enrol the factor they are required to have. It
    // is enough to register a FIRST passkey and nothing else.
    const session = await rpc('CreateSession', {
      identifier: email, password, deviceId: 'passkeylab',
    });
    tokenBox.value = session.token || '';
    document.getElementById('email').value = email;
    document.getElementById('password').value = password;

    show('out-signup', {
      account: email,
      username,
      assuranceLevel: session.assuranceLevel,
      note: 'Signed in. AAL1 is expected here — no second factor yet, and a ' +
            'bootstrap session is exactly what lets you enrol the first one. ' +
            'Go to step 2.',
    });
  } catch (e) { show('out-signup', e.detail || String(e), true); }
};

// --- 1. sign in -------------------------------------------------------------
document.getElementById('signin').onclick = async () => {
  try {
    const out = await rpc('CreateSession', {
      identifier: document.getElementById('email').value.trim(),
      password: document.getElementById('password').value,
      code: document.getElementById('code').value.trim() || undefined,
      deviceId: 'passkeylab',
    });
    tokenBox.value = out.token || '';
    show('out-signin', {
      sessionId: out.sessionId,
      assuranceLevel: out.assuranceLevel,
      note: out.assuranceLevel === 'ASSURANCE_LEVEL_1'
        ? 'AAL1 — a bootstrap session. Enough to enrol a FIRST passkey and nothing else.'
        : 'AAL2.',
    });
  } catch (e) { show('out-signin', e.detail || String(e), true); }
};

// --- 2. register ------------------------------------------------------------
document.getElementById('register').onclick = async () => {
  const bearer = tokenBox.value.trim();
  if (!bearer) { show('out-register', 'No bearer token. Sign in first.', true); return; }
  try {
    const begun = await rpc('BeginPasskeyRegistration', {}, bearer);
    // The server sends protocol.CredentialCreation, which is {"publicKey": {…}}
    // with challenge and user.id already base64url.
    const opts = JSON.parse(begun.optionsJson).publicKey;
    opts.challenge = b64uToBytes(opts.challenge);
    opts.user.id = b64uToBytes(opts.user.id);
    for (const c of opts.excludeCredentials || []) c.id = b64uToBytes(c.id);

    const cred = await navigator.credentials.create({ publicKey: opts });
    const finished = await rpc('FinishPasskeyRegistration', {
      ceremonyId: begun.ceremonyId,
      label: document.getElementById('label').value,
      responseJson: JSON.stringify({
        id: cred.id,
        rawId: bytesToB64u(cred.rawId),
        type: cred.type,
        // Present for a conditional/hybrid transport hint; harmless when empty.
        clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
        response: {
          attestationObject: bytesToB64u(cred.response.attestationObject),
          clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
          transports: cred.response.getTransports ? cred.response.getTransports() : [],
        },
      }),
    }, bearer);

    show('out-register', {
      credentialId: finished.credentialId,
      activated: finished.activated || false,
      recoveryCodes: finished.recoveryCodes && finished.recoveryCodes.length
        ? finished.recoveryCodes
        : '(none — this was not the first passkey on the account)',
    });
  } catch (e) { show('out-register', e.detail || String(e), true); }
};

// --- 2b. TOTP ---------------------------------------------------------------
//
// RFC 6238 in the browser. The secret arrives base32 in the provisioning URI —
// which is what a phone camera scans — so it is decoded here rather than taken
// from the response's raw field, to exercise the same string an authenticator
// app would.
const b32 = (s) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const out = [];
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const i = A.indexOf(c);
    if (i < 0) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
};

async function totpCode(secretB32, when) {
  const key = await crypto.subtle.importKey(
    'raw', b32(secretB32), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  // The counter is a 64-bit big-endian step number. Thirty seconds is the
  // period every authenticator app assumes and the server's own default.
  const step = Math.floor(when / 30000);
  const buf = new ArrayBuffer(8);
  new DataView(buf).setUint32(4, step);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  // Dynamic truncation, RFC 4226 §5.4.
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) |
              (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 1000000).padStart(6, '0');
}

let totpSecret = '';

document.getElementById('totp-enrol').onclick = async () => {
  const bearer = tokenBox.value.trim();
  if (!bearer) { show('out-totp', 'No bearer token. Create an account or sign in first.', true); return; }
  try {
    const out = await rpc('EnrollTotp', {}, bearer);
    // From the URI, not the raw field: this is the string a phone scans.
    const uri = out.provisioningUri || '';
    const m = /[?&]secret=([A-Z2-7]+)/i.exec(uri);
    totpSecret = m ? m[1] : (out.secret || '');
    show('out-totp', {
      credentialId: out.credentialId,
      provisioningUri: uri,
      note: totpSecret
        ? 'Secret captured. Now confirm with a live code — the enrolment is NOT ' +
          'a second factor until a code proves it.'
        : 'No secret found in the provisioning URI.',
    });
  } catch (e) { show('out-totp', e.detail || String(e), true); }
};

document.getElementById('totp-confirm').onclick = async () => {
  const bearer = tokenBox.value.trim();
  if (!totpSecret) { show('out-totp', 'Enrol first — there is no secret to compute a code from.', true); return; }
  try {
    const code = await totpCode(totpSecret, Date.now());
    const out = await rpc('ConfirmTotp', { code }, bearer);
    show('out-totp', {
      code,
      activated: out.activated,
      changed: out.changed,
      note: out.activated
        ? 'The account is ACTIVE: an address was proven and a real second factor ' +
          'is enrolled. Both are required, and neither alone does it.'
        : 'Confirmed. The account was already active.',
    });
  } catch (e) { show('out-totp', e.detail || String(e), true); }
};

document.getElementById('totp-signin').onclick = async () => {
  if (!totpSecret) { show('out-totp', 'Enrol and confirm first.', true); return; }
  try {
    const code = await totpCode(totpSecret, Date.now());
    const out = await rpc('CreateSession', {
      identifier: document.getElementById('email').value.trim(),
      password: document.getElementById('password').value,
      code,
      deviceId: 'passkeylab',
    });
    tokenBox.value = out.token || '';
    show('out-totp', {
      sessionId: out.sessionId,
      assuranceLevel: out.assuranceLevel,
      note: out.assuranceLevel === 'ASSURANCE_LEVEL_2'
        ? 'AAL2 — password AND a second factor. Two independent things, which is ' +
          'what the level means; a passkey reaches the same level in one gesture.'
        : 'Below AAL2 — the code was not accepted as a second factor.',
    });
  } catch (e) { show('out-totp', e.detail || String(e), true); }
};

// --- 3. sign in with the passkey -------------------------------------------
document.getElementById('login').onclick = async () => {
  try {
    const begun = await rpc('BeginPasskeyLogin', {});
    const opts = JSON.parse(begun.optionsJson).publicKey;
    opts.challenge = b64uToBytes(opts.challenge);
    for (const c of opts.allowCredentials || []) c.id = b64uToBytes(c.id);

    const cred = await navigator.credentials.get({ publicKey: opts });
    const out = await rpc('FinishPasskeyLogin', {
      ceremonyId: begun.ceremonyId,
      deviceId: 'passkeylab',
      responseJson: JSON.stringify({
        id: cred.id,
        rawId: bytesToB64u(cred.rawId),
        type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
        response: {
          authenticatorData: bytesToB64u(cred.response.authenticatorData),
          clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
          signature: bytesToB64u(cred.response.signature),
          userHandle: cred.response.userHandle ? bytesToB64u(cred.response.userHandle) : null,
        },
      }),
    });

    tokenBox.value = out.token || '';
    show('out-login', {
      sessionId: out.sessionId,
      assuranceLevel: out.assuranceLevel,
      cloneWarning: out.cloneWarning || false,
      note: out.assuranceLevel === 'ASSURANCE_LEVEL_2'
        ? 'AAL2 from one gesture — the passkey was user-verified.'
        : out.cloneWarning
          ? 'AAL1: the signature counter went BACKWARDS, so the session is capped and step-up will be required. It was NOT refused.'
          : 'AAL1 — no user verification, so this is one factor.',
    });
  } catch (e) { show('out-login', e.detail || String(e), true); }
};

// --- 3b. federated ----------------------------------------------------------
//
// The callback page needs three things this page knows and the query string
// does not carry: which provider was used, whether this was a sign-in or a
// link, and — for a link — the bearer. sessionStorage rather than the state
// parameter, because state is the SERVER's CSRF binding and stuffing client
// data into it would make a value the server compares also a value the client
// authors.
let federatedProviders = [];

async function loadProviders() {
  try {
    const out = await rpc('ListFederatedProviders', {});
    federatedProviders = out.providers || [];
    document.getElementById('providers').textContent = federatedProviders.length
      ? 'Configured: ' + federatedProviders.join(', ')
      : 'No providers configured. Set IDENTITY_FEDERATION_PROVIDERS and the ' +
        'client credentials, then restart cmd/api.';
  } catch (e) {
    document.getElementById('providers').textContent = 'Could not list providers.';
  }
}
loadProviders();

async function startFederated(mode) {
  const provider = federatedProviders[0];
  if (!provider) { show('out-fed', 'No provider is configured.', true); return; }

  const bearer = tokenBox.value.trim();
  if (mode === 'link' && !bearer) {
    show('out-fed', 'Linking needs an authenticated session at AAL2 — §7 rule 3 ' +
      'requires step-up, because a link the holder never proved survives every ' +
      'later recovery. Sign in first.', true);
    return;
  }

  try {
    const method = mode === 'link' ? 'BeginFederatedLink' : 'BeginFederatedSignIn';
    const out = await rpc(method, { provider }, mode === 'link' ? bearer : '');
    sessionStorage.setItem('chronos_provider', provider);
    sessionStorage.setItem('chronos_fed_mode', mode);
    if (bearer) sessionStorage.setItem('chronos_bearer', bearer);
    show('out-fed', { redirectingTo: out.authorizationUrl });
    location.href = out.authorizationUrl;
  } catch (e) { show('out-fed', e.detail || String(e), true); }
}

document.getElementById('fed-signin').onclick = () => startFederated('signin');
document.getElementById('fed-link').onclick = () => startFederated('link');

// --- 4. list ----------------------------------------------------------------
document.getElementById('list').onclick = async () => {
  const bearer = tokenBox.value.trim();
  if (!bearer) { show('out-list', 'No bearer token. Sign in first.', true); return; }
  try {
    const out = await rpc('ListPasskeys', {}, bearer);
    const rows = out.passkeys || [];
    document.getElementById('passkeys').innerHTML = rows.length === 0
      ? '<p class="lede">None enrolled.</p>'
      : '<table><tr><th>Label</th><th>Credential</th><th>Added</th><th>Last used</th><th></th></tr>' +
        rows.map(p =>
          '<tr><td>' + (p.label || '<span class="pill">no label</span>') + '</td>' +
          '<td class="mono">' + p.credentialId.slice(0, 22) + '…</td>' +
          '<td>' + (p.createdAt || '—') + '</td>' +
          '<td>' + (p.lastUsedAt || '<span class="pill">never</span>') + '</td>' +
          '<td>' + (p.cloneWarnedAt ? '<span class="bad">counter regressed</span>' : '') +
          ' <button class="ghost rm" data-id="' + p.credentialId + '">Remove</button></td></tr>'
        ).join('') + '</table>';

    for (const b of document.querySelectorAll('.rm')) {
      b.onclick = async () => {
        try {
          await rpc('RemovePasskey', { credentialId: b.dataset.id }, tokenBox.value.trim());
          show('out-list', 'Removed. Click List again.');
        } catch (e) { show('out-list', e.detail || String(e), true); }
      };
    }
    show('out-list', { count: rows.length });
  } catch (e) { show('out-list', e.detail || String(e), true); }
};
</script>
</body>
</html>`
