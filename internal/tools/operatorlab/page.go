package main

// page is the operator console.
//
// Five panels, in the order the plane requires them: SSO, the second factor,
// then the three reads. Each shows the raw response, because the point of a
// harness is to see what the server actually said rather than a rendering of
// what it was expected to say.
const page = `<!doctype html>
<meta charset="utf-8">
<title>operatorlab</title>
<style>
  :root { color-scheme: light dark; --line: rgba(127,127,127,.28); }
  body { font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace;
         margin: 0; padding: 2rem 2.5rem 6rem; max-width: 66rem; }
  h1 { font-size: 1.1rem; margin: 0 0 .35rem; letter-spacing: .02em; }
  h2 { font-size: .95rem; margin: 0 0 .9rem; letter-spacing: .02em; }
  .hit { border: 1px solid var(--line); border-radius: 6px; padding: .6rem .75rem;
         margin: .7rem 0 0; display: flex; gap: 1rem; align-items: center;
         justify-content: space-between; flex-wrap: wrap; }
  .hit .who { opacity: .74; font-size: .84rem; white-space: pre; }
  .hit button { margin: 0 0 0 .4rem; padding: .3rem .7rem; font-size: .84rem; }
  p.lede { margin: 0 0 2rem; opacity: .72; max-width: 52rem; }
  section { border: 1px solid var(--line); border-radius: 8px;
            padding: 1.1rem 1.25rem 1.25rem; margin: 0 0 1.4rem; }
  section[data-locked="1"] { opacity: .45; }
  label { display: block; margin: .55rem 0 .2rem; opacity: .78; font-size: .85rem; }
  input, textarea { font: inherit; width: 100%; box-sizing: border-box;
                    padding: .45rem .55rem; border: 1px solid var(--line);
                    border-radius: 5px; background: transparent; color: inherit; }
  textarea { min-height: 3.2rem; resize: vertical; }
  button { font: inherit; padding: .45rem .95rem; margin: .9rem .5rem 0 0;
           border: 1px solid var(--line); border-radius: 5px;
           background: rgba(127,127,127,.10); color: inherit; cursor: pointer; }
  button:hover { background: rgba(127,127,127,.20); }
  button:disabled { cursor: not-allowed; opacity: .5; }
  pre { background: rgba(127,127,127,.10); padding: .8rem .95rem; border-radius: 6px;
        white-space: pre-wrap; word-break: break-word; margin: .9rem 0 0;
        max-height: 26rem; overflow: auto; font-size: .87rem; }
  .ok  { color: #128a3e; }
  .bad { color: #c2341d; }
  .row { display: flex; gap: 1rem; }
  .row > * { flex: 1; }
  .note { font-size: .82rem; opacity: .68; margin: .6rem 0 0; }
  code { background: rgba(127,127,127,.14); padding: .06em .35em; border-radius: 3px; }
</style>

<h1>operatorlab</h1>
<p class="lede">
  The back office (ADR-024). Sign-in is <strong>SSO then WebAuthn, in that
  order</strong> — operator.md §3 allows no password and no TOTP fallback, so
  the SSO step alone issues a token that authorizes exactly the step that ends
  it. Every read below appends an audit event <em>before</em> it answers, because
  under GDPR looking is processing.
</p>

<section id="s-sso">
  <h2>1 · SSO</h2>
  <p class="note">
    BeginSignIn names nobody and looks nobody up: an unauthenticated endpoint
    that resolved an operator would answer "does this person work on the back
    office". Who is signing in is learned from the provider's answer.
  </p>
  <button id="b-sso">Begin sign-in →</button>
  <pre id="o-sso">not started</pre>
</section>

<section id="s-wa" data-locked="1">
  <h2>2 · Second factor</h2>
  <p class="note">
    User verification is <strong>required</strong>, not preferred: an assertion
    that proves only possession is one factor wearing the shape of two. A
    freshly provisioned operator has no authenticator yet and passes through the
    bootstrap window exactly once — it does not re-open if credentials are later
    removed.
  </p>
  <label for="label">Authenticator label (enrolment only)</label>
  <input id="label" value="operatorlab test key" maxlength="64">
  <button id="b-wa">Present authenticator →</button>
  <pre id="o-wa">waiting for the SSO step</pre>
</section>

<section id="s-list" data-locked="1">
  <h2>3 · Customer directory</h2>
  <p class="note">
    Org-level columns only. The projection behind this has no member list, no
    address and no content — minimisation is structural, so there is no query
    that <em>could</em> return them. The one person it names is the
    <strong>owner</strong>, by pseudonym: operator.md §2 puts member addresses
    out of scope "beyond the org owner's", and a pseudonym resolves to nothing
    without the justified read in panel 5.
  </p>
  <div class="row">
    <div>
      <label for="q">Search (name or slug)</label>
      <input id="q" placeholder="leave empty for everything">
    </div>
    <div>
      <label for="state">Lifecycle state</label>
      <input id="state" placeholder="active | past_due | suspended | closed">
    </div>
  </div>
  <button id="b-list">ListCustomers</button>
  <div id="hits"></div>
  <pre id="o-list">waiting for a session</pre>
</section>

<section id="s-get" data-locked="1">
  <h2>4 · One customer</h2>
  <p class="note">
    Audited with the org NAMED, unlike the list — a page is an aggregate over
    many tenants and naming one of them would be false. The entry is written
    even when the org does not exist, because enumerating ids is a
    reconnaissance pattern that is invisible in a log of successful reads only.
  </p>
  <label for="org">Organization id</label>
  <input id="org" placeholder="org_01ARZ3NDEKTSV4RRFFQ69G5FAV">
  <button id="b-get">GetCustomer</button>
  <pre id="o-get">waiting for a session</pre>
</section>

<section id="s-reveal" data-locked="1">
  <h2>5 · Reveal personal data</h2>
  <p class="note">
    The only path from this plane to a person's data. One subject, named fields,
    and a justification that is <strong>mandatory</strong>. <em>"Reveal owner"</em>
    in the directory above fills the two identifiers, so nobody hand-copies a
    pseudonym; the justification is yours. It is refused at the edge
    by protovalidate, in the domain by the audit aggregate, and in the database
    by a CHECK constraint. The audit entry is appended <em>before</em> the vault
    is read, and a failure to append fails the call.
  </p>
  <div class="row">
    <div>
      <label for="subj">Subject pseudonym</label>
      <input id="subj" placeholder="subj_01ARZ3NDEKTSV4RRFFQ69G5FAV">
    </div>
    <div>
      <label for="rorg">In the context of org</label>
      <input id="rorg" placeholder="org_01ARZ3NDEKTSV4RRFFQ69G5FAV">
    </div>
  </div>
  <label for="fields">Fields (comma separated)</label>
  <input id="fields" value="email">
  <label for="reason">Justification (8 characters minimum, stored verbatim)</label>
  <textarea id="reason" placeholder="ticket 4711: the customer reports no verification mail"></textarea>
  <button id="b-reveal">RevealPersonalData</button>
  <pre id="o-reveal">waiting for a session</pre>
</section>

<section id="s-glass" data-locked="1">
  <h2>6 · Break the glass</h2>
  <p class="note">
    Take a capability your role does <em>not</em> hold, for fifteen minutes,
    with a recorded reason (operator.md §5). It is <strong>scoped to this
    session</strong> — signing out ends it, and a second session of yours is
    unaffected. Nothing extends it: a second break-glass is a second event with
    its own reason and its own alert, which is what keeps the alert worth
    reading.
  </p>
  <p class="note">
    A role reaches what the role <em>above</em> it holds and no further.
    <code>manage_operators</code> and <code>suspend_organization</code> are
    reachable by nobody — the first grants capabilities, so a time box would
    bound nothing; the second is the only operator action that stops a paying
    customer working.
  </p>
  <div class="row">
    <div>
      <label for="cap">Capability</label>
      <input id="cap" placeholder="issue_refund">
    </div>
    <div>
      <label for="glassreason">Reason (8 characters minimum, stored verbatim)</label>
      <input id="glassreason" placeholder="incident 4711: duplicate charge, customer on the phone">
    </div>
  </div>
  <button id="b-glass">RequestElevation</button>
  <pre id="o-glass">waiting for a session</pre>
</section>

<section id="s-out" data-locked="1">
  <h2>7 · End the session</h2>
  <p class="note">
    Distinct from expiry, which appends nothing: a sign-out is an action
    somebody took, and it belongs in the trail beside the sign-in it ends.
    Sessions are <strong>absolute and non-extendable</strong> — there is no
    refresh endpoint, deliberately.
  </p>
  <button id="b-out">SignOut</button>
  <pre id="o-out">waiting for a session</pre>
</section>

<script>
// ---------------------------------------------------------------------------
// base64url ↔ ArrayBuffer
//
// WebAuthn's JSON serialisation uses base64url WITHOUT padding, and the browser
// APIs take and return ArrayBuffers. Every ceremony bug that looks like "the
// signature did not verify" is one of these two conversions.
// ---------------------------------------------------------------------------
const b64uToBuf = (s) => {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
};

const bufToB64u = (buf) => {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const $ = (id) => document.getElementById(id);

function show(id, value, cls) {
  const el = $(id);
  el.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  el.className = cls || '';
}

function unlock(...ids) { ids.forEach((id) => $(id).removeAttribute('data-locked')); }

async function rpc(method, body, bearer, headers) {
  const h = Object.assign({ 'Content-Type': 'application/json' }, headers || {});
  if (bearer) h['Authorization'] = 'Bearer ' + bearer;

  const res = await fetch('/chronos.operator.v1.OperatorService/' + method, {
    method: 'POST', headers: h, body: JSON.stringify(body || {}),
  });
  const text = await res.text();
  let parsed;
  try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = { raw: text }; }
  if (!res.ok) {
    const err = new Error(parsed.message || ('HTTP ' + res.status));
    err.code = parsed.code;
    err.detail = parsed;
    throw err;
  }
  return parsed;
}

const live    = () => sessionStorage.getItem('operator.token');
const pending = () => sessionStorage.getItem('operator.pending');

function refresh() {
  if (live()) {
    unlock('s-list', 's-get', 's-reveal', 's-glass', 's-out');
    show('o-wa', 'signed in as ' + sessionStorage.getItem('operator.id') +
                 ' (' + sessionStorage.getItem('operator.role') + ')\n' +
                 'session expires ' + sessionStorage.getItem('operator.expires'), 'ok');
    ['o-list', 'o-get', 'o-reveal', 'o-glass', 'o-out'].forEach((id) => {
      if ($(id).textContent.startsWith('waiting')) show(id, 'ready');
    });
  } else if (pending()) {
    unlock('s-wa');
    show('o-wa', 'SSO complete. Present an authenticator to finish.\n' +
                 (sessionStorage.getItem('operator.enrolled')
                    ? 'This operator already holds one — this will be an ASSERTION.'
                    : 'This operator holds none — this will be an ENROLMENT (bootstrap window).'));
  }
}

// ---------------------------------------------------------------------------
// 1 · SSO
// ---------------------------------------------------------------------------
$('b-sso').onclick = async () => {
  show('o-sso', 'starting…');
  try {
    const res = await rpc('BeginSignIn');
    // Stored BEFORE the redirect, and never sent through it: the ceremony id
    // is the handle to server-side state holding the PKCE verifier and the
    // nonce.
    sessionStorage.setItem('operator.ceremony', res.ceremonyId);
    show('o-sso', 'ceremony ' + res.ceremonyId + '\nexpires ' + res.expiresAt +
                  '\n\nredirecting to the provider…', 'ok');
    setTimeout(() => { location.href = res.authorizationUrl; }, 700);
  } catch (e) {
    show('o-sso', 'BeginSignIn failed: ' + e.message +
                  (e.code ? '\ncode: ' + e.code : ''), 'bad');
  }
};

// ---------------------------------------------------------------------------
// 2 · Second factor
// ---------------------------------------------------------------------------
$('b-wa').onclick = async () => {
  const token = pending();
  if (!token) { show('o-wa', 'no pending token — start at step 1', 'bad'); return; }

  show('o-wa', 'requesting a challenge…');
  try {
    const begun = await rpc('BeginWebAuthn', {}, token);
    const opts = JSON.parse(begun.optionsJson);

    let credential;
    if (begun.enrolment) {
      const pk = opts.publicKey;
      pk.challenge = b64uToBuf(pk.challenge);
      pk.user.id   = b64uToBuf(pk.user.id);
      (pk.excludeCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });

      show('o-wa', 'ENROLMENT — the bootstrap window. Touch your authenticator.');
      const c = await navigator.credentials.create({ publicKey: pk });
      credential = {
        id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
        clientExtensionResults: c.getClientExtensionResults(),
        response: {
          clientDataJSON:    bufToB64u(c.response.clientDataJSON),
          attestationObject: bufToB64u(c.response.attestationObject),
        },
      };
    } else {
      const pk = opts.publicKey;
      pk.challenge = b64uToBuf(pk.challenge);
      (pk.allowCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });

      show('o-wa', 'ASSERTION — touch your authenticator.');
      const c = await navigator.credentials.get({ publicKey: pk });
      credential = {
        id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
        clientExtensionResults: c.getClientExtensionResults(),
        response: {
          clientDataJSON:    bufToB64u(c.response.clientDataJSON),
          authenticatorData: bufToB64u(c.response.authenticatorData),
          signature:         bufToB64u(c.response.signature),
          userHandle:        c.response.userHandle ? bufToB64u(c.response.userHandle) : null,
        },
      };
    }

    const res = await rpc('FinishWebAuthn', {
      credentialJson: JSON.stringify(credential),
      ceremonyId: begun.ceremonyId,
      label: $('label').value,
    }, token);

    // A NEW secret, not a promotion of the pending one: a bearer whose
    // privileges change during its life is one a proxy log or a browser
    // extension may have captured before the change.
    sessionStorage.setItem('operator.token',   res.token);
    sessionStorage.setItem('operator.id',      res.operatorId);
    sessionStorage.setItem('operator.role',    res.role);
    sessionStorage.setItem('operator.expires', res.expiresAt);
    sessionStorage.removeItem('operator.pending');

    show('o-wa', 'signed in.\n\n' +
                 '  operator  ' + res.operatorId + '\n' +
                 '  role      ' + res.role + '\n' +
                 '  expires   ' + res.expiresAt + '  (absolute; there is no refresh)\n\n' +
                 'An OperatorSignedIn event was appended before this answer.', 'ok');
    refresh();
  } catch (e) {
    show('o-wa', 'the second factor failed: ' + e.message +
                 (e.code ? '\ncode: ' + e.code : '') +
                 '\n\nOne answer covers every cause on purpose — naming the failed ' +
                 'check tells an attacker which one to work on. The plane logs ' +
                 'which it was.', 'bad');
  }
};

// ---------------------------------------------------------------------------
// 3–6 · The reads, and sign-out
// ---------------------------------------------------------------------------
$('b-list').onclick = async () => {
  show('o-list', 'reading…');
  $('hits').innerHTML = '';
  try {
    const res = await rpc('ListCustomers', {
      query: $('q').value, lifecycleState: $('state').value, pageSize: 25,
    }, live());
    renderHits(res.customers || []);
    show('o-list', res, 'ok');
  } catch (e) { show('o-list', e.message + (e.code ? '\ncode: ' + e.code : ''), 'bad'); }
};

// renderHits turns each result into a row that FILLS the panels below.
//
// # Why this matters more than a convenience
//
// The directory has no member list, so before owner_subject_id existed there
// was no path at all from a customer to a subject — RevealPersonalData was
// reachable only by somebody who already knew a pseudonym, which in practice
// meant reading one out of the database by hand. That has no justification, no
// audit entry and no bound on how many subjects it returns: strictly worse than
// the endpoint it worked around. An access control that is unusable is not a
// strict one, it is one people go around.
//
// One person per customer, and it is the OWNER, because operator.md §2 draws
// the line in its own exclusion — out of scope are "member email addresses
// beyond the org OWNER'S".
function renderHits(customers) {
  const box = $('hits');
  box.innerHTML = '';
  for (const c of customers) {
    const row = document.createElement('div');
    row.className = 'hit';

    const who = document.createElement('span');
    who.className = 'who';
    who.textContent = c.orgName + '  ·  ' + c.orgId + '\n' +
      (c.ownerSubjectId ? 'owner ' + c.ownerSubjectId : 'owner not recorded');
    row.appendChild(who);

    const buttons = document.createElement('span');

    const open = document.createElement('button');
    open.textContent = 'Open';
    open.onclick = () => { $('org').value = c.orgId; $('b-get').click(); };
    buttons.appendChild(open);

    if (c.ownerSubjectId) {
      const reveal = document.createElement('button');
      reveal.textContent = 'Reveal owner →';
      // It fills the two IDENTIFIERS and stops. The justification is the
      // operator's to write, and a prefilled one would be the default that
      // makes a mandatory field mean nothing.
      reveal.onclick = () => {
        $('subj').value = c.ownerSubjectId;
        $('rorg').value = c.orgId;
        $('s-reveal').scrollIntoView({ behavior: 'smooth' });
        $('reason').focus();
      };
      buttons.appendChild(reveal);
    }

    row.appendChild(buttons);
    box.appendChild(row);
  }
}

$('b-get').onclick = async () => {
  show('o-get', 'reading…');
  try {
    const res = await rpc('GetCustomer', { orgId: $('org').value }, live());
    show('o-get', res, 'ok');
  } catch (e) { show('o-get', e.message + (e.code ? '\ncode: ' + e.code : ''), 'bad'); }
};

$('b-reveal').onclick = async () => {
  show('o-reveal', 'recording the access, then resolving…');
  try {
    const res = await rpc('RevealPersonalData', {
      subjectId: $('subj').value,
      orgId:     $('rorg').value,
      fields:    $('fields').value.split(',').map((s) => s.trim()).filter(Boolean),
      reason:    $('reason').value,
    }, live());
    show('o-reveal', res, 'ok');
  } catch (e) {
    show('o-reveal', e.message + (e.code ? '\ncode: ' + e.code : '') +
      (e.detail && e.detail.details ? '\n\n' + JSON.stringify(e.detail.details, null, 2) : ''), 'bad');
  }
};

$('b-glass').onclick = async () => {
  show('o-glass', 'requesting…');
  try {
    const res = await rpc('RequestElevation', {
      capability: $('cap').value.trim(),
      reason: $('glassreason').value,
    }, live());
    show('o-glass',
      'GLASS BROKEN — ' + res.capability + '\n\n' +
      '  expires   ' + res.expiresAt + '  (absolute; nothing extends it)\n' +
      '  audit     ' + res.auditEntryId + '\n\n' +
      'An OperatorElevated event was appended BEFORE the grant, and an alert\n' +
      'was raised at the same moment — a Prometheus counter and a WARN line,\n' +
      'not mail, because this plane holds no operator addresses.', 'ok');
  } catch (e) {
    // The one endpoint here that explains itself. Everywhere else an opaque
    // refusal stops an attacker learning which check failed; here the caller
    // is an authenticated operator asking for a privilege, and being told
    // "your role cannot reach that" is how they learn to ask a human.
    show('o-glass', e.message + (e.code ? '\n\ncode: ' + e.code : ''), 'bad');
  }
};

$('b-out').onclick = async () => {
  show('o-out', 'ending…');
  try {
    const res = await rpc('SignOut', {}, live());
    show('o-out', 'changed: ' + res.changed +
                  '\n\nThe bearer is dead. Reload to start again.', 'ok');
    ['token', 'id', 'role', 'expires'].forEach((k) => sessionStorage.removeItem('operator.' + k));
  } catch (e) { show('o-out', e.message + (e.code ? '\ncode: ' + e.code : ''), 'bad'); }
};

refresh();
if (location.hash === '#second-factor') $('s-wa').scrollIntoView({ behavior: 'smooth' });
</script>
`
