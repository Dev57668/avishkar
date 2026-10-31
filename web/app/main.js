// Console shell: mode detection (live / demo / static), sign-in, hash router (#/...), responsive navigation.
import { api, probe, session, onAuthLost } from './api.js';
import { h, clear, $, icon, toast, confirmDialog, skeleton, errorState, emptyState, num, pill } from './ui.js';
import { overviewView } from './overview.js';
import { repoView } from './repo.js';
import { demoView } from './demo.js';
import { adminView } from './admin.js';
import { githubView } from './github.js';
import { watchRun, canUpload } from './shared.js';
import { gauge } from './charts.js';

const mount = document.getElementById('console');
const FORCED_STATIC = (document.querySelector('meta[name="avishkar-mode"]') || {}).content === 'static';
let mode = 'booting';

const go = (hash) => { if (location.hash === hash) route(); else location.hash = hash; };

function shell() {
  const nav = h('nav', { class: 'cnav', id: 'cnav', 'aria-label': 'Console' },
    link('#/', 'Overview'), link('#/demo', 'Demo lab'), link('#/github', 'GitHub'), session.has('admin') ? link('#/admin', 'Admin') : null);
  const burger = h('button', { class: 'btn burger', type: 'button', 'aria-label': 'Menu', 'aria-expanded': 'false', 'aria-controls': 'cnav',
    onclick: (e) => { const open = nav.classList.toggle('open'); e.currentTarget.setAttribute('aria-expanded', String(open)); } }, icon('menu'));
  const who = h('div', { class: 'who' }, h('span', { class: 'mut sm' }, session.me ? `${session.me.email || session.me.id} · ${session.me.role}` : ''),
    h('button', { class: 'btn sm', type: 'button', onclick: signOut }, 'Sign out'));
  const view = h('div', { class: 'cview', id: 'cview', tabindex: '-1' });
  clear(mount).append(h('div', { class: 'cbar' }, burger, nav, who), banner(), view);
  return view;
}
const link = (href, label) => h('a', { href, class: 'clink', 'data-href': href, onclick: () => $('#cnav') && $('#cnav').classList.remove('open') }, label);

function banner() {
  const frag = h('div', {});
  const sb = session.cfg && session.cfg.sandbox;
  if (sb && !sb.isolationBoundary) frag.append(h('div', { class: 'note-bar' }, icon('shield'), ` Sandbox mode “${sb.mode}” is not an isolation boundary: only scan code you trust.`));
  if (session.pub && session.pub.demo) frag.append(h('div', { class: 'note-bar' }, icon('spark'), ' Public demo: results come from the bundled sample projects, scanned by the real pipeline. Uploads are ',
    session.cfg && session.cfg.uploads === 'all' ? 'enabled.' : session.cfg && session.cfg.uploads === 'limited' ? 'open to signed-in accounts with small size limits (2 MB zip, 3 per hour).' : 'limited to the owner (no container sandbox on this host).'));
  return frag;
}

async function route() {
  if (mode !== 'authed') return;
  if (!location.hash.startsWith('#/') && $('#cview')) return; // landing-page anchors do not re-render the console
  const hash = location.hash.startsWith('#/') ? location.hash : '#/';
  const view = $('#cview') || shell();
  document.querySelectorAll('.clink').forEach((a) => a.setAttribute('aria-current', hash === a.dataset.href || (a.dataset.href === '#/' && hash.startsWith('#/repo')) ? 'page' : 'false'));
  clear(view);
  const [, seg, arg] = hash.split('/');
  if (!seg) { await overviewView(view, go); uploadPanel(view); }
  else if (seg === 'repo' && /^[\w-]{1,64}$/.test(arg || '')) await repoView(view, arg, go);
  else if (seg === 'demo') await demoView(view, go);
  else if (seg === 'github') await githubView(view, go);
  else if (seg === 'admin' && session.has('admin')) adminView(view, session.me.email);
  else view.append(emptyState('Page not found', 'That view does not exist, or you do not have access to it.', h('a', { class: 'btn', href: '#/' }, 'Back to overview')));
  view.focus({ preventScroll: true });
}

function uploadPanel(view) {
  if (!canUpload()) {
    view.append(h('p', { class: 'mut sm' }, session.cfg && !['all', 'limited'].includes(session.cfg.uploads)
      ? 'Uploading your own code is disabled for this account on this instance (it cannot sandbox untrusted code here). Run Avishkar locally with the Docker sandbox to scan your own repositories.' : 'Your role cannot upload.'));
    return;
  }
  const repo = h('input', { id: 'up-repo', required: true, maxlength: '100', placeholder: 'my-project or org/name', 'aria-label': 'Repository name' });
  const file = h('input', { id: 'up-file', type: 'file', accept: '.zip', required: true, 'aria-label': 'Zip archive' });
  const out = h('div', { 'aria-live': 'polite' });
  const btn = h('button', { class: 'btn primary' }, 'Analyze');
  view.append(h('section', { class: 'cs' }, h('div', { class: 'cs-h' }, h('h2', {}, 'Scan a repository snapshot')),
    h('form', { class: 'aform', onsubmit: async (e) => {
      e.preventDefault();
      const f = file.files[0];
      if (!f) return;
      const maxMb = session.has('admin') ? 25 : 2;
      if (f.size > maxMb * 1024 * 1024) { toast(`That file is larger than the ${maxMb} MB upload limit for your account.`, 'warn'); return; }
      // Names may only contain letters, digits, . _ - and /: turn spaces into dashes and drop anything else.
      const name = repo.value.trim().replace(/\s+/g, '-').replace(/[^\w.\-/]/g, '').slice(0, 100);
      if (!name) { clear(out).append(errorState(new Error('Enter a repository name using letters, numbers, dashes or slashes.'))); return; }
      if (name !== repo.value) { repo.value = name; toast(`Repository name adjusted to "${name}"`, 'info', 3500); }
      btn.disabled = true; clear(out).append(skeleton(2));
      try {
        const fd = new FormData(); fd.append('repository', name); fd.append('archive', f);
        const q = await api('/v1/analyses', { method: 'POST', form: fd, timeout: 120000 });
        const run = await watchRun(q.statusUrl, (r) => { out.textContent = `Analysis ${r.status}${r.stages && r.stages.current ? ' · ' + r.stages.current : ''}…`; });
        toast(`Analysis ${run.status}`, run.status === 'complete' ? 'ok' : 'warn');
        go(`#/repo/${q.repositoryId}`);
      } catch (err) { clear(out).append(errorState(err)); } finally { btn.disabled = false; }
    } }, h('label', { class: 'field' }, h('span', {}, 'Repository name'), repo), h('label', { class: 'field' }, h('span', {}, 'Zip archive'), file), btn), out,
    h('p', { class: 'mut sm' }, 'Archives are unpacked with path-traversal, symlink and zip-bomb checks. The code is parsed, never executed.' + (session.cfg && session.cfg.uploads === 'limited' && !session.has('admin') ? ' Limits here: 2 MB zip, 300 files, 3 uploads per hour.' : ''))));
}

async function signOut() {
  if (!(await confirmDialog({ title: 'Sign out?', message: 'You will need to sign in again to see results.', confirmLabel: 'Sign out' }))) return;
  session.save(null); session.me = null; mode = 'login'; renderLogin();
}

/* ---------------- login ---------------- */
function renderLogin(msg) {
  const pub = session.pub || {};
  const L = pub.demoLogin;
  const em = h('input', { id: 'em', type: 'email', autocomplete: 'username', required: true, placeholder: 'admin@your-team.dev' });
  const pw = h('input', { id: 'pw', type: 'password', autocomplete: 'current-password', required: true });
  const err = h('div', { class: 'errstate', role: 'alert', hidden: true });
  const btn = h('button', { class: 'btn primary wide' }, 'Sign in');
  const form = h('form', { class: 'loginform', 'aria-label': 'Sign in', onsubmit: async (e) => {
    e.preventDefault(); btn.disabled = true; err.hidden = true;
    try {
      const r = await fetch('/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: em.value, password: pw.value }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { const ex = new Error((j.error && j.error.message) || 'Sign-in failed'); ex.code = j.error && j.error.code; throw ex; }
      session.save(j.token); pw.value = '';
      await start();
    } catch (x) {
      err.replaceChildren(x.message, ' ');
      if (x.code === 'email_not_verified') err.append(h('button', { class: 'btn sm', type: 'button', onclick: async () => {
        try { await api('/v1/auth/resend', { method: 'POST', body: { email: em.value } }); toast('If that account is waiting for confirmation, a new link is on its way.', 'ok'); } catch (e2) { toast(e2.message, 'bad'); }
      } }, 'Resend the email'));
      err.hidden = false;
    } finally { btn.disabled = false; }
  } }, h('label', { class: 'field' }, h('span', {}, 'Email'), em), h('label', { class: 'field' }, h('span', {}, 'Password'), pw), err, btn);
  clear(mount).append(h('div', { class: 'logincard' },
    h('h2', {}, 'Sign in to the console'), msg ? h('p', { class: 'mut' }, msg) : null,
    pub.demo ? h('div', { class: 'note-bar' }, h('span', {}, h('b', {}, 'Live public demo. '), L ? 'Use the read-only demo account:' : 'The operator has not published a demo login.'), ' ',
      L ? h('code', {}, `${L.email} / ${L.password}`) : null, L ? h('button', { class: 'btn sm', type: 'button', onclick: () => { em.value = L.email; pw.value = L.password; pw.focus(); } }, 'Fill in the login') : null) : null,
    form,
    pub.guest ? h('button', { class: 'btn wide', type: 'button', onclick: async () => {
      try { const j = await api('/v1/auth/guest', { method: 'POST' }); session.save(j.token); await start(); } catch (x) { err.textContent = x.message; err.hidden = false; }
    } }, 'Continue as guest (read-only)') : null,
    pub.signup ? h('button', { class: 'btn wide ghost', type: 'button', onclick: () => renderForgot() }, 'Forgot password?') : null,
    pub.signup ? h('button', { class: 'btn wide', type: 'button', onclick: () => renderSignup() }, 'Create an account') : null,
    null));
}

function renderSignup() {
  const em = h('input', { type: 'email', required: true, autocomplete: 'username' });
  const pw = h('input', { type: 'password', required: true, minlength: '10', autocomplete: 'new-password' });
  const err = h('div', { class: 'errstate', role: 'alert', hidden: true });
  const btn = h('button', { class: 'btn primary wide' }, 'Create account');
  clear(mount).append(h('div', { class: 'logincard' }, h('h2', {}, 'Create an account'),
    h('p', { class: 'mut sm' }, 'Accounts here are read-only (browse and run the demo lab). We email you a link to confirm the address; the email is used only for that, and for password resets. Use a password you do not use elsewhere.'),
    h('form', { class: 'loginform', onsubmit: async (e) => {
      e.preventDefault(); btn.disabled = true; err.hidden = true;
      try {
        await api('/v1/auth/register', { method: 'POST', body: { email: em.value, password: pw.value } });
        clear(mount).append(h('div', { class: 'logincard' }, h('h2', {}, 'Check your email'),
          h('p', {}, `We sent a confirmation link to ${em.value}. Open it to activate your account, then sign in. It expires in 24 hours.`),
          h('button', { class: 'btn wide', type: 'button', onclick: () => renderLogin() }, 'Back to sign in')));
      } catch (x) { err.textContent = x.message; err.hidden = false; } finally { btn.disabled = false; }
    } }, h('label', { class: 'field' }, h('span', {}, 'Email'), em), h('label', { class: 'field' }, h('span', {}, 'Password (10+ characters)'), pw), err, btn),
    h('button', { class: 'btn wide', type: 'button', onclick: () => renderLogin() }, 'Back to sign in')));
}

function renderForgot() {
  const em = h('input', { type: 'email', required: true, autocomplete: 'username' });
  clear(mount).append(h('div', { class: 'logincard' }, h('h2', {}, 'Reset your password'),
    h('p', { class: 'mut sm' }, 'Enter the email you signed up with. If it belongs to a confirmed account we will send a reset link (valid 1 hour). Operator/admin accounts cannot be reset this way.'),
    h('form', { class: 'loginform', onsubmit: async (e) => {
      e.preventDefault();
      try { await api('/v1/auth/forgot', { method: 'POST', body: { email: em.value } }); toast('If that account exists, a reset link is on its way.', 'ok', 6000); renderLogin(); } catch (x) { toast(x.message, 'bad'); }
    } }, h('label', { class: 'field' }, h('span', {}, 'Email'), em), h('button', { class: 'btn primary wide' }, 'Send reset link')),
    h('button', { class: 'btn wide', type: 'button', onclick: () => renderLogin() }, 'Back to sign in')));
}

/* One-time links from emails: #/verify?token=... and #/reset?token=... (the token is in the fragment, so it is never sent to a server). */
function renderToken(kind, token) {
  history.replaceState(null, '', location.pathname + '#/'); // drop the token from the address bar and history
  if (kind === 'verify') {
    clear(mount).append(h('div', { class: 'logincard' }, h('h2', {}, 'Confirming your email…'), skeleton(2)));
    api('/v1/auth/verify', { method: 'POST', body: { token } })
      .then(() => clear(mount).append(h('div', { class: 'logincard' }, h('h2', {}, 'Email confirmed'), h('p', {}, 'Your account is active. You can sign in now.'), h('button', { class: 'btn primary wide', type: 'button', onclick: () => renderLogin() }, 'Sign in'))))
      .catch((e) => clear(mount).append(h('div', { class: 'logincard' }, h('h2', {}, 'Could not confirm'), h('div', { class: 'errstate', role: 'alert' }, e.message), h('button', { class: 'btn wide', type: 'button', onclick: () => renderLogin() }, 'Back to sign in'))));
    return;
  }
  const pw = h('input', { type: 'password', required: true, minlength: '10', autocomplete: 'new-password' });
  const err = h('div', { class: 'errstate', role: 'alert', hidden: true });
  clear(mount).append(h('div', { class: 'logincard' }, h('h2', {}, 'Choose a new password'),
    h('form', { class: 'loginform', onsubmit: async (e) => {
      e.preventDefault(); err.hidden = true;
      try { await api('/v1/auth/reset', { method: 'POST', body: { token, password: pw.value } }); toast('Password changed. Please sign in.', 'ok'); renderLogin(); } catch (x) { err.textContent = x.message; err.hidden = false; }
    } }, h('label', { class: 'field' }, h('span', {}, 'New password (10+ characters)'), pw), err, h('button', { class: 'btn primary wide' }, 'Change password'))));
}

/* ---------------- static mode: recorded results, clearly labelled ---------------- */
async function renderStatic(why) {
  clear(mount).append(h('div', { class: 'note-bar warn' }, icon('shield'), h('span', {}, h('b', {}, why || 'Static showcase: no backend is connected. '),
    ' The numbers below are recorded output of the real scanner on the bundled samples; sign-in and live scanning need the API. ',
    h('a', { href: 'https://github.com/Dev57668/avishkar/blob/master/RUN_LOCALLY.md', rel: 'noopener noreferrer' }, 'Run it locally'), '. ',
    FORCED_STATIC ? null : h('button', { class: 'btn sm', type: 'button', onclick: boot }, 'Try again'))), h('div', { id: 'static-body' }, skeleton(4)));
  try {
    const r = await fetch('/static/demo_results.json');
    if (!r.ok) throw new Error('missing');
    const d = await r.json();
    clear($('#static-body')).append(h('div', { class: 'grid2' }, ...Object.entries(d.samples).map(([id, s]) => h('div', { class: 'card' },
      h('h3', {}, s.name), h('div', { class: 'mut sm' }, `${cap2(s.kind)} · ${s.language} · recorded scan`),
      s.before.normalizedIndex == null ? h('div', { class: 'warnbox' }, 'Analysis incomplete: no score. Some source files were not evaluated.') : gauge(s.before.normalizedIndex),
      h('div', { class: 'mut sm' }, `${s.before.findings} finding(s) as shipped` + (s.after ? ` → ${s.after.findings} after ${s.after.fixesApplied} fixes (index ${num(s.after.normalizedIndex)})` : '')))),
      h('p', { class: 'mut sm' }, `Score version ${d.scoreVersion}, K=${d.k}, uncalibrated. A zero score means no findings from the supported detectors; it is not proof of safety.`)));
  } catch { clear($('#static-body')).append(emptyState('Recorded results unavailable', 'The static results file could not be loaded.')); }
}
const cap2 = (s) => String(s || '').replace(/^./, (c) => c.toUpperCase());

/* ---------------- boot ---------------- */
async function start() {
  try {
    session.me = await api('/v1/auth/me');
    session.cfg = await api('/v1/config');
  } catch { session.save(null); session.me = null; mode = 'login'; renderLogin('Your session expired or is invalid. Please sign in.'); return; }
  mode = 'authed';
  shell();
  route();
}

async function boot() {
  if (FORCED_STATIC) { mode = 'static'; return renderStatic(); }
  clear(mount).append(h('div', { class: 'note-bar' }, 'Connecting to the scanner… a free-tier backend can take up to a minute to wake up.'), skeleton(3));
  session.pub = await probe();
  if (!session.pub) { mode = 'static'; return renderStatic('Backend unreachable right now: it may be asleep or down. Showing recorded results. '); }
  const link = /^#\/(verify|reset)\?token=([\w-]{20,100})$/.exec(location.hash);
  if (link) { mode = 'login'; return renderToken(link[1], link[2]); }
  session.load();
  if (session.token) return start();
  mode = 'login'; renderLogin();
}

onAuthLost(() => { mode = 'login'; renderLogin('You were signed out. Please sign in again.'); });
window.addEventListener('hashchange', route);
boot();
