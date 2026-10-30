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
    session.cfg && session.cfg.uploads === 'all' ? 'enabled.' : 'limited to the owner (no container sandbox on this host).'));
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
    view.append(h('p', { class: 'mut sm' }, session.cfg && session.cfg.uploads !== 'all'
      ? 'Uploading your own code is disabled for this account on this instance (it cannot sandbox untrusted code here). Run Avishkar locally with the Docker sandbox to scan your own repositories.' : 'Your role cannot upload.'));
    return;
  }
  const repo = h('input', { id: 'up-repo', required: true, pattern: '[\\w.\\-/]{1,100}', placeholder: 'org/name', 'aria-label': 'Repository name' });
  const file = h('input', { id: 'up-file', type: 'file', accept: '.zip', required: true, 'aria-label': 'Zip archive' });
  const out = h('div', { 'aria-live': 'polite' });
  const btn = h('button', { class: 'btn primary' }, 'Analyze');
  view.append(h('section', { class: 'cs' }, h('div', { class: 'cs-h' }, h('h2', {}, 'Scan a repository snapshot')),
    h('form', { class: 'aform', onsubmit: async (e) => {
      e.preventDefault();
      const f = file.files[0];
      if (!f) return;
      if (f.size > 50 * 1024 * 1024) { toast('That file is larger than the 50 MB upload limit.', 'warn'); return; }
      btn.disabled = true; clear(out).append(skeleton(2));
      try {
        const fd = new FormData(); fd.append('repository', repo.value); fd.append('archive', f);
        const q = await api('/v1/analyses', { method: 'POST', form: fd, timeout: 120000 });
        const run = await watchRun(q.statusUrl, (r) => { out.textContent = `Analysis ${r.status}${r.stages && r.stages.current ? ' · ' + r.stages.current : ''}…`; });
        toast(`Analysis ${run.status}`, run.status === 'complete' ? 'ok' : 'warn');
        go(`#/repo/${q.repositoryId}`);
      } catch (err) { clear(out).append(errorState(err)); } finally { btn.disabled = false; }
    } }, h('label', { class: 'field' }, h('span', {}, 'Repository name'), repo), h('label', { class: 'field' }, h('span', {}, 'Zip archive'), file), btn), out,
    h('p', { class: 'mut sm' }, 'Archives are unpacked in isolation; path traversal, symlinks and zip bombs are rejected.')));
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
      if (!r.ok) throw new Error((j.error && j.error.message) || 'Sign-in failed');
      session.save(j.token); pw.value = '';
      await start();
    } catch (x) { err.textContent = x.message; err.hidden = false; } finally { btn.disabled = false; }
  } }, h('label', { class: 'field' }, h('span', {}, 'Email'), em), h('label', { class: 'field' }, h('span', {}, 'Password'), pw), err, btn);
  clear(mount).append(h('div', { class: 'logincard' },
    h('h2', {}, 'Sign in to the console'), msg ? h('p', { class: 'mut' }, msg) : null,
    pub.demo ? h('div', { class: 'note-bar' }, h('span', {}, h('b', {}, 'Live public demo. '), L ? 'Use the read-only demo account:' : 'The operator has not published a demo login.'), ' ',
      L ? h('code', {}, `${L.email} / ${L.password}`) : null, L ? h('button', { class: 'btn sm', type: 'button', onclick: () => { em.value = L.email; pw.value = L.password; pw.focus(); } }, 'Fill in the login') : null) : null,
    form,
    h('p', { class: 'mut sm' }, h('b', {}, 'First run? '), 'There is no self sign-up. The first time the server starts it prints an admin email and password in its terminal.')));
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
  session.load();
  if (session.token) return start();
  mode = 'login'; renderLogin();
}

onAuthLost(() => { mode = 'login'; renderLogin('You were signed out. Please sign in again.'); });
window.addEventListener('hashchange', route);
boot();
