// Admin console (admin role only; the API enforces the role regardless of what the UI shows).
import { api } from './api.js';
import { h, clear, cap, icon, pill, toast, confirmDialog, dialog, skeleton, errorState, copyBtn, when, staggerIn, REDUCED_MOTION, EASE_SETTLE } from './ui.js';

const table = (caption, heads, rows, empty = 'None.') => h('div', { class: 'tablewrap' }, h('table', { class: 'tbl' }, h('caption', { class: 'sr' }, caption),
  h('thead', {}, h('tr', {}, heads.map((x) => h('th', { scope: 'col' }, x)))), h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: heads.length, class: 'mut' }, empty)))));
const field = (label, input) => h('label', { class: 'field' }, h('span', {}, label), input);
// Same status-pill vocabulary as decisionBadge/healthBadge elsewhere in the console, so "active/revoked/dead/denied"
// read as the same kind of signal here as a scan decision does, instead of this tab being the one flat, textual area.
const activePill = (active) => pill(active ? 'Active' : 'Inactive', active ? 'st-ok' : 'st-mut');
const JOB_STATUS = { queued: 'st-mut', running: 'st-warn', done: 'st-ok', dead: 'st-bad' };
const jobPill = (status) => pill(cap(status), JOB_STATUS[status] || 'st-mut');
const OUTCOME = { ok: 'st-ok', denied: 'st-bad' };
const outcomePill = (outcome) => pill(cap(outcome), OUTCOME[outcome] || 'st-mut');

// Each tab gets one identity color pulled from tokens already on .console (DESIGN.md's cobalt/teal-highlight plus
// the existing severity/status set) — a deliberate accent per section rather than scattering unrelated hues.
const TAB_META = {
  users: { label: 'Users', icon: 'user', accent: '--cobalt' },
  keys: { label: 'API keys', icon: 'key', accent: '--acc' },
  github: { label: 'GitHub', icon: 'branch', accent: '--teal' },
  jobs: { label: 'Jobs', icon: 'queue', accent: '--warn' },
  audit: { label: 'Audit & metrics', icon: 'shield', accent: '--good' },
};
const accentStyle = (key) => `--accent:var(${TAB_META[key].accent})`;
const sectionHead = (key, title, sub) => h('div', { class: 'admin-head', style: accentStyle(key) }, icon(TAB_META[key].icon), h('h3', {}, title), sub ? h('span', { class: 'mut sm' }, sub) : null);
const card = (key, ...kids) => h('div', { class: 'admin-card', style: accentStyle(key) }, ...kids);
const tableCard = (key, tableNode) => h('div', { class: 'admin-card table-card', style: accentStyle(key) }, tableNode);

const TABS = {
  async users(me, refresh) {
    const { items } = await api('/v1/users');
    const email = h('input', { type: 'email', required: true, autocomplete: 'off' });
    const pw = h('input', { type: 'password', minlength: '10', required: true, autocomplete: 'new-password' });
    const role = h('select', {}, ['viewer', 'analyst', 'admin'].map((r) => h('option', {}, r)));
    const form = h('form', { class: 'aform', onsubmit: async (e) => {
      e.preventDefault();
      try { await api('/v1/users', { method: 'POST', body: { email: email.value, password: pw.value, role: role.value } }); toast('User created', 'ok'); refresh(); } catch (err) { toast(err.message, 'bad'); }
    } }, field('Email', email), field('Password (10+ characters)', pw), field('Role', role), h('button', { class: 'btn primary' }, 'Add user'));
    return h('div', { class: 'admin-tab' },
      sectionHead('users', 'Add a user', null),
      card('users', form),
      sectionHead('users', 'All users', `${items.length} total`),
      tableCard('users', table('Users', ['Email', 'Role', 'Active', ''], items.map((u) => h('tr', {}, h('td', {}, u.email), h('td', {}, u.role), h('td', {}, activePill(u.active)),
        h('td', {}, u.email === me ? h('span', { class: 'mut' }, 'you') : u.active ? h('button', { class: 'btn sm danger', type: 'button', 'aria-label': `Deactivate ${u.email}`, onclick: async () => {
          if (await confirmDialog({ title: 'Deactivate user?', message: `${u.email} will be signed out immediately.`, confirmLabel: 'Deactivate', danger: true })) {
            try { await api(`/v1/users/${u.id}`, { method: 'DELETE' }); toast('User deactivated', 'ok'); refresh(); } catch (err) { toast(err.message, 'bad'); }
          }
        } }, 'Deactivate') : null))))));
  },
  async keys(me, refresh) {
    const { items } = await api('/v1/api-keys');
    const label = h('input', { required: true, maxlength: '100' });
    const role = h('select', {}, ['analyst', 'viewer', 'admin'].map((r) => h('option', {}, r)));
    const form = h('form', { class: 'aform', onsubmit: async (e) => {
      e.preventDefault();
      try {
        const r = await api('/v1/api-keys', { method: 'POST', body: { label: label.value, role: role.value } });
        await dialog({ title: 'Copy your new API key', body: h('div', {}, h('p', {}, 'It is shown once and cannot be retrieved later.'), h('code', { class: 'secret' }, r.key), copyBtn(r.key, 'Copy key')), actions: [{ label: 'Done', primary: true, value: true }] });
        refresh();
      } catch (err) { toast(err.message, 'bad'); }
    } }, field('Label', label), field('Role', role), h('button', { class: 'btn primary' }, 'Create key'));
    return h('div', { class: 'admin-tab' },
      sectionHead('keys', 'Create an API key', null),
      card('keys', form),
      sectionHead('keys', 'All keys', `${items.length} total`),
      tableCard('keys', table('API keys', ['Label', 'Role', 'Status', 'Created', ''], items.map((k) => h('tr', {}, h('td', {}, k.label), h('td', {}, k.role), h('td', {}, pill(k.active ? 'Active' : 'Revoked', k.active ? 'st-ok' : 'st-bad')), h('td', {}, when(k.created_at)),
        h('td', {}, k.active ? h('button', { class: 'btn sm danger', type: 'button', onclick: async () => {
          if (await confirmDialog({ title: 'Revoke key?', message: `Key “${k.label}” stops working immediately.`, confirmLabel: 'Revoke', danger: true })) {
            try { await api(`/v1/api-keys/${k.id}`, { method: 'DELETE' }); toast('Key revoked', 'ok'); refresh(); } catch (err) { toast(err.message, 'bad'); }
          }
        } }, 'Revoke') : null))))));
  },
  async github(me, refresh) {
    const [{ items }, cfg] = await Promise.all([api('/v1/github/installations'), api('/v1/config')]);
    const ok = cfg.github.configured;
    const inst = h('input', { pattern: '\\d{1,20}', required: true, inputmode: 'numeric' });
    const acct = h('input', { required: true, maxlength: '100' });
    const form = h('form', { class: 'aform', onsubmit: async (e) => { e.preventDefault(); try { await api('/v1/github/installations', { method: 'POST', body: { installation_id: inst.value, account: acct.value } }); toast('Installation linked', 'ok'); refresh(); } catch (err) { toast(err.message, 'bad'); } } },
      field('Installation ID', inst), field('Account', acct), h('button', { class: 'btn primary' }, 'Link installation'));
    return h('div', { class: 'admin-tab' },
      sectionHead('github', 'Server configuration', null),
      card('github',
        h('div', { class: ok ? 'okbox' : 'warnbox' }, ok ? 'GitHub App credentials and webhook secret are configured on the server.'
          : 'GitHub is NOT connected. Set GITHUB_WEBHOOK_SECRET, GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY on the server. Until then no repositories can be listed or scanned from GitHub, and webhooks are rejected.'),
        h('p', { class: 'mut sm' }, 'Webhook URL: ', h('code', {}, '/v1/github/webhook'))),
      sectionHead('github', 'Link an installation', null),
      card('github', form),
      sectionHead('github', 'Installations', `${items.length} linked`),
      tableCard('github', table('GitHub installations', ['Installation', 'Account', 'Active'], items.map((i) => h('tr', {}, h('td', {}, String(i.installation_id)), h('td', {}, i.account), h('td', {}, activePill(i.active)))))));
  },
  async jobs(me, refresh) {
    const { items } = await api('/v1/jobs');
    return h('div', { class: 'admin-tab' },
      sectionHead('jobs', 'Job queue', `${items.length} tracked`),
      tableCard('jobs', table('Jobs', ['Job', 'Kind', 'Status', 'Attempts', 'Error', 'Updated', ''], items.map((j) => h('tr', {}, h('td', {}, h('code', {}, j.id)), h('td', {}, j.kind), h('td', {}, jobPill(j.status)), h('td', {}, `${j.attempts}/${j.max_attempts}`),
        h('td', {}, j.error || ''), h('td', {}, when(j.updated_at)),
        h('td', {}, j.status === 'dead' ? h('button', { class: 'btn sm', type: 'button', onclick: async () => { try { await api(`/v1/jobs/${j.id}/requeue`, { method: 'POST' }); toast('Job requeued', 'ok'); refresh(); } catch (err) { toast(err.message, 'bad'); } } }, 'Requeue') : null))))));
  },
  async audit() {
    const [a, m] = await Promise.all([api('/v1/audit'), api('/v1/metrics')]);
    return h('div', { class: 'admin-tab' },
      sectionHead('audit', 'Counters', null),
      card('audit', h('p', { class: 'row' }, Object.entries(m.counters).map(([k, v]) => h('span', { class: 'chip' }, h('code', {}, k), ' ', String(v))))),
      sectionHead('audit', 'Audit events', `last ${Math.min(50, a.items.length)}`),
      tableCard('audit', table('Audit events', ['When', 'Actor', 'Action', 'Object', 'Outcome'], a.items.slice(0, 50).map((e) => h('tr', {}, h('td', {}, when(e.ts)), h('td', {}, e.actor), h('td', {}, e.action), h('td', {}, h('code', {}, e.object_id)), h('td', {}, outcomePill(e.outcome)))))));
  },
};

export function adminView(root, me) {
  let tab = 'users';
  const bar = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Admin sections' });
  const panel = h('div', { role: 'tabpanel', class: 'panel' });
  async function show() {
    clear(bar).append(...Object.keys(TABS).map((k) => h('button', { role: 'tab', type: 'button', class: 'tab', style: `--tab-accent:var(${TAB_META[k].accent})`,
      'aria-selected': String(k === tab), tabindex: k === tab ? '0' : '-1', onclick: () => { tab = k; show(); },
      onkeydown: (e) => { const ks = Object.keys(TABS); const i = ks.indexOf(tab); if (e.key === 'ArrowRight') { tab = ks[(i + 1) % ks.length]; show().then(() => bar.querySelector('[aria-selected=true]').focus()); } if (e.key === 'ArrowLeft') { tab = ks[(i + ks.length - 1) % ks.length]; show().then(() => bar.querySelector('[aria-selected=true]').focus()); } } },
      icon(TAB_META[k].icon), TAB_META[k].label)));
    // A different section (or a refreshed one) is a state change worth a quick crossfade — exit faster than entrance,
    // and skip it entirely on first render (nothing to fade from) or under reduced motion.
    if (panel.childElementCount && !REDUCED_MOTION && panel.animate) {
      await panel.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 90, easing: 'ease-in' }).finished;
    }
    clear(panel).append(skeleton(4));
    try { clear(panel).append(await TABS[tab](me, show)); } catch (e) { clear(panel).append(errorState(e, show)); }
    if (!REDUCED_MOTION && panel.animate) panel.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: EASE_SETTLE });
    staggerIn(panel, '.tbl tbody tr');
  }
  root.append(h('h2', {}, 'Administration'), bar, panel);
  show();
}
