// GitHub view: browse repositories and branches of a linked GitHub App installation and scan a branch head.
// Shows "not connected" honestly when the server has no GitHub App credentials; nothing here is simulated.
import { api, session } from './api.js';
import { h, clear, icon, toast, skeleton, errorState, emptyState, confirmDialog, num, when } from './ui.js';
import { section, stepper, watchRun, decisionBadge } from './shared.js';

export async function githubView(root, go) {
  root.append(skeleton(4));
  let cfg, inst = { items: [] };
  try {
    cfg = await api('/v1/config');
    if (session.has('admin')) inst = await api('/v1/github/installations');
  } catch (e) { root.replaceChildren(errorState(e)); return; }
  root.replaceChildren(h('h2', {}, icon('branch'), ' GitHub'));
  if (!cfg.github.configured) {
    root.append(h('div', { class: 'warnbox', role: 'status' }, h('b', {}, 'GitHub is not connected on this server. '),
      'No repositories can be listed or scanned from GitHub, no check runs are posted, and webhooks are rejected until the operator sets ',
      h('code', {}, 'GITHUB_APP_ID'), ', ', h('code', {}, 'GITHUB_APP_PRIVATE_KEY'), ' and ', h('code', {}, 'GITHUB_WEBHOOK_SECRET'), ' and links an installation.'),
      h('p', { class: 'mut' }, 'You can still scan the bundled samples in the demo lab or upload a zip (where uploads are enabled).'),
      h('button', { class: 'btn', type: 'button', onclick: () => go('#/demo') }, 'Open demo lab'));
    return;
  }
  if (!session.has('analyst')) { root.append(emptyState('Analyst role required', 'Browsing and scanning GitHub repositories needs the analyst role.')); return; }
  const installs = inst.items.filter((i) => i.active);
  const instSel = h('select', { 'aria-label': 'GitHub installation' }, installs.map((i) => h('option', { value: i.installation_id }, `${i.account} (#${i.installation_id})`)));
  const repoSel = h('select', { 'aria-label': 'Repository', disabled: true }, h('option', { value: '' }, 'Choose a repository'));
  const brSel = h('select', { 'aria-label': 'Branch', disabled: true }, h('option', { value: '' }, 'Choose a branch'));
  const btn = h('button', { class: 'btn primary', type: 'button', disabled: true }, icon('play'), ' Scan branch head');
  const out = h('div', { 'aria-live': 'polite' });
  const fill = (sel, first, items, label) => { clear(sel).append(h('option', { value: '' }, first), ...items.map((x) => h('option', { value: label(x)[0] }, label(x)[1]))); sel.disabled = !items.length; };

  async function loadRepos() {
    if (!instSel.value) return;
    fill(repoSel, 'Loading…', [], () => []); fill(brSel, 'Choose a branch', [], () => []); btn.disabled = true;
    try { const r = await api(`/v1/github/repositories?installation=${instSel.value}`); fill(repoSel, r.items.length ? 'Choose a repository' : 'No repositories visible to this installation', r.items, (x) => [x.name, `${x.name}${x.private ? ' (private)' : ''}`]); }
    catch (e) { fill(repoSel, 'Unavailable', [], () => []); toast(e.message, 'bad'); }
  }
  async function loadBranches() {
    btn.disabled = true;
    if (!repoSel.value) return fill(brSel, 'Choose a branch', [], () => []);
    fill(brSel, 'Loading…', [], () => []);
    try { const r = await api(`/v1/github/branches?installation=${instSel.value}&repo=${encodeURIComponent(repoSel.value).replace('%2F', '/')}`); fill(brSel, 'Choose a branch', r.items, (x) => [x.name, `${x.name} @ ${x.sha.slice(0, 8)}`]); }
    catch (e) { fill(brSel, 'Unavailable', [], () => []); toast(e.message, 'bad'); }
  }
  instSel.addEventListener('change', loadRepos);
  repoSel.addEventListener('change', loadBranches);
  brSel.addEventListener('change', () => { btn.disabled = !brSel.value; });
  btn.addEventListener('click', async () => {
    btn.disabled = true; clear(out).append(h('div', { id: 'gh-steps' }, stepper(null)));
    try {
      const q = await api('/v1/github/scan', { method: 'POST', body: { installation: instSel.value, repo: repoSel.value, branch: brSel.value } });
      if (q.deduplicated) toast('This commit was already queued or scanned; showing that run.', 'info');
      const run = await watchRun(q.statusUrl, (r) => out.querySelector('#gh-steps').replaceChildren(stepper(r)));
      clear(out).append(h('div', { class: 'card' }, h('div', { class: 'row' }, decisionBadge(run.decision.outcome), h('span', {}, `Analysis ${run.status} at commit ${q.commitSha.slice(0, 8)}`)),
        run.status !== 'complete' ? h('div', { class: 'warnbox' }, 'Incomplete analysis: this is not a pass.') : null,
        h('p', { class: 'mut sm' }, 'A GitHub check run is posted by the same pipeline for webhook-triggered scans; manual branch scans do not post PR comments.'),
        h('button', { class: 'btn primary', type: 'button', onclick: () => go(`#/repo/${q.repositoryId}`) }, 'Open dashboard')));
    } catch (e) { clear(out).append(errorState(e)); } finally { btn.disabled = !brSel.value; }
  });
  if (!installs.length) { root.append(emptyState('No active installation', session.has('admin') ? 'Link an installation in Administration → GitHub.' : 'Ask an admin to link a GitHub App installation.')); return; }
  root.append(section('gh', 'Scan a branch', h('div', {}, h('div', { class: 'aform' },
    h('label', { class: 'field' }, h('span', {}, 'Installation'), instSel), h('label', { class: 'field' }, h('span', {}, 'Repository'), repoSel),
    h('label', { class: 'field' }, h('span', {}, 'Branch'), brSel), btn), out,
    h('p', { class: 'mut sm' }, 'The commit is resolved by GitHub at scan time; it is never taken from your browser. Results appear as a normal repository with a run history, so you can compare commits.'))));
  if (session.has('admin')) schedulePanel(root, instSel, repoSel, brSel);
  loadRepos();
}

/* Scheduled rescans (admin): re-scan a branch every N hours and email a summary when something changed. */
function schedulePanel(root, instSel, repoSel, brSel) {
  const body = h('div', {});
  root.append(section('sched', 'Scheduled rescans', body));
  const every = h('select', { 'aria-label': 'Rescan every' }, [[6, 'every 6 hours'], [12, 'every 12 hours'], [24, 'every day'], [72, 'every 3 days'], [168, 'every week']].map(([v, l]) => h('option', { value: v, selected: v === 24 }, l)));
  const notify = h('select', { 'aria-label': 'Email changes to' }, h('option', { value: '' }, 'No email'));
  const add = h('button', { class: 'btn primary', type: 'button' }, icon('refresh'), ' Schedule rescans');
  const list = h('div', {});

  async function load() {
    clear(list).append(skeleton(2));
    try {
      const [s, users] = await Promise.all([api('/v1/schedules'), api('/v1/users')]);
      clear(notify).append(h('option', { value: '' }, s.emailConfigured ? 'No email' : 'No email (email is not set up on this server)'),
        ...(s.emailConfigured ? users.items.filter((u) => u.active).map((u) => h('option', { value: u.email }, u.email)) : []));
      clear(list).append(s.items.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'tbl' }, h('caption', { class: 'sr' }, 'Scheduled rescans'),
        h('thead', {}, h('tr', {}, ['Repository', 'Branch', 'Every', 'Last result', 'Email', 'Next scan', ''].map((x) => h('th', { scope: 'col' }, x)))),
        h('tbody', {}, s.items.map((x) => h('tr', {}, h('td', {}, h('a', { href: `#/repo/${x.repositoryId}` }, x.repo)), h('td', {}, x.branch), h('td', {}, `${x.everyHours} h`),
          h('td', {}, x.lastStatus ? `${x.lastStatus === 'complete' ? 'index ' + (x.lastIndex == null ? 'n/a' : num(x.lastIndex)) : x.lastStatus}` : 'waiting for the first scan'),
          h('td', {}, x.notifyEmail || '-'), h('td', {}, when(x.nextRun)),
          h('td', {}, h('button', { class: 'btn sm danger', type: 'button', 'aria-label': `Stop rescanning ${x.repo} ${x.branch}`, onclick: async () => {
            if (await confirmDialog({ title: 'Stop scheduled rescans?', message: `${x.repo} (${x.branch}) will no longer be rescanned automatically. Existing results stay.`, confirmLabel: 'Stop', danger: true })) {
              try { await api(`/v1/schedules/${x.id}`, { method: 'DELETE' }); toast('Schedule removed', 'ok'); load(); } catch (e) { toast(e.message, 'bad'); }
            }
          } }, 'Stop'))))))) : h('p', { class: 'mut' }, `No schedules yet (up to ${s.max}).`));
    } catch (e) { clear(list).append(errorState(e, load)); }
  }

  add.addEventListener('click', async () => {
    if (!instSel.value || !repoSel.value || !brSel.value) { toast('Choose an installation, repository and branch above first.', 'warn'); return; }
    add.disabled = true;
    try {
      await api('/v1/schedules', { method: 'POST', body: { installation: instSel.value, repo: repoSel.value, branch: brSel.value, everyHours: Number(every.value), notifyEmail: notify.value || null } });
      toast('Scheduled. The first scan starts within a minute and sets the baseline; later scans email you only when something changed.', 'ok', 6000);
      load();
    } catch (e) { toast(e.message, 'bad'); } finally { add.disabled = false; }
  });

  body.append(h('p', { class: 'mut sm' }, 'Pick a repository and branch in the form above, then schedule it here. The same commit is rescanned on purpose, because the vulnerability database changes even when the code does not. Emails list counts, rule titles and file locations only, never code.'),
    h('div', { class: 'aform' }, h('label', { class: 'field' }, h('span', {}, 'Rescan'), every), h('label', { class: 'field' }, h('span', {}, 'Email changes to'), notify), add), list);
  load();
}
