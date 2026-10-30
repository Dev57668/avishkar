// GitHub view: browse repositories and branches of a linked GitHub App installation and scan a branch head.
// Shows "not connected" honestly when the server has no GitHub App credentials; nothing here is simulated.
import { api, session } from './api.js';
import { h, clear, icon, toast, skeleton, errorState, emptyState } from './ui.js';
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
  loadRepos();
}
