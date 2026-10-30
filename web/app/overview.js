// Organization overview: every repository, worst first, with real severity counts. Nothing is estimated.
import { api } from './api.js';
import { h, num, cap, skeleton, emptyState, errorState, sr } from './ui.js';
import { severityBar, hbars, SEV_COLOR } from './charts.js';
import { kpi, section, healthBadge, rel, canUpload } from './shared.js';

const HEALTH = { critical: 'Critical open', attention: 'High open', watch: 'Lower open', none_detected: 'None detected', incomplete: 'Incomplete', no_data: 'No data' };

export async function overviewView(root, go) {
  root.append(skeleton(6));
  let o;
  try { o = await api('/v1/overview'); } catch (e) { root.replaceChildren(errorState(e, () => { root.replaceChildren(); overviewView(root, go); })); return; }
  root.replaceChildren();
  const total = Object.values(o.severity).reduce((a, b) => a + b, 0);
  root.append(
    h('div', { class: 'kpis' },
      kpi('Repositories', String(o.repositoryCount), `${o.scoredRepositories} with a calculated score`),
      kpi('Open findings', String(total), 'across all repositories'),
      kpi('Highest index', o.highestIndex == null ? 'n/a' : num(o.highestIndex), 'higher = more debt, uncalibrated'),
      kpi('Critical + high', String(o.severity.critical + o.severity.high), 'open')),
    section('sev', 'Open findings by severity', severityBar(o.severity)),
    section('repos', 'Repositories, highest debt first',
      o.repositories.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'tbl' },
        h('caption', { class: 'sr' }, 'Repositories'),
        h('thead', {}, h('tr', {}, ['Repository', 'Index', 'Open findings', 'Health', 'Runs', 'Last scan', ''].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', {}, o.repositories.map((r) => {
          const open = Object.values(r.severity).reduce((a, b) => a + b, 0);
          return h('tr', { class: 'clickrow', tabindex: '0', onclick: () => go(`#/repo/${r.id}`), onkeydown: (e) => { if (e.key === 'Enter') go(`#/repo/${r.id}`); } },
            h('td', {}, h('b', {}, r.name)),
            h('td', { class: 'mono' }, r.normalizedIndex == null ? h('span', { class: 'mut', title: 'No calculated score (no scan, or the analysis was incomplete)' }, 'n/a') : num(r.normalizedIndex)),
            h('td', {}, String(open), ' ', h('span', { class: 'minisev' }, SEV_ORDER.filter((s) => r.severity[s]).map((s) => h('i', { style: `background:${SEV_COLOR[s]}`, title: `${r.severity[s]} ${s}` }, r.severity[s])))),
            h('td', {}, h('span', { class: `pill health-${r.health}` }, HEALTH[r.health] || r.health)),
            h('td', { class: 'mono' }, String(r.runs)), h('td', {}, r.lastScan ? rel(r.lastScan) : '–'),
            h('td', {}, h('button', { class: 'btn sm', type: 'button', 'aria-label': `Open ${r.name}`, onclick: (e) => { e.stopPropagation(); go(`#/repo/${r.id}`); } }, 'Open')));
        })))) : emptyState('No repositories yet', canUpload() ? 'Upload a zip to run the first scan, or try the demo lab.' : 'Try the demo lab to run a real scan of a bundled sample.',
        h('button', { class: 'btn primary', type: 'button', onclick: () => go('#/demo') }, 'Open demo lab'))),
    h('p', { class: 'mut sm disclaimer' }, o.disclaimer));
}
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
