// Repository command center: gauge, posture, severity, trend, most-vulnerable files, activity, score explanation, compare, findings.
import { api, session } from './api.js';
import { h, clear, num, cap, pill, tip, toast, skeleton, emptyState, errorState, sr, when } from './ui.js';
import { gauge, severityBar, trendChart, hbars, SEV_COLOR } from './charts.js';
import { kpi, section, healthBadge, decisionBadge, exportMenu, rel, stepper } from './shared.js';
import { explorer } from './explorer.js';

export async function repoView(root, repoId, go) {
  root.append(skeleton(8));
  let d;
  try { d = await api(`/v1/repositories/${repoId}/dashboard`); } catch (e) { root.replaceChildren(errorState(e, () => { root.replaceChildren(); repoView(root, repoId, go); })); return; }
  root.replaceChildren();
  const name = d.repository.name, sc = d.score, latest = d.latest;
  const refresh = () => { root.replaceChildren(); repoView(root, repoId, go); };

  const head = h('div', { class: 'repo-head' },
    h('div', {}, h('a', { href: '#/', class: 'crumb' }, '← All repositories'), h('h2', { class: 'repo-name' }, name),
      h('div', { class: 'row' }, healthBadge(d.health), latest ? decisionBadge(latest.decision) : null, latest ? h('span', { class: 'mut sm' }, 'last scan ', rel(latest.startedAt)) : null)),
    latest && latest.status === 'complete' ? exportMenu(latest.runId, name.replace('/', '_')) : null);

  const incomplete = latest && latest.status !== 'complete'
    ? h('div', { class: 'warnbox', role: 'alert' }, h('b', {}, 'The latest analysis did not complete. '), 'This is not a pass and its score is not shown. ', d.coverage && Object.keys(d.coverage.notEvaluated).length ? 'Not evaluated: ' + Object.entries(d.coverage.notEvaluated).map(([k, v]) => `${k} (${v} file${v > 1 ? 's' : ''})`).join(', ') + '.' : '')
    : null;

  // Debt units and the normalized index are the same metric, pre/post transform, not two separate facts — show
  // them together in the gauge's own detail rather than as a competing fourth KPI tile (distill: redundant numbers).
  const gaugeCard = h('div', { class: 'card gauge-card' }, gauge(sc ? sc.normalizedIndex : null),
    h('div', { class: 'gauge-meta' },
      sc && sc.delta != null ? h('div', { class: sc.delta < 0 ? 'good' : sc.delta > 0 ? 'bad' : 'mut' }, `${sc.delta > 0 ? '+' : ''}${num(sc.delta)} vs previous scan (${num(sc.previousIndex)})`) : h('div', { class: 'mut' }, sc ? 'First complete scan: nothing to compare yet' : 'No score yet'),
      sc ? h('div', { class: 'mut sm' }, `${sc.scoreVersion} · K=${sc.k} · uncalibrated · ${num(sc.grossUnits, 2)} debt units (raw, open only: ${num(sc.rawUnits, 2)})`) : null,
      h('div', { class: 'mut sm' }, tip('What does this mean?', 'A prioritization index from provisional weights. It is not a probability of compromise or proof of safety.'))));

  // Triage is the actual job this view supports, so the explorer sits right under the decision/gauge
  // instead of after seven read-only charts (critique: console P1, "buried actionable surface").
  root.append(head, incomplete || '',
    h('div', { class: 'grid2' }, gaugeCard,
      h('div', { class: 'kpis tight' },
        kpi('Open findings', String(d.totalFindings), `${d.severity.critical} critical · ${d.severity.high} high`, null, d.severity.critical ? 'kpi-crit' : d.severity.high ? 'kpi-high' : ''),
        kpi('Files scanned', d.filesScanned == null ? 'n/a' : String(d.filesScanned), d.coverage.analyzedSourceFiles != null ? `${d.coverage.analyzedSourceFiles} source files analyzed` : ''),
        kpi('Scans', String(d.runs), 'recorded'))),
    section('find', 'Vulnerability explorer', latest ? explorer({ repoId, runId: latest.status === 'complete' ? latest.runId : undefined, repoName: name, onChange: () => {} }) : emptyState('No scans yet', 'Run a scan to see findings.')),
    // One card for every way to slice the same findings set (severity, category, file) instead of three separate
    // card shells repeating "open findings" framing — severity leads full-width since it's the primary signal.
    section('breakdown', 'Findings breakdown', h('div', { class: 'fb' },
      h('div', { class: 'fb-sev' }, h('h3', {}, 'By severity'), severityBar(d.severity)),
      h('div', { class: 'fb-split' },
        h('div', {}, h('h3', {}, 'By category'), hbars(Object.entries(d.categories).map(([k, v]) => ({ label: cap(k), value: v })), { empty: 'No open findings.', unit: '' })),
        h('div', {}, h('h3', {}, 'Most vulnerable files'), hbars(d.topFiles.map((f) => ({ label: f.path, value: f.debt, color: SEV_COLOR[f.worst], sub: `${f.findings} finding(s) · worst: ${f.worst}`, tip: `${f.path}: ${num(f.debt, 2)} debt units` })), { empty: 'No files with counted findings.' }))))),
    h('div', { class: 'grid2' },
      section('trend', 'Security debt index over time', trendChart(d.trend.map((t) => ({ y: t.normalizedIndex, ts: t.startedAt, status: t.status, sub: `${t.findings} counted finding(s) · ${t.commitSha || ''}` })))),
      section('act', 'Recent activity', activity(d.activity), null, 'secondary')));

  const slot = h('div', {});
  root.append(section('score', 'Why this score', slot, null, 'secondary'));
  if (latest) lazyExplain(slot, latest.runId, sc);
  const cmp = h('div', {});
  root.append(section('cmp', 'Compare scans (before / after)', cmp, null, 'secondary'));
  compareView(cmp, repoId, d.runs);
  root.append(h('p', { class: 'mut sm disclaimer' }, d.disclaimer));
}

function activity(items) {
  if (!items.length) return h('div', { class: 'chart-empty' }, 'No activity recorded yet.');
  return h('ul', { class: 'activity' }, items.map((a) => h('li', {}, rel(a.ts), h('span', {}, ` ${a.text}`))));
}

async function lazyExplain(slot, runId, sc) {
  const btn = h('button', { class: 'btn', type: 'button', 'aria-expanded': 'false' }, 'Show the arithmetic');
  const body = h('div', { hidden: true });
  slot.append(h('p', { class: 'mut' }, sc ? `Index = 100 × (1 − e^(−D / K)), where D is the sum of per-finding weights. Each finding is weighted I × E × C × A (impact, exposure, confidence, age).` : 'Not calculated for the latest scan.'), btn, body);
  let loaded = false;
  btn.addEventListener('click', async () => {
    body.hidden = !body.hidden; btn.setAttribute('aria-expanded', String(!body.hidden));
    btn.textContent = body.hidden ? 'Show the arithmetic' : 'Hide the arithmetic';
    if (loaded || body.hidden) return;
    body.append(skeleton(4));
    try { const e = await api(`/v1/analyses/${runId}/explain`); loaded = true; clear(body).append(renderExplain(e)); } catch (err) { clear(body).append(errorState(err)); }
  });
}

function renderExplain(e) {
  if (e.status !== 'calculated') return h('div', { class: 'warnbox' }, e.reason);
  const t = e.totals;
  return h('div', {},
    h('ul', { class: 'plain' }, [e.method.formula, e.method.aggregation, e.method.normalization].map((x) => h('li', {}, h('code', {}, x)))),
    h('div', { class: 'tot' }, `Σ D = ${num(t.grossUnits, 3)} → index ${num(t.normalizedIndex)}; recomputed here ${num(t.recomputedIndex)} `, pill(t.reproducible ? 'reproducible' : 'MISMATCH', t.reproducible ? 'st-ok' : 'st-bad')),
    e.flags.exposureUnknown ? h('p', { class: 'mut sm' }, `${e.flags.exposureUnknown} finding(s) have unknown exposure (neutral 1.0, never treated as safe). ${num(e.flags.heuristicShare)}% of debt comes from heuristic rules.`) : null,
    h('div', { class: 'tablewrap' }, h('table', { class: 'tbl' }, h('caption', { class: 'sr' }, 'Per-finding contribution'),
      h('thead', {}, h('tr', {}, ['Finding', 'Where', 'I×E×C×A', 'D', 'Share'].map((x) => h('th', { scope: 'col' }, x)))),
      h('tbody', {}, e.contributions.slice(0, 40).map((c) => h('tr', {}, h('td', {}, h('b', {}, c.title || c.rule), h('div', { class: 'mut sm' }, c.rule)),
        h('td', { class: 'mono' }, `${c.path}:${c.line}`), h('td', { class: 'mono sm' }, c.calculation), h('td', { class: 'mono' }, num(c.D, 2)),
        h('td', {}, h('div', { class: 'mini', role: 'img', 'aria-label': `${c.share}% of total` }, h('i', { style: `width:${Math.min(100, c.share)}%` })), h('span', { class: 'mut sm' }, ` ${c.share}%`))))))),
    e.contributions.length > 40 ? h('p', { class: 'mut sm' }, `Showing the 40 largest of ${e.contributions.length}.`) : null,
    h('ul', { class: 'plain mut sm' }, e.method.notes.map((n) => h('li', {}, n))),
    h('p', { class: 'mut sm' }, e.method.disclaimer));
}

export async function compareView(slot, repoId, runCount) {
  if (runCount < 2) { slot.append(emptyState('Need two scans', 'Scan again after a change to see what moved. Incomplete scans are never compared as zero.')); return; }
  slot.append(skeleton(3));
  let c;
  try { c = await api(`/v1/repositories/${repoId}/compare`); } catch (e) { clear(slot).append(e.status === 422 ? emptyState('Need two complete scans', e.message) : errorState(e)); return; }
  clear(slot).append(renderCompare(c));
}

export function renderCompare(c) {
  if (!c.comparable) return h('div', { class: 'warnbox' }, c.reason);
  const side = (r, l) => h('div', { class: 'cmp-side' }, h('div', { class: 'mut sm' }, l), h('div', { class: 'cmp-n' }, r.normalizedIndex == null ? 'n/a' : num(r.normalizedIndex)), h('div', { class: 'mut sm' }, r.commitSha || ''), h('div', { class: 'mut sm' }, when(r.startedAt)));
  const list = (title, items, cls, fn) => items.length ? h('div', { class: `cmp-list ${cls}` }, h('h3', {}, `${title} (${items.length})`), h('ul', {}, items.slice(0, 25).map((i) => h('li', {}, h('b', {}, i.title || i.rule), ' ', h('code', {}, `${i.path}:${i.line}`), ' ', h('span', { class: 'mono' }, fn(i))))), items.length > 25 ? h('p', { class: 'mut sm' }, `+${items.length - 25} more`) : null) : null;
  return h('div', {},
    h('div', { class: 'cmp-head' }, side(c.base, 'Before'), h('div', { class: `cmp-delta ${c.delta.index < 0 ? 'good' : c.delta.index > 0 ? 'bad' : ''}` }, `${c.delta.index > 0 ? '+' : ''}${num(c.delta.index)}`, h('div', { class: 'mut sm' }, 'index change')), side(c.head, 'After')),
    h('ul', { class: 'plain' }, c.explanation.map((x) => h('li', {}, x))),
    list('Fixed', c.fixed, 'good', (i) => `−${num(i.D, 2)}`), list('Introduced', c.introduced, 'bad', (i) => `+${num(i.D, 2)}`),
    list('Changed weight', c.changed, '', (i) => `${num(i.before, 2)} → ${num(i.after, 2)}`),
    h('p', { class: 'mut sm' }, `${c.unchanged} finding(s) unchanged. `, c.reconciles ? 'The per-finding changes add up exactly to the change in total debt.' : h('b', {}, 'Warning: the per-finding changes do not reconcile with the total.')),
    c.note ? h('p', { class: 'mut sm' }, c.note) : null);
}
