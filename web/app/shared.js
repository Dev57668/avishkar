// Shared view helpers: run polling, the real stage stepper, export menu, severity/health badges.
import { api, download, openInNewTab, session } from './api.js';
import { h, icon, num, cap, pill, sevPill, toast, ago, when } from './ui.js';

export const STAGES = [
  ['queued', 'Queued'], ['preparing', 'Preparing files'], ['scanning', 'Scanning in sandbox'],
  ['scoring', 'Scoring'], ['saving', 'Saving results'], ['complete', 'Done'],
];

/** Poll a run until it leaves queued/running. `onUpdate(run)` fires for every poll so the UI can show real stages. */
export async function watchRun(statusUrl, onUpdate, { interval = 700, maxMs = 240000 } = {}) {
  const t0 = Date.now();
  for (;;) {
    const run = await api(statusUrl);
    onUpdate && onUpdate(run);
    if (!['queued', 'running'].includes(run.status)) return run;
    if (Date.now() - t0 > maxMs) throw new Error('The scan is taking too long. It may still finish in the background.');
    await new Promise((r) => setTimeout(r, interval));
  }
}

/** Stage stepper driven by the run's recorded timeline (nothing here is animated independently of the backend). */
export function stepper(run) {
  const tl = (run && run.stages && run.stages.timeline) || [];
  const seen = new Map(tl.map((x) => [x.stage, x.ts]));
  const cur = run && run.stages && run.stages.current;
  const failed = run && ['incomplete', 'failed'].includes(run.status);
  return h('ol', { class: 'stepper', 'aria-label': 'Scan progress' }, STAGES.map(([k, label]) => {
    const done = seen.has(k) && (k !== cur || ['complete', 'incomplete'].includes(run.status));
    const active = k === cur && !done;
    const dur = seen.has(k) ? (() => {
      const idx = tl.findIndex((x) => x.stage === k);
      const next = tl[idx + 1];
      return next ? `${((next.ts - seen.get(k))).toFixed(2)}s` : '';
    })() : '';
    const state = failed && k === 'complete' ? 'bad' : done ? 'done' : active ? 'active' : 'todo';
    return h('li', { class: `step ${state}`, 'aria-current': active ? 'step' : false },
      h('span', { class: 'step-dot' }, state === 'done' ? icon('check') : state === 'bad' ? icon('x') : ''),
      h('span', { class: 'step-l' }, failed && k === 'complete' ? 'Incomplete' : label), dur ? h('span', { class: 'mut sm' }, dur) : null);
  }));
}

export const healthBadge = (hl) => pill(hl.label, `health-${hl.status}`, hl.reason);

export function decisionBadge(outcome) {
  const map = { pass: 'ok', warn: 'warn', block: 'bad', would_block: 'warn', not_evaluated: 'bad', pending: 'mut' };
  return pill(cap(outcome || 'pending'), `st-${map[outcome] || 'mut'}`);
}

export function exportMenu(runId, repoName) {
  const wrap = h('div', { class: 'menu' });
  const btn = h('button', { class: 'btn', type: 'button', 'aria-haspopup': 'true', 'aria-expanded': 'false' }, icon('download'), ' Export');
  const list = h('ul', { class: 'menu-list', role: 'menu', hidden: true });
  const safe = repoName.replace(/[^\w.-]+/g, '_');
  const items = [
    ['SARIF 2.1.0 (code scanning)', async () => download(`/v1/analyses/${runId}/sarif`, `${safe}.sarif`)],
    ['JSON report', async () => download(`/v1/analyses/${runId}/report?format=json`, `${safe}-report.json`)],
    ['HTML report (print to PDF)', async () => { await openInNewTab(`/v1/analyses/${runId}/report?format=html`); }],
  ];
  const close = () => { list.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
  for (const [label, fn] of items) {
    list.append(h('li', { role: 'none' }, h('button', { class: 'menu-item', role: 'menuitem', type: 'button', onclick: async () => {
      close();
      try { await fn(); toast(`${label} ready`, 'ok', 2500); } catch (e) { toast(e.message || 'Export failed', 'bad'); }
    } }, label)));
  }
  btn.addEventListener('click', () => { list.hidden = !list.hidden; btn.setAttribute('aria-expanded', String(!list.hidden)); if (!list.hidden) list.querySelector('button').focus(); });
  wrap.addEventListener('keydown', (e) => { if (e.key === 'Escape') { close(); btn.focus(); } });
  document.addEventListener('click', (e) => { if (!wrap.contains(e.target)) close(); });
  wrap.append(btn, list);
  return wrap;
}

export const kpi = (label, value, sub, extra) => h('div', { class: 'kpi' }, h('div', { class: 'kpi-l' }, label), h('div', { class: 'kpi-v' }, value), sub ? h('div', { class: 'kpi-s mut' }, sub) : null, extra || null);

export function section(id, title, body, actions) {
  return h('section', { class: 'cs', id: `sec-${id}`, 'aria-labelledby': `h-${id}` },
    h('div', { class: 'cs-h' }, h('h2', { id: `h-${id}` }, title), actions || null), body);
}

export const canUpload = () => {
  const up = session.cfg && session.cfg.uploads;
  return (up === 'all' && session.has('analyst')) || (up === 'admin' && session.has('admin'));
};

export const rel = (ts) => h('time', { title: when(ts), datetime: ts ? new Date(ts * 1000).toISOString() : false }, ago(ts));
export { sevPill };
