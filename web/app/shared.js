// Shared view helpers: run polling, the real stage stepper, export menu, severity/health badges.
import { api, download, openInNewTab, session } from './api.js';
import { h, icon, num, cap, pill, sevPill, toast, ago, when, dialog } from './ui.js';

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
  const reason = {
    would_block: 'Report-only mode: the policy says what it would block. Nothing is actually blocked.',
    not_evaluated: 'The scan did not complete, so no decision could be reached. This is never the same as a pass.',
    pending: 'No completed scan yet.',
  };
  return pill(cap(outcome || 'pending'), `st-${map[outcome] || 'mut'}`, reason[outcome] || '');
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

// accent is an optional modifier class (e.g. a severity tint) so the one KPI that's actually a security signal
// can outrank the purely administrative ones (files scanned, scan count) without inventing a new visual language.
export const kpi = (label, value, sub, extra, accent) => h('div', { class: `kpi ${accent || ''}`.trim() }, h('div', { class: 'kpi-l' }, label), h('div', { class: 'kpi-v' }, value), sub ? h('div', { class: 'kpi-s mut' }, sub) : null, extra || null);

// tone 'secondary' keeps the real <h2> (document outline stays correct) but renders it visually lighter, so a
// repo page can tell apart what matters most (the explorer, the breakdown) from supporting detail (compare, activity).
export function section(id, title, body, actions, tone) {
  return h('section', { class: `cs${tone === 'secondary' ? ' cs-secondary' : ''}`, id: `sec-${id}`, 'aria-labelledby': `h-${id}` },
    h('div', { class: 'cs-h' }, h('h2', { id: `h-${id}` }, title), actions || null), body);
}

// Known-cheap check against the config already fetched at boot, so the explorer can skip rendering
// "Ask AI about this" (and the wasted click + drawer round-trip) when it could never work anyway.
// The drawer's own /v1/assistant/status call stays authoritative for the reason/role-detail copy.
export const canUseAssistant = () => !!(session.cfg && session.cfg.ai && session.cfg.ai.enabled) && session.has('analyst');

export const canUpload = () => {
  const up = session.cfg && session.cfg.uploads;
  return ((up === 'all' || up === 'limited') && session.has('analyst')) || (up === 'admin' && session.has('admin'));
};

export const rel = (ts) => h('time', { title: when(ts), datetime: ts ? new Date(ts * 1000).toISOString() : false }, ago(ts));
export { sevPill };

// Persistent glossary for the specialized vocabulary the honesty stance depends on (would_block, uncalibrated,
// assurance levels, ...), which otherwise recurs across the console with at most one scattered hover tooltip.
const GLOSSARY = [
  ['Security debt index', 'A 0–100 prioritization score from provisional, uncalibrated weights. It is not a probability of compromise or proof that code is safe.'],
  ['Uncalibrated', 'The scoring weights have not been validated against a real, independently-labelled corpus. Treat the index as a ranking signal, not a verdict.'],
  ['Would block', 'This instance runs in report-only mode: the policy states what it would block, but nothing is actually blocked.'],
  ['Not evaluated', 'The scan could not analyze this language or file. It is never shown as clean — "not evaluated" is not the same as "no findings."'],
  ['Structural / Heuristic / Advisory database', 'How a finding was matched. Structural: found in parsed code (exploitability still depends on data flow the scanner does not prove). Heuristic: a naming/shape pattern — expect false positives. Advisory database: matched a bundled advisory list; the version is a fact, relevance to your code is not.'],
  ['Reproducible', 'The displayed index is recomputed independently from the per-finding contributions and compared. A "MISMATCH" would mean the total cannot be trusted.'],
  ['Exposure unknown (neutral)', "When a finding's real-world exposure can't be determined, it's scored as neutral (1.0) rather than assumed safe."],
];
export function openGlossary() {
  dialog({
    title: 'What am I looking at?',
    body: h('dl', { class: 'glossary' }, GLOSSARY.flatMap(([term, def]) => [h('dt', {}, term), h('dd', {}, def)])),
    actions: [{ label: 'Close', value: true, primary: true }],
  });
}
