// Dependency-free SVG charts. Every chart has a text alternative (aria-label + a visually hidden data table) and
// keyboard-reachable data points with tooltips. Only values passed in are drawn: nothing is smoothed, filled or invented.
import { h, svg, num, cap, SEV, when, sr } from './ui.js';

export const SEV_COLOR = { critical: '#ff4d5e', high: '#ff8a4d', medium: '#ffb547', low: '#7cb4ff', informational: '#9aa7b8' };

/* Security Debt Index gauge: a 0-100 scale. The colour ramp is a visual scale only, NOT risk bands (the score is uncalibrated). */
export function gauge(value, { label = 'Security debt index', size = 220 } = {}) {
  const R = 86, C = Math.PI * R; // half circle length
  const pct = value == null ? 0 : Math.max(0, Math.min(100, value)) / 100;
  const id = 'g' + Math.random().toString(36).slice(2, 7);
  const arc = `M ${size / 2 - R} ${size / 2 + 10} A ${R} ${R} 0 0 1 ${size / 2 + R} ${size / 2 + 10}`;
  const wrap = h('div', { class: 'gauge', role: 'img', 'aria-label': value == null ? `${label}: not calculated` : `${label}: ${num(value)} out of 100, higher means more debt. Uncalibrated.` });
  const g = svg('svg', { viewBox: `0 0 ${size} ${size / 2 + 34}`, width: '100%', 'aria-hidden': 'true' },
    svg('defs', {}, svg('linearGradient', { id, x1: 0, x2: 1, y1: 0, y2: 0 },
      svg('stop', { offset: '0%', 'stop-color': '#22e1ff' }), svg('stop', { offset: '55%', 'stop-color': '#ffb547' }), svg('stop', { offset: '100%', 'stop-color': '#ff4d5e' }))),
    svg('path', { d: arc, fill: 'none', stroke: 'rgba(140,200,255,.14)', 'stroke-width': 16, 'stroke-linecap': 'round' }),
    value != null ? svg('path', { d: arc, fill: 'none', stroke: `url(#${id})`, 'stroke-width': 16, 'stroke-linecap': 'round',
      'stroke-dasharray': `${C * pct} ${C}`, class: 'gauge-arc' }) : null,
    svg('text', { x: size / 2, y: size / 2 - 8, 'text-anchor': 'middle', class: 'gauge-n' }, value == null ? 'n/a' : num(value)),
    svg('text', { x: size / 2, y: size / 2 + 14, 'text-anchor': 'middle', class: 'gauge-l' }, value == null ? 'not calculated' : 'out of 100'),
    svg('text', { x: size / 2 - R, y: size / 2 + 32, 'text-anchor': 'middle', class: 'gauge-t' }, '0'),
    svg('text', { x: size / 2 + R, y: size / 2 + 32, 'text-anchor': 'middle', class: 'gauge-t' }, '100'));
  wrap.append(g);
  return wrap;
}

/* Horizontal stacked severity bar with a legend; segments are focusable and carry tooltips. */
export function severityBar(counts) {
  const total = SEV.reduce((a, s) => a + (counts[s] || 0), 0);
  const bar = h('div', { class: 'sevbar', role: 'img', 'aria-label': total ? SEV.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(', ') : 'No open findings' });
  if (!total) bar.append(h('div', { class: 'sevbar-empty' }, 'No open findings'));
  for (const s of SEV) {
    if (!counts[s]) continue;
    bar.append(h('div', { class: 'sevbar-seg', style: `flex:${counts[s]};background:${SEV_COLOR[s]}`, tabindex: '0', 'data-tip': `${counts[s]} ${s} (${Math.round(100 * counts[s] / total)}%)` }));
  }
  const legend = h('ul', { class: 'legend' }, SEV.map((s) => h('li', {}, h('span', { class: 'dot', style: `background:${SEV_COLOR[s]}` }), `${cap(s)} `, h('b', {}, String(counts[s] || 0)))));
  return h('div', {}, bar, legend);
}

/* Line chart for the index across runs. Incomplete runs have no score: they are shown as gap markers, never as 0. */
export function trendChart(points, { height = 200 } = {}) {
  const W = 560, H = height, pad = { l: 34, r: 12, t: 12, b: 26 };
  const wrap = h('div', { class: 'trend' });
  const scored = points.filter((p) => p.y != null);
  const label = points.length ? `Security debt index over ${points.length} scan(s): ` + points.map((p) => `${when(p.ts)}: ${p.y == null ? p.status : num(p.y)}`).join('; ') : 'No scans yet';
  const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, width: '100%', role: 'img', 'aria-label': label });
  const x = (i) => pad.l + (points.length < 2 ? (W - pad.l - pad.r) / 2 : (i * (W - pad.l - pad.r)) / (points.length - 1));
  const y = (v) => pad.t + (1 - v / 100) * (H - pad.t - pad.b);
  for (const g of [0, 25, 50, 75, 100]) {
    s.append(svg('line', { x1: pad.l, x2: W - pad.r, y1: y(g), y2: y(g), stroke: 'rgba(140,200,255,.10)' }),
      svg('text', { x: pad.l - 6, y: y(g) + 4, 'text-anchor': 'end', class: 'ax' }, String(g)));
  }
  let d = '', pen = false;
  points.forEach((p, i) => { if (p.y == null) { pen = false; return; } d += `${pen ? 'L' : 'M'}${x(i)} ${y(p.y)} `; pen = true; });
  if (d) s.append(svg('path', { d, fill: 'none', stroke: '#22e1ff', 'stroke-width': 2.2, 'stroke-linejoin': 'round' }));
  const tipEl = h('div', { class: 'charttip', hidden: true, role: 'tooltip' });
  const show = (p, i, node) => {
    tipEl.hidden = false;
    tipEl.replaceChildren(h('b', {}, p.y == null ? `Scan ${p.status}` : `Index ${num(p.y)}`), h('div', { class: 'mut' }, when(p.ts)),
      p.sub ? h('div', {}, p.sub) : null, p.y == null ? h('div', { class: 'mut' }, 'No score: an incomplete scan is never shown as zero.') : null);
    tipEl.style.left = `${(x(i) / W) * 100}%`;
    tipEl.style.top = `${(p.y == null ? 50 : (y(p.y) / H) * 100)}%`;
    node.setAttribute('aria-describedby', 'x');
  };
  points.forEach((p, i) => {
    const c = p.y == null
      ? svg('path', { d: `M${x(i) - 5} ${H - pad.b - 6} l10 0 l-5 -10 z`, fill: '#ffb547', tabindex: 0, class: 'pt gap' })
      : svg('circle', { cx: x(i), cy: y(p.y), r: 5, fill: '#0b1220', stroke: '#22e1ff', 'stroke-width': 2, tabindex: 0, class: 'pt' });
    c.addEventListener('mouseenter', () => show(p, i, c)); c.addEventListener('focus', () => show(p, i, c));
    c.addEventListener('mouseleave', () => { tipEl.hidden = true; }); c.addEventListener('blur', () => { tipEl.hidden = true; });
    s.append(c);
  });
  wrap.append(s, tipEl);
  if (!scored.length) wrap.append(h('div', { class: 'chart-empty' }, points.length ? 'No completed scans with a score yet.' : 'Run a scan to start a trend.'));
  wrap.append(h('table', { class: 'sr' }, h('caption', {}, 'Security debt index per scan'),
    h('thead', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'Status'), h('th', {}, 'Index'))),
    h('tbody', {}, points.map((p) => h('tr', {}, h('td', {}, when(p.ts)), h('td', {}, p.status), h('td', {}, p.y == null ? 'not calculated' : num(p.y)))))));
  return wrap;
}

/* Horizontal bars: label, value, optional sub text. */
export function hbars(items, { max, unit = '', empty = 'Nothing to show.' } = {}) {
  if (!items.length) return h('div', { class: 'chart-empty' }, empty);
  const top = max || Math.max(...items.map((i) => i.value), 1);
  return h('ul', { class: 'hbars' }, items.map((i) => h('li', {},
    h('div', { class: 'hb-top' }, h('span', { class: 'hb-l', title: i.label }, i.label), h('b', {}, `${num(i.value, 2)}${unit}`)),
    h('div', { class: 'hb-track', 'data-tip': i.tip || false, tabindex: i.tip ? '0' : false }, h('div', { class: 'hb-fill', style: `width:${Math.max(2, (100 * i.value) / top)}%;background:${i.color || '#22e1ff'}` })),
    i.sub ? h('div', { class: 'mut sm' }, i.sub) : null)));
}

export const miniBar = (value, max = 100, color = '#22e1ff') =>
  h('div', { class: 'mini', role: 'img', 'aria-label': `${num(value)} of ${max}` }, h('i', { style: `width:${value == null ? 0 : Math.min(100, (100 * value) / max)}%;background:${color}` }));
