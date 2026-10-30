// UI primitives. Everything is built with DOM APIs (textContent / createElement): API data is never parsed as HTML,
// so there is no injection path from scan results, file names or evidence into the page.

export function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'hidden' || k === 'open' || k === 'selected') el[k] = !!v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, kids);
  return el;
}

export function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}

const SVGNS = 'http://www.w3.org/2000/svg';
export function svg(tag, attrs = {}, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null && v !== false) el.setAttribute(k, String(v));
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return el;
}

export const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ---------- formatting ---------- */
export const num = (v, d = 1) => (v == null ? 'n/a' : Number(v).toFixed(d).replace(/\.0+$/, '').replace(/(\.\d*?)0+$/, '$1'));
export function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
export const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '');
export const cap = (s) => String(s ?? '').replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
export const SEV = ['critical', 'high', 'medium', 'low', 'informational'];

/* ---------- small components ---------- */
export const sevPill = (sev) => h('span', { class: `pill sev-${sev}`, title: `${cap(sev)} severity` }, cap(sev));
export const pill = (text, cls = '', title = '') => h('span', { class: `pill ${cls}`, title: title || false }, text);
export const tip = (text, tipText) => h('span', { class: 'tip', tabindex: '0', 'data-tip': tipText, 'aria-label': `${text}: ${tipText}` }, text);
export const icon = (name) => {
  const paths = {
    copy: 'M9 9h9v11H9zM6 15V6h9', check: 'M5 12l5 5 9-10', search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-5-5',
    chevron: 'M8 5l8 7-8 7', download: 'M12 4v11m0 0l-4-4m4 4l4-4M5 20h14', x: 'M6 6l12 12M18 6L6 18',
    spark: 'M12 3l2 6 6 2-6 2-2 6-2-6-6-2 6-2z', shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z', play: 'M7 5l12 7-12 7z',
    refresh: 'M20 12a8 8 0 1 1-3-6.2M20 4v5h-5', menu: 'M4 7h16M4 12h16M4 17h16', branch: 'M6 3v12M6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 9c0 5-12 3-12 6',
  };
  return svg('svg', { class: 'ic', viewBox: '0 0 24 24', width: 16, height: 16, 'aria-hidden': 'true', fill: 'none', stroke: 'currentColor',
    'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, svg('path', { d: paths[name] || '' }));
};

export function skeleton(lines = 3, height = 14) {
  return h('div', { class: 'skel-wrap', 'aria-hidden': 'true' },
    Array.from({ length: lines }, (_, i) => h('div', { class: 'skel', style: `height:${height}px;width:${i === lines - 1 ? 60 : 100}%` })));
}
export const emptyState = (title, body, ...actions) =>
  h('div', { class: 'empty' }, h('div', { class: 'empty-t' }, title), h('p', { class: 'mut' }, body), actions.length ? h('div', { class: 'row' }, actions) : null);
export const errorState = (err, retry) =>
  h('div', { class: 'errstate', role: 'alert' }, h('b', {}, 'Could not load this.'), ' ', err && err.message ? err.message : String(err), ' ',
    retry ? h('button', { class: 'btn sm', type: 'button', onclick: retry }, 'Try again') : null);

/* ---------- toasts ---------- */
let toastHost;
export function toast(message, type = 'info', ms = 4500) {
  if (!toastHost) {
    toastHost = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.append(toastHost);
  }
  const t = h('div', { class: `toast ${type}` }, h('span', {}, message), h('button', { class: 'x', type: 'button', 'aria-label': 'Dismiss notification', onclick: () => t.remove() }, icon('x')));
  toastHost.append(t);
  if (ms) setTimeout(() => t.remove(), ms);
  return t;
}

/* ---------- copy ---------- */
export async function copyText(text, label = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h('textarea', { 'aria-hidden': 'true', style: 'position:fixed;opacity:0' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    try { document.execCommand('copy'); } finally { ta.remove(); }
  }
  toast(`${label} to clipboard`, 'ok', 2200);
}
export const copyBtn = (getText, label = 'Copy') =>
  h('button', { class: 'btn sm ghost', type: 'button', 'aria-label': label, onclick: (e) => { copyText(typeof getText === 'function' ? getText() : getText, 'Copied'); e.currentTarget.classList.add('done'); setTimeout(() => e.currentTarget?.classList.remove('done'), 1200); } }, icon('copy'), ' ', label);

/* ---------- modal dialogs (native <dialog>: focus trap, Esc, inert background) ---------- */
export function dialog({ title, body, actions = [], wide = false, className = '' }) {
  return new Promise((resolve) => {
    const dlg = h('dialog', { class: `dlg ${wide ? 'wide' : ''} ${className}`, 'aria-labelledby': 'dlg-title' });
    const close = (v) => { dlg.close(); dlg.remove(); resolve(v); };
    dlg.append(h('div', { class: 'dlg-h' }, h('h2', { id: 'dlg-title' }, title),
      h('button', { class: 'x', type: 'button', 'aria-label': 'Close dialog', onclick: () => close(null) }, icon('x'))),
      h('div', { class: 'dlg-b' }, body),
      h('div', { class: 'dlg-f' }, actions.map((a) => h('button', { class: `btn ${a.primary ? 'primary' : ''} ${a.danger ? 'danger' : ''}`, type: 'button',
        onclick: async () => { const v = typeof a.value === 'function' ? await a.value(dlg) : a.value; if (v !== undefined || !a.keepOpen) close(v === undefined ? null : v); } }, a.label))));
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); close(null); });
    document.body.append(dlg);
    const opener = document.activeElement;
    dlg.showModal();
    dlg.addEventListener('close', () => opener && opener.focus && opener.focus(), { once: true });
    const first = dlg.querySelector('[autofocus], input, textarea, select') || dlg.querySelector('.dlg-f .btn');
    first && first.focus();
  });
}
export const confirmDialog = ({ title, message, confirmLabel = 'Confirm', danger = false }) =>
  dialog({ title, body: h('p', {}, message), actions: [{ label: 'Cancel', value: false }, { label: confirmLabel, value: true, primary: !danger, danger }] });

/* ---------- misc ---------- */
export function debounce(fn, ms = 250) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
export const sr = (text) => h('span', { class: 'sr' }, text);
