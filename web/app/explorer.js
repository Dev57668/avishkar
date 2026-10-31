// Vulnerability explorer: search, filters, sorting, expandable details with CWE, explanation, impact, fix and secure example.
import { api, qs, session } from './api.js';
import { h, clear, icon, num, cap, pill, sevPill, tip, toast, copyBtn, dialog, confirmDialog, debounce, skeleton, emptyState, errorState, SEV, sr, staggerIn, REDUCED_MOTION, EASE_SETTLE } from './ui.js';
import { openAssistant } from './assistant.js';
import { canUseAssistant } from './shared.js';

const STATES = ['open', 'fixed', 'accepted_risk', 'false_positive', 'duplicate', 'not_applicable'];
const ASSURANCE = {
  structural: ['Structural match', 'The dangerous construct was found in the parsed code. Whether it is exploitable depends on data flow the scanner does not prove.'],
  heuristic: ['Heuristic', 'A naming/shape heuristic. Expect false positives; verify before acting.'],
  database: ['Advisory database', 'Matched a bundled advisory list. The version is a fact; relevance to your code is not proven.'],
};

export function explorer({ repoId, runId, repoName, onChange }) {
  const st = { q: '', severity: '', state: 'open', category: '', path: '', cwe: '', sort: 'severity', order: 'asc', offset: 0, items: [], total: 0, loading: false, open: null };
  const root = h('div', { class: 'explorer' });
  const list = h('ul', { class: 'flist', 'aria-label': 'Findings' });
  const count = h('div', { class: 'f-count mut', 'aria-live': 'polite' });
  const more = h('button', { class: 'btn', type: 'button', hidden: true, onclick: () => load(true) }, 'Load more');

  /* ---------- toolbar ---------- */
  const search = h('input', { type: 'search', id: 'f-q', placeholder: 'Search title, rule, file, code…', 'aria-label': 'Search findings', autocomplete: 'off',
    oninput: debounce((e) => { st.q = e.target.value; reload(); }, 250) });
  const sevChips = h('div', { class: 'chips', role: 'group', 'aria-label': 'Filter by severity' },
    [['', 'All'], ...SEV.map((s) => [s, cap(s)])].map(([v, l]) => h('button', { type: 'button', class: `chip ${v === '' ? 'on' : ''}`, 'aria-pressed': String(v === ''), dataset: { v },
      onclick: (e) => { st.severity = v; [...sevChips.children].forEach((c) => { const on = c.dataset.v === v; c.classList.toggle('on', on); c.setAttribute('aria-pressed', String(on)); }); reload(); } }, l)));
  const sel = (id, label, opts, key, onch) => h('label', { class: 'fsel' }, h('span', {}, label),
    h('select', { id, onchange: (e) => { st[key] = e.target.value; onch ? onch() : reload(); } }, opts.map(([v, l]) => h('option', { value: v, selected: st[key] === v }, l))));
  const catSel = sel('f-cat', 'Category', [['', 'All']], 'category');
  const cweSel = sel('f-cwe', 'CWE', [['', 'All']], 'cwe');
  const fileIn = h('input', { type: 'text', id: 'f-path', placeholder: 'e.g. utils.py', 'aria-label': 'Filter by file path', autocomplete: 'off', oninput: debounce((e) => { st.path = e.target.value; reload(); }, 250) });
  const bar = h('div', { class: 'ftools' },
    h('div', { class: 'fsearch' }, icon('search'), search),
    sevChips,
    h('div', { class: 'frow' },
      sel('f-state', 'State', [['', 'Any'], ...STATES.map((s) => [s, cap(s)])], 'state'), catSel, cweSel,
      h('label', { class: 'fsel' }, h('span', {}, 'File'), fileIn),
      sel('f-sort', 'Sort by', [['severity', 'Severity'], ['confidence', 'Confidence'], ['path', 'File'], ['rule', 'Rule'], ['first_seen', 'First seen'], ['last_seen', 'Last seen']], 'sort'),
      h('button', { class: 'btn sm', type: 'button', id: 'f-order', 'aria-label': 'Toggle sort direction', onclick: (e) => { st.order = st.order === 'asc' ? 'desc' : 'asc'; e.currentTarget.textContent = st.order === 'asc' ? '↑ Asc' : '↓ Desc'; reload(); } }, '↑ Asc'),
      h('button', { class: 'btn sm ghost', type: 'button', onclick: resetFilters }, 'Reset')));
  document.addEventListener('keydown', (e) => { if (e.key === '/' && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) && root.isConnected) { e.preventDefault(); search.focus(); } });

  function resetFilters() {
    Object.assign(st, { q: '', severity: '', state: 'open', category: '', path: '', cwe: '', sort: 'severity', order: 'asc' });
    search.value = ''; fileIn.value = '';
    bar.querySelector('#f-state').value = 'open'; bar.querySelector('#f-cat').value = ''; bar.querySelector('#f-cwe').value = ''; bar.querySelector('#f-sort').value = 'severity';
    [...sevChips.children].forEach((c) => { const on = c.dataset.v === ''; c.classList.toggle('on', on); c.setAttribute('aria-pressed', String(on)); });
    reload();
  }

  /* ---------- data ---------- */
  async function load(append = false) {
    if (st.loading) return;
    st.loading = true;
    if (!append) { clear(list).append(h('li', { class: 'fskel' }, skeleton(3, 18))); }
    try {
      const r = await api(`/v1/repositories/${repoId}/findings${qs({ state: st.state, severity: st.severity, category: st.category, cwe: st.cwe, q: st.q, path: st.path, sort: st.sort, order: st.order, offset: append ? st.offset : 0, limit: 25 })}`);
      st.total = r.total;
      st.offset = r.nextOffset ?? (append ? st.offset + r.items.length : r.items.length);
      st.items = append ? st.items.concat(r.items) : r.items;
      st.next = r.nextOffset != null;
      render();
      learnFacets(r.items);
    } catch (e) {
      clear(list).append(h('li', {}, errorState(e, () => load(false))));
    } finally { st.loading = false; }
  }
  const reload = () => { st.offset = 0; load(false); };
  const facets = { cat: new Set(), cwe: new Set() };
  function learnFacets(items) {
    let ch = false;
    for (const f of items) { if (!facets.cat.has(f.category)) { facets.cat.add(f.category); ch = true; } for (const c of f.cwe || []) if (!facets.cwe.has(c)) { facets.cwe.add(c); ch = true; } }
    if (!ch) return;
    const fill = (selEl, set, cur) => { const v = cur; clear(selEl).append(h('option', { value: '' }, 'All'), ...[...set].sort().map((x) => h('option', { value: x, selected: x === v }, cap(x)))); };
    fill(bar.querySelector('#f-cat'), facets.cat, st.category); fill(bar.querySelector('#f-cwe'), facets.cwe, st.cwe);
  }

  /* ---------- rendering ---------- */
  function render() {
    clear(list);
    count.textContent = st.total ? `Showing ${st.items.length} of ${st.total} finding${st.total === 1 ? '' : 's'}` : '';
    if (!st.items.length) {
      list.append(h('li', {}, emptyState(st.q || st.severity || st.category || st.path || st.cwe ? 'No findings match these filters' : st.state === 'open' ? 'No open findings' : 'No findings in this state',
        st.state === 'open' && !st.q && !st.severity ? 'No open findings from the supported detectors. This does not prove the code is secure.' : 'Try clearing a filter.',
        h('button', { class: 'btn sm', type: 'button', onclick: resetFilters }, 'Reset filters'))));
    }
    for (const f of st.items) list.append(row(f));
    more.hidden = !st.next;
    staggerIn(list, '.frow-item');
  }

  function row(f) {
    const body = h('div', { class: 'fdetail', hidden: true });
    const head = h('button', { class: 'fhead', type: 'button', 'aria-expanded': 'false', 'aria-controls': `d-${f.id}`,
      onclick: async () => {
        const open = head.getAttribute('aria-expanded') !== 'true';
        head.setAttribute('aria-expanded', String(open)); body.hidden = !open; li.classList.toggle('open', open);
        if (open && !body.dataset.loaded) { body.dataset.loaded = '1'; await fillDetail(body, f); }
        // Closing exits instantly (fastest possible exit); opening fades the now-settled content in,
        // so a dense detail panel doesn't just pop — skipped under reduced motion, same as elsewhere.
        if (open && !REDUCED_MOTION && body.animate) body.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 220, easing: EASE_SETTLE });
      } },
      icon('chevron'), sevPill(f.severity),
      h('span', { class: 'ft' }, h('b', {}, f.title), h('span', { class: 'mut mono sm' }, ` ${f.location || ''}`)),
      h('span', { class: 'fmeta' }, f.state !== 'open' ? pill(cap(f.state), 'st-mut') : null,
        pill(f.assurance === 'heuristic' ? 'Heuristic' : f.assurance === 'database' ? 'Advisory' : 'Structural', f.assurance === 'heuristic' ? 'warn' : 'ok', (ASSURANCE[f.assurance] || [])[1] || ''),
        f.debt ? h('span', { class: 'debt', 'data-tip': `${f.debt.impact} × ${f.debt.exposure} × ${f.debt.confidence} × ${f.debt.age}` }, `${num(f.debt.units, 2)} u`) : null));
    body.id = `d-${f.id}`;
    const li = h('li', { class: `frow-item sev-b-${f.severity}` }, head, body);
    return li;
  }

  async function fillDetail(body, f) {
    body.append(skeleton(4));
    let d;
    try { d = await api(`/v1/findings/${f.id}`); } catch (e) { clear(body).append(errorState(e)); body.dataset.loaded = ''; return; }
    const k = d.knowledge, inst = (d.instances && d.instances[0]) || {};
    const as = ASSURANCE[k.detection.assurance] || ['Unknown', ''];
    clear(body).append(
      h('div', { class: 'fd-grid' },
        h('div', { class: 'fd-main' },
          h('div', { class: 'fd-tags' },
            ...k.cwe.map((c) => h('a', { class: 'pill link', href: c.url, target: '_blank', rel: 'noopener noreferrer', title: c.name }, c.id)),
            !k.cwe.length ? pill('No CWE mapped', 'st-mut') : null, k.owasp ? pill(k.owasp, 'st-mut') : null,
            pill(`Rule ${d.rule_id}`, 'st-mut', 'Detection rule identifier'), pill(`Confidence ${d.confidence}`, d.confidence === 'high' ? 'ok' : d.confidence === 'low' ? 'warn' : 'st-mut', 'Detector confidence (a measured cap can only lower it)'),
            pill(as[0], k.detection.assurance === 'heuristic' ? 'warn' : 'ok', as[1]), pill(`via ${k.detection.method}`, 'st-mut'),
            !k.curated ? pill('No curated guidance', 'warn', 'This rule comes from an external scanner without a curated explanation.') : null),
          h('div', { class: 'fd-loc' }, h('span', { class: 'mut' }, 'Location '), h('code', {}, `${inst.path || ''}:${inst.line_start || ''}`), ' ', copyBtn(`${inst.path}:${inst.line_start}`, 'Copy location')),
          h('div', { class: 'code' }, h('div', { class: 'code-h' }, h('span', {}, 'Detected code (secrets redacted)'), copyBtn(inst.evidence || '', 'Copy code')),
            h('pre', {}, h('code', {}, inst.evidence || ''))),
          h('h4', {}, 'Why it matters'), h('p', {}, k.why),
          h('h4', {}, 'Potential impact'), h('p', {}, k.impact),
          h('h4', {}, 'How to fix it'), h('p', {}, k.remediation),
          k.secureExample ? h('div', { class: 'code ok' }, h('div', { class: 'code-h' }, h('span', {}, `Secure example (${k.secureExample.language})`), copyBtn(k.secureExample.code, 'Copy example')),
            h('pre', {}, h('code', {}, k.secureExample.code))) : null,
          h('p', { class: 'mut sm' }, 'Reference text from a static knowledge base, not generated by a model. CWE mappings are the closest classification, not a certification.')),
        h('aside', { class: 'fd-side' },
          h('h4', {}, 'Contribution to the score'),
          d.debt ? h('div', {}, h('div', { class: 'formula' }, `${num(d.debt.impact)} × ${num(d.debt.exposure)} × ${num(d.debt.confidence)} × ${num(d.debt.age)} = `, h('b', {}, `${num(d.debt.units, 2)} units`)),
            h('div', { class: 'mut sm' }, 'impact × exposure × confidence × age'),
            h('div', { class: 'mut sm' }, d.debt.exposure === 1 ? 'Exposure is unknown (neutral): the scanner has no reachability data.' : '')) : h('p', { class: 'mut sm' }, `Not counted in the latest score (state: ${cap(d.state)}).`),
          h('h4', {}, 'History'), h('p', { class: 'sm' }, `State: ${cap(d.state)}`, h('br'), `Seen in ${d.instances.length} scan(s)`),
          d.dispositions && d.dispositions.length ? h('ul', { class: 'sm hist' }, d.dispositions.map((x) => h('li', {}, `${cap(x.type)} by ${x.actor}: ${x.rationale}`))) : null,
          triage(d, () => { onChange && onChange(); reload(); }),
          canUseAssistant() ? h('button', { class: 'btn', type: 'button', onclick: () => openAssistant({ repoId, runId, finding: d, repoName }) }, icon('spark'), ' Ask AI about this') : null)));
  }

  function triage(d, done) {
    if (!session.has('analyst')) return h('p', { class: 'mut sm' }, 'Triage needs the analyst role.');
    const s = h('select', { 'aria-label': 'Triage this finding' }, h('option', { value: '' }, 'Triage…'),
      ...[['false_positive', 'False positive'], ['not_applicable', 'Not applicable'], ['accepted_risk', 'Accept risk (30 days)'], ['open', 'Reopen']].filter(([v]) => v !== d.state).map(([v, l]) => h('option', { value: v }, l)));
    s.addEventListener('change', async () => {
      if (!s.value) return;
      const type = s.value; s.value = '';
      const ta = h('textarea', { rows: 3, 'aria-label': 'Rationale', placeholder: 'Why? (min 5 characters, stored in the audit trail)', autofocus: true });
      const r = await dialog({ title: `Mark as ${cap(type)}`, body: h('div', {}, h('p', { class: 'mut' }, `"${d.title}" — ${type === 'accepted_risk' ? 'the risk stays in gross debt and expires in 30 days.' : 'it will no longer count toward the score. Evidence and history are kept; you can reverse this.'}`), ta),
        actions: [{ label: 'Cancel', value: null }, { label: 'Save', primary: true, keepOpen: true, value: () => (ta.value.trim().length >= 5 ? ta.value.trim() : (ta.setCustomValidity('At least 5 characters'), ta.reportValidity(), undefined)) }] });
      if (!r) return;
      try {
        await api(`/v1/findings/${d.id}/dispositions`, { method: 'POST', body: { type, rationale: r, expected_version: d.version, ...(type === 'accepted_risk' ? { expires_at: Date.now() / 1000 + 30 * 86400 } : {}) } });
        toast('Saved. Rescan to refresh the score.', 'ok'); done();
      } catch (e) { toast(e.code === 'conflict' ? 'Someone else changed this finding. Reload and try again.' : e.message, 'bad'); }
    });
    return h('div', { class: 'triage' }, h('label', {}, 'Triage'), s);
  }

  root.append(bar, count, list, h('div', { class: 'more' }, more));
  load(false);
  return root;
}
