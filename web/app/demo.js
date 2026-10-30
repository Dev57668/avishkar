// Demo lab: pick a bundled sample, run a REAL scan through the pipeline, watch the real stages, apply fixes, rescan, compare.
// Every number shown comes from a scan run on the server; nothing here is scripted or animated independently of it.
import { api, session } from './api.js';
import { h, clear, num, cap, pill, sevPill, toast, skeleton, errorState, emptyState, icon, copyBtn } from './ui.js';
import { gauge, severityBar } from './charts.js';
import { section, stepper, watchRun, decisionBadge } from './shared.js';
import { renderCompare } from './repo.js';

export async function demoView(root, go) {
  root.append(skeleton(5));
  let list;
  try { list = await api('/v1/demo/samples'); } catch (e) { root.replaceChildren(errorState(e, () => { root.replaceChildren(); demoView(root, go); })); return; }
  root.replaceChildren();
  const st = { sample: list.items[0], applied: new Set(), repoId: null, runs: [], busy: false };
  const stage = h('div', { class: 'demo-stage' });
  const picker = h('div', { class: 'samples', role: 'radiogroup', 'aria-label': 'Sample project' });
  const fixesBox = h('div', {});
  const result = h('div', { class: 'demo-result', 'aria-live': 'polite' });

  const renderPicker = () => {
    clear(picker).append(...list.items.map((s) => h('button', { class: `sample ${s.id === st.sample.id ? 'on' : ''}`, type: 'button', role: 'radio', 'aria-checked': String(s.id === st.sample.id),
      onclick: () => { if (st.busy) return; st.sample = s; st.applied = new Set(); st.repoId = null; clear(result); renderPicker(); renderFixes(); },
    }, h('b', {}, s.name), h('span', { class: 'mut sm' }, `${cap(s.kind)} · ${s.language} · ${s.files.length} file(s)`), h('span', { class: 'sm' }, s.description))));
  };

  const renderFixes = () => {
    const s = st.sample;
    clear(fixesBox);
    if (!s.fixes.length) {
      fixesBox.append(h('p', { class: 'mut sm' }, s.kind === 'secure' ? 'This sample is written securely: a scan should find nothing, which still does not prove it is secure.' : 'This sample has no fix pack.'));
      return;
    }
    fixesBox.append(h('div', { class: 'row between' }, h('h3', {}, 'Fix pack'),
      h('span', { class: 'row' },
        h('button', { class: 'btn sm', type: 'button', onclick: () => { s.fixes.forEach((f) => st.applied.add(f.id)); renderFixes(); } }, 'Select all'),
        h('button', { class: 'btn sm', type: 'button', onclick: () => { st.applied.clear(); renderFixes(); } }, 'Clear'))),
      h('p', { class: 'mut sm' }, 'Tick the fixes to apply to a copy of the sample, then scan again. Each fix is a real code edit.'),
      h('ul', { class: 'fixes' }, s.fixes.map((f) => {
        const cb = h('input', { type: 'checkbox', id: `fx-${f.id}`, checked: st.applied.has(f.id), onchange: (e) => { e.target.checked ? st.applied.add(f.id) : st.applied.delete(f.id); } });
        const diffSlot = h('div', { hidden: true });
        const more = h('button', { class: 'btn sm ghost', type: 'button', 'aria-expanded': 'false', onclick: async (e) => {
          diffSlot.hidden = !diffSlot.hidden; e.currentTarget.setAttribute('aria-expanded', String(!diffSlot.hidden));
          if (diffSlot.hidden || diffSlot.childElementCount) return;
          diffSlot.append(skeleton(3));
          try {
            const r = await api(`/v1/demo/samples/${s.id}?fixes=${f.id}`);
            clear(diffSlot).append(diffView(r.diffs[f.id]));
          } catch (err) { clear(diffSlot).append(errorState(err)); }
        } }, 'View diff');
        return h('li', {}, h('label', { for: `fx-${f.id}`, class: 'check' }, cb, ' ', h('b', {}, f.title), h('span', { class: 'mut sm' }, ` · ${f.file}`)),
          h('div', { class: 'mut sm' }, f.explanation), h('div', { class: 'mut sm' }, f.removes.length ? `Expected to remove: ${f.removes.join(', ')}` : 'Not detectable by the scanner (included for completeness).'), more, diffSlot);
      })));
  };

  async function scan(withFixes) {
    if (st.busy) return;
    if (!list.scanAllowed) { toast('Your account cannot run demo scans on this instance.', 'warn'); return; }
    st.busy = true; setButtons();
    const fixes = withFixes ? [...st.applied] : [];
    clear(stage).append(h('div', { class: 'card' }, h('h3', {}, withFixes ? `Scanning ${st.sample.name} with ${fixes.length} fix(es)…` : `Scanning ${st.sample.name} as shipped…`), h('div', { id: 'stepper-slot' }, stepper(null))));
    try {
      const q = await api('/v1/demo/scan', { method: 'POST', body: { sample: st.sample.id, fixes } });
      st.repoId = q.repositoryId;
      const slot = stage.querySelector('#stepper-slot');
      const run = await watchRun(q.statusUrl, (r) => slot.replaceChildren(stepper(r)));
      slot.replaceChildren(stepper(run));
      await showResult(run, q.repositoryId, withFixes);
    } catch (e) {
      clear(stage).append(errorState(e)); toast(e.message, 'bad');
    } finally { st.busy = false; setButtons(); }
  }

  async function showResult(run, repoId, afterFix) {
    clear(result);
    const sd = run.securityDebt;
    if (run.status !== 'complete') {
      result.append(h('div', { class: 'warnbox', role: 'alert' }, h('b', {}, 'Scan incomplete. '), 'Required coverage is missing, so no score is shown; this is not a pass. ', (run.completeness.missing || []).join(', ')));
      return;
    }
    const f = await api(`/v1/repositories/${repoId}/findings?limit=200&state=open&sort=severity`);
    const counts = {};
    f.items.forEach((x) => { counts[x.severity] = (counts[x.severity] || 0) + 1; });
    result.append(h('div', { class: 'grid2' },
      h('div', { class: 'card gauge-card' }, gauge(sd.normalizedIndex), h('div', { class: 'gauge-meta' }, decisionBadge(run.decision.outcome), h('div', { class: 'mut sm' }, `${sd.scoreVersion} · uncalibrated · ${run.completeness.filesScanned ?? '?'} files scanned`))),
      h('div', { class: 'card' }, h('h3', {}, `${f.total ?? f.items.length} finding(s) in this scan`), severityBar(counts),
        run.completeness && run.completeness.notEvaluated ? null : null)),
      f.items.length ? h('ul', { class: 'mini-findings' }, f.items.slice(0, 12).map((x) => h('li', {}, sevPill(x.severity), ' ', h('b', {}, x.title), ' ', h('code', {}, x.location)))) : h('p', { class: 'mut' }, 'No findings from the supported detectors. That is not proof the code is secure.'),
      f.items.length > 12 ? h('p', { class: 'mut sm' }, `Showing 12 of ${f.items.length}.`) : '',
      h('div', { class: 'row' },
        h('button', { class: 'btn primary', type: 'button', onclick: () => go(`#/repo/${repoId}`) }, 'Open full dashboard'),
        afterFix ? null : st.sample.fixes.length ? h('span', { class: 'mut sm' }, 'Now tick fixes above and scan again to see the score move.') : null));
    if (afterFix) {
      const cmpSlot = h('div', { class: 'card' }, h('h3', {}, 'Before / after'), skeleton(3));
      result.append(cmpSlot);
      try { const c = await api(`/v1/repositories/${repoId}/compare`); clear(cmpSlot).append(h('h3', {}, 'Before / after'), renderCompare(c)); } catch (e) { clear(cmpSlot).append(h('h3', {}, 'Before / after'), errorState(e)); }
    }
  }

  const btnScan = h('button', { class: 'btn primary', type: 'button', onclick: () => scan(false) }, icon('play'), ' Scan sample');
  const btnFix = h('button', { class: 'btn', type: 'button', onclick: () => { if (!st.applied.size) { toast('Tick at least one fix first.', 'warn'); return; } scan(true); } }, icon('refresh'), ' Apply fixes & rescan');
  const setButtons = () => { btnScan.disabled = st.busy; btnFix.disabled = st.busy || !st.sample.fixes.length; };

  root.append(
    h('p', { class: 'mut' }, list.note),
    !list.scanAllowed ? h('div', { class: 'warnbox' }, 'Your account is read-only here, so scans are disabled. You can still browse the pre-scanned demo repositories on the overview.') : '',
    section('pick', '1 · Choose a sample', picker),
    section('fix', '2 · Review the fixes', fixesBox),
    section('run', '3 · Scan', h('div', {}, h('div', { class: 'row' }, btnScan, btnFix), stage, result)));
  renderPicker(); renderFixes(); setButtons();
}

function diffView(text) {
  return h('pre', { class: 'diff', tabindex: '0', 'aria-label': 'Unified diff' }, (text || '').split('\n').map((l) =>
    h('span', { class: l.startsWith('+') && !l.startsWith('+++') ? 'add' : l.startsWith('-') && !l.startsWith('---') ? 'del' : l.startsWith('@@') ? 'hunk' : '' }, l + '\n')));
}
