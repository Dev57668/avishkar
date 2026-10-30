// AI assistant panel. Server-side only (no key in the browser), consent-gated, shows exactly what would be sent,
// and labels every answer as AI-generated and advisory. It never changes scan results.
import { api, session } from './api.js';
import { h, clear, icon, cap, pill, toast, copyBtn, skeleton, sr } from './ui.js';

const MODES = [
  ['ask', 'Ask a question', 'Ask anything about these scan results.'],
  ['prioritize', 'Prioritize remediation', 'Which findings should I fix first, and why?'],
  ['explain_cwe', 'Explain the CWE', 'Explain the weakness class of the selected finding.'],
  ['secure_alternative', 'Secure alternative', 'Show a safer way to write the selected code.'],
  ['review_fix', 'Review my fix', 'Paste a proposed fix and I will review it against the finding.'],
];

export async function openAssistant({ repoId, runId, finding, repoName }) {
  const dlg = h('dialog', { class: 'drawer', 'aria-labelledby': 'as-title' });
  const out = h('div', { class: 'as-out', 'aria-live': 'polite' });
  const body = h('div', { class: 'as-body' });
  dlg.append(h('div', { class: 'dlg-h' }, h('h2', { id: 'as-title' }, icon('spark'), ' AI security assistant'),
    h('button', { class: 'x', type: 'button', 'aria-label': 'Close assistant', onclick: () => dlg.close() }, icon('x'))), body);
  dlg.addEventListener('close', () => dlg.remove());
  dlg.addEventListener('cancel', () => dlg.close());
  document.body.append(dlg);
  const opener = document.activeElement;
  dlg.addEventListener('close', () => opener && opener.focus && opener.focus(), { once: true });
  dlg.showModal();
  body.append(skeleton(3));

  let st;
  try { st = await api('/v1/assistant/status'); } catch (e) { clear(body).append(h('div', { class: 'errstate', role: 'alert' }, e.message)); return; }
  clear(body);
  body.append(h('div', { class: 'as-label' }, icon('shield'), ' AI answers are advisory. They cannot change findings, severity, state, score or policy, and they can be wrong: verify before you act.'));

  if (!st.available) {
    body.append(h('div', { class: 'empty' }, h('div', { class: 'empty-t' }, 'AI assistant unavailable'), h('p', {}, st.message),
      h('p', { class: 'mut sm' }, 'Scan results, scoring and reports work without it. To enable it, the server operator sets AVISHKAR_AI_ENABLED=1 and a provider key; the key stays on the server and is never sent to your browser.')));
    return;
  }
  if (!st.canAsk) {
    body.append(h('div', { class: 'empty' }, h('div', { class: 'empty-t' }, 'Your role cannot use the assistant'), h('p', {}, 'The assistant needs the analyst role on this instance, so a read-only viewer cannot spend the owner’s AI credits.')));
    return;
  }

  let mode = finding ? 'explain_cwe' : 'ask';
  const modeSel = h('select', { id: 'as-mode', 'aria-label': 'What do you want to do?', onchange: (e) => { mode = e.target.value; sync(); } },
    MODES.map(([v, l]) => h('option', { value: v, selected: v === mode, disabled: (v === 'secure_alternative' || v === 'explain_cwe') && !finding && v === 'secure_alternative' }, l)));
  const hint = h('p', { class: 'mut sm' });
  const q = h('textarea', { id: 'as-q', rows: 3, maxlength: '600', 'aria-label': 'Your question', placeholder: 'Your question (max 600 characters)' });
  const fix = h('textarea', { id: 'as-fix', rows: 6, maxlength: '4000', 'aria-label': 'Proposed fix', placeholder: 'Paste the proposed fix here (max 4000 characters). It is redacted for secrets before sending.', hidden: true });
  const snippets = h('input', { type: 'checkbox', id: 'as-snip' });
  const consent = h('input', { type: 'checkbox', id: 'as-consent' });
  const preview = h('pre', { class: 'as-preview', hidden: true, tabindex: '0', 'aria-label': 'Exact payload that would be sent' });
  const askBtn = h('button', { class: 'btn primary', type: 'button', disabled: true }, icon('spark'), ' Ask');
  const previewBtn = h('button', { class: 'btn', type: 'button' }, 'Preview what will be sent');

  function sync() {
    const m = MODES.find((x) => x[0] === mode);
    hint.textContent = m[2];
    fix.hidden = mode !== 'review_fix';
    if (!q.value) q.value = mode === 'ask' ? '' : m[2];
  }
  const payload = () => ({ repositoryId: repoId, runId: runId || null, findingId: finding ? finding.id : null, mode, question: q.value.trim() || MODES.find((x) => x[0] === mode)[2],
    proposedFix: mode === 'review_fix' ? fix.value : null, includeSnippets: snippets.checked, consent: consent.checked });

  previewBtn.addEventListener('click', async () => {
    previewBtn.disabled = true;
    try {
      const r = await api('/v1/assistant/preview', { method: 'POST', body: payload() });
      preview.hidden = false;
      preview.textContent = JSON.stringify(r.payload, null, 2);
      toast(`Preview ready: ${r.bytes} bytes, ${r.sendsCodeLines ? 'includes code lines' : 'metadata only, no code'}`, 'info', 3500);
    } catch (e) { toast(e.message, 'bad'); } finally { previewBtn.disabled = false; }
  });
  consent.addEventListener('change', () => { askBtn.disabled = !consent.checked; });
  askBtn.addEventListener('click', async () => {
    askBtn.disabled = true;
    clear(out).append(skeleton(4));
    try {
      const r = await api('/v1/assistant/ask', { method: 'POST', body: payload(), timeout: 90000 });
      clear(out).append(renderAnswer(r, repoId));
    } catch (e) { clear(out).append(h('div', { class: 'errstate', role: 'alert' }, e.code === 'consent_required' ? 'Consent is required.' : e.message)); } finally { askBtn.disabled = !consent.checked; }
  });

  body.append(
    finding ? h('div', { class: 'as-focus' }, h('span', { class: 'mut' }, 'About '), h('b', {}, finding.title), h('code', {}, ` ${finding.rule_id}`)) : h('p', { class: 'mut sm' }, 'No finding selected: the assistant sees the highest-weight findings of the latest scan.'),
    h('label', { for: 'as-mode' }, 'What do you want to do?'), modeSel, hint,
    h('label', { for: 'as-q' }, 'Question'), q, fix,
    h('fieldset', { class: 'as-consent' }, h('legend', {}, 'Data sharing'),
      h('p', { class: 'sm' }, 'By default only finding metadata is sent (rule, CWE, severity, file path, line, weight) and no source code. Secrets are redacted before anything leaves the server.'),
      h('label', { class: 'check' }, snippets, ' Also include the (redacted) detected code line for each finding'),
      previewBtn, preview,
      h('label', { class: 'check strong' }, consent, ` I consent to sending this data to the AI provider (${st.provider}${st.model ? ', ' + st.model : ''}).`)),
    askBtn, out);
  sync();
  q.focus();
}

function renderAnswer(r, repoId) {
  if (r.status === 'unavailable') return h('div', { class: 'errstate', role: 'alert' }, r.message);
  if (r.status === 'discarded') return h('div', { class: 'errstate', role: 'alert' }, h('b', {}, 'Answer discarded. '), r.message);
  const card = h('div', { class: 'as-answer' },
    h('div', { class: 'as-badge' }, icon('spark'), ' AI-generated · advisory', h('span', { class: 'mut sm' }, ` · ${r.model || ''} · confidence ${r.confidence}`)),
    ...r.answer.split(/\n{2,}/).map((p) => h('p', {}, p)),
    r.secureCode ? h('div', { class: 'code' }, h('div', { class: 'code-h' }, h('span', {}, `Suggested code (${r.secureCode.language}) — unverified`), copyBtn(r.secureCode.code, 'Copy code')), h('pre', {}, h('code', {}, r.secureCode.code))) : null,
    r.warnings && r.warnings.length ? h('div', { class: 'warnbox', role: 'alert' }, h('b', {}, 'Check before trusting this'), h('ul', {}, r.warnings.map((w) => h('li', {}, w)))) : null,
    r.caveats && r.caveats.length ? h('div', { class: 'mut sm' }, h('b', {}, 'Caveats: '), r.caveats.join(' · ')) : null,
    r.citedFindingIds && r.citedFindingIds.length ? h('div', { class: 'mut sm' }, `Based on ${r.citedFindingIds.length} finding(s) from the scan.`) : null,
    h('p', { class: 'mut sm' }, r.label));
  return card;
}
