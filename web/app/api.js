// API client. The session token lives in sessionStorage (cleared when the tab closes); it is sent as a Bearer header.
// No provider keys or secrets ever exist in the browser: the AI assistant and GitHub integration are server-side.

export class ApiError extends Error {
  constructor(message, status, code, correlationId) {
    super(message);
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
  }
}

export const session = {
  token: null,
  me: null,
  cfg: null,
  pub: null,
  load() { try { this.token = sessionStorage.getItem('tk'); } catch { this.token = null; } },
  save(t) { this.token = t; try { t ? sessionStorage.setItem('tk', t) : sessionStorage.removeItem('tk'); } catch { /* storage unavailable */ } },
  get role() { return this.me ? this.me.role : null; },
  has(role) { const r = ['viewer', 'analyst', 'admin']; return this.me ? r.indexOf(this.me.role) >= r.indexOf(role) : false; },
};

const listeners = new Set();
export const onAuthLost = (fn) => listeners.add(fn);

export async function api(path, { method = 'GET', body, form, signal, timeout = 60000 } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);
  if (signal) signal.addEventListener('abort', () => ctl.abort(), { once: true });
  const headers = {};
  if (session.token) headers.Authorization = 'Bearer ' + session.token;
  let payload;
  if (form) payload = form;
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  let r;
  try {
    r = await fetch(path, { method, headers, body: payload, signal: ctl.signal });
  } catch (e) {
    throw new ApiError(e.name === 'AbortError' ? 'The request timed out.' : 'Could not reach the server.', 0, 'network');
  } finally {
    clearTimeout(timer);
  }
  let data = null;
  const text = await r.text();
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!r.ok) {
    const err = (data && data.error) || {};
    if (r.status === 401 && session.token) { session.save(null); listeners.forEach((f) => f()); }
    throw new ApiError(err.message || (r.status === 404 ? 'Not found.' : `Request failed (${r.status}).`), r.status, err.code || 'error', err.correlationId);
  }
  return data;
}

export async function probe() {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 75000);
  try {
    const r = await fetch('/v1/public/status', { signal: ctl.signal });
    if (!r.ok) return null;
    const j = await r.json();
    return j && j.service === 'avishkar' ? j : null;
  } catch { return null; } finally { clearTimeout(t); }
}

export async function download(path, filename, accept) {
  const headers = session.token ? { Authorization: 'Bearer ' + session.token } : {};
  if (accept) headers.Accept = accept;
  const r = await fetch(path, { headers });
  if (!r.ok) throw new ApiError('Download failed.', r.status, 'download');
  const blob = await r.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

export async function openInNewTab(path) {
  // authenticated HTML report: fetch with the token, then show it from a blob URL (the token never goes in a URL)
  const r = await fetch(path, { headers: { Authorization: 'Bearer ' + session.token } });
  if (!r.ok) throw new ApiError('Could not load the report.', r.status, 'report');
  const url = URL.createObjectURL(new Blob([await r.text()], { type: 'text/html' }));
  const w = window.open(url, '_blank', 'noopener');
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  return w;
}

export const qs = (o) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== '' && v != null) p.set(k, v);
  const s = p.toString();
  return s ? '?' + s : '';
};
