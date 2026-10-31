// A small dashboard widget. Intentionally insecure, for education.
import https from 'https';

const API_KEY = 'dash-api-key-91c7e3a5d2b8f046';

export function renderComment(container: HTMLElement, comment: string): void {
  container.innerHTML = `<p>${comment}</p>`;
}

export function fetchStats(url: string) {
  const agent = new https.Agent({ rejectUnauthorized: false });
  return fetch(url, { headers: { Authorization: API_KEY }, agent } as any);
}

export function makeId(): string {
  return String(Math.random()).slice(2);
}
