// Builds the web page for a static host (Vercel) into dist/.
//   node scripts/build_static.mjs            page probes GET /v1/public/status and picks live / demo / static itself
//   node scripts/build_static.mjs --static   force the inert "no backend" mode (no probing)
// The FastAPI app serves web/ under /static and index.html at /. A static host serves the same URLs from dist/:
//   * web/* (except index.html) -> dist/static/   (the absolute /static/... URLs in the page keep working)
//   * index.html                -> dist/index.html (with a <meta name="avishkar-mode" content="static"> only if --static)
// If the host rewrites /v1/* to a deployed API (see vercel.json + docs/DEPLOY_ONLINE.md) the page becomes live;
// if not, the probe fails and it falls back to the static note. No dependencies.
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const web = join(root, 'web');
const dist = join(root, 'dist');

rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, 'static'), { recursive: true });

for (const name of readdirSync(web)) {
  if (name === 'index.html') continue;
  cpSync(join(web, name), join(dist, 'static', name), { recursive: true });
}

let html = readFileSync(join(web, 'index.html'), 'utf8');
if (process.argv.includes('--static')) {
  const meta = '<meta name="avishkar-mode" content="static">';
  if (!html.includes('<meta charset="utf-8">')) throw new Error('index.html: expected <meta charset="utf-8"> anchor');
  html = html.replace('<meta charset="utf-8">', `<meta charset="utf-8">\n${meta}`);
}
writeFileSync(join(dist, 'index.html'), html);

// licenses ship with the site (GSAP terms, OFL text for fonts)
if (existsSync(join(root, 'THIRD_PARTY_NOTICES.md'))) {
  cpSync(join(root, 'THIRD_PARTY_NOTICES.md'), join(dist, 'THIRD_PARTY_NOTICES.md'));
}

// sanity: everything the page references must exist in dist
const refs = [...html.matchAll(/(?:src|href)="(\/static\/[^"]+)"/g)].map((m) => m[1]);
for (const r of refs) {
  if (!existsSync(join(dist, r.slice(1)))) throw new Error(`missing in dist: ${r}`);
}
let files = 0, bytes = 0;
const walk = (d) => { for (const n of readdirSync(d)) { const p = join(d, n); const s = statSync(p); if (s.isDirectory()) walk(p); else { files++; bytes += s.size; } } };
walk(dist);
console.log(`dist ready: ${files} files, ${(bytes / 1024).toFixed(0)} KB, ${refs.length} page references verified`);
