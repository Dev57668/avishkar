"""Writes the *holdout* calibration cases (tests/corpus/hold_*).

These were written AFTER the Python/JS detectors in this branch were frozen, and they deliberately include code styles
the detectors do not understand (known gaps) and safe code that looks suspicious (hard negatives). They are reported
separately from the 'tuning' cohort (cases that existed while the rules were being written) so recall/precision
improvements that merely reflect tuning to known samples cannot be mistaken for real generalisation.
Labels are authored by the implementer, not adjudicated by a second reviewer. Vulnerable lines are located by text.

    python scripts/build_corpus_holdout.py
"""
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "tests" / "corpus"


def locate(text, needle):
    if needle is None:
        return None
    hits = [i + 1 for i, line in enumerate(text.splitlines()) if needle in line]
    assert len(hits) == 1, (needle, hits)
    return hits[0]


# Holdout cases that exposed a real gap and were then used to extend a rule. They stop being held-out evidence for
# that rule, so they are reclassified as tuning data (the frozen pre-fix holdout numbers are in
# docs/calibration-holdout-frozen.json).
RECLASSIFIED = {"hold_django_raw_sql", "hold_sqlalchemy_text", "hold_send_file_traversal", "hold_session_verify_off",
                "hold_js_eval_variants", "hold_knex_prisma"}


def case(name, files, vulns=(), note="", cohort="holdout"):
    if name in RECLASSIFIED:
        cohort, note = "tuning", note.replace("known gap", "was a known gap (rule added after this case)")
    d = ROOT / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    for fn, body in files.items():
        (d / fn).parent.mkdir(parents=True, exist_ok=True)
        (d / fn).write_text(body, encoding="utf8", newline="\n")
    lab = {"source": "synthetic", "cohort": cohort, "fully_labeled": True,
           "vulns": [{"path": p, "line": locate(files[p], n), "kind": k} for p, n, k in vulns],
           "adjudicated": False, "reviewers": 0,
           "note": (note + " | " if note else "") + "written after the detectors were frozen; labels by the implementer, not adjudicated"}
    (d / "labels.json").write_text(json.dumps(lab, indent=1), encoding="utf8")


# ------------------------------------------------------------------------------------------------ Python
case("hold_flask_login_sqli", {"views.py": '''from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    user = request.form["username"]
    query = "SELECT id FROM users WHERE name = '%s'" % user
    cur.execute(query)
    row = cur.fetchone()
    return jsonify({"ok": row is not None})
'''}, [("views.py", "cur.execute(query)", "sqli")])

case("hold_django_raw_sql", {"models.py": '''from django.db import models


class Report(models.Model):
    name = models.CharField(max_length=100)

    @classmethod
    def search(cls, term):
        return cls.objects.raw("SELECT * FROM app_report WHERE name LIKE '%%%s%%'" % term)
'''}, [("models.py", "cls.objects.raw", "sqli")], "known gap: ORM raw() is not a recognised SQL sink")

case("hold_sqlalchemy_text", {"repo.py": '''from sqlalchemy import text


def find(conn, ident):
    return conn.execute(text(f"SELECT * FROM items WHERE id = {ident}")).fetchall()
'''}, [("repo.py", "conn.execute(text", "sqli")], "known gap: the formatted string is wrapped in text()")

case("hold_safe_queries", {"db.py": '''import sqlite3


def by_name(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE name = ?", (name,))
    return cur.fetchall()


def insert(conn, rows):
    conn.executemany("INSERT INTO t(a, b) VALUES (?, ?)", rows)


def table_exists(conn):
    return conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
'''})

case("hold_subprocess_safe", {"run.py": '''import shlex
import subprocess


def convert(src, dst):
    return subprocess.run(["convert", src, dst], check=True, capture_output=True)


def listing(path):
    return subprocess.check_output(["ls", "-l", shlex.quote(path)])
'''})

case("hold_os_system_constant", {"util.py": '''import os


def clear_screen():
    os.system("clear")
'''}, [], "constant command: not injectable. The rule flags every os.system, so this is a expected false positive")

case("hold_yaml_fullloader", {"cfg.py": '''import yaml


def load(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.FullLoader)


def load_safe(path):
    with open(path) as f:
        return yaml.safe_load(f)
'''}, [("cfg.py", "yaml.FullLoader", "deserialization")])

case("hold_django_settings", {"settings.py": '''import os

SECRET_KEY = "django-insecure-8x!k2m9q#w7z$r5t1y3u6i0o"
DEBUG = True
ALLOWED_HOSTS = ["*"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "shop",
        "USER": "shop",
        "PASSWORD": "pg_pass_Zq81xK02",
        "HOST": "db.internal",
    }
}

EMAIL_HOST_PASSWORD = os.environ["EMAIL_HOST_PASSWORD"]
STATIC_URL = "/static/"
SECRET_KEY_FALLBACKS_NOTE = "see the deployment runbook"
'''}, [("settings.py", "SECRET_KEY = ", "secret"), ("settings.py", "DEBUG = True", "debug"),
       ("settings.py", '"PASSWORD":', "secret")])

case("hold_test_credentials", {"login_check.py": '''def test_login(client):
    password = "test-password-123"
    resp = client.post("/login", data={"user": "alice", "password": password})
    assert resp.status_code == 200
'''}, [], "test credential: reported at low confidence, not a real secret")

case("hold_hash_not_security", {"cache.py": '''import hashlib


def etag(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
'''}, [], "md5 for a cache key with usedforsecurity=False: an expected false positive")

case("hold_random_security", {"auth.py": '''import random
import string


def generate_password(n=16):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def pick_greeting():
    return random.choice(["hi", "hello", "hey"])
'''}, [("auth.py", "random.choices", "weak-random")])

case("hold_send_file_traversal", {"files.py": '''import os
from flask import send_file

UPLOAD_DIR = "/srv/uploads"


def download(filename):
    return send_file(os.path.join(UPLOAD_DIR, filename))
'''}, [("files.py", "send_file(", "path-traversal")], "known gap: send_file() is not a recognised file sink")

case("hold_flask_debug_config", {"app.py": '''import os
from flask import Flask

app = Flask(__name__)
app.config["DEBUG"] = True


if __name__ == "__main__":
    app.run(debug=os.getenv("APP_DEBUG") == "1")
'''}, [("app.py", 'app.config["DEBUG"]', "debug")])

case("hold_session_verify_off", {"client.py": '''import requests

session = requests.Session()
session.verify = False


def fetch(url):
    return session.get(url, timeout=5)
'''}, [("client.py", "session.verify = False", "noverify")], "known gap: verification disabled by attribute assignment, not keyword")

case("hold_defusedxml_safe", {"xmlio.py": '''from defusedxml import ElementTree as ET


def parse(s):
    return ET.fromstring(s)
'''})

case("hold_realistic_module", {"service.py": '''"""Order service: mixed good and bad code."""
import hashlib
import json
import os
import pickle
import subprocess

import requests

API_BASE = "https://api.example.com"
WEBHOOK_SECRET = "whsec_9f3c1d7a4b6e8f20"


def checksum(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def load_cache(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def ship(order_id: str):
    out = subprocess.run(["label-printer", order_id], capture_output=True, check=False)
    return out.stdout


def notify(url, payload):
    return requests.post(url, data=json.dumps(payload), verify=False, timeout=5)


def tag(order):
    return os.system("tag-order %s" % order["id"])
'''}, [("service.py", "WEBHOOK_SECRET", "secret"), ("service.py", "pickle.load(fh)", "pickle"),
       ("service.py", "verify=False", "noverify"), ("service.py", "os.system(", "cmdi")])

# ------------------------------------------------------------------------------------------------ JavaScript / TypeScript
case("hold_express_routes", {"server.js": '''const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/hello', (req, res) => {
  res.send(`<p>Hello ${req.query.name}</p>`);
});

app.get('/user/:id', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.params.id, (err, rows) => res.json(rows));
});

app.get('/ls', (req, res) => {
  exec("ls " + req.query.dir, (err, out) => res.send(out));
});

app.get('/ok', (req, res) => res.json({ ok: true }));
'''}, [("server.js", "res.send(`<p>Hello", "xss"), ("server.js", 'db.query("SELECT', "sqli"),
       ("server.js", 'exec("ls "', "cmdi")])

case("hold_react_component", {"Post.tsx": '''import React from 'react';

export function Post({ html, title }: { html: string; title: string }) {
  return (
    <article>
      <h1>{title}</h1>
      <div dangerouslySetInnerHTML={{ __html: html }} />
    </article>
  );
}
'''}, [("Post.tsx", "dangerouslySetInnerHTML", "xss")])

case("hold_node_fs_safe", {"files.js": '''const fs = require('fs');
const path = require('path');
const BASE = path.resolve('/srv/uploads');

function read(name) {
  const full = path.resolve(BASE, name);
  if (!full.startsWith(BASE + path.sep)) throw new Error('invalid path');
  return fs.readFileSync(full, 'utf8');
}
module.exports = { read };
'''})

case("hold_node_crypto", {"crypto.js": '''const crypto = require('crypto');

function fingerprint(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

function digest(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function generateSessionId() {
  return Math.random().toString(36).slice(2);
}

function newKey() {
  return crypto.randomBytes(32).toString('hex');
}
'''}, [("crypto.js", "createHash('sha1')", "weakhash"), ("crypto.js", "Math.random()", "weak-random")])

case("hold_ts_secrets", {"payments.ts": '''const STRIPE_SECRET = "sk_live_51Habcdef0123456789xyz";
const apiKey = process.env.API_KEY;
const PUBLIC_KEY_URL = "https://cdn.example.com/keys/public.pem";

export async function charge(amount: number) {
  return fetch("https://api.stripe.com/v1/charges", {
    method: "POST",
    headers: { Authorization: `Bearer ${STRIPE_SECRET}` },
    body: JSON.stringify({ amount }),
  });
}
'''}, [("payments.ts", "STRIPE_SECRET =", "secret")])

case("hold_js_eval_variants", {"run.js": '''const vm = require('vm');

function parse(text) {
  return JSON.parse(text);
}

function run(code) {
  return eval(code);
}

function sandboxed(userCode) {
  return vm.runInNewContext(userCode);
}
'''}, [("run.js", "return eval(code)", "eval"), ("run.js", "vm.runInNewContext", "eval")],
     "known gap: vm.runInNewContext executes strings but is not a recognised sink")

case("hold_js_tls_off", {"net.js": '''const https = require('https');

const agent = new https.Agent({ rejectUnauthorized: false });

module.exports = { agent };
'''}, [("net.js", "rejectUnauthorized", "noverify")])

case("hold_js_text_only", {"notes.js": '''// Never use eval(code) or el.innerHTML = x; do not set rejectUnauthorized: false.
/* child_process.exec(`rm -rf ${dir}`) is dangerous */
const doc = `Example: db.query("SELECT * FROM t WHERE id=" + id) is vulnerable`;
const msg = 'document.write(userInput) is a classic XSS sink';
const ok = 1 / 2 / 3;
module.exports = { doc, msg, ok };
'''})

case("hold_knex_prisma", {"repo.js": '''function byId(knex, id) {
  return knex.raw(`SELECT * FROM users WHERE id = ${id}`);
}

async function byName(prisma, name) {
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`);
}

function safe(knex, id) {
  return knex.raw('SELECT * FROM users WHERE id = ?', [id]);
}
'''}, [("repo.js", "knex.raw(`SELECT", "sqli"), ("repo.js", "$queryRawUnsafe", "sqli")],
     "known gap: $queryRawUnsafe is not a recognised SQL sink")

# ------------------------------------------------------------------------------------------------ dependencies
case("hold_deps_node", {"package.json": '''{
  "name": "demo",
  "dependencies": {
    "minimist": "1.2.0",
    "express": "^4.19.2"
  }
}
'''}, [("package.json", None, "dependency"), ("package.json", None, "dependency")], "old minimist + missing lockfile")

case("hold_deps_min_bound", {"requirements.txt": '''django>=3.1
flask==2.3.3
requests==2.32.0
'''}, [], "django>=3.1 is a minimum bound that permits current releases; flagging it is an expected false positive")



# ================================================================================================ holdout-2
# Written after the first round of gap fixes (ORM raw/text, send_file, session.verify, vm.*, $queryRawUnsafe), to estimate
# generalisation of the rules as they stand. Again authored by the implementer; not adjudicated.
H2 = "holdout-2"

case("h2_fastapi_endpoints", {"main.py": '''import subprocess
from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()


@app.post("/clone")
def clone(repo_url: str):
    subprocess.run(f"git clone {repo_url}", shell=True, check=False)
    return {"ok": True}


@app.get("/files/{name}")
def get_file(name: str):
    return FileResponse(f"/data/{name}")


@app.get("/health")
def health():
    return {"status": "ok"}
'''}, [("main.py", "subprocess.run(f", "cmdi"), ("main.py", "FileResponse(f", "path-traversal")], cohort=H2)

case("h2_celery_tasks", {"tasks.py": '''import base64
import os
import pickle


def run_report(cmd):
    return os.popen(cmd).read()


def restore(blob):
    return pickle.loads(base64.b64decode(blob))
'''}, [("tasks.py", "os.popen", "cmdi"), ("tasks.py", "pickle.loads", "pickle")], cohort=H2)

case("h2_orm_safe", {"queries.py": '''from sqlalchemy import text


def by_id(session, i):
    return session.execute(text("SELECT * FROM t WHERE id = :id"), {"id": i}).fetchall()


def by_name(User, name):
    return User.objects.filter(name=name)
'''}, [], cohort=H2)

case("h2_hash_password", {"accounts.py": '''import hashlib
from cryptography.fernet import Fernet


def store_password(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()


def encrypt(key: bytes, data: bytes) -> bytes:
    return Fernet(key).encrypt(data)
'''}, [("accounts.py", "hashlib.sha1", "weakhash")], cohort=H2)

case("h2_aws_example_and_url_creds", {"config.py": '''AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_URI = "postgresql://appuser:Pr0d-Passw0rd-2026@db.internal:5432/shop"
REGION = "eu-west-1"
'''}, [("config.py", "DB_URI", "secret")], "AWS documentation example key is not a credential (expected low-confidence FP); "
   "a password embedded in a URL is a real secret the detectors do not parse (known gap)", cohort=H2)

case("h2_requests_ok", {"http.py": '''import requests


def get(url):
    return requests.get(url, timeout=5, verify=True)
'''}, [], cohort=H2)

case("h2_koa_ts", {"app.ts": '''import Koa from 'koa';

const app = new Koa();

app.use(async (ctx) => {
  ctx.body = `<h1>Results for ${ctx.query.q}</h1>`;
});
'''}, [("app.ts", "ctx.body =", "xss")], "known gap: framework-specific response sink (ctx.body)", cohort=H2)

case("h2_next_api", {"pages/api/post.js": '''export default async function handler(req, res) {
  const { id } = req.query;
  const rows = await pool.query(`SELECT * FROM posts WHERE id = ${id}`);
  res.status(200).json(rows);
}
'''}, [("pages/api/post.js", "pool.query", "sqli")], cohort=H2)

case("h2_node_cli", {"cli.js": '''const { execSync } = require('node:child_process');

function checkout(branch) {
  execSync(`git checkout ${branch}`);
}

function status() {
  return execSync('git status').toString();
}
'''}, [("cli.js", "execSync(`git checkout", "cmdi")], cohort=H2)

case("h2_jwt", {"auth.js": '''const jwt = require('jsonwebtoken');

function issue(payload) {
  return jwt.sign(payload, 'supersecretkey123');
}

function check(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}
'''}, [("auth.js", "jwt.sign", "secret")], "known gap: literal secret passed as an argument rather than assigned to a named variable", cohort=H2)

case("h2_requirements", {"requirements.txt": '''Django==3.0.5
PyYAML==5.3
requests
urllib3==2.2.2
'''}, [("requirements.txt", "Django==3.0.5", "dependency"), ("requirements.txt", "PyYAML==5.3", "dependency"),
       ("requirements.txt", "requests", "dependency")], cohort=H2)

print("holdout cases:", len(list(ROOT.glob("hold_*"))), "holdout-2 cases:", len(list(ROOT.glob("h2_*"))))
