import pytest

from avishkar.workers.goscan import scan_go


def rules(src: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in scan_go(src, "x.go"):
        out[f.rule_id] = out.get(f.rule_id, 0) + 1
    return out


WEB = 'package main\n'


# ------------------------------------------------------------------ vulnerable shapes are found
@pytest.mark.parametrize("src,rule", [
    ('rows, _ := db.Query("SELECT * FROM t WHERE id=" + id)', "GO-SQLI"),
    ('rows, _ := db.Query(fmt.Sprintf("SELECT * FROM t WHERE n=\'%s\'", n))', "GO-SQLI"),
    ('q := fmt.Sprintf("SELECT * FROM t WHERE n=\'%s\'", n)\nrows, _ := db.Query(q)', "GO-SQLI"),
    ('rows, _ := db.QueryContext(ctx, "DELETE FROM t WHERE id="+id)', "GO-SQLI"),
    ('exec.Command("sh", "-c", "ls "+dir).Run()', "GO-CMDI"),
    ('exec.Command("bash", "-c", fmt.Sprintf("tar %s", name)).Run()', "GO-CMDI"),
    ('exec.Command(r.FormValue("prog")).Run()', "GO-CMDI"),
    ('sum := md5.Sum(data)', "GO-WEAKHASH"),
    ('h := sha1.New()', "GO-WEAKHASH"),
    ('c, _ := des.NewCipher(key)', "GO-WEAKCIPHER"),
    ('c, _ := rc4.NewCipher(key)', "GO-WEAKCIPHER"),
    ('import "math/rand"\nfunc newSessionToken() int { return rand.Int() }', "GO-RANDOM"),
    ('const adminToken = "go-admin-token-5d83a1c9e7"', "GO-SECRET-ASSIGN"),
    ('password := "hunter2-secret-value"', "GO-SECRET-ASSIGN"),
    ('cfg := Config{APIKey: "sk-live-1234567890abcdef"}', "GO-SECRET-ASSIGN"),
    ('cfg := &tls.Config{InsecureSkipVerify: true}', "GO-TLS"),
    ('cfg.InsecureSkipVerify = true', "GO-TLS"),
    ('data, _ := os.ReadFile("/srv/" + r.FormValue("name"))', "GO-PATH"),
    ('name := r.FormValue("n")\nos.Open(name)', "GO-PATH"),
    ('http.ServeFile(w, r, r.URL.Query().Get("f"))', "GO-PATH"),
    ('fmt.Fprintf(w, "<h1>%s</h1>", r.FormValue("name"))', "GO-XSS-REFLECT"),
    ('w.Write([]byte(r.URL.Query().Get("q")))', "GO-XSS-REFLECT"),
])
def test_vulnerable_shape_is_detected(src, rule):
    assert rule in rules(src)


# ------------------------------------------------------------------ safe code is not flagged
@pytest.mark.parametrize("src", [
    'rows, _ := db.Query("SELECT * FROM t WHERE id = $1", id)',
    'rows, _ := db.Query("SELECT 1")',
    'rows, _ := db.QueryContext(ctx, "SELECT * FROM t WHERE id = ?", id)',
    'exec.Command("ls", "-l", dir).Run()',
    'exec.Command("sh", "-c", "echo hello").Run()',
    'sum := sha256.Sum256(data)',
    'block, _ := aes.NewCipher(key)',
    'import "crypto/rand"\nfunc newSessionToken() { rand.Read(buf) }',
    'import "math/rand"\nfunc shuffle(xs []int) { rand.Shuffle(len(xs), func(i, j int) {}) }',
    'adminToken := os.Getenv("ADMIN_TOKEN")',
    'passwordLabel := "Enter your password here"',
    'cfg := &tls.Config{MinVersion: tls.VersionTLS12}',
    'data, _ := os.ReadFile(filepath.Join("/srv", filepath.Base(r.FormValue("name"))))',
    'fmt.Fprintf(w, "<h1>%s</h1>", html.EscapeString(r.FormValue("name")))',
    'fmt.Fprintf(w, "ok")',
    # a value read back from a command or a file is output of a sink, not request data
    'out, _ := exec.Command("ls", "--", r.FormValue("d")).Output()\nw.Write(out)',
    'data, _ := os.ReadFile(filepath.Join("/srv", filepath.Base(r.FormValue("n"))))\nw.Write(data)',
])
def test_safe_code_is_not_flagged(src):
    assert rules(src) == {}, rules(src)


# ------------------------------------------------------------------ the lexer ignores text that is not code
def test_comments_strings_and_raw_strings_never_trigger_rules():
    src = '''
// exec.Command("sh", "-c", "rm -rf "+x)
/* md5.Sum(data); InsecureSkipVerify: true */
var doc = "Call db.Query(\\"SELECT \\" + id) and md5.Sum(x) here"
var raw = `
    exec.Command("sh", "-c", "ls "+dir)
    cfg := &tls.Config{InsecureSkipVerify: true}
`
'''
    assert rules(src) == {}


def test_line_numbers_survive_comments_and_raw_strings():
    src = "// a\n/* b\n c */\nvar t = `x\ny\n`\nsum := md5.Sum(data)\n"
    f = next(f for f in scan_go(src, "x.go") if f.rule_id == "GO-WEAKHASH")
    assert f.line == 7


def test_secret_evidence_is_redacted():
    f = next(f for f in scan_go('const apiKey = "sk-go-1234567890abcdef"', "x.go") if f.rule_id == "GO-SECRET-ASSIGN")
    assert "1234567890abcdef" not in f.evidence


def test_placeholder_secret_is_low_confidence():
    f = next(f for f in scan_go('password := "changeme-example-value"', "x.go") if f.rule_id == "GO-SECRET-ASSIGN")
    assert f.confidence.value == "low"


def test_query_built_in_another_package_is_a_documented_miss_not_a_clean_bill():
    assert rules("rows, _ := db.Query(queries.Build(id))") == {}


def test_concatenated_path_is_only_flagged_in_web_handlers():
    desktop = 'data, _ := os.ReadFile(base + "/x.txt")'
    web = 'q := r.FormValue("q")\ndata, _ := os.ReadFile(base + "/x.txt")'
    assert "GO-PATH" not in rules(desktop) and "GO-PATH" in rules(web)


def test_garbage_and_unterminated_input_do_not_crash():
    for src in ['s := "unterminated', "/* never closed", "`never closed", "((((((((", "}}}}}", "", "\x00\x01", ":= := :="]:
        scan_go(src, "x.go")
