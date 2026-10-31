import pytest

from avishkar.workers.javascan import scan_java


def rules(src: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in scan_java(src, "X.java"):
        out[f.rule_id] = out.get(f.rule_id, 0) + 1
    return out


def one(src: str, rule: str):
    return next(f for f in scan_java(src, "X.java") if f.rule_id == rule)


# ------------------------------------------------------------------ vulnerable shapes are found
@pytest.mark.parametrize("src,rule", [
    ('stmt.executeQuery("SELECT * FROM t WHERE id=" + id);', "JAVA-SQLI"),
    ('String q = "SELECT * FROM t WHERE n=\'" + n + "\'";\nstmt.executeQuery(q);', "JAVA-SQLI"),
    ('conn.prepareStatement(String.format("SELECT * FROM t WHERE n=\'%s\'", n));', "JAVA-SQLI"),
    ('Runtime.getRuntime().exec("ping " + host);', "JAVA-CMDI"),
    ('Runtime rt = Runtime.getRuntime();\nrt.exec(cmd);', "JAVA-CMDI"),
    ('new ProcessBuilder("sh", "-c", "ls " + dir).start();', "JAVA-CMDI"),
    ('Object o = new ObjectInputStream(in).readObject();', "JAVA-DESER"),
    ('Yaml y = new Yaml();', "JAVA-DESER"),
    ('MessageDigest.getInstance("MD5");', "JAVA-WEAKHASH"),
    ('MessageDigest.getInstance("SHA-1");', "JAVA-WEAKHASH"),
    ('Cipher.getInstance("DES/CBC/PKCS5Padding");', "JAVA-WEAKCIPHER"),
    ('Cipher.getInstance("AES");', "JAVA-WEAKCIPHER"),
    ('Cipher.getInstance("AES/ECB/PKCS5Padding");', "JAVA-WEAKCIPHER"),
    ('String sessionToken(){ return String.valueOf(new Random().nextLong()); }', "JAVA-RANDOM"),
    ('String dbPassword = "hunter2-secret-value";', "JAVA-SECRET-ASSIGN"),
    ('DriverManager.getConnection(url, "root", "Sup3rS3cretPw");', "JAVA-SECRET-ASSIGN"),
    ('conn.setHostnameVerifier((h, s) -> true);', "JAVA-TLS"),
    ('public void checkServerTrusted(X509Certificate[] c, String a) { }', "JAVA-TLS"),
    ('DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.newDocumentBuilder().parse(in);', "JAVA-XXE"),
    ('var f = TransformerFactory.newInstance();\nf.newTransformer().transform(new StreamSource(in), out);', "JAVA-XXE"),
    ('String[] c = {"sh", "-c", cmd};\nRuntime.getRuntime().exec(c);', "JAVA-CMDI"),
    ('String n = request.getParameter("f");\nnew FileInputStream("/data/" + n);', "JAVA-PATH"),
    ('String q = request.getParameter("q");\nout.println("<p>" + q + "</p>");', "JAVA-XSS-REFLECT"),
    ('ScriptEngine e = m.getEngineByName("js");\ne.eval(userInput);', "JAVA-EVAL"),
])
def test_vulnerable_shape_is_detected(src, rule):
    assert rule in rules(src)


# ------------------------------------------------------------------ safe code is not flagged
@pytest.mark.parametrize("src", [
    'PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\nps.setInt(1, id);\nps.executeQuery();',
    'stmt.executeQuery("SELECT 1");',
    'Runtime.getRuntime().exec("ls");',
    # regression: found by hand-reviewing a real project (Logisim Evolution); both were false positives
    'final String[] cmd1 = {"xxd", file.toString(), out.toString()};\nRuntime.getRuntime().exec(cmd1).waitFor();',
    'Runtime.getRuntime().exec(new String[]{"ls", dir});',
    'var f = TransformerFactory.newInstance();\nf.newTransformer().transform(new DOMSource(doc), new StreamResult(writer));',
    'new ProcessBuilder("ping", "-c", "1", host).start();',
    'MessageDigest.getInstance("SHA-256");',
    'Cipher.getInstance("AES/GCM/NoPadding");',
    'new SecureRandom().nextBytes(sessionToken);',
    'String dbPassword = System.getenv("DB_PASSWORD");',
    'String passwordLabel = "Enter your password here";',
    'String s = "a" + "b";\nstmt.executeQuery("SELECT * FROM t WHERE x=" + "1");',
    'out.println(Encode.forHtml(request.getParameter("q")));',
    'Path p = base.resolve(name).normalize();',
    'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
    'new Yaml(new SafeConstructor(new LoaderOptions()));',
])
def test_safe_code_is_not_flagged(src):
    assert rules(src) == {}, rules(src)


# ------------------------------------------------------------------ the lexer ignores text that is not code
def test_comments_and_strings_never_trigger_rules():
    src = '''
// Runtime.getRuntime().exec("rm -rf " + x);
/* MessageDigest.getInstance("MD5"); new ObjectInputStream(in); */
String doc = "Call stmt.executeQuery(\\"SELECT \\" + id) and MessageDigest.getInstance(\\"MD5\\") here";
String block = """
    Runtime.getRuntime().exec("ping " + host);
    new ObjectInputStream(in);
    """;
'''
    assert rules(src) == {}


def test_line_numbers_survive_comments_and_text_blocks():
    src = "// a\n/* b\n c */\nString t = \"\"\"\nx\ny\n\"\"\";\nMessageDigest.getInstance(\"MD5\");\n"
    assert one(src, "JAVA-WEAKHASH").line == 8


def test_secret_evidence_is_redacted():
    f = one('String apiKey = "sk-java-1234567890abcdef";', "JAVA-SECRET-ASSIGN")
    assert "1234567890abcdef" not in f.evidence and "sk-j" in f.evidence


def test_placeholder_secret_is_low_confidence():
    f = one('String password = "changeme-example-value";', "JAVA-SECRET-ASSIGN")
    assert f.confidence.value == "low"


def test_alias_and_taint_flows_are_followed_but_not_across_methods_or_files():
    assert "JAVA-CMDI" in rules("Runtime r = Runtime.getRuntime();\nr.exec(cmd);")
    # a query built in another class cannot be seen: documented limit, not a clean bill of health
    assert rules("stmt.executeQuery(Queries.build(id));") == {}


def test_concatenated_file_path_is_only_flagged_in_web_handlers():
    desktop = 'new File(base + "/x.txt");'
    web = 'String q = request.getParameter("q");\nnew File(base + "/x.txt");'
    assert "JAVA-PATH" not in rules(desktop) and "JAVA-PATH" in rules(web)


def test_garbage_and_unterminated_input_do_not_crash():
    for src in ['String s = "unterminated', "/* never closed", '"""never closed', "((((((((", "}}}}}", "", "\x00\x01"]:
        scan_java(src, "X.java")
