import pytest

from avishkar.workers.csscan import scan_csharp


def rules(src: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in scan_csharp(src, "X.cs"):
        out[f.rule_id] = out.get(f.rule_id, 0) + 1
    return out


@pytest.mark.parametrize("src,rule", [
    ('var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = \'" + name + "\'", conn);', "CS-SQLI"),
    ('var cmd = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", conn);', "CS-SQLI"),
    ('var q = "SELECT * FROM T WHERE A=" + a;\nvar cmd = new SqlCommand(q, conn);', "CS-SQLI"),
    ('ctx.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = \'" + name + "\'");', "CS-SQLI"),
    ('cmd.CommandText = "DELETE FROM T WHERE Id=" + id;', "CS-SQLI"),
    ('Process.Start("cmd.exe", "/c dir " + path);', "CS-CMDI"),
    ('var psi = new ProcessStartInfo("powershell", $"-Command {script}");', "CS-CMDI"),
    ('var f = new BinaryFormatter();', "CS-DESER"),
    ('var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };', "CS-DESER"),
    ('using var h = MD5.Create();', "CS-WEAKHASH"),
    ('var h = new SHA1Managed();', "CS-WEAKHASH"),
    ('var c = DES.Create();', "CS-WEAKCIPHER"),
    ('aes.Mode = CipherMode.ECB;', "CS-WEAKCIPHER"),
    ('string NewSessionToken() { return new Random().Next().ToString(); }', "CS-RANDOM"),
    ('string password = "hunter2-secret-value";', "CS-SECRET-ASSIGN"),
    ('var o = new Options { ApiKey = "sk-live-1234567890abcdef" };', "CS-SECRET-ASSIGN"),
    ('ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;', "CS-TLS"),
    ('var h = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };', "CS-TLS"),
    ('var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };', "CS-XXE"),
    ('var t = File.ReadAllText("/data/" + Request.Query["name"]);', "CS-PATH"),
    ('public IActionResult Get([FromQuery] string name) { return Content(File.ReadAllText(name)); }', "CS-PATH"),
    ('Response.Write("<h1>" + Request.QueryString["n"] + "</h1>");', "CS-XSS-REFLECT"),
    ('await CSharpScript.EvaluateAsync(userCode);', "CS-EVAL"),
])
def test_vulnerable_shape_is_detected(src, rule):
    assert rule in rules(src)


@pytest.mark.parametrize("src", [
    'var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);\ncmd.Parameters.AddWithValue("@name", name);',
    'var cmd = new SqlCommand("SELECT 1", conn);',
    'ctx.Users.FromSqlInterpolated($"SELECT 1");' if False else 'var cmd = new SqlCommand("SELECT * FROM A WHERE B = " + "1", conn);',
    'Process.Start("ping", "127.0.0.1");',
    'var dto = System.Text.Json.JsonSerializer.Deserialize<Dto>(json);',
    'using var h = SHA256.Create();',
    'using var aes = new AesGcm(key, 16);',
    'var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));',
    'string password = Environment.GetEnvironmentVariable("DB_PASSWORD");',
    'string passwordLabel = "Enter your password";',
    'var h = new HttpClient();',
    'var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };',
    'var t = File.ReadAllText(Path.Combine(baseDir, Path.GetFileName(Request.Query["name"])));',
    'Response.Write(HtmlEncoder.Default.Encode(Request.QueryString["n"]));',
    'var psi = new ProcessStartInfo("ping");\npsi.ArgumentList.Add(host);',
])
def test_safe_code_is_not_flagged(src):
    assert rules(src) == {}, rules(src)


def test_comments_and_strings_never_trigger_rules():
    src = '''
// Process.Start("cmd.exe", "/c " + x); new BinaryFormatter();
/* MD5.Create(); CipherMode.ECB */
var doc = "Call new SqlCommand(\\"SELECT \\" + id) and MD5.Create() here";
var verb = @"MD5.Create(); new BinaryFormatter();";
var raw = """
    Process.Start("cmd", "/c " + x);
    """;
'''
    assert rules(src) == {}


def test_line_numbers_survive_comments_and_verbatim_strings():
    src = '// a\n/* b\n c */\nvar t = @"x\ny";\nusing var h = MD5.Create();\n'
    assert next(f for f in scan_csharp(src, "X.cs") if f.rule_id == "CS-WEAKHASH").line == 6


def test_secret_evidence_is_redacted_and_placeholder_is_low():
    f = next(f for f in scan_csharp('string apiKey = "sk-cs-1234567890abcdef";', "X.cs") if f.rule_id == "CS-SECRET-ASSIGN")
    assert "1234567890abcdef" not in f.evidence
    g = next(f for f in scan_csharp('string password = "changeme-example-value";', "X.cs") if f.rule_id == "CS-SECRET-ASSIGN")
    assert g.confidence.value == "low"


def test_query_built_elsewhere_is_a_documented_miss():
    assert rules("var cmd = new SqlCommand(Queries.Build(id), conn);") == {}


def test_garbage_input_does_not_crash():
    for src in ['var s = "unterminated', "/* never closed", '@"never closed', '$"{', "((((((((", "}}}}}", "", "\x00\x01", "=> => =>"]:
        scan_csharp(src, "X.cs")
