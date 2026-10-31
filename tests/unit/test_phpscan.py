import pytest

from avishkar.workers.phpscan import scan_php


def rules(src: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in scan_php(src, "x.php"):
        out[f.rule_id] = out.get(f.rule_id, 0) + 1
    return out


@pytest.mark.parametrize("src,rule", [
    ('mysqli_query($c, "SELECT * FROM t WHERE id=" . $_GET["id"]);', "PHP-SQLI"),
    ('$q = "SELECT * FROM t WHERE n=\'$name\'";\nmysqli_query($c, $q);', "PHP-SQLI"),
    ('$r = $pdo->query("SELECT * FROM t WHERE id=" . $id);', "PHP-SQLI"),
    ('$wpdb->get_results("SELECT * FROM t WHERE a=\'" . $_POST["a"] . "\'");', "PHP-SQLI"),
    ('system("ls " . $_GET["d"]);', "PHP-CMDI"),
    ('$out = shell_exec($cmd);', "PHP-CMDI"),
    ('$out = `ls $dir`;', "PHP-CMDI"),
    ('eval($code);', "PHP-EVAL"),
    ('$f = create_function("$a", $body);', "PHP-EVAL"),
    ('include $_GET["page"];', "PHP-INCLUDE"),
    ('require_once("pages/" . $_GET["p"] . ".php");', "PHP-INCLUDE"),
    ('$o = unserialize($_COOKIE["data"]);', "PHP-DESER"),
    ('function hashPassword($password) { return md5($password); }', "PHP-WEAKHASH"),
    ('function newToken() { return mt_rand(); }', "PHP-RANDOM"),
    ('$password = "hunter2-secret-value";', "PHP-SECRET-ASSIGN"),
    ('$cfg = ["password" => "hunter2-secret-value"];', "PHP-SECRET-ASSIGN"),
    ('define("DB_PASSWORD", "hunter2-secret-value");', "PHP-SECRET-ASSIGN"),
    ('$d = file_get_contents("/srv/" . $_GET["f"]);', "PHP-PATH"),
    ('echo "<h1>" . $_GET["name"] . "</h1>";', "PHP-XSS-REFLECT"),
    ('$name = $_POST["n"];\nprint $name;', "PHP-XSS-REFLECT"),
    ('curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);', "PHP-TLS"),
    ('$ctx = stream_context_create(["ssl" => ["verify_peer" => false]]);', "PHP-TLS"),
])
def test_vulnerable_shape_is_detected(src, rule):
    assert rule in rules(src)


@pytest.mark.parametrize("src", [
    '$stmt = $pdo->prepare("SELECT * FROM t WHERE id = ?");\n$stmt->execute([$id]);',
    '$r = $pdo->query("SELECT 1");',
    'system("ls " . escapeshellarg($_GET["d"]));',
    'system("ls -l");',
    '$result = $operations[$name]($a, $b);',
    '$pages = ["home" => "home.php"];\ninclude $pages[$_GET["p"]] ?? "home.php";',
    '$o = json_decode($_COOKIE["data"], true);',
    '$h = hash("sha256", $data);',
    'function newToken() { return bin2hex(random_bytes(32)); }',
    'function pick() { return mt_rand(1, 6); }',
    '$password = getenv("DB_PASSWORD");',
    '$passwordLabel = "Enter your password";',
    '$d = file_get_contents("/srv/" . basename($_GET["f"]));',
    'echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");',
    'echo "Hello";',
    'curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);',
    '$id = (int)$_GET["id"];\n$r = $pdo->query("SELECT * FROM t WHERE id=" . $id);',
])
def test_safe_code_is_not_flagged(src):
    assert rules(src) == {}, rules(src)


def test_html_outside_php_tags_and_comments_never_trigger_rules():
    src = '''<html><body><p>Don't call system($_GET['x']) in HTML text; it's just text.</p>
<?php
// system($_GET['cmd']);
# eval($_POST['x']);
/* include $_GET['p']; */
$doc = 'mysqli_query($c, "SELECT " . $_GET["id"]);';
echo "Welcome";
?>
<script>var a = "unserialize($_COOKIE)";</script>
'''
    assert rules(src) == {}


def test_line_numbers_survive_html_and_heredoc():
    src = "<html>\n<?php\n$t = <<<EOT\nx\ny\nEOT;\nsystem($_GET['c']);\n?>"
    assert next(f for f in scan_php(src, "x.php") if f.rule_id == "PHP-CMDI").line == 7


def test_short_echo_tag_is_an_echo():
    assert "PHP-XSS-REFLECT" in rules('<p><?= $_GET["name"] ?></p>')


def test_secret_evidence_is_redacted_and_placeholder_is_low():
    f = next(f for f in scan_php('$apiKey = "sk-php-1234567890abcdef";', "x.php") if f.rule_id == "PHP-SECRET-ASSIGN")
    assert "1234567890abcdef" not in f.evidence
    g = next(f for f in scan_php('$password = "changeme-example-value";', "x.php") if f.rule_id == "PHP-SECRET-ASSIGN")
    assert g.confidence.value == "low"


def test_framework_helpers_are_a_documented_miss_not_a_clean_bill():
    assert rules("DB::select(DB::raw('SELECT * FROM t WHERE id=' . request('id')));") == {}


def test_garbage_input_does_not_crash():
    for src in ["<?php $s = 'unterminated", "<?php /* never closed", "<?php <<<EOT\nnever closed", "<?php `", "<?php ((((((((", "<?php }}}}}", "", "\x00\x01", "<?"]:
        scan_php(src, "x.php")
