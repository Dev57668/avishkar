"""Each test pins a false alarm found by hand-reviewing a real open-source project (see docs/REAL_WORLD_EVAL.md).

Only the SHAPE of the code is reproduced here, written fresh; no project code is copied into this repository.
"""
from avishkar.workers.csscan import scan_csharp
from avishkar.workers.detectors import detect_patterns
from avishkar.workers.goscan import scan_go
from avishkar.workers.javascan import scan_java, scan_kotlin
from avishkar.workers.jsscan import scan_js
from avishkar.workers.phpscan import scan_php
from avishkar.workers.shapes import is_placeholder


def rules(fn, src, name="x"):
    return sorted(f.rule_id for f in fn(src, name))


# ------------------------------------------------------------------ constant-style names are not data
def test_csharp_constant_table_names_with_bound_parameters_are_not_sql_injection():
    safe = ('cmd.CommandText = "DELETE FROM " + USER_TB_NAME + " WHERE Name = $Name AND App = $App";\n'
            'cmd.CommandText = "SELECT * FROM " + Tables.USERS_TABLE + " WHERE Id = $Id";\n')
    assert rules(scan_csharp, safe) == []
    assert "CS-SQLI" in rules(scan_csharp, 'cmd.CommandText = "DELETE FROM " + tableName + " WHERE Id = 1";')  # a variable still is
    assert "CS-SQLI" in rules(scan_csharp, 'cmd.CommandText = "SELECT * FROM " + USER_TB + " WHERE n = \'" + name + "\'";')  # constant + input


def test_java_and_go_and_php_constant_names_are_not_data():
    assert rules(scan_java, 'stmt.executeQuery("SELECT * FROM " + USER_TABLE + " WHERE id = 1");') == []
    assert rules(scan_go, 'db.Exec("DELETE FROM " + USERS_TABLE + " WHERE id = $1", id)') == []
    assert rules(scan_php, 'mysqli_query($c, "SELECT * FROM " . TABLE_NAME . " LIMIT 1");') == []
    assert "JAVA-SQLI" in rules(scan_java, 'stmt.executeQuery("SELECT * FROM " + tableName + " WHERE id = 1");')


# ------------------------------------------------------------------ a name reused elsewhere must not carry state with it
def test_go_the_same_variable_name_in_another_function_is_a_different_variable():
    src = ('func a(db *sql.DB, r *http.Request) {\n  query := fmt.Sprintf("SELECT * FROM t WHERE n=\'%s\'", r.FormValue("n"))\n  db.Query(query)\n}\n'
           'func b(db *sql.DB) {\n  query := "SELECT * FROM t WHERE n = ?"\n  db.Query(query, 1)\n}\n')
    found = [(f.rule_id, f.line) for f in scan_go(src, "x.go")]
    assert found == [("GO-SQLI", 3)]


def test_go_a_later_constant_assignment_clears_an_earlier_built_query():
    src = ('func a(db *sql.DB, in string) {\n  switch mode {\n  case unsafe:\n    query := fmt.Sprintf("SELECT %s FROM t", in)\n    db.Exec(query)\n'
           '  case safe:\n    query := "SELECT ? FROM t"\n    db.Exec(query, in)\n  }\n}\n')
    assert [(f.rule_id, f.line) for f in scan_go(src, "x.go")] == [("GO-SQLI", 5)]


def test_java_csharp_php_scope_and_order():
    java = ('void a(String id) { String q = "SELECT * FROM t WHERE a=" + id; stmt.executeQuery(q); }\n'
            'void b() { String q = "SELECT 1"; stmt.executeQuery(q); }\n')
    assert [f.line for f in scan_java(java, "X.java") if f.rule_id == "JAVA-SQLI"] == [1]
    assert rules(scan_java, 'String q = "SELECT * FROM t WHERE a=" + x;\nq = "SELECT 1";\nstmt.executeQuery(q);') == []
    cs = ('void A(string id) { var q = "SELECT * FROM T WHERE a=" + id; var c = new SqlCommand(q, conn); }\n'
          'void B() { var q = "SELECT 1"; var c = new SqlCommand(q, conn); }\n')
    assert [f.line for f in scan_csharp(cs, "X.cs") if f.rule_id == "CS-SQLI"] == [1]
    php = ('function a() { $q = "SELECT * FROM t WHERE a=\'" . $_GET["a"] . "\'"; mysqli_query($c, $q); }\n'
           'function b() { $q = "SELECT 1"; mysqli_query($c, $q); }\n')
    assert [f.line for f in scan_php(php, "x.php") if f.rule_id == "PHP-SQLI"] == [1]


def test_kotlin_scoping_matches_java():
    kt = 'fun a(id: String) { val q = "SELECT * FROM t WHERE a=$id"\n stmt.executeQuery(q) }\nfun b() { val q = "SELECT 1"\n stmt.executeQuery(q) }\n'
    assert [f.line for f in scan_kotlin(kt, "a.kt") if f.rule_id == "JAVA-SQLI"] == [2]


# ------------------------------------------------------------------ PHP include
def test_php_include_of_a_variable_chosen_from_fixed_names_is_not_flagged():
    chosen = ('switch ($level) { case "low": $file = "low.php"; break; default: $file = "high.php"; }\n'
              'require_once ROOT . "pages/source/{$file}";\n')
    assert rules(scan_php, chosen) == []
    assert "PHP-INCLUDE" in rules(scan_php, '$p = $_GET["page"];\ninclude "pages/" . $p . ".php";')
    assert "PHP-INCLUDE" in rules(scan_php, 'include $_GET["page"];')


# ------------------------------------------------------------------ JavaScript
def test_eval_of_a_constant_string_is_not_injection_but_eval_of_data_is():
    assert rules(scan_js, 'var c = eval("require(\'crypto\')");') == []
    assert rules(scan_js, "var v = eval(text);") == ["JS-EVAL"]
    assert rules(scan_js, 'var v = eval("(" + text + ")");') == ["JS-EVAL"]


def test_minified_vendor_bundles_are_not_scanned(tmp_path):
    (tmp_path / "jquery.min.js").write_text("e.innerHTML=a;eval(x);" * 50)
    bundle = tmp_path / "vendor.js"
    bundle.write_text(("var a=b;el.innerHTML=x;" * 400 + "\n") * 2)  # two enormous lines: a bundler's output
    own = tmp_path / "own.js"
    own.write_text("el.innerHTML = userInput;\n")
    found = {f.path for f in detect_patterns(tmp_path, [tmp_path / "jquery.min.js", bundle, own])}
    assert found == {"own.js"}


def test_placeholder_secret_wording():
    assert is_placeholder("session_cookie_secret_key_here") and is_placeholder("your-secret-key-here")
    assert not is_placeholder("a8f3k29dj2lq9z81xk")
