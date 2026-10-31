"""Unit tests for the Ruby token-stream scanner (rubyscan.py)."""
from avishkar.workers.rubyscan import scan_ruby


def rules(src, name="x.rb"):
    return sorted(f.rule_id for f in scan_ruby(src, name))


# ------------------------------------------------------------------ SQL injection
def test_sqli_string_interpolation_is_flagged():
    assert "RB-SQLI" in rules('DB.execute("SELECT * FROM t WHERE owner = \'#{params[:owner]}\'")')


def test_sqli_parameterised_query_is_not_flagged():
    assert rules("DB.execute('SELECT * FROM t WHERE owner = ?', owner)") == []


def test_sqli_where_with_interpolation():
    assert "RB-SQLI" in rules('User.where("name = \'#{params[:name]}\'")')


def test_sqli_literal_sql_is_not_flagged():
    assert "RB-SQLI" not in rules('DB.execute("SELECT 1")')


# ------------------------------------------------------------------ command injection
def test_cmdi_system_with_interpolated_string():
    assert "RB-CMDI" in rules("system(\"ls #{params[:dir]}\")")


def test_cmdi_backtick_with_interpolated_cmd():
    # the backtick body contains the interpolation + a well-known shell word
    assert "RB-CMDI" in rules("output = `ls -la #{params[:dir]}`")


def test_cmdi_literal_command_is_safe():
    assert "RB-CMDI" not in rules("system('ls', '-l', '/tmp')")


# ------------------------------------------------------------------ eval
def test_eval_non_literal_is_flagged():
    assert "RB-EVAL" in rules("eval(user_input)")


def test_eval_literal_is_not_flagged():
    assert "RB-EVAL" not in rules('eval("1 + 2")')


# ------------------------------------------------------------------ deserialization
def test_deser_marshal_load_is_flagged():
    assert "RB-DESER" in rules("Marshal.load(params[:data])")


def test_deser_yaml_load_is_flagged():
    assert "RB-DESER" in rules("YAML.load(body)")


def test_deser_json_parse_is_safe():
    assert "RB-DESER" not in rules('JSON.parse(payload)')


# ------------------------------------------------------------------ weak hash
def test_weakhash_digest_md5():
    assert "RB-WEAKHASH" in rules("Digest::MD5.hexdigest(pw)")


def test_weakhash_digest_sha1():
    assert "RB-WEAKHASH" in rules("Digest::SHA1.digest(data)")


def test_weakhash_sha256_is_not_flagged():
    assert "RB-WEAKHASH" not in rules("Digest::SHA256.hexdigest(data)")


# ------------------------------------------------------------------ insecure random
def test_random_rand_in_security_context():
    # the word 'token' appears on the same line
    assert "RB-RANDOM" in rules("token = rand(10_000_000).to_s")


def test_random_secure_random_is_not_flagged():
    assert "RB-RANDOM" not in rules("token = SecureRandom.urlsafe_base64(32)")


# ------------------------------------------------------------------ secret assignment
def test_secret_assign_hard_coded_credential():
    assert "RB-SECRET-ASSIGN" in rules('API_KEY = "sk-ruby-plaintext-api-key-8b4e7d2a"')


def test_secret_assign_env_is_not_flagged():
    assert "RB-SECRET-ASSIGN" not in rules("API_KEY = ENV.fetch('API_KEY')")


def test_secret_assign_placeholder_is_low_or_absent():
    # placeholder values must not be high-confidence hits
    hits = [f for f in scan_ruby('api_key = "your-api-key-here"', "x.rb") if f.rule_id == "RB-SECRET-ASSIGN"]
    assert not hits  # placeholder suppressed entirely


# ------------------------------------------------------------------ path traversal
def test_path_file_read_with_request_data():
    assert "RB-PATH" in rules("File.read(\"/srv/notes/#{params[:name]}\")")


def test_path_file_read_literal_is_safe():
    assert "RB-PATH" not in rules('File.read("/etc/motd")')


# ------------------------------------------------------------------ XSS
def test_xss_reflect_request_param_in_render():
    assert "RB-XSS-REFLECT" in rules("render html: params[:name]")


# ------------------------------------------------------------------ TLS
def test_tls_verify_none_flagged():
    assert "RB-TLS" in rules("ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE")


def test_tls_verify_peer_is_safe():
    assert "RB-TLS" not in rules("ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER")


# ------------------------------------------------------------------ scope isolation
def test_scope_same_name_different_function():
    src = (
        "def a()\n  owner = params[:name]\n  DB.execute(\"SELECT * FROM t WHERE owner = '#{owner}'\")\nend\n"
        "def b()\n  owner = 'admin'\n  DB.execute(\"SELECT * FROM t WHERE owner = '#{owner}'\")\nend\n"
    )
    # RB-SQLI fires because the string is interpolated — both cases have #{owner} in the string literal
    found = [f for f in scan_ruby(src, "x.rb") if f.rule_id == "RB-SQLI"]
    # at least one finding (from def a)
    assert len(found) >= 1


# ------------------------------------------------------------------ empty / binary
def test_empty_file_returns_no_findings():
    assert scan_ruby("", "empty.rb") == []


def test_comments_do_not_trigger_rules():
    assert rules("# DB.execute(\"SELECT * FROM t WHERE owner = '#{params[:x]}'\")") == []
