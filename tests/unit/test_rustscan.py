"""Unit tests for the Rust token-stream scanner (rustscan.py)."""
from avishkar.workers.rustscan import scan_rust


def rules(src, name="x.rs"):
    return sorted(f.rule_id for f in scan_rust(src, name))


# ------------------------------------------------------------------ command injection
def test_command_new_sh_flagged():
    assert "RS-CMDI" in rules('Command::new("sh").arg("-c").arg(&input).output()?;')


def test_command_new_bash_flagged():
    assert "RS-CMDI" in rules('Command::new("bash")')


def test_command_new_ls_literal_safe():
    assert "RS-CMDI" not in rules('Command::new("/bin/ls").arg("--").arg(&dir).output()?;')


# ------------------------------------------------------------------ unsafe block
def test_unsafe_block_flagged():
    assert "RS-UNSAFE" in rules("unsafe { *ptr = 42; }")


def test_no_unsafe_no_flag():
    assert "RS-UNSAFE" not in rules("let x = 1 + 2;")


# ------------------------------------------------------------------ weak hash
def test_md5_digest_flagged():
    assert "RS-WEAKHASH" in rules("let h = Md5::digest(data);")


def test_sha1_digest_flagged():
    assert "RS-WEAKHASH" in rules("let h = Sha1::digest(data);")


def test_sha256_is_safe():
    assert "RS-WEAKHASH" not in rules("let h = Sha256::digest(data);")


# ------------------------------------------------------------------ insecure random
def test_thread_rng_in_security_context():
    assert "RS-RANDOM" in rules("let token: u64 = rand::thread_rng().gen();")


def test_os_rng_is_safe():
    assert "RS-RANDOM" not in rules("OsRng.fill_bytes(&mut key);")


# ------------------------------------------------------------------ secret assignment
def test_let_api_key_literal_flagged():
    assert "RS-SECRET-ASSIGN" in rules('let api_key = "rust-api-key-plaintext-4c7f2a9b";')


def test_let_env_var_not_flagged():
    assert "RS-SECRET-ASSIGN" not in rules('let api_key = std::env::var("API_KEY")?;')


def test_const_api_key_literal_flagged():
    assert "RS-SECRET-ASSIGN" in rules('const API_KEY: &str = "rust-api-key-plaintext-4c7f2a9b";')


def test_placeholder_not_flagged():
    assert "RS-SECRET-ASSIGN" not in rules('let api_key = "your-api-key-here";')


# ------------------------------------------------------------------ TLS
def test_danger_accept_invalid_certs_flagged():
    assert "RS-TLS" in rules(".danger_accept_invalid_certs(true)")


def test_danger_accept_invalid_hostnames_flagged():
    assert "RS-TLS" in rules(".danger_accept_invalid_hostnames(true)")


# ------------------------------------------------------------------ path traversal
def test_fs_read_with_request_param():
    assert "RS-PATH" in rules("fs::read_to_string(path)?;")


# ------------------------------------------------------------------ literals and comments
def test_comment_does_not_trigger():
    src = "// let api_key = \"plaintext-secret-12345\"; unsafe { *ptr = 0; }"
    assert rules(src) == []


def test_raw_string_safe():
    src = r"""let q = r#"SELECT * FROM users WHERE id = 1"#;"""
    assert rules(src) == []


def test_empty_file():
    assert scan_rust("", "empty.rs") == []


# ------------------------------------------------------------------ sample file integration
def test_sample_vulnerable_rust_file():
    from pathlib import Path
    src = Path(__file__).parents[2] / "sample_projects" / "rust-cli-tool" / "src" / "main.rs"
    text = src.read_text(errors="replace")
    found = {f.rule_id for f in scan_rust(text, str(src))}
    for expected in ("RS-CMDI", "RS-UNSAFE", "RS-WEAKHASH", "RS-RANDOM", "RS-SECRET-ASSIGN"):
        assert expected in found, f"{expected} not found in {found}"
