"""Unit tests for the C/C++ token-stream scanner (cscan.py)."""
from avishkar.workers.cscan import scan_c


def rules(src, name="x.c"):
    return sorted(f.rule_id for f in scan_c(src, name))


# ------------------------------------------------------------------ buffer overflow
def test_strcpy_is_flagged():
    assert "C-BUFOV" in rules("strcpy(dst, src);")


def test_gets_is_always_flagged():
    assert "C-BUFOV" in rules("gets(buf);")


def test_scanf_string_is_flagged():
    assert "C-BUFOV" in rules('scanf("%s", buf);')


def test_snprintf_is_not_flagged():
    assert "C-BUFOV" not in rules('snprintf(buf, sizeof(buf), "%s", input);')


def test_fgets_is_not_flagged():
    assert "C-BUFOV" not in rules("fgets(buf, sizeof(buf), stdin);")


# ------------------------------------------------------------------ format string
def test_printf_variable_format_flagged():
    assert "C-FMTSTR" in rules("printf(user_input);")


def test_printf_literal_format_not_flagged():
    assert "C-FMTSTR" not in rules('printf("%s", msg);')


def test_syslog_variable_format_flagged():
    assert "C-FMTSTR" in rules("syslog(LOG_ERR, fmt);")


# ------------------------------------------------------------------ command injection
def test_system_non_literal_flagged():
    assert "C-CMDI" in rules("system(cmd);")


def test_popen_non_literal_flagged():
    assert "C-CMDI" in rules("popen(command, \"r\");")


# ------------------------------------------------------------------ weak hash
def test_md5_init_flagged():
    assert "C-WEAKHASH" in rules("MD5_Init(&ctx);")


def test_evp_md5_flagged():
    assert "C-WEAKHASH" in rules("EVP_DigestInit_ex(ctx, EVP_md5(), NULL);")


def test_sha256_is_safe():
    assert "C-WEAKHASH" not in rules("SHA256_Init(&ctx);")


def test_evp_sha256_is_safe():
    assert "C-WEAKHASH" not in rules("EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);")


# ------------------------------------------------------------------ secret assignment
def test_char_api_key_literal_is_flagged():
    assert "C-SECRET-ASSIGN" in rules('const char *api_key = "abc-plaintext-8b4e7d2a1f3c";')


def test_char_getenv_is_not_flagged():
    assert "C-SECRET-ASSIGN" not in rules('const char *api_key = getenv("API_KEY");')


def test_placeholder_not_flagged():
    assert "C-SECRET-ASSIGN" not in rules('const char *api_key = "your-api-key-here";')


# ------------------------------------------------------------------ integer overflow
def test_malloc_with_expression_flagged():
    assert "C-INTOV" in rules("char *buf = malloc(n * sizeof(char));")


# ------------------------------------------------------------------ comments do not trigger
def test_comment_does_not_trigger():
    src = "// const char *db_password = \"plaintext-9f2c3d1a\";\nint x = 1;"
    assert rules(src) == []


def test_empty_file():
    assert scan_c("", "empty.c") == []


# ------------------------------------------------------------------ both C and C++ extensions
def test_cpp_extension_is_scanned():
    assert "C-BUFOV" in rules("strcpy(dst, src);", "utils.cpp")


def test_header_extension_is_scanned():
    assert "C-BUFOV" in rules("strcpy(dst, src);", "utils.h")


# ------------------------------------------------------------------ sample file integration
def test_sample_vulnerable_c_file(tmp_path):
    from pathlib import Path
    src = Path(__file__).parents[2] / "sample_projects" / "c-string-utils" / "utils.c"
    text = src.read_text(errors="replace")
    found = {f.rule_id for f in scan_c(text, str(src))}
    for expected in ("C-BUFOV", "C-FMTSTR", "C-CMDI", "C-WEAKHASH", "C-SECRET-ASSIGN"):
        assert expected in found, f"{expected} not found in {found}"
