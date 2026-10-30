import pytest

from avishkar.domain.redaction import redact_text

SECRETS = [
    "AKIAQ3EXZ4HT7WN2K5ML",
    "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
    "xoxb-123456789012-abcdefABCDEF",
    "sk-ant-api03-abcdefghijklmnopqrstuv",
    "sk_live_51Habcdef0123456789xyz",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fw",
    "hunter2hunter2",
    "Sup3rS3cretPass",
]


@pytest.mark.parametrize("text", [
    "key AKIAQ3EXZ4HT7WN2K5ML used",
    "token = ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "GITHUB_PAT github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
    "slack xoxb-123456789012-abcdefABCDEF",
    "use sk-ant-api03-abcdefghijklmnopqrstuv here",
    "stripe sk_live_51Habcdef0123456789xyz",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fw",
    "password=hunter2hunter2 and more",
    "password: hunter2hunter2",
    'DB_PASSWORD="hunter2hunter2"',
    "api_key = 'hunter2hunter2'",
    "postgres://app:Sup3rS3cretPass@db.internal:5432/shop",
    "curl -H 'X-Auth-Token: hunter2hunter2' https://x",
    "SECRET_KEY = hunter2hunter2;",
])
def test_known_secret_shapes_are_removed(text):
    out = redact_text(text)
    assert not any(s in out for s in SECRETS), out
    assert "[REDACTED]" in out


@pytest.mark.parametrize("text", [
    "def hash_password(password):", "password = input('Password: ')", "token = get_token()", "api_key = os.environ['API_KEY']",
    "res.send(`<h1>${q}</h1>`)", "subprocess.run(['ping', host])", "see https://example.com/docs and user@example.com",
    "line 42 of utils.py", "x = {'a': 1}", "token: str", "password:",
])
def test_ordinary_code_is_left_alone(text):
    assert redact_text(text) == text or "[REDACTED]" not in redact_text(text)


def test_labels_survive_so_redacted_text_stays_readable():
    assert redact_text("password=hunter2hunter2") == "password=[REDACTED]"
    assert redact_text("postgres://app:Sup3rS3cretPass@db/x") == "postgres://app:[REDACTED]@db/x"
    assert redact_text("Bearer abcdefghijklmnop12345") == "Bearer [REDACTED]"


def test_redaction_is_idempotent_and_total_on_empty():
    once = redact_text("password=hunter2hunter2 AKIAQ3EXZ4HT7WN2K5ML")
    assert redact_text(once) == once and redact_text("") == ""
