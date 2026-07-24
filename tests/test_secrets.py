"""Tests for the credential-scanner module.

Patterns are tested against vendor-shape sample values that are NOT
real credentials. The strings here look like keys but they're random
or revoked; they exist to exercise the regex set, not to leak anything.
"""

from __future__ import annotations

from notari.secrets import (
    hit_summary,
    patterns,
    scan,
    scan_args,
)

# ---------------------------------------------------------------------------
# detection: each pattern matches its vendor-shape sample
# ---------------------------------------------------------------------------


def test_aws_access_key_detected():
    s = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'  # AWS published example value
    hits = scan(s)
    assert any(h.pattern_name == "AWS Access Key ID" for h in hits)


def test_openai_legacy_key_detected():
    s = 'OPENAI_KEY = "sk-' + "A" * 48 + '"'
    hits = scan(s)
    assert any("OpenAI" in h.pattern_name for h in hits)


def test_openai_project_key_detected():
    s = "sk-proj-" + "x" * 80
    hits = scan(s)
    assert any(h.pattern_name == "OpenAI Project API Key" for h in hits)


def test_anthropic_key_detected():
    s = "sk-ant-api03-" + "x" * 90
    hits = scan(s)
    assert any(h.pattern_name == "Anthropic API Key" for h in hits)


def test_github_classic_pat_detected():
    s = "GITHUB_TOKEN=ghp_" + "A" * 36
    hits = scan(s)
    assert any("classic" in h.pattern_name for h in hits)


def test_github_fine_grained_pat_detected():
    s = "github_pat_" + "A" * 82
    hits = scan(s)
    assert any("fine-grained" in h.pattern_name for h in hits)


def test_stripe_live_key_detected():
    s = "STRIPE = sk_live_" + "x" * 30
    hits = scan(s)
    assert any(h.pattern_name == "Stripe Live Secret Key" for h in hits)


def test_slack_bot_token_detected():
    s = "SLACK = xoxb-" + "1" * 60
    hits = scan(s)
    assert any("Slack Bot" in h.pattern_name for h in hits)


def test_slack_webhook_detected():
    # Assembled at runtime so the literal never appears in the source: GitHub
    # push protection pattern-matches Slack webhook URLs even in test fixtures.
    s = (
        "hook = https://"
        + "hooks.slack.com/services"
        + "/T00000000/B11111111/"
        + "abcdefghijklmnopqrstuvwx"
    )
    hits = scan(s)
    assert any(h.pattern_name == "Slack Webhook URL" for h in hits)


def test_google_api_key_detected():
    s = "GOOGLE_KEY = AIza" + "x" * 35
    hits = scan(s)
    assert any(h.pattern_name == "Google API Key" for h in hits)


def test_jwt_detected():
    s = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepartABCDEF"
    hits = scan(s)
    assert any(h.pattern_name == "JWT" for h in hits)


def test_pem_private_key_detected():
    s = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    hits = scan(s)
    assert any("Private Key" in h.pattern_name for h in hits)


def test_huggingface_token_detected():
    s = "HF = hf_" + "A" * 30
    hits = scan(s)
    assert any(h.pattern_name == "HuggingFace Token" for h in hits)


# ---------------------------------------------------------------------------
# negative cases: clean code should produce no hits
# ---------------------------------------------------------------------------


def test_clean_python_file_produces_no_hits():
    s = """
def add(a, b):
    return a + b

print(add(2, 3))
"""
    assert scan(s) == []


def test_short_random_strings_dont_match():
    # Below vendor-published lengths -> no match
    assert scan("sk-short") == []
    assert scan("ghp_short") == []
    assert scan("AKIA_too_short") == []


def test_empty_input_returns_empty_list():
    assert scan("") == []


# ---------------------------------------------------------------------------
# scan_args integration: Edit/Write/MultiEdit/NotebookEdit
# ---------------------------------------------------------------------------


def test_scan_args_edit_new_string_with_secret():
    args = {
        "file_path": "/x/config.py",
        "old_string": "API_KEY = ''",
        "new_string": "API_KEY = 'ghp_" + "A" * 36 + "'",
    }
    hits = scan_args("Edit", args)
    assert len(hits) >= 1
    assert "GitHub" in hits[0].pattern_name


def test_scan_args_write_content():
    args = {
        "file_path": "/x/.env",
        "content": "STRIPE_SECRET=sk_live_" + "x" * 30,
    }
    hits = scan_args("Write", args)
    assert len(hits) >= 1


def test_scan_args_notebook_edit():
    args = {
        "notebook_path": "/x/nb.ipynb",
        "new_source": "ANTHROPIC = 'sk-ant-api03-" + "x" * 90 + "'",
    }
    hits = scan_args("NotebookEdit", args)
    assert len(hits) >= 1
    assert "Anthropic" in hits[0].pattern_name


def test_scan_args_multi_edit_walks_edits_list():
    args = {
        "file_path": "/x/f.py",
        "edits": [
            {"old_string": "a", "new_string": "b"},  # clean
            {"old_string": "c", "new_string": "OAI = 'sk-proj-" + "x" * 80 + "'"},
        ],
    }
    hits = scan_args("MultiEdit", args)
    assert len(hits) >= 1


def test_scan_args_unknown_tool_returns_empty():
    """Tools that don't write files (Bash, Read, etc.) aren't scanned by scan_args."""
    args = {"command": "echo 'AKIAIOSFODNN7EXAMPLE'"}
    assert scan_args("Bash", args) == []
    assert scan_args("Read", {"file_path": "/x.py"}) == []


def test_scan_args_clean_write_returns_empty():
    args = {
        "file_path": "/x/clean.py",
        "content": "def add(a, b): return a + b\n",
    }
    assert scan_args("Write", args) == []


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def test_hit_summary_handles_multiple_pattern_types():
    args = {
        "content": ("ghp_" + "A" * 36 + "\nsk_live_" + "x" * 30 + "\nsk_live_" + "y" * 30),
    }
    hits = scan_args("Write", args)
    summary = hit_summary(hits)
    # 1× GitHub PAT, 2× Stripe Live, all with line numbers
    assert "GitHub Personal Access Token (classic)" in summary
    assert "2× Stripe Live Secret Key" in summary
    # Line numbers should appear
    assert "line 1" in summary  # the GitHub PAT is on line 1


def test_hit_carries_line_number():
    from notari.secrets import scan

    text = "first line, clean\nsecond line: ghp_" + "A" * 36 + "\nthird line\n"
    hits = scan(text)
    assert len(hits) == 1
    assert hits[0].line == 2


def test_hit_line_one_when_no_newline():
    from notari.secrets import scan

    hits = scan("ghp_" + "A" * 36)
    assert hits[0].line == 1


def test_hit_summary_groups_lines_when_same_pattern_fires_multiple():
    from notari.secrets import scan

    text = "ghp_" + "A" * 36 + "\nghp_" + "B" * 36 + "\nghp_" + "C" * 36 + "\n"
    hits = scan(text)
    summary = hit_summary(hits)
    # Three GitHub PATs at lines 1, 2, 3
    assert "3× GitHub Personal Access Token (classic)" in summary
    assert "1" in summary and "2" in summary and "3" in summary


def test_hit_summary_empty():
    assert hit_summary([]) == ""


def test_patterns_returns_immutable_view():
    p = patterns()
    assert isinstance(p, tuple)
    assert len(p) >= 25


def test_twilio_account_sid_detected():
    s = "TWILIO_ACCOUNT_SID = 'AC" + "a" * 32 + "'"
    hits = scan(s)
    assert any(h.pattern_name == "Twilio Account SID" for h in hits)


def test_sendgrid_api_key_detected():
    s = "SG." + "a" * 22 + "." + "b" * 43
    hits = scan(s)
    assert any(h.pattern_name == "SendGrid API Key" for h in hits)


def test_stripe_webhook_secret_detected():
    s = "STRIPE_WEBHOOK_SECRET = 'whsec_" + "a" * 50 + "'"
    hits = scan(s)
    assert any(h.pattern_name == "Stripe Webhook Secret" for h in hits)


def test_notion_integration_secret_detected():
    s = "NOTION = 'secret_" + "x" * 43 + "'"
    hits = scan(s)
    assert any(h.pattern_name == "Notion Integration Secret" for h in hits)


# ---------------------------------------------------------------------------
# claude_code adapter integration
# ---------------------------------------------------------------------------


def test_classify_event_escalates_to_critical_on_secret_write():
    from notari.adapters.claude_code import classify_event
    from notari.policy import Risk

    args = {
        "file_path": "/x/config.py",
        "content": "TOKEN = 'ghp_" + "A" * 36 + "'",
    }
    risk, reason, suggestion = classify_event("Write", args)
    assert risk is Risk.CRITICAL
    assert "secret detected" in reason
    assert "GitHub" in reason


def test_classify_event_normal_write_unaffected():
    from notari.adapters.claude_code import classify_event

    args = {"file_path": "/x/f.py", "content": "def add(a,b): return a+b"}
    risk, reason, suggestion = classify_event("Write", args)
    # Without secrets, Write keeps its default classification
    assert "secret" not in reason.lower()


# ---------------------------------------------------------------------------
# redact(): strip secrets from audit-logged / exported text (audit #17, #18)
# ---------------------------------------------------------------------------


def test_redact_vendor_token_value_gone():
    from notari.secrets import redact

    tok = "ghp_" + "A" * 36
    out = redact(f"echo {tok} >> ~/.netrc")
    assert tok not in out
    assert "[REDACTED:GitHub Personal Access Token (classic)]" in out


def test_redact_inline_credential_shapes():
    from notari.secrets import redact

    assert "hunter2x" not in redact("mysql -u root -phunter2x")
    assert "Bearer sk-live-abc123" not in redact("curl -H 'Authorization: Bearer sk-live-abc123'")
    assert "wJalrXUt" not in redact("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI7MDENGbAB")
    assert "p4ssw0rd" not in redact("psql postgres://u:p4ssw0rd@db:5432/app")


def test_redact_keeps_command_shape_legible():
    from notari.secrets import redact

    out = redact("mysql -u root -phunter2x")
    # Command stays readable: only the password value is removed.
    assert out.startswith("mysql -u root -p[REDACTED:")


def test_redact_idempotent_and_noop_on_clean_text():
    from notari.secrets import redact

    clean = "rm -rf node_modules && git status"
    assert redact(clean) == clean
    once = redact("token=ghp_" + "B" * 36)
    assert redact(once) == once  # re-redacting changes nothing


def test_redact_does_not_corrupt_plain_short_flags():
    from notari.secrets import redact

    # `-print` / `-parse` look like the mysql `-p<pw>` shape but are plain
    # lowercase flags; they must survive untouched.
    assert redact("find . -print") == "find . -print"


def test_audit_what_field_is_redacted_end_to_end():
    """The `what` summary that lands in the audit log must carry no secret."""
    from notari.adapters.claude_code import _summarize_call

    what = _summarize_call("Bash", {"command": "deploy --token=ghp_" + "C" * 36})
    assert "ghp_" not in what
    assert "REDACTED" in what


def test_redact_userless_dsn_password() -> None:
    # 2nd-review gap #4: the userless connection-string form (no user before the
    # colon) was passing through un-redacted.
    from notari.secrets import redact

    out = redact("redis://:authpass123@cache:6379/0")
    assert "authpass123" not in out
    assert "[REDACTED:dsn-password]" in out


# ---------------------------------------------------------------------------
# scan() must catch the inline-credential shapes, not only redact() them.
# Before the 2026-07-22 red-team fix these lived only in redact(), so the CI
# verdict scanner (which calls scan()) reported PASS on a working credential in
# any of these forms.
# ---------------------------------------------------------------------------


def test_scan_catches_aws_secret_access_key():
    s = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    assert any(h.pattern_name == "aws-secret-key" for h in scan(s))


def test_scan_catches_bearer_header():
    s = "Authorization: Bearer abc123DEF456ghi789JKL012mno345"
    assert any(h.pattern_name == "bearer-token" for h in scan(s))


def test_scan_catches_dsn_password():
    s = "DATABASE_URL=postgres://admin:s3cr3tPassw0rd@db.internal:5432/app"
    assert any(h.pattern_name == "dsn-password" for h in scan(s))


def test_scan_catches_password_flag():
    s = "mysql --user root --password hunter2secret --host db"
    assert any(h.pattern_name == "password-flag" for h in scan(s))


def test_scan_catches_env_secret_assignment():
    s = "DJANGO_SECRET_KEY=x9f2k3j4l5m6n7o8p9q0r1s2t3u4v5w6"
    assert any(h.pattern_name == "env-secret" for h in scan(s))


def test_scan_does_not_flag_ordinary_prose():
    # The env-secret / password-flag patterns must not fire on plain sentences
    # that merely mention the words, or the CI gate would false-BLOCK routine
    # docs and commit messages.
    s = "Update the password reset flow and document the secret rotation policy."
    hits = [h.pattern_name for h in scan(s)]
    assert "env-secret" not in hits
    assert "password-flag" not in hits


# ---------------------------------------------------------------------------
# F5 re-review (2026-07-23): the low-confidence inline shapes REGRESSED
# usability by BLOCKing ordinary code. scan() must not fire on env/command
# references, filesystem paths, placeholders, or doc-flag stand-ins, while a
# genuine hardcoded opaque credential is still caught.
# ---------------------------------------------------------------------------


def test_scan_ignores_env_lookup_not_a_literal():
    for s in (
        'API_KEY = os.environ["API_KEY"]',
        "DB_PASSWORD = os.getenv('DB_PASSWORD')",
        "token = process.env.TOKEN",
        'SECRET = config.get("secret")',
    ):
        hits = [h.pattern_name for h in scan(s)]
        assert "env-secret" not in hits, s


def test_scan_ignores_working_dir_and_path_values():
    for s in ("PWD=$(pwd)", "export OLDPWD=$PWD", "SECRET_DIR=/etc/app/secrets"):
        hits = [h.pattern_name for h in scan(s)]
        assert "env-secret" not in hits, s


def test_scan_ignores_placeholders_and_doc_flags():
    for s in (
        "PASSWORD=changeme",
        "API_KEY=your-api-key-here",
        "SECRET=xxxxxxxx",
        "app --password <your-password>",
        "connect --token TOKEN --host db",
        "DB_SECRET=${DB_SECRET}",
    ):
        hits = [h.pattern_name for h in scan(s)]
        assert "env-secret" not in hits, s
        assert "password-flag" not in hits, s


def test_scan_still_catches_opaque_hardcoded_password():
    # A real embedded credential (no reference, no placeholder) must survive the
    # value filter so the fix narrows false positives without going blind.
    assert any(h.pattern_name == "env-secret" for h in scan("DB_PASSWORD=hunter2secret"))
    assert any(h.pattern_name == "password-flag" for h in scan("mysql --password hunter2secret"))


def test_scan_env_secret_regex_is_not_redos():
    # Two unbounded [A-Z_]* around the keyword made this polynomial-backtracking
    # on a long keyword-free run with no trailing assignment. Bounded quantifiers
    # keep it linear: a pathological input must return promptly and match nothing.
    import time

    pathological = ("PASSWORD" * 5000) + "!"  # long, keyword-dense, no '=' value
    start = time.perf_counter()
    hits = [h.pattern_name for h in scan(pathological)]
    elapsed = time.perf_counter() - start
    assert "env-secret" not in hits
    assert elapsed < 1.0, f"scan took {elapsed:.2f}s, possible ReDoS"
