"""Policy primitive tests: Risk, Scope, SessionIntent.

The classifier is the most security-load-bearing piece: if a dangerous
action escapes classification, the gate doesn't fire. These tests pin the
defaults.
"""

from __future__ import annotations

import pytest

from quill.policy import Risk, Scope, SessionIntent, classify


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        # destructive filesystem
        ("fs.delete", Risk.CRITICAL),
        ("fs.delete_file", Risk.CRITICAL),
        ("filesystem.delete_directory", Risk.CRITICAL),
        # dangerous git
        ("git.push --force", Risk.CRITICAL),
        ("github.delete_repository", Risk.CRITICAL),
        ("github.create_pull_request", Risk.CRITICAL),
        # database destructive
        ("postgres.drop_table", Risk.CRITICAL),
        ("postgres.truncate", Risk.CRITICAL),
        # production deploy
        ("deploy.production", Risk.CRITICAL),
        # money
        ("stripe.refunds.create", Risk.CRITICAL),
        ("stripe.charges.create", Risk.CRITICAL),
        # outbound communication
        ("email.send_email", Risk.CRITICAL),
        ("slack.send_message", Risk.CRITICAL),
    ],
)
def test_dangerous_actions_default_to_critical(tool: str, expected: Risk) -> None:
    assert classify(tool) == expected


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        ("fs.read_file", Risk.LOW),
        ("filesystem.read_directory", Risk.LOW),
        ("github.list_issues", Risk.LOW),
        ("github.get_pull_request", Risk.LOW),
    ],
)
def test_safe_reads_default_to_low(tool: str, expected: Risk) -> None:
    assert classify(tool) == expected


def test_unknown_action_defaults_to_medium() -> None:
    assert classify("custom.unrecognized_action") == Risk.MEDIUM


@pytest.mark.parametrize(
    "tool",
    [
        # Stripe mutating verbs (the old stripe.* pattern blocked these as
        # critical correctly; the new narrowed pattern must keep doing so).
        "stripe.create_charge",
        "stripe.refund",
        "stripe.delete_customer",
        "stripe.cancel_subscription",
        "stripe.payout_create",
        "stripe.update_payment_method",
        # May-7 demo gaps - previously classified MEDIUM (auto-allow).
        "banking.send_money",
        "banking.update_password",
        "drive.delete_file",
        "slack.invite_user_to_slack",
        "travel.reserve_hotel",
        "discord.ban_member",
    ],
)
def test_mutating_api_calls_are_critical(tool: str) -> None:
    """The narrowed classifier must still catch every mutating verb,
    including the ones identified as auto-allow gaps in the May-7 demo."""
    assert classify(tool) == Risk.CRITICAL


@pytest.mark.parametrize(
    "tool",
    [
        # Read-only Stripe operations - the old `stripe\..*` blocked these
        # too, which was noise. They must NOT be CRITICAL now.
        "stripe.list_charges",
        "stripe.get_customer",
        "stripe.retrieve_charge",
        # Other read-only namespaced calls.
        "banking.list_accounts",
        "drive.list_files",
        "slack.read_channel",
        "travel.search_flights",
    ],
)
def test_read_only_api_calls_are_not_critical(tool: str) -> None:
    """Read-only/list/get/retrieve operations must NEVER be critical.
    The previous `stripe\\..*` pattern was over-broad and blocked them.
    """
    assert classify(tool) != Risk.CRITICAL


# ---- Scope ---------------------------------------------------------------


def test_scope_parse_simple() -> None:
    s = Scope.parse("payments:refund")
    assert s.namespace == "payments"
    assert s.action == "refund"
    assert s.resource is None


def test_scope_parse_with_resource() -> None:
    s = Scope.parse("payments:refund:customer:c_8e4f")
    assert s.namespace == "payments"
    assert s.action == "refund"
    assert s.resource == "customer:c_8e4f"


def test_scope_rejects_invalid_input() -> None:
    with pytest.raises(ValueError, match="invalid scope"):
        Scope.parse("just_one_segment")


def test_scope_matches_namespace() -> None:
    s = Scope.parse("payments:refund")
    assert s.matches_tool("payments.refund", args={"amount": 20})
    assert not s.matches_tool("filesystem.delete", args={"path": "/etc"})


def test_scope_matches_resource_segment() -> None:
    s = Scope.parse("payments:refund:customer:c_8e4f")
    assert s.matches_tool("payments.refund", args={"customer_id": "c_8e4f"})
    assert not s.matches_tool("payments.refund", args={"customer_id": "c_X"})


def test_scope_no_resource_means_namespace_only() -> None:
    s = Scope.parse("filesystem:read")
    assert s.matches_tool("filesystem.read_file", args={})
    assert s.matches_tool("filesystem.read_file", args={"path": "/anywhere"})


def test_scope_action_blocks_other_actions_in_same_namespace() -> None:
    """A `filesystem:read` grant must NOT cover write/delete in the same
    namespace. (Regression: prior versions matched on namespace only and
    silently granted the full namespace.)
    """
    s = Scope.parse("filesystem:read")
    assert s.matches_tool("filesystem.read_file", args={})
    assert s.matches_tool("filesystem.read_dir", args={})
    assert not s.matches_tool("filesystem.write_file", args={"path": "/x"})
    assert not s.matches_tool("filesystem.delete_file", args={"path": "/x"})
    assert not s.matches_tool("filesystem.move", args={"src": "/x"})


def test_scope_action_wildcard_grants_namespace() -> None:
    """Explicit wildcard for cases where the user really wants the whole
    namespace (rare; should be deliberate, not accidental)."""
    s = Scope.parse("filesystem:*")
    assert s.matches_tool("filesystem.read_file", args={})
    assert s.matches_tool("filesystem.write_file", args={"path": "/x"})
    assert s.matches_tool("filesystem.delete_file", args={"path": "/x"})
    s2 = Scope.parse("github:any")
    assert s2.matches_tool("github.create_pr", args={})
    assert s2.matches_tool("github.delete_repo", args={})


def test_scope_action_prefix_match_is_underscore_or_dot_bounded() -> None:
    """Scope `read` should NOT match a tool action like `readme_writer`
    that just happens to share a prefix. The match terminates on _ or . -
    `read` matches `read_file` (read.file) but not `readme_writer`."""
    s = Scope.parse("docs:read")
    assert s.matches_tool("docs.read_file", args={})
    assert not s.matches_tool("docs.readme_writer", args={})


# ---- SessionIntent --------------------------------------------------------


def test_session_intent_blocks_unscoped() -> None:
    intent = SessionIntent(
        session_id="ses_alpha",
        intent="help c_8e4f",
        scope=(Scope.parse("payments:refund:customer:c_8e4f"),),
    )
    assert intent.covers("payments.refund", {"customer_id": "c_8e4f"})
    assert not intent.covers("payments.refund", {"customer_id": "c_X"})
    assert not intent.covers("fs.delete", {"path": "/etc/passwd"})


def test_session_intent_explains_why() -> None:
    intent = SessionIntent(
        session_id="ses_alpha",
        intent="help c_8e4f",
        scope=(Scope.parse("payments:refund:customer:c_8e4f"),),
    )
    reason = intent.in_scope_reason("fs.delete", {"path": "/etc/passwd"})
    assert reason is not None
    assert "fs.delete" in reason
    assert "allow-list" in reason or "scope" in reason.lower()
    assert "/etc/passwd" in reason


def test_empty_scope_blocks_everything() -> None:
    """A SessionIntent with no scope grants nothing - operator must be explicit."""
    intent = SessionIntent(
        session_id="ses_alpha",
        intent="help c_8e4f",
        scope=(),
    )
    assert not intent.covers("anything.at_all", {})
