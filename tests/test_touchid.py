"""Touch ID gating tests.

We can't fire a real Touch ID prompt from automated tests (the OS dialog
needs a human finger). What we CAN unit-test:

  - is_available() returns False when LocalAuthentication is missing
    (Linux, Windows, or macOS without the optional dep installed).
  - authenticate() returns TouchIDResult(False, "not_available") on the
    same conditions, never raises.
  - The TouchIDResult dataclass shape is stable.
  - The policy constant we pass to canEvaluatePolicy is the
    biometrics-only one - never the password-fallback variant.
    This is a SECURITY invariant; if a future refactor swaps the constant
    silently, this test fails loudly.
  - Lockout / user-cancel reasons map to the right structured strings
    (mocked LAError objects).
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from quill.touchid import (
    DEFAULT_REASON,
    DEFAULT_TIMEOUT_S,
    TouchIDResult,
    authenticate,
    is_available,
)


def test_default_reason_is_concrete_one_sentence() -> None:
    """Apple HIG: reason should tell the user exactly what they're approving."""
    assert "tool call" in DEFAULT_REASON
    assert "quill" in DEFAULT_REASON.lower()
    assert "." not in DEFAULT_REASON or DEFAULT_REASON.count(".") <= 1


def test_default_timeout_matches_apple_dialog() -> None:
    assert DEFAULT_TIMEOUT_S >= 30.0  # Apple's own dialog auto-cancels ~30s
    assert DEFAULT_TIMEOUT_S <= 60.0  # any longer is bad UX


def test_is_available_false_when_localauthentication_missing() -> None:
    """On Linux/Windows or macOS without the touchid extra installed,
    `import LocalAuthentication` raises ImportError. is_available() must
    return False - never raise - so the caller falls through cleanly."""
    real_import = (
        __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__
    )

    def _no_la(name: str, *args: object, **kwargs: object) -> object:
        if name == "LocalAuthentication":
            raise ImportError("simulated: not installed")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_no_la):
        # Force a fresh import resolution inside the function under test.
        if "LocalAuthentication" in sys.modules:
            sys.modules.pop("LocalAuthentication")
        assert is_available() is False


def test_authenticate_returns_not_available_when_module_missing() -> None:
    real_import = (
        __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__
    )

    def _no_la(name: str, *args: object, **kwargs: object) -> object:
        if name == "LocalAuthentication":
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_no_la):
        if "LocalAuthentication" in sys.modules:
            sys.modules.pop("LocalAuthentication")
        result = authenticate("test")
        assert result.success is False
        assert result.reason == "not_available"


def test_touchid_result_is_immutable() -> None:
    """frozen=True so callers can't accidentally flip success after the fact."""
    r = TouchIDResult(True, "ok")
    try:
        r.success = False  # type: ignore[misc]
    except Exception:
        return  # frozen as expected
    raise AssertionError("TouchIDResult should be frozen")


def test_authenticate_uses_biometrics_only_policy_not_password_fallback() -> None:
    """SECURITY invariant: the policy constant passed to LAContext must be
    the biometrics-only one (LAPolicyDeviceOwnerAuthenticationWithBiometrics,
    value 1) - never the password-fallback variant (LAPolicyDeviceOwnerAuthentication,
    value 2). The latter falls back to a typeable password that a keylogger
    captures, which defeats the entire hardware-root.

    We mock LocalAuthentication and capture the policy constant.
    """
    fake_la = MagicMock()
    fake_la.LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1
    fake_la.LAPolicyDeviceOwnerAuthentication = 2
    fake_la.LAErrorUserCancel = -2
    fake_la.LAErrorBiometryLockout = -8
    fake_la.LAErrorAuthenticationFailed = -1
    fake_la.LAErrorNotInteractive = -1004

    fake_ctx = MagicMock()
    fake_ctx.canEvaluatePolicy_error_.return_value = (True, None)

    captured: dict[str, object] = {}

    def _evaluate(policy: int, reason: str, reply: object) -> None:
        captured["policy"] = policy
        captured["reason"] = reason
        # Simulate a successful auth so the function returns.
        reply(True, None)

    fake_ctx.evaluatePolicy_localizedReason_reply_.side_effect = _evaluate
    fake_la.LAContext.new.return_value = fake_ctx

    sys.modules["LocalAuthentication"] = fake_la
    try:
        res = authenticate("test reason")
    finally:
        sys.modules.pop("LocalAuthentication", None)

    assert res.success is True
    assert captured["policy"] == 1, (
        f"WRONG POLICY: got {captured['policy']}, expected 1 "
        "(LAPolicyDeviceOwnerAuthenticationWithBiometrics). The current "
        "code path may have silently fallen back to the password-fallback "
        "policy, which a keylogger defeats. SEE SECURITY.md."
    )
    assert captured["reason"] == "test reason"


def test_authenticate_maps_user_cancel_correctly() -> None:
    fake_la = MagicMock()
    fake_la.LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1
    fake_la.LAErrorUserCancel = -2
    fake_la.LAErrorBiometryLockout = -8
    fake_la.LAErrorAuthenticationFailed = -1
    fake_la.LAErrorNotInteractive = -1004

    fake_ctx = MagicMock()
    fake_ctx.canEvaluatePolicy_error_.return_value = (True, None)

    fake_err = MagicMock()
    fake_err.code.return_value = -2  # LAErrorUserCancel

    def _evaluate(policy: int, reason: str, reply: object) -> None:
        reply(False, fake_err)

    fake_ctx.evaluatePolicy_localizedReason_reply_.side_effect = _evaluate
    fake_la.LAContext.new.return_value = fake_ctx

    sys.modules["LocalAuthentication"] = fake_la
    try:
        res = authenticate("test")
    finally:
        sys.modules.pop("LocalAuthentication", None)

    assert res.success is False
    assert res.reason == "user_canceled"


def test_authenticate_maps_lockout_correctly() -> None:
    fake_la = MagicMock()
    fake_la.LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1
    fake_la.LAErrorUserCancel = -2
    fake_la.LAErrorBiometryLockout = -8
    fake_la.LAErrorAuthenticationFailed = -1
    fake_la.LAErrorNotInteractive = -1004

    fake_ctx = MagicMock()
    fake_ctx.canEvaluatePolicy_error_.return_value = (True, None)

    fake_err = MagicMock()
    fake_err.code.return_value = -8  # lockout

    def _evaluate(policy: int, reason: str, reply: object) -> None:
        reply(False, fake_err)

    fake_ctx.evaluatePolicy_localizedReason_reply_.side_effect = _evaluate
    fake_la.LAContext.new.return_value = fake_ctx

    sys.modules["LocalAuthentication"] = fake_la
    try:
        res = authenticate("test")
    finally:
        sys.modules.pop("LocalAuthentication", None)

    assert res.success is False
    assert res.reason == "lockout"


# ---------------------------------------------------------------------------
# REAL (un-mocked) probe. Everything above mocks LocalAuthentication; this runs
# the actual codesign-based can_present_ui() that decides whether Touch ID is
# even attempted. On the ad-hoc-signed uv interpreter this returns False - the
# exact silent-failure path that broke `quill off` in production. If this code
# raised or stopped returning a bool, the gate-disable flow would misbehave and
# no mocked test would catch it.
# ---------------------------------------------------------------------------


def test_can_present_ui_runs_real_codesign_and_returns_bool() -> None:
    from quill import touchid

    if hasattr(touchid.can_present_ui, "cache_clear"):
        touchid.can_present_ui.cache_clear()
    result = touchid.can_present_ui()
    assert isinstance(result, bool)


def test_signature_allows_ui_logic_not_inverted() -> None:
    # Pins the decision LOGIC (not just "returns a bool") against known codesign
    # blobs, so a logic inversion - allowing UI for an ad-hoc signature - fails.
    from quill.touchid import _signature_allows_ui

    adhoc = "Executable=/x/python3\nIdentifier=-\nSignature=adhoc\nTeamIdentifier=not set\n"
    assert _signature_allows_ui(adhoc) is False

    signed = (
        "Executable=/Applications/X.app\nIdentifier=com.x.app\n"
        "Authority=Developer ID Application: X\nTeamIdentifier=ABCDE12345\n"
    )
    assert _signature_allows_ui(signed) is True

    # No Team Identifier at all -> cannot present.
    assert _signature_allows_ui("TeamIdentifier=not set\n") is False
