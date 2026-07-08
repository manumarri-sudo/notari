"""Touch ID gating for `nota approve`.

The default approve flow is: user types `nota approve <token>`, the token
gets persisted, and the agent's next call is allowed. A compromised terminal
or a hijacked agent can self-approve by typing the token. This module adds
hardware-rooted liveness - Touch ID - so the approval requires a fingerprint
match against the user's enrolled biometrics. The match is performed in the
Secure Enclave; userspace gets only a yes/no and never sees the biometric.

macOS only. On Linux/Windows, on SSH sessions, on Macs without Touch ID
hardware enrolled, `is_available()` returns False and the caller falls
through to today's typed-token-only flow with an `approve.biometric.skipped`
audit event.

Critical security note: we use `LAPolicyDeviceOwnerAuthenticationWithBiometrics`
NOT `LAPolicyDeviceOwnerAuthentication`. The latter falls back to the user's
login password - which a keylogger captures, defeating the whole point.
DO NOT change the policy constant without reading SECURITY.md.

Verified live on Apple Silicon macOS (2026-05-08). The threading.Event +
reply-block pattern fires without requiring a separate NSRunLoop pump.
"""

from __future__ import annotations

import functools
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Final

# Reason strings shown in the Touch ID system banner. Apple guidelines say
# these should be a single concrete sentence; the user reads the banner
# under stress, so be specific about what they're approving.
DEFAULT_REASON: Final[str] = "release a nota-blocked tool call"

# Wait at most this long for the user to fingerprint. Apple's own dialog
# auto-cancels after ~30s; we match.
DEFAULT_TIMEOUT_S: Final[float] = 30.0


@dataclass(slots=True, frozen=True)
class TouchIDResult:
    success: bool
    reason: str  # "ok" | "user_canceled" | "lockout" | "not_available" | "error:<code>"


@functools.lru_cache(maxsize=1)
def can_present_ui() -> bool:
    """True iff the running interpreter can actually PRESENT the biometric sheet.

    `canEvaluatePolicy` returns True on any Mac with enrolled Touch ID, but the
    system UI agent (coreauthd / LocalAuthentication UIAgent) only DRAWS the
    prompt for a process carrying a real, stable code-signing identity (a Team
    Identifier). An ad-hoc / linker-signed interpreter - uv's
    python-build-standalone, which is the common pip/uv install - has
    `TeamIdentifier=not set`, so `evaluatePolicy` never presents a dialog and
    hangs until timeout. We detect that cheaply (once, cached) by inspecting the
    interpreter's signature, so callers can skip the doomed ~30s wait and fall
    straight to the typed-phrase human-presence fallback.

    Conservative: any error, or an ad-hoc signature, returns False (prefer the
    instant typed challenge over a hang). A genuinely signed build with a Team
    Identifier returns True and gets real Touch ID.
    """
    try:
        proc = subprocess.run(
            ["codesign", "--display", "--verbose=2", sys.executable],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return _signature_allows_ui((proc.stderr or "") + (proc.stdout or ""))


def _signature_allows_ui(codesign_output: str) -> bool:
    """Pure predicate: does this `codesign --verbose=2` output describe a
    process that can present the LocalAuthentication biometric sheet?

    Ad-hoc / linker-signed (no Team Identifier) cannot. Split out from the
    subprocess call so the decision LOGIC is unit-testable against known
    signature blobs - a live `codesign` call alone can't catch a logic
    inversion (returning True for an ad-hoc signature), only a crash.
    """
    if "Signature=adhoc" in codesign_output:
        return False
    return any(
        line.startswith("TeamIdentifier=") and line.strip() != "TeamIdentifier=not set"
        for line in codesign_output.splitlines()
    )


def is_available() -> bool:
    """True iff Touch ID hardware can EVALUATE on this machine.

    Checks: macOS LocalAuthentication framework loads, hardware sensor is
    present, user has enrolled fingerprints, the current process context can
    reach the prompter (SSH sessions and launchd-spawned daemons return
    False here, which is correct).

    NOTE: this is hardware/enrollment availability, NOT whether the biometric
    sheet can actually PRESENT for this process - see `can_present_ui` for that
    (an ad-hoc-signed uv/pip interpreter can evaluate but cannot present).
    Callers that must not hang on a dialog that never draws should gate on
    `is_available() and can_present_ui()`.
    """
    try:
        import LocalAuthentication
    except ImportError:
        return False
    try:
        ctx = LocalAuthentication.LAContext.new()
        # canEvaluatePolicy returns (bool, NSError|None). Don't try to
        # evaluate without enrollment - the SDK call itself throws.
        can, _err = ctx.canEvaluatePolicy_error_(
            LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,
            None,
        )
        return bool(can)
    except Exception:
        return False


def authenticate(
    reason: str = DEFAULT_REASON,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> TouchIDResult:
    """Block until Touch ID fires, returns a structured result.

    Returns TouchIDResult with success=True on a real fingerprint match.
    Failure modes:
      - "not_available"   - Touch ID can't fire (Linux, SSH, no hardware,
                            no enrollment, biometry locked out).
      - "user_canceled"   - user pressed Cancel / closed the dialog.
      - "lockout"         - too many failed attempts; locked until login.
      - "timeout"         - reply block didn't fire in `timeout_s`.
      - "error:<code>"    - any other LAError.

    Never raises. The caller decides whether to fall through to the
    typed-token-only path (when result.success is False) or refuse the
    approval entirely (paranoid mode).
    """
    if not is_available():
        return TouchIDResult(False, "not_available")

    import LocalAuthentication

    ctx = LocalAuthentication.LAContext.new()
    event = threading.Event()
    captured: dict[str, object] = {}

    def reply(success: bool, error: object) -> None:
        captured["success"] = bool(success)
        captured["error"] = error
        event.set()

    try:
        ctx.evaluatePolicy_localizedReason_reply_(
            LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,
            reason,
            reply,
        )
    except Exception as e:
        return TouchIDResult(False, f"error:{type(e).__name__}")

    if not event.wait(timeout=timeout_s):
        return TouchIDResult(False, "timeout")

    if captured.get("success"):
        return TouchIDResult(True, "ok")

    err = captured.get("error")
    code = getattr(err, "code", lambda: 0)()
    # LAError codes - see Apple LocalAuthentication framework docs.
    if code == LocalAuthentication.LAErrorUserCancel:
        return TouchIDResult(False, "user_canceled")
    if code == LocalAuthentication.LAErrorBiometryLockout:
        return TouchIDResult(False, "lockout")
    if code == LocalAuthentication.LAErrorAuthenticationFailed:
        return TouchIDResult(False, "auth_failed")
    if code == LocalAuthentication.LAErrorNotInteractive:
        return TouchIDResult(False, "not_available")
    return TouchIDResult(False, f"error:{code}")
