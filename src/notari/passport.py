"""The Notari Change Passport: the evidence artifact a verification produces.

A passport is a small, self-contained summary of one `notari verify` run - the
verdict, the contract it was measured against, and the evidence behind it (scope
violations, secret hits, sensitive surfaces, applied exceptions). It is rendered
two ways from the same VerifyResult:

  - ``passport.json`` - machine-readable, for downstream tooling / status checks.
  - ``passport.md``   - human-readable, designed to be posted on a pull request.

The passport cites the ``verification.run`` audit mac, so a reader can trace the
verdict back to the tamper-evident chain rather than trusting the markdown alone.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from notari import attest, explain
from notari.verify import Verdict, VerifyResult

SIGNATURE_KEY = "signature"

_VERDICT_BADGE = {
    Verdict.PASS: "✅ PASS",
    Verdict.NEEDS_REVIEW: "⚠️ NEEDS REVIEW",
    Verdict.BLOCK: "⛔ BLOCK",
}


def build_passport(result: VerifyResult, *, generated_at: str | None = None) -> dict[str, Any]:
    """Assemble the machine-readable passport from a VerifyResult.

    Schema v1.1 adds the top-level `remediation` array (what to do about each
    finding, see explain.py), additive only, v1 readers keep working.
    """
    c = result.contract
    passport: dict[str, Any] = {
        "schema": "notari.change-passport/v1.1",
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "verdict": result.verdict.value,
        "exit_code": result.verdict.exit_code,
        "contract": {
            "id": c.contract_id,
            "task": c.task,
            "task_source": c.task_source,
            "allowed_paths": list(c.allowed_paths),
            "approved_by": c.approved_by,
            "created_at": c.created_at,
            "expires_at": c.expires_at,
            "repo": c.repo,
        },
        "base_commit": result.base_commit,
        "head_commit": result.head_commit,
        "reasons": list(result.reasons),
        "evidence": {
            "changed_files": list(result.changed_paths),
            "out_of_scope": list(result.out_of_scope),
            "forbidden_hits": list(result.forbidden_hits),
            "gate_tamper_hits": list(result.gate_tamper_hits),
            "secret_findings": [
                {"path": f.path, "line": f.line, "pattern": f.pattern_name}
                for f in result.secret_findings
            ],
            "sensitive_surfaces": {k: list(v) for k, v in result.sensitive_surfaces.items() if v},
            "submodule_changes": [dict(c) for c in result.submodule_changes],
            "symlink_changes": [dict(c) for c in result.symlink_changes],
            "scan_dispositions": list(result.scan_dispositions),
            "exceptions_applied": list(result.exceptions_applied),
        },
        "trust": {
            "perimeter_id": result.perimeter_id,
            "strict": result.strict,
            "provenance": result.provenance.status.value if result.provenance else None,
            "provenance_key_id": result.provenance.key_id if result.provenance else None,
            "contract_provenance": (
                result.contract_provenance.status.value if result.contract_provenance else None
            ),
            "contract_signer_key_id": (
                result.contract_provenance.key_id if result.contract_provenance else None
            ),
        },
        "audit": {"verification_run_mac": result.audit_mac},
    }
    passport["remediation"] = explain.build_remediations(passport)
    return passport


def render_markdown(
    result: VerifyResult, *, generated_at: str | None = None, signed: bool = False
) -> str:
    """Render the PR-ready markdown passport.

    Leads with an actionable block (what to do next, a compact coding-agent
    fix prompt, and what Notari does not prove), reusing the same remediation
    logic as `notari explain` so the PR surface is the action loop, not a raw
    evidence dump. The evidence/trust/audit detail stays lower in the document.
    """
    from notari import explain, teach

    c = result.contract
    badge = _VERDICT_BADGE[result.verdict]
    ts = generated_at or datetime.now(UTC).isoformat()
    passport_dict = build_passport(result, generated_at=ts)
    d = explain.explain_dict(passport_dict)

    lines: list[str] = []
    lines.append("# Notari Change Passport")
    lines.append("")
    lines.append(f"## Verdict: {badge}")
    lines.append("")
    for r in result.reasons:
        lines.append(f"- {r}")
    lines.append("")

    # Action block, only when there's something to act on (BLOCK / NEEDS_REVIEW).
    if d["remediations"]:
        lines.append("## What to do next")
        lines.append("")
        for n, rem in enumerate(d["remediations"], start=1):
            where = f" (`{_md_code(str(rem['where']))}`)" if rem["where"] else ""
            # plain / self_fix are sentences that embed a candidate path; strip
            # line breaks so an embedded newline can't end the list item and
            # start a fake heading (finding 11). No backtick swap here: these
            # are prose, and _undo() paths are shell-quoted, not backtick-wrapped.
            lines.append(f"{n}. {_md_line(str(rem['plain']))}{where}")
            lines.append(f"   - Fix: {_md_line(str(rem['self_fix']))}")
        lines.append("")
        if d["inspect_first"]:
            inspect = ", ".join(f"`{_md_code(p)}`" for p in d["inspect_first"])
            lines.append(f"**Reviewer should inspect first:** {inspect}")
            lines.append("")
        lines.append("## Prompt to give Claude Code / Codex / Cursor")
        lines.append("")
        lines.append("```text")
        # Neutralize any triple-backtick a candidate path could carry, so the
        # embedded fix prompt cannot close this fence and inject markdown after
        # it (finding 11). Inside the fence, headings are already inert.
        lines.append(teach.fix_prompt(passport_dict).replace("```", "ˋˋˋ"))
        lines.append("```")
        lines.append("")
        lines.append(f"> {d['does_not_prove']}")
        lines.append("")
        lines.append("## Evidence trust")
        lines.append("")
        lines.append(
            "This markdown is for humans. For tamper detection, verify "
            "`passport.json` with `notari verify-passport`."
        )
        if signed:
            lines.append(
                "The JSON passport is gate-signed and can be verified with "
                "`notari verify-passport`, a reviewer can confirm this verdict "
                "without trusting the repo it came from."
            )
        else:
            lines.append(
                "This passport is unsigned; treat it as report-grade evidence, "
                "not a gate-signed verdict. Configure a gate key in CI to get a "
                "signature a reviewer can independently verify."
            )
        lines.append("")

    lines.append("## Contract")
    lines.append("")
    lines.append(f"- **Task:** {c.task}")
    lines.append(f"- **Contract id:** `{c.contract_id}`")
    if c.approved_by:
        lines.append(f"- **Approved by:** {c.approved_by}")
    scope = ", ".join(f"`{_md_code(p)}`" for p in c.allowed_paths) or "_(no path restriction)_"
    lines.append(f"- **Approved scope:** {scope}")
    lines.append(f"- **Base commit:** `{_short(result.base_commit)}`")
    lines.append(f"- **Head commit:** `{_short(result.head_commit)}`")
    lines.append("")

    # Collapse the raw evidence/trust detail so the PR summary stays scannable:
    # the verdict + action block are what a reader needs first; the full
    # inventory is one click away (GitHub renders <details> in step summaries).
    lines.append("<details>")
    lines.append("<summary>Full evidence (changed files, scope, secrets, trust)</summary>")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    changed = result.changed_paths
    lines.append(f"### Changed files ({len(changed)})")
    lines.append("")
    if changed:
        for p in changed:
            lines.append(f"- `{_md_code(p)}`")
    else:
        lines.append("_No changes between base and head._")
    lines.append("")

    lines.append(f"### Out-of-scope paths ({len(result.out_of_scope)})")
    lines.append("")
    if result.out_of_scope:
        for p in result.out_of_scope:
            lines.append(f"- ⛔ `{_md_code(p)}`, outside approved scope")
    else:
        lines.append("_None, every change is within the approved scope._")
    lines.append("")

    if result.forbidden_hits:
        lines.append(f"### Forbidden perimeter surfaces ({len(result.forbidden_hits)})")
        lines.append("")
        for p in result.forbidden_hits:
            lines.append(f"- ⛔ `{_md_code(p)}`, the signed perimeter forbids changes here")
        lines.append("")

    if result.gate_tamper_hits:
        lines.append(f"### Gate-tamper edits ({len(result.gate_tamper_hits)})")
        lines.append("")
        lines.append("_This PR edits Notari's own trust surfaces, always a BLOCK:_")
        for p in result.gate_tamper_hits:
            lines.append(f"- ⛔ `{_md_code(p)}`")
        lines.append("")

    secrets = result.secret_findings
    lines.append(f"### Secret scan ({len(secrets)})")
    lines.append("")
    if secrets:
        for f in secrets:
            lines.append(f"- ⛔ `{_md_code(f.path)}:{f.line}`, {_md_code(f.pattern_name)}")
    else:
        lines.append("_No secrets detected on added lines._")
    lines.append("")

    surfaces = {k: v for k, v in result.sensitive_surfaces.items() if v}
    lines.append("### Sensitive surfaces")
    lines.append("")
    if surfaces:
        for category, paths in surfaces.items():
            lines.append(f"- **{category}:**")
            for p in paths:
                lines.append(f"  - `{_md_code(p)}`")
    else:
        lines.append("_No tests, CI workflows, or lockfiles touched._")
    lines.append("")

    if result.exceptions_applied:
        lines.append(f"### Human exceptions applied ({len(result.exceptions_applied)})")
        lines.append("")
        for e in result.exceptions_applied:
            reason = e.get("reason", "(no reason given)")
            target = e.get("path") or e.get("category") or "*"
            lines.append(
                f"- `{_md_code(str(e.get('type', '?')))}` on `{_md_code(str(target))}`, {reason}"
            )
        lines.append("")

    if result.perimeter_id:
        lines.append("## Trust")
        lines.append("")
        lines.append(f"- **Perimeter:** `{result.perimeter_id}`")
        if result.provenance is not None:
            prov = result.provenance
            mark = "✅" if prov.status.is_trustworthy else "⚠️"
            signer = f" (approver `{prov.key_id}`)" if prov.key_id else ""
            lines.append(f"- **Perimeter provenance:** {mark} {prov.status.value}{signer}")
        lines.append(f"- **Strict mode:** {'on' if result.strict else 'off'}")
        lines.append("")

    lines.append("</details>")
    lines.append("")
    lines.append("---")
    mac = result.audit_mac or "(not chained)"
    lines.append(f"_Generated {ts} · verification.run audit mac: `{_short(mac, 16)}`_")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Gate-signed passports: the verdict a reviewer can verify without trusting    #
# the repo. The gate signs; anyone with the gate public key re-verifies; only  #
# the off-box private key can mint a new PASS.                                  #
# --------------------------------------------------------------------------- #


def sign_passport(passport: dict[str, Any], private_pem: str) -> dict[str, Any]:
    """Return `passport` with an embedded gate signature over its content.

    The signature covers the passport minus the ``signature`` field itself, so a
    verifier reconstructs the same bytes by dropping that field before checking.
    """
    body = {k: v for k, v in passport.items() if k != SIGNATURE_KEY}
    priv = attest.load_private_key(private_pem)
    sig = attest.sign_payload(body, priv)
    return {**passport, SIGNATURE_KEY: sig.to_dict()}


def verify_passport(passport: dict[str, Any], gate_keys: dict[str, Any]) -> str | None:
    """Return the trusted gate key_id that signed `passport`, or None.

    `gate_keys` maps key_id -> Ed25519PublicKey (load via attest.load_public_key).
    A passport with no signature, a tampered body, or an untrusted signer fails.
    """
    raw = passport.get(SIGNATURE_KEY)
    if not isinstance(raw, dict):
        return None
    try:
        sig = attest.Signature.from_dict(raw)
    except attest.AttestError:
        return None
    body = {k: v for k, v in passport.items() if k != SIGNATURE_KEY}
    return attest.verify_against_any(body, sig, gate_keys)


def write_passport(
    result: VerifyResult,
    *,
    out_dir: Path,
    generated_at: str | None = None,
    sign_key_pem: str | None = None,
) -> tuple[Path, Path]:
    """Write passport.json and passport.md into `out_dir`. Returns both paths.

    When `sign_key_pem` is given (the gate identity's private key, an off-box CI
    secret), the JSON passport is signed so a reviewer can verify the verdict
    with ``notari verify-passport`` without trusting the repo it came from.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "passport.json"
    md_path = out_dir / "passport.md"
    passport = build_passport(result, generated_at=generated_at)
    if sign_key_pem:
        passport = sign_passport(passport, sign_key_pem)
    json_path.write_text(json.dumps(passport, indent=2) + "\n")
    md_path.write_text(
        render_markdown(result, generated_at=generated_at, signed=bool(sign_key_pem))
    )
    return json_path, md_path


def _short(sha: str | None, n: int = 12) -> str:
    if not sha:
        return "-"
    return sha[:n]


def _md_code(s: str, *, max_len: int = 240) -> str:
    """Neutralize a candidate-controlled string for safe inline-code display.

    Filenames are attacker-controlled (a PR can commit any path), and this
    passport is appended to GITHUB_STEP_SUMMARY. Without escaping, a filename
    containing a newline could break out of its list line, and a backtick could
    close the code span, letting a crafted path inject fake headings or a fake
    verdict into the human-facing summary (security red-team 2026-07-22, finding
    11). We strip line breaks and tabs (they end the line/span structure) and
    swap backticks for a lookalike so the span cannot be closed, then cap length
    so a pathological path cannot flood the summary.
    """
    s = s.replace("\r", "␤").replace("\n", "␤").replace("\t", " ")
    s = s.replace("`", "ˋ")  # modifier-letter grave: displays, cannot close a span
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def _md_line(s: str) -> str:
    """Collapse line breaks in a prose field so an embedded candidate path
    cannot end the current markdown line and inject a following standalone
    heading. Backticks are left intact (prose legitimately uses code spans)."""
    return s.replace("\r", " ").replace("\n", " ")
