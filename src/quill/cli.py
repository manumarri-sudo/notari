"""quill CLI.

  quill begin          write .quill/contract.json from the approved task
  quill verify         compare the diff to the contract, emit a verdict
  quill init           write a starter ~/.quill/config.toml
  quill tail           live-stream the audit log in a separate terminal
  quill audit verify   walk the HMAC chain on an existing log file
  quill audit show     pretty-print the log

The CLI is deliberately thin. Logic lives in the library; this module is wiring.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from quill.readiness import Posture
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from quill import decay as decay_mod
from quill import journal as journal_mod
from quill import telemetry as tel
from quill._version import __version__
from quill.adapters import claude_code as cc_adapter
from quill.audit import AuditLog, verify_chain
from quill.config import (
    default_audit_path,
    default_config_path,
    render_starter_config,
)
from quill.doctor import run_doctor
from quill.errors import QuillError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="quill change control: verify AI-written diffs against the human-approved task.\n\n"
    "  quill begin      capture the approved task into .quill/contract.json\n"
    "  quill verify     compare the diff to the contract, emit PASS / NEEDS_REVIEW / BLOCK\n"
    "  quill onboard    first-run interactive setup (detects agents, installs hooks)\n"
    "  quill approve    go-ahead a blocked call (run from a notification)\n"
    "  quill audit      review what got blocked / allowed / asked\n"
    "  quill receipts   per-session did / changed / uncertain / to-verify\n"
    "  quill bridge     A2A handoff edges between agents\n"
    "  quill trifecta   exposure tracking (untrusted input + private data + exfil)\n"
    "  quill pins       tool description pins (anti-poisoning, anti-rug-pull)\n"
    "  quill approvals  list / revoke pending approval tokens\n"
    "  quill decay      permissions that erode without reinforcement\n"
    "  quill doctor     diagnose the install\n",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"quill {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the quill version and exit.",
        ),
    ] = None,
) -> None:
    """quill change control: verify AI-written diffs against the human-approved task."""


audit_app = typer.Typer(
    no_args_is_help=True,
    help="see what got blocked / allowed / asked.",
)
app.add_typer(audit_app, name="audit")
decay_app = typer.Typer(
    no_args_is_help=True,
    help="track permissions that erode without reinforcement (Permission Decay framework).",
)
app.add_typer(decay_app, name="decay")
journal_app = typer.Typer(no_args_is_help=True, help="session-journal subcommands.")
app.add_typer(journal_app, name="journal", hidden=True)
telemetry_app = typer.Typer(
    no_args_is_help=True,
    help="opt-in anonymous usage telemetry.",
)
app.add_typer(telemetry_app, name="telemetry", hidden=True)

receipts_app = typer.Typer(
    no_args_is_help=True,
    help="agent receipts: did / changed / uncertain / to-verify per session.",
)
app.add_typer(receipts_app, name="receipts")

bridge_app = typer.Typer(
    no_args_is_help=True,
    help="A2A bridge: handoff edges between agents (sub-agent spawns).",
)
app.add_typer(bridge_app, name="bridge")

trifecta_app = typer.Typer(
    no_args_is_help=True,
    help="exposure tracking: did this session see untrusted input + private data + an exfil vector?",
)
app.add_typer(trifecta_app, name="trifecta")

pins_app = typer.Typer(
    no_args_is_help=True,
    help="tool description pins: detect rug-pulls and tool-poisoning attacks.",
)
app.add_typer(pins_app, name="pins")

approvals_app = typer.Typer(
    no_args_is_help=True,
    help="one-shot approvals - list / revoke pending tokens.",
)
app.add_typer(approvals_app, name="approvals")

trust_app = typer.Typer(
    no_args_is_help=True,
    help="trusted directories - downshift default Edit/Write risk to auto-allow inside listed paths. The fix for approval fatigue.",
)
app.add_typer(trust_app, name="trust")

suggestions_app = typer.Typer(
    no_args_is_help=True,
    help="review and promote learner-surfaced suggestions. Auto-tightenings already applied; loosenings stay pending until the operator promotes.",
)
app.add_typer(suggestions_app, name="suggestions")


# --------------------------------------------------------------------------
# Change Control: begin (capture the contract) + verify (gate the diff)
# --------------------------------------------------------------------------


@app.command("begin")
def begin_cmd(
    task: Annotated[
        str,
        typer.Argument(help="the approved task: an issue URL or free text."),
    ],
    scope: Annotated[
        list[str] | None,
        typer.Option(
            "--scope",
            "-s",
            help="allowed path (glob / dir / file). Repeatable. "
            "Omit to declare no path restriction.",
        ),
    ] = None,
    approved_by: Annotated[
        str | None,
        typer.Option("--approved-by", help="who approved this task (recorded in the contract)."),
    ] = None,
    key: Annotated[
        Path | None,
        typer.Option(
            "--key",
            "-k",
            help="approver PRIVATE key (PEM) to sign the contract. Required for "
            "`quill verify --strict`: an unsigned contract is forgeable by the agent.",
        ),
    ] = None,
    expires_in: Annotated[
        int | None,
        typer.Option(
            "--expires-in",
            help="days until the approval lapses. After it, `quill verify --strict` "
            "BLOCKs so a stale contract can't authorize work indefinitely.",
        ),
    ] = None,
    repo: Annotated[
        str | None,
        typer.Option(
            "--repo",
            help="bind this approval to a repository (owner/name). `quill verify "
            "--strict` then BLOCKs if run elsewhere, so a signed contract can't be "
            "replayed across repos. Defaults to $GITHUB_REPOSITORY when present.",
        ),
    ] = None,
) -> None:
    """Capture the human-approved task into .quill/contract.json.

    Records WHAT was approved, WHERE it may touch (--scope), and the current
    HEAD as the base commit. Sign it with --key so `quill verify --strict` can
    prove a human (not the agent) authored it. `quill verify` measures the diff
    against it. Commit the contract (and .sig) to the BASE branch, not the PR.
    """
    from quill import contract as contract_mod
    from quill import perimeter as perimeter_mod
    from quill import provenance as provenance_mod

    try:
        with AuditLog(path=default_audit_path(), hmac_key=_hmac_key()) as audit:
            contract, path = contract_mod.begin(
                task,
                allowed_paths=tuple(scope or ()),
                approved_by=approved_by,
                expires_in_days=expires_in,
                repo=repo or os.environ.get("GITHUB_REPOSITORY"),
                audit=audit,
            )
    except QuillError as e:
        console.print(f"[red]cannot create contract:[/red] {e}")
        raise typer.Exit(code=2) from e

    signed = False
    if key is not None:
        root = perimeter_mod.perimeter_path(contract_mod.repo_root()).parent.parent
        provenance_mod.sign_artifact(
            contract.to_dict(), key.read_text(), root / ".quill" / "contract.sig"
        )
        signed = True

    out = Console()  # stdout - this is the command's primary output
    out.print(
        f"[green]✓[/green] contract [bold]{contract.contract_id}[/bold] written to {path}"
        + ("  [dim](signed)[/dim]" if signed else "")
    )
    if not signed:
        out.print(
            "  [yellow]unsigned[/yellow] - pass --key <approver.pem> so "
            "`quill verify --strict` can establish provenance."
        )
    out.print(f"  task: {contract.task}")
    scope_str = ", ".join(contract.allowed_paths) or "(no path restriction)"
    out.print(f"  scope: {scope_str}")
    out.print(f"  base commit: {contract.base_commit or '(no commits yet)'}")
    out.print("  next: let the agent work, then run [bold]quill verify[/bold]")


@app.command("verify")
def verify_cmd(
    head: Annotated[
        str,
        typer.Option("--head", help="ref to verify against the base commit."),
    ] = "HEAD",
    passport_dir: Annotated[
        Path | None,
        typer.Option(
            "--passport-dir",
            help="where to write passport.json + passport.md (default: <repo>/.quill).",
        ),
    ] = None,
    write_passport: Annotated[
        bool,
        typer.Option("--passport/--no-passport", help="write the passport artifacts."),
    ] = True,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="print the machine-readable passport to stdout."),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="require a signed perimeter from a trusted approver; BLOCK if absent / "
            "unsigned / tampered. Recommended in CI.",
        ),
    ] = False,
    sign_key: Annotated[
        Path | None,
        typer.Option(
            "--sign-key",
            help="gate private key (PEM) to sign the passport with; off-box CI secret. "
            "Falls back to the QUILL_GATE_KEY env value.",
        ),
    ] = None,
) -> None:
    """Compare the diff to the contract and emit PASS / NEEDS_REVIEW / BLOCK.

    Exit code is 0 for PASS / NEEDS_REVIEW and 1 for BLOCK, so this drops
    straight into a CI gate. When a signed perimeter exists it is enforced
    (forbidden paths and gate-tamper edits BLOCK); with --strict an unsigned or
    tampered perimeter also BLOCKs. Evidence goes to .quill/passport.{json,md}.
    """
    import os

    from quill import contract as contract_mod
    from quill import passport as passport_mod
    from quill import perimeter as perimeter_mod
    from quill import verify as verify_mod

    try:
        contract = contract_mod.load()
        root = contract_mod.repo_root()
        perimeter = perimeter_mod.load(root)
        with AuditLog(path=default_audit_path(), hmac_key=_hmac_key()) as audit:
            result = verify_mod.verify(
                contract=contract,
                root=root,
                head=head,
                audit=audit,
                perimeter=perimeter,
                strict=strict,
            )
    except QuillError as e:
        console.print(f"[red]verify failed:[/red] {e}")
        raise typer.Exit(code=2) from e

    # Make the runtime match the docs: a non-strict run does NOT establish that a
    # human (not the agent) authored the contract/perimeter, so its verdict is
    # advisory and forgeable by the same agent that wrote the diff. Say so loudly
    # rather than letting an authoritative-looking PASS imply a boundary it isn't.
    if not strict:
        console.print(
            "[yellow]⚠ cooperative mode:[/yellow] this verdict is advisory — the "
            "contract/perimeter are not checked as human-signed, so the agent that "
            "wrote the diff could also forge them. For an enforced boundary run "
            "[bold]quill verify --strict[/bold] with approver keys pinned off-box "
            "([bold]QUILL_APPROVER_PUBKEYS[/bold]). See docs/SECURITY-MODEL.md."
        )

    gate_pem: str | None = None
    if sign_key is not None:
        gate_pem = sign_key.read_text()
    elif os.environ.get("QUILL_GATE_KEY"):
        gate_pem = os.environ["QUILL_GATE_KEY"]

    if write_passport:
        out_dir = passport_dir or (root / ".quill")
        json_path, md_path = passport_mod.write_passport(
            result, out_dir=out_dir, sign_key_pem=gate_pem
        )
        signed = " [dim](signed)[/dim]" if gate_pem else ""
        console.print(f"[dim]passport: {md_path} · {json_path}[/dim]{signed}")

    out = Console()  # stdout
    if as_json:
        out.print_json(data=passport_mod.build_passport(result))
    else:
        out.print(passport_mod.render_markdown(result))

    raise typer.Exit(code=result.verdict.exit_code)


@app.command("keygen")
def keygen_cmd(
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="write <out> (private, 0600) and <out>.pub (public). "
            "Omit to print both to stdout.",
        ),
    ] = None,
) -> None:
    """Generate an Ed25519 keypair for signing perimeters or passports.

    The private key is the human approver's (or the CI gate's) off-box secret;
    the .pub goes in .quill/approvers/ or QUILL_APPROVER_PUBKEYS so the gate can
    verify without ever being able to forge.
    """
    from quill import attest

    priv, pub = attest.generate_keypair()
    kid = attest.key_id(attest.load_public_key(pub))
    if out is None:
        o = Console()
        o.print("[yellow]# keep the private key OFF the agent's machine[/yellow]")
        o.print(f"[bold]key id:[/bold] {kid}")
        o.print("\n[bold]--- PRIVATE (secret) ---[/bold]")
        o.print(priv.rstrip())
        o.print("\n[bold]--- PUBLIC (share / commit) ---[/bold]")
        o.print(pub.rstrip())
        return
    fd = os.open(str(out), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, priv.encode())
    finally:
        os.close(fd)
    pub_path = out.with_name(out.name + ".pub")
    pub_path.write_text(pub)
    console.print(f"[green]✓[/green] private key (0600) → {out}")
    console.print(f"[green]✓[/green] public key → {pub_path}")
    console.print(f"  key id: [bold]{kid}[/bold]")


@app.command("guard")
def guard_cmd(
    key: Annotated[
        Path,
        typer.Option("--key", "-k", help="approver PRIVATE key (PEM) to sign the perimeter."),
    ],
    allow: Annotated[
        list[str] | None,
        typer.Option("--allow", help="path agents MAY touch (glob). Repeatable."),
    ] = None,
    forbid: Annotated[
        list[str] | None,
        typer.Option("--forbid", help="path agents may NEVER touch (glob). Repeatable."),
    ] = None,
    approved_by: Annotated[
        str | None,
        typer.Option("--approved-by", help="name recorded as the approver."),
    ] = None,
) -> None:
    """Sign the standing perimeter once; every PR is then checked against it.

    Builds (or re-signs) .quill/perimeter.json from --allow / --forbid, signs it
    into .quill/perimeter.sig with your approver key, and reminds you to publish
    the matching public key. After this, `quill verify --strict` enforces the
    boundary on every agent's PR with no further human approval per change.
    """
    from quill import attest
    from quill import contract as contract_mod
    from quill import perimeter as perimeter_mod
    from quill import provenance as provenance_mod

    root = contract_mod.repo_root()
    try:
        priv_pem = key.read_text()
        kid = attest.key_id(attest.load_private_key(priv_pem).public_key())
    except (OSError, QuillError) as e:
        console.print(f"[red]cannot read approver key:[/red] {e}")
        raise typer.Exit(code=2) from e

    existing = perimeter_mod.load(root)
    if allow or forbid or existing is None:
        per = perimeter_mod.default_perimeter(
            allowed_paths=tuple(allow or ()),
            forbidden_paths=tuple(forbid or ()),
            approved_by=approved_by,
        )
    else:
        per = existing  # re-sign the existing perimeter unchanged
    per.write(root)
    provenance_mod.sign_artifact(per.to_dict(), priv_pem, perimeter_mod.signature_path(root))

    out = Console()
    out.print(f"[green]✓[/green] perimeter [bold]{per.perimeter_id}[/bold] signed by {kid}")
    out.print(f"  allowed: {', '.join(per.allowed_paths) or '(anywhere not forbidden)'}")
    out.print(f"  forbidden: {', '.join(per.forbidden_paths)}")
    out.print(
        "  next: publish the matching public key so the gate can verify it — either\n"
        "    commit it to [bold].quill/approvers/<name>.pub[/bold], or set it as the\n"
        "    [bold]QUILL_APPROVER_PUBKEYS[/bold] CI secret (stronger: a PR can't edit it)."
    )


@app.command("verify-passport")
def verify_passport_cmd(
    passport_file: Annotated[
        Path,
        typer.Argument(help="passport.json to verify."),
    ],
    gate_key: Annotated[
        list[Path] | None,
        typer.Option("--gate-key", help="trusted gate PUBLIC key (PEM). Repeatable."),
    ] = None,
    head_sha: Annotated[
        str | None,
        typer.Option(
            "--head-sha",
            help="require the passport to describe THIS candidate commit (else fail).",
        ),
    ] = None,
    max_age_days: Annotated[
        float | None,
        typer.Option(
            "--max-age-days",
            help="reject a passport older than this many days (freshness).",
        ),
    ] = None,
    status_fingerprint: Annotated[
        Path | None,
        typer.Option(
            "--status-fingerprint",
            help="status-fingerprint file written by the wrapper; cross-checks the MAC.",
        ),
    ] = None,
) -> None:
    """Independently verify a signed passport's verdict AND its validity.

    Checks the passport's signature against the trusted gate public keys (from
    --gate-key files and/or the QUILL_GATE_PUBKEYS env). A passport with no
    signature, a tampered body (e.g. a flipped verdict), or an untrusted signer
    fails with exit 1 - so a reviewer can trust the verdict without trusting the
    repo it came from. Authenticity is not validity, so optionally bind the
    passport to the expected candidate (--head-sha), reject stale evidence
    (--max-age-days), and reject a passport whose contract has expired (security
    review M-5).
    """
    import json
    import os
    from datetime import UTC, datetime

    from quill import attest
    from quill import passport as passport_mod

    pems: list[str] = []
    for p in gate_key or []:
        pems.append(p.read_text())
    env_val = os.environ.get("QUILL_GATE_PUBKEYS", "")
    for raw_chunk in env_val.replace(",", "\n\n").split("\n\n"):
        chunk = raw_chunk.strip()
        if not chunk:
            continue
        gp = Path(chunk).expanduser()
        pems.append(gp.read_text() if ("BEGIN" not in chunk and gp.is_file()) else chunk)

    gate_keys: dict[str, Any] = {}
    for pem in pems:
        try:
            pub = attest.load_public_key(pem)
            gate_keys[attest.key_id(pub)] = pub
        except attest.AttestError:
            continue

    if not gate_keys:
        console.print(
            "[red]no trusted gate public keys[/red] (pass --gate-key or set QUILL_GATE_PUBKEYS)"
        )
        raise typer.Exit(code=2)

    try:
        passport = json.loads(passport_file.read_text())
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]cannot read passport:[/red] {e}")
        raise typer.Exit(code=2) from e

    signer = passport_mod.verify_passport(passport, gate_keys)
    out = Console()
    if signer is None:
        out.print("[red]✗ passport signature INVALID[/red] — untrusted signer or tampered content")
        raise typer.Exit(code=1)

    # Authenticity established; now validity. Each check fails closed (exit 1).
    if head_sha is not None and passport.get("head_commit") != head_sha:
        out.print(
            f"[red]✗ candidate mismatch[/red] — passport describes "
            f"{passport.get('head_commit')!r}, expected {head_sha!r}"
        )
        raise typer.Exit(code=1)

    contract_block = passport.get("contract") or {}
    expires_at = contract_block.get("expires_at")
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at)
        except ValueError:
            out.print(f"[red]✗ contract expiry malformed[/red] ({expires_at!r})")
            raise typer.Exit(code=1) from None
        if datetime.now(UTC) >= exp:
            out.print(f"[red]✗ contract expired[/red] at {expires_at}")
            raise typer.Exit(code=1)

    if max_age_days is not None:
        generated_at = passport.get("generated_at")
        try:
            gen = datetime.fromisoformat(generated_at)
        except (ValueError, TypeError):
            out.print(f"[red]✗ passport timestamp malformed[/red] ({generated_at!r})")
            raise typer.Exit(code=1) from None
        if (datetime.now(UTC) - gen).total_seconds() > max_age_days * 86400:
            out.print(
                f"[red]✗ passport too old[/red] — generated {generated_at}, max age {max_age_days}d"
            )
            raise typer.Exit(code=1)

    if status_fingerprint is not None:
        try:
            fp_text = status_fingerprint.read_text()
        except OSError as e:
            out.print(f"[red]✗ cannot read status-fingerprint:[/red] {e}")
            raise typer.Exit(code=2) from e
        fp: dict[str, str] = {}
        for line in fp_text.strip().splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                fp[k.strip()] = v.strip()
        passport_mac = (passport.get("audit") or {}).get("verification_run_mac", "")
        fp_mac = fp.get("mac", "")
        if not passport_mac:
            out.print("[red]✗ passport has no audit MAC — cannot verify status fingerprint[/red]")
            raise typer.Exit(code=1)
        if not fp_mac or len(fp_mac) < 12:
            out.print(
                "[red]✗ status-fingerprint MAC missing or too short (need ≥12 hex chars)[/red]"
            )
            raise typer.Exit(code=1)
        if passport_mac != fp_mac:
            out.print(
                f"[red]✗ status fingerprint mismatch[/red] — passport MAC "
                f"{passport_mac[:12]}… ≠ fingerprint MAC {fp_mac[:12]}…"
            )
            raise typer.Exit(code=1)
        fp_sha = fp.get("sha", "")
        if head_sha is not None and fp_sha and fp_sha != head_sha:
            out.print(
                f"[red]✗ status fingerprint SHA mismatch[/red] — "
                f"fingerprint sha={fp_sha[:12]}… ≠ --head-sha {head_sha[:12]}…"
            )
            raise typer.Exit(code=1)

    out.print(
        f"[green]✓ passport verified[/green] · verdict [bold]{passport.get('verdict')}[/bold] "
        f"· signed by gate {signer}"
    )


@app.command("check-approval")
def check_approval_cmd(
    pr: Annotated[int, typer.Option("--pr", help="pull request number.")],
    head_sha: Annotated[str, typer.Option("--head-sha", help="current head commit SHA.")],
    author: Annotated[str, typer.Option("--author", help="the PR author's login.")],
    repo: Annotated[
        str | None,
        typer.Option("--repo", help="owner/repo (default: $GITHUB_REPOSITORY)."),
    ] = None,
    allow_reviewer: Annotated[
        list[str] | None,
        typer.Option("--allow-reviewer", help="restrict approvals to these logins. Repeatable."),
    ] = None,
) -> None:
    """Require a human (non-author) GitHub approval on the current head commit.

    The other root of trust besides a signed perimeter: a human clicks Approve on
    the PR. An agent can't approve its own PR, and the approval must be on the
    current head, so it can't be replayed against newly pushed code. Reads the
    token from $GITHUB_TOKEN. Exit 0 if approved, 1 if not.
    """
    import os

    from quill import github_review as gh

    slug = repo or os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if "/" not in slug or not token:
        console.print("[red]need --repo owner/repo (or $GITHUB_REPOSITORY) and $GITHUB_TOKEN[/red]")
        raise typer.Exit(code=2)
    owner, name = slug.split("/", 1)

    try:
        result = gh.check_pr_approval(
            owner=owner,
            repo=name,
            pr_number=pr,
            head_sha=head_sha,
            pr_author=author,
            token=token,
            allowed_reviewers=allow_reviewer or None,
        )
    except QuillError as e:
        console.print(f"[red]approval check failed:[/red] {e}")
        raise typer.Exit(code=2) from e

    out = Console()
    if result.approved:
        out.print(f"[green]✓ {result.detail}[/green]")
        raise typer.Exit(code=0)
    out.print(f"[red]✗ {result.detail}[/red]")
    raise typer.Exit(code=1)


# The Quill action pinned to an immutable commit SHA. A mutable tag (@v0) lets
# whoever controls the tag swap the gate's code, and `quill status` (readiness)
# rejects a non-SHA pin, so init and status stay consistent. Bump this SHA on
# every release (part of the release process); it is the SINGLE source of truth
# shared with docs/secure-workflow.yml.
_QUILL_ACTION_PIN = "manumarri-sudo/quill@bde249a49480199e12de07f16b45ac21be7bdb47"  # v0

_CONSUMER_WORKFLOW = f"""\
name: quill-change-control
# Gate every PR against the signed perimeter and publish a Change Passport.
#
# WHY pull_request_target: the 'pull_request' event runs the PR's version of
# the workflow, so an agent can remove this step entirely. pull_request_target
# runs from the base branch — immune to PR modifications.
#
# WHY path: _pr_checkout + checkout-path: the PR is checked out into a DATA-ONLY
# subdirectory. No trusted Python process uses it as cwd or sys.path, so a
# candidate pip.py / sitecustomize.py / json.py cannot shadow trusted imports.
# The Action installs Quill in isolated mode (python -I) and reads the checkout
# only via git. persist-credentials: false keeps the write token out of that tree.
on:
  pull_request_target:
    branches: [main]
permissions:
  contents: read
  statuses: write
jobs:
  change-control:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          fetch-depth: 0
          path: _pr_checkout
          persist-credentials: false
      - uses: {_QUILL_ACTION_PIN}  # v0 — SHA-pinned; bump on release
        with:
          strict: "true"
          head: ${{{{ github.event.pull_request.head.sha }}}}
          head-sha: ${{{{ github.event.pull_request.head.sha }}}}
          checkout-path: _pr_checkout
          passport-dir: _pr_checkout/.quill
          gate-key: ${{{{ secrets.QUILL_GATE_KEY }}}}
          gate-pubkeys: ${{{{ vars.QUILL_GATE_PUBKEYS }}}}
          approver-pubkeys: ${{{{ secrets.QUILL_APPROVER_PUBKEYS }}}}
"""


@app.command("init")
def init_cmd(
    allow: Annotated[
        list[str] | None,
        typer.Option("--allow", help="path agents MAY touch (glob). Repeatable."),
    ] = None,
    forbid: Annotated[
        list[str] | None,
        typer.Option("--forbid", help="path agents may NEVER touch (glob). Repeatable."),
    ] = None,
    approved_by: Annotated[
        str | None, typer.Option("--approved-by", help="name recorded as the approver.")
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="overwrite an existing perimeter / keys.")
    ] = False,
) -> None:
    """One command to set up Change Control: keys, signed perimeter, CI workflow.

    Generates an approver + gate keypair, signs a secure-by-default perimeter,
    writes the pinned GitHub workflow, and gitignores the private keys. Then it
    tells you the only steps that must happen OFF this machine to make the gate a
    real boundary - because a key sitting on this laptop is readable by the agent.
    """
    from quill import attest, readiness
    from quill import contract as contract_mod
    from quill import perimeter as perimeter_mod
    from quill import provenance as provenance_mod

    out = Console()
    root = contract_mod.repo_root()
    keys_dir = root / ".quill" / "keys"
    approvers = provenance_mod.approvers_dir(root)

    if perimeter_mod.perimeter_path(root).exists() and not force:
        out.print("[yellow]a perimeter already exists; pass --force to overwrite.[/yellow]")
        raise typer.Exit(code=1)

    keys_dir.mkdir(parents=True, exist_ok=True)
    approvers.mkdir(parents=True, exist_ok=True)

    # Private keys must never be committed. gitignore the keys dir up front.
    gitignore = root / ".gitignore"
    ignore_line = ".quill/keys/"
    existing = gitignore.read_text() if gitignore.exists() else ""
    if ignore_line not in existing:
        gitignore.write_text(
            existing
            + ("" if existing.endswith("\n") or not existing else "\n")
            + f"{ignore_line}\n"
        )

    approver_priv, approver_pub = attest.generate_keypair()
    gate_priv, gate_pub = attest.generate_keypair()
    for name, content, mode in (
        ("approver.pem", approver_priv, 0o600),
        ("approver.pub", approver_pub, 0o644),
        ("gate.pem", gate_priv, 0o600),
        ("gate.pub", gate_pub, 0o644),
    ):
        p = keys_dir / name
        if p.exists() and force:
            p.unlink()
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
    (approvers / "human.pub").write_text(approver_pub)

    per = perimeter_mod.default_perimeter(
        allowed_paths=tuple(allow or ()),
        forbidden_paths=tuple(forbid or ()),
        approved_by=approved_by,
    )
    per.write(root)
    provenance_mod.sign_artifact(per.to_dict(), approver_priv, perimeter_mod.signature_path(root))

    wf = root / ".github" / "workflows" / "quill-change-control.yml"
    if not wf.exists() or force:
        wf.parent.mkdir(parents=True, exist_ok=True)
        wf.write_text(_CONSUMER_WORKFLOW)

    out.print(f"[green]✓[/green] perimeter [bold]{per.perimeter_id}[/bold] signed")
    out.print(f"[green]✓[/green] keys in [bold]{keys_dir}[/bold] (gitignored) · workflow written")
    out.print("\n[bold]To make this a real boundary, do these 3 things OFF this machine[/bold]")
    out.print(
        "[dim](a key on this laptop is readable by the agent — these move trust off-box):[/dim]"
    )
    out.print("  1. Set CI secrets, then delete the local private keys:")
    out.print(f"     [dim]gh secret set QUILL_GATE_KEY < {keys_dir / 'gate.pem'}[/dim]")
    out.print(f"     [dim]gh secret set QUILL_APPROVER_PUBKEYS < {keys_dir / 'approver.pub'}[/dim]")
    out.print("     [dim](better: keep the approver key on a YubiKey/HSM, never on disk)[/dim]")
    out.print(
        "  2. The workflow uses [bold]pull_request_target[/bold] and SHA-pinned actions (already set)."
    )
    out.print("  3. Make the [bold]quill/change-control[/bold] status check REQUIRED in branch")
    out.print("     protection on main (admin-bypass + force-push off).")
    out.print(
        "\n[bold]Now:[/bold] commit .quill/ (NOT .quill/keys/), then run [bold]quill status[/bold]."
    )
    report = readiness.assess(root, env=dict(__import__("os").environ))
    out.print(f"\ncurrent posture: {_posture_badge(report.posture)}")


def _posture_badge(posture: Posture) -> str:
    from quill.readiness import Posture

    return {
        Posture.ENFORCED: "[green]🟢 enforced boundary[/green]",
        Posture.COOPERATIVE: "[yellow]🟡 cooperative (trust root still on this machine)[/yellow]",
        Posture.UNCONFIGURED: "[red]🔴 unconfigured[/red]",
    }[posture]


@app.command("status")
def status_cmd() -> None:
    """One glance: is the gate a real boundary, or still cooperative? Says what's missing."""
    from quill import contract as contract_mod
    from quill import readiness

    report = readiness.assess(contract_mod.repo_root(), env=dict(__import__("os").environ))
    out = Console()
    out.print(f"Change Control posture: {_posture_badge(report.posture)}\n")
    for c in report.checks:
        mark = "[green]✓[/green]" if c.ok else "[red]✗[/red]"
        tag = "" if c.ok else f" [dim]({c.level.value})[/dim]"
        out.print(f"  {mark} [bold]{c.name}[/bold]{tag}: {c.detail}")
    if report.blockers:
        out.print(
            "\n[yellow]Not yet a hard boundary.[/yellow] Close the blockers above "
            "(usually: move the trust root into CI secrets / hardware, off this machine)."
        )
        raise typer.Exit(code=1)
    if report.posture.value == "enforced":
        out.print(
            "\n[green]This is an enforced boundary: the agent can't forge, skip, or erase it.[/green]"
        )


@app.command("frameworks")
def frameworks_cmd(
    standard: Annotated[
        str | None,
        typer.Option("--standard", "-s", help="filter to one framework (substring match)."),
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="machine-readable output for piping.")
    ] = False,
) -> None:
    """One command: every compliance framework Quill produces evidence for.

    Prints each control, the evidence it produces, and how an auditor would
    sample it — the whole crosswalk, no audit log or setup required. To turn a
    real audit log into a shareable PDF/HTML pack, use `quill audit export --pack`.
    """

    from quill import exports

    controls = exports.CONTROLS
    if standard:
        controls = tuple(c for c in controls if standard.lower() in c.standard.lower())

    if as_json:
        Console().print_json(
            data=[
                {
                    "standard": c.standard,
                    "code": c.code,
                    "title": c.title,
                    "evidence_events": list(c.quill_event_types),
                    "auditor_sampling": c.auditor_sampling,
                }
                for c in controls
            ]
        )
        return

    by_std: dict[str, list[exports.Control]] = {}
    for c in controls:
        by_std.setdefault(c.standard, []).append(c)

    out = Console()
    if not controls:
        out.print(f"[yellow]no controls match {standard!r}[/yellow]")
        raise typer.Exit(code=1)
    out.print(
        f"[bold]Quill produces audit evidence for {len(controls)} controls "
        f"across {len(by_std)} frameworks.[/bold]"
    )
    out.print("[dim]Each line: what Quill records, and how an auditor would test it.[/dim]\n")
    for std in sorted(by_std):
        out.print(f"[bold cyan]{std}[/bold cyan]")
        for c in by_std[std]:
            out.print(f"  [bold]{c.code}[/bold]  {c.title}")
            out.print(f"    [dim]evidence:[/dim] {', '.join(c.quill_event_types)}")
            if c.auditor_sampling:
                out.print(f"    [dim]auditor samples by:[/dim] {c.auditor_sampling}")
        out.print("")
    out.print(
        "[dim]→ `quill audit export --pack` turns your real audit log into a "
        "signed PDF/HTML evidence pack across all of the above.[/dim]"
    )


@app.command("roster")
def roster_cmd(
    log_path: Annotated[
        Path | None, typer.Option("--log", "-l", help="audit log to read (default: ~/.quill).")
    ] = None,
    last: Annotated[int, typer.Option("--last", help="show only the most recent N rows.")] = 20,
    as_json: Annotated[bool, typer.Option("--json", help="machine-readable output.")] = False,
) -> None:
    """Which agents ran, what they were permitted, and what they touched.

    The shadow-AI / audit-readiness view: one row per agent + session, with its
    action count, verdict mix (allowed / asked / blocked), the tools and
    directories it touched, and approvals consumed. A read over the audit chain;
    nothing is written.
    """
    from quill import roster as roster_mod
    from quill.receipt import load_audit_events

    events = load_audit_events(log_path or default_audit_path())
    rows = roster_mod.derive_roster(events)[:last]

    out = Console()
    if as_json:
        out.print_json(data=[r.to_dict() for r in rows])
        return
    if not rows:
        out.print("[yellow]no agent activity in the audit log yet.[/yellow]")
        return
    out.print(f"[bold]Agent roster[/bold] ({len(rows)} most-recent agent/session rows)\n")
    for r in rows:
        tools = ", ".join(r.tools) or "-"
        touched = ", ".join(r.touched_dirs) or "-"
        out.print(f"[bold]{r.agent_id}[/bold]  [dim]session {r.session_id[:12]}[/dim]")
        out.print(
            f"  {r.actions} actions · "
            f"[green]{r.allowed} allowed[/green] · "
            f"[yellow]{r.asked} asked[/yellow] · "
            f"[red]{r.blocked} blocked[/red] · {r.approvals} approvals"
        )
        out.print(f"  [dim]tools:[/dim] {tools}")
        out.print(f"  [dim]touched:[/dim] {touched}\n")


@app.command(
    "git-hook",
    hidden=True,
    # Git's prepare-commit-msg passes positional args (msg path, source type,
    # optional SHA). Typer must accept them without typing them as a single
    # Argument because the count varies.
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def git_hook_cmd(ctx: typer.Context) -> None:
    """Run as the prepare-commit-msg hook (called by the installed shim).

    Git passes: <commit_msg_path> <source_type> [<sha>]. We forward
    these to quill.githook.prepare_commit_msg.
    """
    from quill.githook import prepare_commit_msg

    args = list(ctx.args)
    if not args:
        raise typer.Exit(code=0)
    msg_path = Path(args[0])
    source_type = args[1] if len(args) > 1 else ""
    raise typer.Exit(code=prepare_commit_msg(msg_path, source_type=source_type))


@app.command("commit-hook-install")
def commit_hook_install(
    repo: Annotated[
        Path | None,
        typer.Option(
            "--repo",
            help="path to a git repo (default: current working directory)",
        ),
    ] = None,
) -> None:
    """Install the prepare-commit-msg hook into a repo.

    The hook reads the latest active agent session from your audit log
    and appends a `#`-prefixed summary block to the commit message
    template. Git ignores the comment lines by default; uncomment a
    line to surface it in the commit message, or delete the block.

    Safe to re-run. Refuses to overwrite a non-Quill prepare-commit-msg.
    """
    from quill.githook import install_hook

    repo_root = repo or Path.cwd()
    if not (repo_root / ".git").exists():
        console.print(f"[red]not a git repo:[/red] {repo_root}")
        raise typer.Exit(code=1)
    try:
        p, already = install_hook(repo_root)
    except FileExistsError as e:
        console.print(f"[yellow]{e}[/yellow]")
        raise typer.Exit(code=1) from e
    if already:
        console.print(f"[dim]already installed[/dim] at {p}")
    else:
        console.print(f"[green]installed[/green] {p}")
        console.print(
            "  every `git commit` in this repo will now pre-fill a Quill "
            "session summary as comment lines.",
        )


@app.command("commit-hook-uninstall")
def commit_hook_uninstall(
    repo: Annotated[
        Path | None,
        typer.Option(
            "--repo",
            help="path to a git repo (default: current working directory)",
        ),
    ] = None,
) -> None:
    """Remove the prepare-commit-msg hook from a repo."""
    from quill.githook import uninstall_hook

    repo_root = repo or Path.cwd()
    try:
        p, removed = uninstall_hook(repo_root)
    except RuntimeError as e:
        console.print(f"[yellow]{e}[/yellow]")
        raise typer.Exit(code=1) from e
    if removed:
        console.print(f"[green]removed[/green] {p}")
    else:
        console.print(f"[dim]no hook to remove at[/dim] {p}")


@app.command("insights")
def insights_cmd(
    window_today: Annotated[bool, typer.Option("--today")] = False,
    window_week: Annotated[bool, typer.Option("--week")] = False,
    window_month: Annotated[bool, typer.Option("--month")] = False,
    window_all: Annotated[bool, typer.Option("--all")] = False,
    since: Annotated[str | None, typer.Option("--since")] = None,
    log_path: Annotated[Path | None, typer.Option("--log", "-l")] = None,
    plain: Annotated[bool, typer.Option("--plain")] = False,
) -> None:
    """Per-pattern analysis + suggested overrides + sessions worth reviewing.

    Goes deeper than `quill saves`: for each pattern, shows fire frequency,
    block vs ask ratio, and a calibrated recommendation (keep critical,
    trust-path candidate, watching). Surfaces trust-path effectiveness and
    flags sessions that closed the trifecta or had critical blocks at
    unusual hours.
    """
    from quill.insights import compute_insights, format_insights
    from quill.saves import parse_window

    p = log_path or default_audit_path()
    start, end = parse_window(
        today=window_today,
        week=window_week,
        month=window_month,
        all_time=window_all,
        since=since,
    )
    insights = compute_insights(p, window_start=start, window_end=end)
    Console().print(format_insights(insights, plain=plain))


@app.command("integrate")
def integrate_cmd(
    agent: Annotated[
        str,
        typer.Argument(
            help="agent id (claude-code / cursor / aider) or 'auto' / 'list'",
        ),
    ] = "auto",
    global_scope: Annotated[
        bool,
        typer.Option(
            "--global",
            help="write to the per-user rules file (~/.claude/CLAUDE.md) instead of the project one",
        ),
    ] = False,
    remove: Annotated[
        bool,
        typer.Option("--remove", help="remove the Quill snippet instead of installing"),
    ] = False,
) -> None:
    """Teach your coding agent how to query Quill data via its existing LLM.

    Appends a small instructions snippet to your coding-agent's rules file
    (CLAUDE.md / .cursorrules / CONVENTIONS.md). The snippet lists the
    deterministic `quill` commands your agent can run when you ask about
    agent activity. Idempotent; safe to re-run after Quill upgrades.

    No LLM ships in Quill itself. Your existing coding agent does the asking.

    Examples:
      quill integrate            # auto-detect agents and prompt for which to set up
      quill integrate list       # show what's supported + currently installed
      quill integrate claude-code           # install for Claude Code (project scope)
      quill integrate claude-code --global  # install for Claude Code (user scope)
      quill integrate cursor                # install for Cursor in current repo
      quill integrate claude-code --remove  # uninstall
    """
    from quill.integrate import (
        all_integrations,
        detect_installed,
        get_integration,
        install,
        uninstall,
    )

    out = Console()

    if agent == "list":
        installed = {i.name for i in detect_installed()}
        out.print("[bold]quill integrate — supported agents[/bold]\n")
        for entry in all_integrations():
            mark = "[green]found[/green]" if entry.name in installed else "[dim]not found[/dim]"
            out.print(f"  {entry.name:14}  {entry.label:18}  {mark}")
        out.print(
            "\n[dim]run `quill integrate <name>` to install the rules snippet.[/dim]",
        )
        return

    if agent == "auto":
        found = detect_installed()
        if not found:
            out.print("[yellow]no supported coding agents detected.[/yellow]")
            out.print("  run `quill integrate list` to see what's supported.")
            raise typer.Exit(code=1)
        if len(found) == 1:
            agent = found[0].name
        else:
            out.print("[bold]multiple agents detected.[/bold] pick one:")
            for cand in found:
                out.print(f"  quill integrate {cand.name}   ({cand.label})")
            raise typer.Exit(code=0)

    integ = get_integration(agent)
    if integ is None:
        out.print(f"[red]unknown agent:[/red] {agent}")
        out.print("  run `quill integrate list` to see supported agents.")
        raise typer.Exit(code=1)

    if remove:
        path, removed = uninstall(integ, global_scope=global_scope)
        if removed:
            out.print(f"[green]removed[/green] Quill snippet from {path}")
        else:
            out.print(f"[dim]no snippet to remove[/dim] in {path}")
        return

    try:
        path, status = install(integ, global_scope=global_scope)
    except ValueError as e:
        out.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1) from e

    status_color = {
        "installed": "green",
        "refreshed": "yellow",
        "current": "dim",
    }[status]
    out.print(f"[{status_color}]{status}[/{status_color}]  {path}")
    if status in ("installed", "refreshed"):
        out.print(
            "\n[dim]your coding agent will now know how to query Quill data when you ask.\n"
            f'try: open {integ.label} and ask "what did the agent do this morning?"[/dim]',
        )


@app.command("saves")
def saves_cmd(
    window_today: Annotated[
        bool,
        typer.Option("--today", help="window: last calendar day (UTC)"),
    ] = False,
    window_week: Annotated[
        bool,
        typer.Option("--week", help="window: last 7 days (default)"),
    ] = False,
    window_month: Annotated[
        bool,
        typer.Option("--month", help="window: last 30 days"),
    ] = False,
    window_all: Annotated[
        bool,
        typer.Option("--all", help="window: every event ever logged"),
    ] = False,
    since: Annotated[
        str | None,
        typer.Option(
            "--since",
            help="window start: ISO date or datetime, e.g. 2026-05-01",
        ),
    ] = None,
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="audit log path (default: ~/.quill/audit.log.jsonl)"),
    ] = None,
    plain: Annotated[
        bool,
        typer.Option("--plain", help="strip Rich markup; useful for piping / CI"),
    ] = False,
) -> None:
    """Show what Quill caught for you (verified counts + estimated savings).

    Reads the audit log, classifies every event in the selected window, and
    prints a summary that separates verified counts (every event type the
    log emits) from estimated time-saved (with the per-prompt assumption
    documented inline). Default window is the last 7 days; override with
    --today, --month, --all, or --since YYYY-MM-DD.

    Streaming O(N) over the log; safe on hundred-MB audit chains.
    """
    from quill.saves import compute_saves, format_saves, parse_window

    p = log_path or default_audit_path()
    start, end = parse_window(
        today=window_today,
        week=window_week,
        month=window_month,
        all_time=window_all,
        since=since,
    )
    saves = compute_saves(p, window_start=start, window_end=end)
    Console().print(format_saves(saves, plain=plain))


@app.command("scan-prompts")
def scan_prompts_cmd(
    paths: Annotated[
        list[Path],
        typer.Argument(help="one or more files or directories to scan"),
    ],
    no_gitignore: Annotated[
        bool,
        typer.Option(
            "--no-gitignore",
            help="don't ask git which files to ignore; scan everything (slower)",
        ),
    ] = False,
) -> None:
    """Scan files for prompt-injection-shape patterns (observation signal only).

    Useful before ingesting third-party text into an agent's context: scrape
    output, RAG corpora, fetched web pages, user-uploaded documents. Hits do
    NOT indicate the content is necessarily malicious; they indicate the
    content has the *shape* of common published injection attacks and is
    worth a human review before the agent acts on it.

    Exit code is 0 even when hits are found (this is a signal, not a verdict).
    See `quill scan-secrets` for the hard-block secret detector.
    """
    from quill.prompt_injection import scan as pi_scan

    out = Console()
    total_hits = 0
    files_scanned = 0
    for p in paths:
        targets = _collect_scan_targets(p, respect_gitignore=not no_gitignore)
        if targets is None:
            out.print(f"[yellow]skip:[/yellow] {p} (not a file or directory)")
            continue
        for f in targets:
            try:
                text = f.read_text(errors="replace")
            except OSError as e:
                out.print(f"[yellow]skip:[/yellow] {f} ({e})")
                continue
            files_scanned += 1
            hits = pi_scan(text)
            for h in hits:
                total_hits += 1
                out.print(
                    f"[yellow]injection-shape[/yellow] {f}:{h.line if h.line else '?'}: "
                    f"[bold]{h.pattern_name}[/bold] ({h.category})",
                )
    if total_hits:
        out.print(
            f"\n[yellow]{total_hits} injection-shape pattern(s) found across "
            f"{files_scanned} file(s).[/yellow]\n"
            "  This is a heuristic SIGNAL, not a verdict. Review the matched "
            "content; pair with model-level guardrails.",
        )
    else:
        out.print(
            f"[green]no prompt-injection-shape patterns detected[/green] "
            f"across {files_scanned} file(s).",
        )


@app.command("scan-secrets")
def scan_secrets_cmd(
    paths: Annotated[
        list[Path],
        typer.Argument(help="one or more files or directories to scan"),
    ],
    no_gitignore: Annotated[
        bool,
        typer.Option(
            "--no-gitignore",
            help="don't ask git which files to ignore; scan everything (slower)",
        ),
    ] = False,
) -> None:
    """Scan files for hardcoded credentials (AWS, OpenAI, Anthropic, GitHub, Stripe...).

    Returns exit code 1 if any secrets are detected, 0 otherwise. Useful
    as a pre-commit check or in CI. Uses the same regex set as the
    runtime gate's file-write protection.

    Inside a git repo, scan-secrets walks `git ls-files` by default so it
    skips node_modules, build artifacts, .venv, and anything else listed
    in .gitignore. Use `--no-gitignore` to scan everything regardless.
    """
    from quill.secrets import scan

    out = Console()
    total_hits = 0
    files_scanned = 0
    for p in paths:
        targets = _collect_scan_targets(p, respect_gitignore=not no_gitignore)
        if targets is None:
            out.print(f"[yellow]skip:[/yellow] {p} (not a file or directory)")
            continue
        for f in targets:
            try:
                text = f.read_text(errors="replace")
            except OSError as e:
                out.print(f"[yellow]skip:[/yellow] {f} ({e})")
                continue
            files_scanned += 1
            hits = scan(text)
            for h in hits:
                total_hits += 1
                location = f"line {h.line}" if h.line else f"offset {h.matched_at}"
                out.print(
                    f"[red]secret[/red] {f}:{h.line if h.line else '?'}: "
                    f"[bold]{h.pattern_name}[/bold] at {location}",
                )
    if total_hits:
        out.print(
            f"\n[red]{total_hits} secret(s) found across {files_scanned} file(s).[/red] "
            "Move them to environment variables or a secrets manager.",
        )
        raise typer.Exit(code=1)
    out.print(f"[green]no secrets detected[/green] across {files_scanned} file(s).")


def _collect_scan_targets(
    path: Path,
    *,
    respect_gitignore: bool,
) -> list[Path] | None:
    """Resolve a path into the list of files to scan.

    Returns None if path is neither file nor directory. For directories
    inside a git repo (when respect_gitignore=True), uses `git ls-files`
    so .gitignore'd content is skipped. Falls back to rglob otherwise.
    """
    if path.is_file():
        return [path]
    if not path.is_dir():
        return None

    if respect_gitignore and _is_inside_git_repo(path):
        files = _git_ls_files(path)
        if files is not None:
            return files
    return [f for f in path.rglob("*") if f.is_file()]


def _is_inside_git_repo(path: Path) -> bool:
    """True if `path` is inside a directory that contains a .git directory
    or has one in any ancestor up to the filesystem root."""
    p = path.resolve()
    return any((ancestor / ".git").exists() for ancestor in (p, *p.parents))


def _git_ls_files(path: Path) -> list[Path] | None:
    """Return absolute paths of files git considers tracked or unignored.

    Uses `git ls-files --cached --others --exclude-standard` so we get
    both tracked files and new untracked files that aren't in .gitignore.
    Returns None if git isn't available or the command fails.
    """
    import subprocess

    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    base = path.resolve()
    files: list[Path] = []
    for line in result.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        absolute = (base / rel).resolve()
        if absolute.is_file():
            files.append(absolute)
    return files


@app.command("onboard")
def onboard_cmd(
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="overwrite existing config without asking",
        ),
    ] = False,
) -> None:
    """Interactive 60-second setup: detect agents, pick channels, install hooks.

    Replaces the placeholder values from `quill init` with a guided flow
    that auto-detects Claude Code, Cursor, Cline, Aider, Continue, Windsurf,
    and Zed; asks which to gate; prompts for log location, notification
    channels, and a risk preset; writes config.toml and installs hooks.

    Safe to re-run. Existing config is preserved unless you confirm
    overwrite (or pass --force).
    """
    from quill.onboard import run as run_onboard

    raise typer.Exit(code=run_onboard(force=force))


@app.command("learn")
def learn_cmd(
    since_days: Annotated[
        int,
        typer.Option(
            "--since-days",
            "-d",
            help="window to analyse (0 = full history)",
        ),
    ] = 7,
    json_out: Annotated[
        bool,
        typer.Option("--json", help="emit suggestions as JSON for tooling"),
    ] = False,
) -> None:
    """Read the audit log and surface self-improvement suggestions.

    The audit log is the source of truth; this command turns it into
    prioritised, paste-able actions. Operator decides whether to apply
    each one. Quill never auto-applies learning to its own gate.

    Categories surfaced:
      - trust_scope candidates (the 991-asks-per-week problem)
      - decayed permissions (reaffirm or forget)
      - false_positive_override (repeat operator bypasses)
      - heavy_bash_pattern (frequent classifier hits)
      - silent_failure (e.g. stub journals from a broken parser)
    """
    from quill.learn import analyze

    suggestions, _ = analyze(since_days=since_days)

    if json_out:
        import json as _json

        out = [
            {
                "severity": s.severity,
                "category": s.category,
                "title": s.title,
                "rationale": s.rationale,
                "paste_command": s.paste_command,
                "evidence": list(s.evidence),
            }
            for s in suggestions
        ]
        print(_json.dumps(out, indent=2))
        return

    if not suggestions:
        console.print(
            f"[dim]no suggestions for the last {since_days}d.[/dim] "
            "Run with [bold]--since-days 0[/bold] for full history.",
        )
        return

    sev_color = {"high": "red", "medium": "yellow", "low": "dim"}
    console.print(
        f"[bold]quill learn[/bold] [dim]· "
        f"{len(suggestions)} suggestion(s) from the last "
        f"{since_days}d of audit data[/dim]\n",
    )
    for s in suggestions:
        color = sev_color.get(s.severity, "white")
        console.print(
            f"  [{color}]{s.severity:>6}[/{color}]  [bold]{s.title}[/bold]",
        )
        console.print(f"          [dim]{s.rationale}[/dim]")
        console.print(f"          [bold]apply:[/bold] {s.paste_command}")
        if s.evidence:
            console.print(
                f"          [dim]evidence: {', '.join(s.evidence)}[/dim]",
            )
        console.print()


@app.command("kpis")
def kpis_cmd(
    since_days: Annotated[
        int,
        typer.Option("--since-days", "-d", help="window (0 = full history)"),
    ] = 7,
) -> None:
    """Three KPIs that genuinely measure whether the gate is healthy.

    These are NOT framework name-drops. Each one was picked because
    your actual audit log can answer it concretely and because the
    optimisation direction is right (a quieter gate does NOT score
    higher; a gate that catches real things does).

      noise_ratio    = asks / max(real_blocks, 1)
                       How many friction prompts per real catch.
                       Healthy < 5. Loud 5-20. Broken > 20.

      taint_closures = absolute count of sessions that closed the
                       lethal trifecta (untrusted + private + exfil).
                       Normally 0. Non-zero = real exposure event.

      cascade_events = absolute count of one-parent-spawned-3+-subs
                       fan-out incidents. Each one is a blast-radius
                       review candidate.

    Plus context: the top blocked patterns (which classifier rules
    fired most), and the operator-bypass count (sparse data; reported
    as count, not ratio, until volume grows).
    """
    from quill.learn import analyze

    _, kpis = analyze(since_days=since_days)

    if kpis.n_events == 0:
        console.print(
            f"[dim]no audit data for the last {since_days}d.[/dim]",
        )
        return

    health_color = {
        "healthy": "green",
        "loud": "yellow",
        "broken": "red",
    }[kpis.health]

    window_label = "full history" if since_days == 0 else f"last {since_days}d"
    console.print(
        f"\n[bold]quill kpis[/bold] [dim]({window_label}, {kpis.n_events} events)[/dim]\n",
    )

    # Headline KPI
    console.print(
        f"  [bold]noise_ratio[/bold]    "
        f"[{health_color}]{kpis.noise_ratio:.1f}[/{health_color}]  "
        f"[dim]({kpis.n_asks} asks / max({kpis.n_blocks},1) real blocks  "
        f"->  {kpis.health})[/dim]",
    )

    closure_style = "red" if kpis.n_taint_closures > 0 else "dim"
    console.print(
        f"  [bold]taint_closures[/bold] "
        f"[{closure_style}]{kpis.n_taint_closures}[/{closure_style}]  "
        f"[dim]sessions that closed the lethal trifecta[/dim]",
    )

    cascade_style = "yellow" if kpis.n_cascade_events > 0 else "dim"
    console.print(
        f"  [bold]cascade_events[/bold] "
        f"[{cascade_style}]{kpis.n_cascade_events}[/{cascade_style}]  "
        f"[dim]one-parent -> 3+ sub-agents fan-outs[/dim]",
    )

    console.print(
        f"  [dim]operator_bypasses[/dim]  "
        f"{kpis.n_overrides}  [dim](approved one-shot via quill approve)[/dim]",
    )
    console.print()

    if kpis.top_blocked_patterns:
        table = Table(title="top blocked patterns", show_header=True)
        table.add_column("pattern", overflow="fold")
        table.add_column("hits", justify="right", style="red")
        for pat, n in kpis.top_blocked_patterns:
            table.add_row(pat[:60], str(n))
        console.print(table)


console = Console(stderr=True)


def _maybe_emit_telemetry(audit_path: Path) -> None:
    """Best-effort send of a session.summary if the user has opted in.

    Reads the audit log we just wrote, derives the aggregate, fires off the
    POST. Never raises - telemetry must not affect proxy correctness.
    """
    state = tel.TelemetryState.load()
    if not state.opted_in:
        return
    if not audit_path.exists():
        return
    try:
        events = []
        with audit_path.open() as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        aggregate = tel.aggregate_events(events)
        tel.emit_session_summary(aggregate, state=state)
    except Exception:
        pass


def _hmac_key() -> bytes:
    """Load the HMAC signing key from ~/.quill/key, or generate on first run.

    File is mode 0o600. Document key rotation in SECURITY.md.

    First-run is race-safe: two concurrent hook subprocesses (which is the
    common case on a cold Claude Code start) used to both enter the
    else-branch, both `secrets.token_bytes(32)`, both write the file. The
    second writer overwrote the first, invalidating events the first had
    already signed and breaking the chain. We now use `O_CREAT | O_EXCL`:
    exactly one writer wins; the loser sees FileExistsError, falls back
    to read.
    """
    from quill.paths import default_path

    p = default_path("key", env_override="QUILL_KEY")
    # Fast path: key already exists.
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    try:
        # O_EXCL: fails if the file already exists. Only one process can
        # win this open() across concurrent invocations.
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Lost the race - read the winner's key.
        return p.read_bytes()
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


# --------------------------------------------------------------------------
# night / day - overnight auto-approval for unattended agents
# --------------------------------------------------------------------------


@app.command("night")
def night_cmd(
    state_arg: Annotated[
        str,
        typer.Argument(
            help="on | off | status (default: on)",
            metavar="[on|off|status]",
        ),
    ] = "on",
    hours: Annotated[
        float,
        typer.Option(
            "--hours",
            "-H",
            help="auto-expiry in hours (default 12). only applies to `on`.",
        ),
    ] = 12.0,
    no_biometric: Annotated[
        bool,
        typer.Option(
            "--no-biometric",
            help="explicit opt-in to enable without Touch ID on a genuine "
            "headless box (logged); without it, an unavailable sensor refuses",
        ),
    ] = False,
) -> None:
    """toggle overnight mode - auto-approve HIGH-risk actions so unattended agents do not stall.

    CRITICAL actions (rm -rf, DROP TABLE, vercel --prod, git push --force,
    sudo, etc.) STILL gate. overnight mode trades attended HIGH-risk
    friction for sleep, never safety.

    flip on before bed:    quill night
    flip on for 4 hours:   quill night on --hours 4
    flip off in morning:   quill day
    check current state:   quill night status
    """
    from quill import overnight as ovn

    console = Console()
    cmd = (state_arg or "on").strip().lower()

    if cmd in ("on", ""):
        if hours <= 0 or hours > 24:
            console.print(
                "[red]--hours must be in (0, 24]. refusing to set a multi-day toggle - "
                "safety contract requires a bounded window.[/red]"
            )
            raise typer.Exit(2)
        # Self-disable defense: overnight auto-approves HIGH for 12h, which is a
        # partial gate-disable, so it requires a human fingerprint same as `off`.
        _require_disable_auth(
            console, action="enable overnight auto-approve", no_biometric=no_biometric
        )
        state = ovn.turn_on(duration_hours=hours)
        console.print("[bold green]overnight mode ON[/bold green]")
        console.print(
            f"HIGH-risk Edit / Write / Bash etc. will auto-approve until [bold]{state.expires_at}[/bold]."
        )
        console.print(
            "CRITICAL actions (rm -rf, DROP TABLE, vercel --prod, sudo, force-push) "
            "still gate. sleep well."
        )
        console.print(
            "[dim]run `quill day` to flip off sooner, or `quill night status` to check.[/dim]"
        )
        return

    if cmd == "off":
        state = ovn.turn_off()
        still_active, still_reason = ovn.is_active_from_config()
        if still_active:
            console.print(
                f"[bold yellow]manual toggle off, but overnight is STILL active "
                f"({still_reason}).[/bold yellow]"
            )
            console.print(
                "[dim]edit ~/.quill/config.toml `[overnight] enabled = false` to fully disable, "
                "or wait for the window to close.[/dim]"
            )
        else:
            console.print("[bold yellow]overnight mode OFF[/bold yellow]. all gates restored.")
        if state.high_approved or state.critical_blocked:
            console.print(
                f"overnight recap: [bold]{state.high_approved}[/bold] HIGH auto-approved, "
                f"[bold]{state.critical_blocked}[/bold] CRITICAL still blocked."
            )
            console.print(
                "[dim]run `quill audit show --since 12h` to review what was auto-approved.[/dim]"
            )
        return

    if cmd == "status":
        state = ovn.load_state()
        active, reason = ovn.is_active_from_config()
        if active:
            console.print(f"[bold green]overnight mode ACTIVE[/bold green] ({reason})")
        else:
            console.print("[dim]overnight mode inactive[/dim]")
        console.print(
            f"counters this session: [bold]{state.high_approved}[/bold] HIGH auto-approved, "
            f"[bold]{state.critical_blocked}[/bold] CRITICAL blocked"
        )
        if state.expires_at:
            console.print(f"toggle auto-expires: {state.expires_at}")
        return

    console.print(
        f"[red]unknown: {state_arg!r}.[/red] use: [bold]on[/bold] | [bold]off[/bold] | [bold]status[/bold]"
    )
    raise typer.Exit(2)


@app.command("day")
def day_cmd() -> None:
    """flip overnight mode off. alias for `quill night off`."""
    from quill import overnight as ovn

    console = Console()
    state = ovn.turn_off()
    still_active, still_reason = ovn.is_active_from_config()
    if still_active:
        console.print(
            f"[bold yellow]manual toggle off, but overnight is STILL active "
            f"({still_reason}).[/bold yellow]"
        )
        console.print(
            "[dim]edit ~/.quill/config.toml `[overnight] enabled = false` to fully disable, "
            "or wait for the window to close.[/dim]"
        )
    else:
        console.print("[bold yellow]overnight mode OFF[/bold yellow]. all gates restored.")
    if state.high_approved or state.critical_blocked:
        console.print(
            f"overnight recap: [bold]{state.high_approved}[/bold] HIGH auto-approved, "
            f"[bold]{state.critical_blocked}[/bold] CRITICAL still blocked."
        )
        console.print(
            "[dim]run `quill audit show --since 12h` to review what was auto-approved.[/dim]"
        )


# --------------------------------------------------------------------------
# pause / resume - the bounded, audited off switch
# --------------------------------------------------------------------------


def _parse_duration_hours(s: str) -> float | None:
    """Parse a human duration like '30m', '2h', '90m', '1.5h', '45' (minutes
    assumed when bare) into hours. Returns None on malformed input."""
    raw = (s or "").strip().lower()
    if not raw:
        return None
    try:
        if raw.endswith("h"):
            return float(raw[:-1])
        if raw.endswith("m"):
            return float(raw[:-1]) / 60.0
        # bare number → minutes (the friendlier default for a quick pause)
        return float(raw) / 60.0
    except ValueError:
        return None


def _emit_gate_event(event_type: str, payload: dict[str, Any]) -> None:
    """Write a gate.paused / gate.resumed event to the audit log now, so the
    transition is on the record immediately (not only on the next hook call)."""
    with contextlib.suppress(Exception):
        with AuditLog(path=default_audit_path(), hmac_key=_hmac_key()) as audit:
            audit.emit(
                event_type=event_type,
                session_id="quill-cli",
                agent_id="quill.pause",
                risk="low",
                payload=payload,
                force_fsync=True,
            )


def _human_tty_challenge(console: Console, action: str) -> bool:
    """Human-presence fallback for when Touch ID cannot present a dialog.

    Writes a random phrase to /dev/tty and reads the reply from /dev/tty (NOT
    stdout/stdin): a piped/redirected/headless invocation has no controlling
    tty and fails with OSError, and the phrase goes to the terminal device
    rather than to the stdout/stderr pipes a host harness captures into an
    agent's context.

    This is DEFENSE-IN-DEPTH, not a hard agent/human boundary - an agent in its
    own PTY-backed shell could in principle scrape the tty. The HARD self-
    disable guarantee is the hook-layer CRITICAL classification of
    `quill off|pause|night` (policy.CRITICAL_COMMAND_PATTERNS), which denies an
    agent's call before it reaches this code. This challenge only ever runs for
    a human typing in their own terminal (the human path is never hooked).
    """
    phrase = "-".join(secrets.token_hex(2) for _ in range(3))  # e.g. 1a2b-3c4d-5e6f
    try:
        with open("/dev/tty", "r+", buffering=1) as tty:
            tty.write(
                f"\n  Confirm you are a human present at this terminal.\n"
                f"  To {action}, type this phrase exactly:\n\n"
                f"      {phrase}\n\n  > "
            )
            tty.flush()
            typed = tty.readline().strip()
    except OSError:
        return False  # no controlling tty: piped / headless / agent-redirected
    return secrets.compare_digest(typed, phrase)


def _require_disable_auth(
    console: Console,
    *,
    action: str = "turn the Quill gate OFF",
    no_biometric: bool = False,
) -> None:
    """Require a live human before disabling any layer of the gate.

    Defense ladder:
      1. Real Touch ID, IF it can actually present a dialog (works on a build
         where the LocalAuthentication UIAgent presents for this process -
         today's ad-hoc-signed uv interpreter cannot, see SECURITY.md).
      2. TTY + typed-phrase challenge via /dev/tty, when Touch ID can't present
         (the ad-hoc-signing / macOS-26 case). Rejects piped/headless calls.
      3. No controlling tty at all -> REFUSE unless --no-biometric is passed
         explicitly (logged loudly), for genuine headless operators.

    The HARD self-disable guarantee does NOT live here. It lives in the hook:
    `quill off|pause|night` is CRITICAL (policy.CRITICAL_COMMAND_PATTERNS), so an
    agent's Bash call is denied before reaching this code. This CLI check only
    ever runs for the human, who is not subject to the hook. The earlier design
    hard-refused every human when `touchid.is_available()` was False, which made
    `quill off` unusable on every normal uv/pip install (the binding never
    presents a dialog), so the gate could not be turned off at all without the
    --no-biometric escape. (audit #1/#3, self-disable closure 2026-06-12.)

    Tests inject their verdict by monkeypatching `quill.touchid.authenticate`
    and/or `quill.cli._human_tty_challenge`.
    """
    from quill import touchid

    # Tier 1: hardware biometrics, ONLY when the dialog can actually present.
    # `is_available()` (hardware/enrollment) is True even on an ad-hoc-signed
    # uv interpreter, but the sheet never draws there and would hang 30s; gating
    # on `can_present_ui()` too means we skip straight to the typed challenge on
    # those builds and only attempt Touch ID where it can really show.
    if touchid.is_available() and touchid.can_present_ui():
        result = touchid.authenticate(reason=action)
        if result.success:
            _emit_gate_event("gate.disable_auth", {"method": "touchid", "action": action})
            return
        # An EXPLICIT human deny (cancel / failed / lockout) refuses outright -
        # we do NOT fall through to the weaker check on a real "no".
        if result.reason in ("user_canceled", "auth_failed", "lockout"):
            console.print(f"[red]Touch ID denied for: {action} ({result.reason}). Refused.[/red]")
            raise typer.Exit(1)
        # is_available() was True but evaluatePolicy never presented a dialog
        # (ad-hoc-signed interpreter / presentation bug): reason is "timeout" /
        # "not_available" / "error:*". Fall through to the TTY challenge rather
        # than hard-refusing a human who simply can't get a dialog on this build.

    # Tier 2: TTY + typed-phrase human-presence challenge.
    if _human_tty_challenge(console, action):
        _emit_gate_event("gate.disable_auth", {"method": "tty_challenge", "action": action})
        return

    # Tier 3: no biometrics AND no human at a controlling tty.
    if no_biometric:
        console.print(
            "[yellow]No biometrics and no interactive terminal - proceeding via "
            "explicit --no-biometric opt-in (this is logged loudly).[/yellow]"
        )
        _emit_gate_event(
            "gate.disable_auth",
            {"method": "no_biometric_optin", "action": action, "downgraded": True},
        )
        return

    console.print(
        f"[red]Cannot confirm a human for: {action}. Refused.[/red]\n"
        "  Touch ID could not present a dialog and there is no interactive "
        "terminal to challenge. Run this from a terminal where you can type the "
        "confirmation phrase, or pass --no-biometric to opt into an "
        "unauthenticated disable on a genuine headless box (logged)."
    )
    raise typer.Exit(1)


@app.command("off")
def off_cmd(
    action: Annotated[
        str,
        typer.Argument(
            help="leave blank to pause, or 'status' to check current state",
            metavar="[status]",
        ),
    ] = "",
    for_: Annotated[
        str,
        typer.Option(
            "--for",
            "-f",
            help="how long to stay off, e.g. 30m, 2h, 90m (default 1h, max 24h)",
        ),
    ] = "1h",
    reason: Annotated[
        str,
        typer.Option("--reason", "-r", help="why you're pausing (goes in the audit log)"),
    ] = "",
    no_biometric: Annotated[
        bool,
        typer.Option(
            "--no-biometric",
            help="explicit opt-in to disable without Touch ID on a genuine "
            "headless box (logged); without it, an unavailable sensor refuses",
        ),
    ] = False,
) -> None:
    """pause the gate - one command to turn quill OFF, bounded and logged.

    Every pause auto-expires (default 1h, max 24h) so a forgotten toggle
    self-heals. The pause itself, the resume, and every tool call let
    through while paused are all written to the audit log, so turning the
    gate off never creates a silent gap - just a bounded, on-the-record one.

    Unlike `quill night` (which auto-approves HIGH but still gates CRITICAL),
    `quill off` turns the gate FULLY off, including the destructive class.
    That is intentional: a half-off switch is what pushes people to
    --dangerously-skip-permissions, which leaves no trail at all.

      pause 1 hour:        quill off
      pause 30 minutes:    quill off --for 30m --reason "noisy refactor"
      turn back on:        quill on
      check state:         quill off status
    """
    from quill import pause as _pause

    console = Console()

    if action.strip().lower() == "status":
        _print_pause_status(console)
        return

    hours = _parse_duration_hours(for_)
    if hours is None:
        console.print(f"[red]could not parse --for {for_!r}.[/red] use e.g. 30m, 2h, 90m.")
        raise typer.Exit(2)

    # Self-disable defense: turning the gate OFF needs a human fingerprint;
    # when Touch ID is unavailable (e.g. an agent's own process) it refuses by
    # default, so a hijacked agent can't neuter Quill via its own CLI.
    _require_disable_auth(console, no_biometric=no_biometric)

    state = _pause.pause(duration_hours=hours, reason=reason)
    _emit_gate_event(
        "gate.paused",
        {
            "reason": reason or "(none given)",
            "expires_at": state.expires_at,
            "duration_hours": round(hours, 4),
            "set_via": "quill off",
        },
    )
    console.print(
        "[bold yellow]quill gate OFF[/bold yellow] - all tool calls will be allowed and logged."
    )
    console.print(f"auto-resumes at [bold]{state.expires_at}[/bold] (in {for_}).")
    if reason:
        console.print(f"reason logged: [dim]{reason}[/dim]")
    console.print(
        "[dim]every call while paused is written to the audit log with "
        "gate_paused=true. run `quill on` to re-enable now.[/dim]"
    )


@app.command("on")
def on_cmd() -> None:
    """resume the gate - turn quill back ON. Logs a gate.resumed event with a
    recap of how many calls were let through while it was off."""
    from quill import pause as _pause

    console = Console()
    was_paused, _ = _pause.is_paused()
    state = _pause.resume()
    _emit_gate_event(
        "gate.resumed",
        {
            "trigger": "manual",
            "reason": state.reason,
            "allowed_while_paused": state.allowed_count,
        },
    )
    if not was_paused:
        console.print("[dim]gate was already on. nothing to resume.[/dim]")
        return
    console.print("[bold green]quill gate ON[/bold green] - full gating restored.")
    if state.allowed_count:
        console.print(
            f"recap: [bold]{state.allowed_count}[/bold] call(s) were allowed while paused. "
            "review them: [dim]quill audit show --since 24h[/dim] (look for gate_paused)."
        )


# Memorable aliases: `quill pause` / `quill resume` do the same as off / on.
@app.command("pause")
def pause_cmd(
    for_: Annotated[
        str,
        typer.Option("--for", "-f", help="how long, e.g. 30m, 2h (default 1h, max 24h)"),
    ] = "1h",
    reason: Annotated[
        str,
        typer.Option("--reason", "-r", help="why (goes in the audit log)"),
    ] = "",
) -> None:
    """alias for `quill off` - pause the gate (bounded + logged)."""
    off_cmd(for_=for_, reason=reason)


@app.command("resume")
def resume_cmd() -> None:
    """alias for `quill on` - resume the gate."""
    on_cmd()


def _print_pause_status(console: Console) -> None:
    from quill import pause as _pause

    state = _pause.load_state()
    paused, reason = _pause.is_paused(state)
    if paused:
        remaining = state.remaining()
        mins = int(remaining.total_seconds() // 60) if remaining else 0
        console.print(f"[bold yellow]gate is OFF[/bold yellow] (paused) - reason: {reason}")
        console.print(f"auto-resumes in ~{mins} min (at {state.expires_at}).")
        console.print(f"calls allowed so far this window: [bold]{state.allowed_count}[/bold]")
    else:
        console.print("[bold green]gate is ON[/bold green] - normal gating active.")


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------


@app.command("init-config", hidden=True)
def init_config(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="where to write the starter config"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="overwrite an existing config"),
    ] = False,
) -> None:
    """Write a starter quill config to ~/.quill/config.toml."""
    p = config_path or default_config_path()
    if p.exists() and not force:
        console.print(f"[yellow]exists:[/yellow] {p}  (--force to overwrite)")
        raise typer.Exit(code=1)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_starter_config())
    p.chmod(0o600)
    console.print(f"[green]wrote[/green] {p}")
    console.print("edit it to declare your session intent, scope, and upstreams.")
    console.print("then: [bold]quill start[/bold]")


# --------------------------------------------------------------------------
# tail
# --------------------------------------------------------------------------


@app.command(hidden=True)
def tail(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l"),
    ] = None,
    follow: Annotated[
        bool,
        typer.Option("--follow/--no-follow", "-f"),
    ] = True,
) -> None:
    """Live-stream the audit log. Run this in a side terminal while Quill serves."""
    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log yet:[/yellow] {p}")
        raise typer.Exit(code=1)

    # Canonical vocabulary - must match audit_show + TUI + dashboard.
    # Five labels: allow / ask / block / scope / sub-agent; six glyphs:
    # ✓ ✗ ? ↳ ▸ · - that's the lexicon every Quill surface uses.
    risk_color = {
        "low": "green",
        "medium": "cyan",
        "high": "yellow",
        "critical": "bold red",
    }
    type_glyph = {
        "session.start": ("cyan", "▸ session"),
        "session.end": ("cyan", "◂ session"),
        "agent.spawned": ("magenta", "▸ spawn"),
        "agent.closed": ("magenta", "◂ close"),
        "tool.attempted": ("dim", "· attempt"),
        "tool.completed": ("green", "✓ done"),
        "tool.errored": ("red", "✗ error"),
        "verdict.allowed": ("green", "✓ allow"),
        "verdict.blocked": ("bold red", "✗ block"),
        "verdict.scope_violation": ("magenta", "✗ scope"),
        "verdict.ask": ("yellow", "? ask"),
    }

    def _summarise(evt: dict[str, object]) -> str:
        """One-line plain-English summary of what's interesting in this event."""
        p = evt.get("payload", {}) or {}
        if not isinstance(p, dict):
            return ""
        tool = str(p.get("tool_name") or "")
        ap = p.get("args_preview") or {}
        snippet = ""
        if isinstance(ap, dict):
            v = ap.get("command") or ap.get("path") or ap.get("file_path") or ""
            if isinstance(v, str) and v:
                snippet = v.replace("\n", " ")[:90]
        reason = p.get("reason") or p.get("risk_reason") or ""
        bits: list[str] = []
        if tool:
            bits.append(f"[bold]{tool}[/bold]")
        if snippet:
            bits.append(f"[dim]{snippet}[/dim]")
        if reason:
            bits.append(f"[dim italic]- {reason}[/dim italic]")
        return "  ".join(bits)

    # session_id → short label so sub-agents are visually identifiable
    sub_labels: dict[str, str] = {}
    sub_counter = [0]

    def _label(evt: dict[str, object]) -> str:
        if str(evt.get("type")) == "agent.spawned":
            sid = str(evt.get("session_id", ""))
            if sid not in sub_labels:
                sub_counter[0] += 1
                sub_labels[sid] = f"sub·{sub_counter[0]}"
        return ""

    def _print(line: str) -> None:
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            return
        _label(evt)
        ts = str(evt.get("ts", ""))[11:19]
        risk = str(evt.get("risk", "low"))
        rcolor = risk_color.get(risk, "white")
        tcolor, tlabel = type_glyph.get(str(evt.get("type", "")), ("dim", str(evt.get("type", ""))))
        line_summary = _summarise(evt)

        # if this event came from a sub-agent, indent + tag with ↳ sub·N
        payload = evt.get("payload") or {}
        parent = ""
        if isinstance(payload, dict):
            parent = str(payload.get("parent_session_id") or "")
        sid = str(evt.get("session_id", ""))
        sub_tag = ""
        indent = ""
        if parent:
            tag = sub_labels.get(sid, "sub")
            sub_tag = f" [magenta]↳ {tag}[/magenta]"
            indent = "  "

        out.print(
            f"{indent}  [dim]{ts}[/dim]  "
            f"[{rcolor}]{risk:<8}[/{rcolor}]  "
            f"[{tcolor}]{tlabel:<14}[/{tcolor}]"
            f"{sub_tag}  "
            f"{line_summary}",
        )

    # Tail's output IS data - write to stdout so users can pipe.
    # The module-level `console` is stderr-only (for warnings); for
    # tail we want a fresh stdout console.
    out = Console()
    legend = (
        "[dim]legend:[/dim]  "
        "[green]✓ allow[/green]   "
        "[yellow]? ask[/yellow]   "
        "[bold red]✗ block[/bold red]   "
        "[magenta]✗ scope[/magenta]   "
        "[magenta]↳ sub-agent[/magenta]"
    )
    out.print(legend)
    out.print()

    # Initial drain
    with p.open() as f:
        for line in f:
            _print(line.strip())

    if not follow:
        return

    # Tail: re-open and seek to end, poll for new lines.
    import time

    with p.open() as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            _print(line.strip())


# --------------------------------------------------------------------------
# audit verify / show
# --------------------------------------------------------------------------


@audit_app.command("verify")
def audit_verify(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l"),
    ] = None,
) -> None:
    """Walk the HMAC chain. Reports any tampered or missing entries."""
    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)
    total, failures = verify_chain(p, _hmac_key())
    if failures:
        console.print(f"[red]chain BROKEN[/red]: {len(failures)} of {total} entries fail")
        console.print(f"  failed line numbers: {failures[:20]}")
        console.print(
            "  if these failures pre-date quill 0.1.1, they may be from "
            "concurrent-write breaks fixed in 0.1.1.\n"
            "  to re-chain those entries: [bold]quill audit repair --legacy --yes[/bold]"
        )
        raise typer.Exit(code=2)
    console.print(f"[green]chain intact[/green]: {total} entries verified.")


@audit_app.command("export")
def audit_export(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="audit log to export from"),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="output directory (default: ./quill-evidence-pack)"),
    ] = None,
    aiuc_1: Annotated[
        bool,
        typer.Option("--aiuc-1/--no-aiuc-1", help="include AIUC-1 controls"),
    ] = True,
    eu_ai_act: Annotated[
        bool,
        typer.Option(
            "--eu-ai-act-art-14/--no-eu-ai-act-art-14",
            help="include EU AI Act Art. 14 + Art. 12 + Art. 19 controls",
        ),
    ] = True,
    nist: Annotated[
        bool,
        typer.Option("--nist/--no-nist", help="include NIST AI RMF + GenAI Profile"),
    ] = False,
    iso_42001: Annotated[
        bool,
        typer.Option("--iso-42001/--no-iso-42001", help="include ISO/IEC 42001"),
    ] = False,
    soc2: Annotated[
        bool,
        typer.Option("--soc2/--no-soc2", help="include SOC 2 Common Criteria"),
    ] = False,
    mitre_atlas: Annotated[
        bool,
        typer.Option("--mitre-atlas/--no-mitre-atlas", help="include MITRE ATLAS"),
    ] = False,
    pack: Annotated[
        bool,
        typer.Option(
            "--pack",
            help=(
                "one-command full pack: enables every standard, renders to "
                "PDF via headless Chrome (no LaTeX needed), and opens it"
            ),
        ),
    ] = False,
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="emit format: html | md | pdf | all (default: both md+html)",
        ),
    ] = "both",
    open_after: Annotated[
        bool,
        typer.Option("--open/--no-open", help="open the PDF/HTML when done"),
    ] = False,
) -> None:
    """Export the audit log as a customer-shareable evidence pack.

    Maps Quill's audit-event taxonomy to EU AI Act (Art 12 + 14 + 19),
    AIUC-1 (E015.2, D003.1/3/4, C007.3, plus Security/Reliability/Society),
    NIST AI RMF + GenAI Profile, ISO/IEC 42001 A.6.2.8, SOC 2 Common
    Criteria (CC6/7/8/9), and MITRE ATLAS techniques.

    Use `--pack` to enable every standard + produce a real PDF in one
    shot (the $4,500 EU AI Act Evidence Pack SKU deliverable).
    """
    from quill.exports import aggregate, render_html, render_markdown

    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)

    # --pack: turn everything on, force PDF, force open.
    standards: list[str] = []
    if pack:
        # The full pack includes EVERY framework in the crosswalk, derived from
        # controls.toml so a newly-mapped framework (e.g. a US regulatory one)
        # is always in the pack and can't silently drop out.
        from quill.exports import CONTROLS

        standards = sorted({c.standard for c in CONTROLS})
        if fmt == "both":
            fmt = "all"
        open_after = True
    else:
        if eu_ai_act:
            standards += ["EU AI Act Art. 14", "EU AI Act Art. 12", "EU AI Act Art. 19"]
        if aiuc_1:
            standards.append("AIUC-1")
        if nist:
            standards += ["NIST AI RMF", "NIST GenAI Profile"]
        if iso_42001:
            standards.append("ISO/IEC 42001")
        if soc2:
            standards.append("SOC 2 Common Criteria")
        if mitre_atlas:
            standards.append("MITRE ATLAS")
    if not standards:
        console.print(
            "[red]no standards selected - pass --aiuc-1 or "
            "--eu-ai-act-art-14, or use --pack for the full set[/red]"
        )
        raise typer.Exit(code=1)

    # Verify the chain so the export reports tamper-evidence status honestly.
    chain_failures: list[int] = []
    chain_total = 0
    try:
        chain_total, chain_failures = verify_chain(p, _hmac_key())
    except Exception:
        pass

    events: list[dict[str, Any]] = []
    with p.open() as f:
        for line in f:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                continue

    report = aggregate(
        events,
        log_path=p,
        standards=standards,
        chain_total=chain_total,
        chain_failures=chain_failures,
    )

    out_dir = output_dir or Path.cwd() / "quill-evidence-pack"
    out_dir.mkdir(parents=True, exist_ok=True)

    want_md = fmt in ("md", "both", "all")
    want_html = fmt in ("html", "both", "all")
    want_pdf = fmt in ("pdf", "all")

    written: list[Path] = []
    if want_md:
        md_path = out_dir / "audit-evidence.md"
        md_path.write_text(render_markdown(report))
        written.append(md_path)
    html_path: Path | None = None
    if want_html or want_pdf:
        html_path = out_dir / "audit-evidence.html"
        html_path.write_text(render_html(report))
        if want_html:
            written.append(html_path)
    if want_pdf:
        assert html_path is not None
        pdf_path = out_dir / "audit-evidence.pdf"
        ok, msg = _render_html_to_pdf(html_path, pdf_path)
        if ok:
            written.append(pdf_path)
        else:
            console.print(f"  [yellow]pdf render failed:[/yellow] {msg}")
            console.print(
                "  [dim]fallback: print the HTML to PDF via your browser (Cmd+P).[/dim]",
            )

    console.print(
        f"[green]exported[/green] {report.total_events} events · "
        f"{len(report.by_control)} controls · chain: {report.chain_status}",
    )
    for w in written:
        console.print(f"  [dim]wrote[/dim] {w}")

    if open_after and written:
        # Prefer PDF, then HTML, then md.
        for w in reversed(written):
            if w.suffix in (".pdf", ".html", ".md"):
                _open_path(w)
                break


def _render_html_to_pdf(html_path: Path, pdf_path: Path) -> tuple[bool, str]:
    """Convert an HTML file to PDF.

    Returns (ok, error_message). Tries headless Chrome / Brave / Edge /
    Chromium first (no Python deps, fast). Falls back to weasyprint if
    installed (cross-platform, slower, requires `pip install quillx[pdf]`).
    """
    # Path 1: headless browser. Fast, no Python deps.
    ok, msg = _try_headless_browser_pdf(html_path, pdf_path)
    if ok:
        return True, ""

    # Path 2: weasyprint fallback (optional [pdf] extra).
    ok_w, msg_w = _try_weasyprint_pdf(html_path, pdf_path)
    if ok_w:
        return True, ""

    return False, (
        f"no PDF renderer available (browser path: {msg}; "
        f"weasyprint path: {msg_w}). "
        "Install Chrome/Brave/Edge/Chromium, OR `pip install quillx[pdf]` "
        "for the weasyprint fallback."
    )


def _try_headless_browser_pdf(html_path: Path, pdf_path: Path) -> tuple[bool, str]:
    """First-choice PDF path: headless Chrome / Brave / Edge / Chromium."""
    import platform
    import subprocess
    from shutil import which as _which

    candidates: list[Path] = []
    if platform.system() == "Darwin":
        candidates = [
            Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Path("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
            Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        ]
    else:
        for bin_name in ("google-chrome", "chromium", "chromium-browser", "brave-browser"):
            found = _which(bin_name)
            if found:
                candidates.append(Path(found))

    chrome: Path | None = next((c for c in candidates if c.exists()), None)
    if not chrome:
        return False, "no Chrome/Brave/Edge/Chromium found"

    try:
        result = subprocess.run(
            [
                str(chrome),
                "--headless",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_path}",
                f"file://{html_path.resolve()}",
            ],
            capture_output=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False, "headless browser timed out after 60s"
    except OSError as e:
        return False, f"could not invoke browser: {e}"
    if not pdf_path.exists():
        return False, f"browser exited {result.returncode} without writing PDF"
    return True, ""


def _try_weasyprint_pdf(html_path: Path, pdf_path: Path) -> tuple[bool, str]:
    """Fallback PDF path: weasyprint (requires `pip install quillx[pdf]`)."""
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]
    except ImportError:
        return False, "weasyprint not installed (pip install quillx[pdf])"
    try:
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    except Exception as e:
        return False, f"weasyprint failed: {e}"
    if not pdf_path.exists():
        return False, "weasyprint completed without writing PDF"
    return True, ""


def _open_path(p: Path) -> None:
    """Open a file in the OS default viewer (Preview on Mac, xdg-open on Linux)."""
    import platform
    import subprocess

    try:
        if platform.system() == "Darwin":
            subprocess.run(["open", str(p)], check=False)
        elif platform.system() == "Linux":
            subprocess.run(["xdg-open", str(p)], check=False)
        # Windows: skip; no reliable default-app launcher
    except OSError:
        pass


@audit_app.command("repair")
def audit_repair(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l"),
    ] = None,
    legacy: Annotated[
        bool,
        typer.Option(
            "--legacy",
            help="acknowledge this is for pre-0.1.1 concurrent-write breaks, not tampering.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="confirm rewrite of audit history."),
    ] = False,
) -> None:
    """Re-chain a log file whose chain was broken by a known-cause defect.

    This rewrites historical audit entries. It is the only quill command that
    modifies on-disk audit history. Refuses to run without --legacy --yes.
    Appends a chain.repaired event documenting the operation.
    """
    if not (legacy and yes):
        console.print(
            "[red]refusing to rewrite audit history.[/red]\n"
            "  this command modifies historical entries to recover from the "
            "concurrent-write defect fixed in 0.1.1.\n"
            "  pass [bold]--legacy --yes[/bold] to confirm you understand."
        )
        raise typer.Exit(code=2)

    import hashlib
    import hmac as hmac_mod

    from quill.audit import _canon

    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)
    key = _hmac_key()
    total, failures = verify_chain(p, key)
    if not failures:
        console.print(f"[green]chain already intact[/green]: {total} entries.")
        return

    repaired_lines: list[int] = []
    new_lines: list[bytes] = []
    prev_mac_hex = ""
    with p.open("rb") as f:
        for i, raw in enumerate(f, start=1):
            try:
                evt = json.loads(raw)
            except json.JSONDecodeError:
                console.print(f"[red]line {i}: malformed JSON, leaving as-is[/red]")
                new_lines.append(raw)
                continue
            old_mac = evt.get("mac", "")
            evt["prev_mac"] = prev_mac_hex
            evt.pop("mac", None)
            new_mac = hmac_mod.new(key, _canon(evt), hashlib.sha256).hexdigest()
            evt["mac"] = new_mac
            new_lines.append(
                (json.dumps(evt, separators=(",", ":")) + "\n").encode("utf-8"),
            )
            if new_mac != old_mac:
                repaired_lines.append(i)
            prev_mac_hex = new_mac

    tmp = p.with_suffix(p.suffix + ".repair")
    tmp.write_bytes(b"".join(new_lines))
    tmp.chmod(0o600)
    tmp.replace(p)

    # Append a chain.repaired event so the operation itself is audited.
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(
            event_type="chain.repaired",
            session_id="quill-audit-repair",
            risk="high",
            payload={
                "by": "quill audit repair",
                "reason": "legacy-concurrent-write-break (pre-0.1.1)",
                "repaired_count": len(repaired_lines),
                "repaired_lines": repaired_lines[:50],
                "total_entries_before": total,
            },
        )
    console.print(
        f"[green]repaired[/green] {len(repaired_lines)} entries; chain.repaired event appended.",
    )


@audit_app.command("show")
def audit_show(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l"),
    ] = None,
    last: Annotated[
        int,
        typer.Option("--last", "-n", help="how many tool calls to show"),
    ] = 30,
    only: Annotated[
        str | None,
        typer.Option(
            "--only",
            help="filter by verdict: 'blocked', 'allowed', 'ask', 'scope'",
        ),
    ] = None,
    raw: Annotated[
        bool,
        typer.Option(
            "--raw",
            help="show every audit event separately instead of pairing "
            "tool.attempted with its verdict",
        ),
    ] = False,
    full: Annotated[
        bool,
        typer.Option(
            "--full",
            help="show full reason text wrapped across multiple lines. "
            "Default is one-line-per-row with truncation.",
        ),
    ] = False,
    project: Annotated[
        Path | None,
        typer.Option(
            "--project",
            "-P",
            help="filter to events whose cwd is inside this directory "
            "(uses the cwd recorded by the Claude Code hook adapter)",
        ),
    ] = None,
    sub_only: Annotated[
        bool,
        typer.Option(
            "--sub",
            help="show only events from spawned sub-agents",
        ),
    ] = False,
) -> None:
    """Pretty-print recent gate decisions.

    By default each tool call is rendered as ONE row: the command/path
    that was attempted, the risk, the verdict, the plain-English reason.
    Use --raw to see every audit event separately (for debugging).
    Use --project <dir> to scope to a single repo. Use --sub to show
    only sub-agent (Task-spawned) events.
    """
    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)
    with p.open() as f:
        events = [json.loads(line) for line in f if line.strip()]

    # filters at the event level (applied before pairing)
    if project is not None:
        proj = str(project.expanduser().resolve())

        def _in_project(e: dict[str, Any]) -> bool:
            cwd = (e.get("payload") or {}).get("cwd") or ""
            return isinstance(cwd, str) and (
                cwd == proj or cwd.startswith(proj + "/") or cwd.startswith(proj + "\\")
            )

        events = [e for e in events if _in_project(e)]
    if sub_only:

        def _is_sub(e: dict[str, Any]) -> bool:
            p_ = (e.get("payload") or {}).get("parent_session_id")
            return bool(p_)

        events = [e for e in events if _is_sub(e)]

    risk_style = {
        "low": "green",
        "medium": "cyan",
        "high": "yellow",
        "critical": "bold red",
    }
    verdict_glyph = {
        "verdict.allowed": ("green", "✓ allow"),
        "verdict.blocked": ("bold red", "✗ block"),
        "verdict.scope_violation": ("magenta", "✗ scope"),
        "verdict.ask": ("yellow", "? ask "),
    }

    out = Console()
    table = Table(
        show_header=True,
        header_style="dim",
        box=None,
        pad_edge=False,
        show_lines=False,
    )

    if raw:
        # Per-event view (one row per audit event, no pairing).
        # Same vocabulary as the paired view + tail: ✓ allow / ? ask /
        # ✗ block / ✗ scope / ▸ spawn / ↳ sub.
        type_label = {
            "session.start": ("cyan", "▸ session"),
            "session.end": ("cyan", "◂ session"),
            "agent.spawned": ("magenta", "▸ spawn"),
            "agent.closed": ("magenta", "◂ close"),
            "tool.attempted": ("dim", "· attempt"),
            "tool.completed": ("green", "✓ done"),
            "tool.errored": ("red", "✗ error"),
            **{k: v for k, v in verdict_glyph.items()},
        }

        # Pre-pass to assign stable sub·N labels in spawn order.
        sub_labels: dict[str, str] = {}
        n = 0
        for evt in events:
            if evt.get("type") == "agent.spawned":
                sid = str(evt.get("session_id", ""))
                if sid and sid not in sub_labels:
                    n += 1
                    sub_labels[sid] = f"sub·{n}"

        table.add_column("time", style="dim", no_wrap=True, width=8)
        table.add_column("risk", no_wrap=True, width=8)
        table.add_column("event", no_wrap=True, width=14)
        table.add_column("tool", no_wrap=True, max_width=18)
        table.add_column("what / reason", no_wrap=False)
        for evt in events[-last:]:
            etype = str(evt.get("type", ""))
            if only and only not in etype:
                continue
            payload = evt.get("payload") or {}
            tool = str(payload.get("tool_name") or "-")
            risk = str(evt.get("risk", "low"))
            rcolor = risk_style.get(risk, "white")
            tcolor, tlabel = type_label.get(etype, ("dim", etype))
            ap = payload.get("args_preview") or {}
            piece = ""
            if isinstance(ap, dict):
                v = ap.get("command") or ap.get("path") or ap.get("file_path") or ""
                if isinstance(v, str):
                    piece = v.replace("\n", " ")[:80]
            reason = payload.get("reason") or payload.get("risk_reason") or ""
            text = piece + (f"  [dim italic]- {reason}[/dim italic]" if reason else "")

            # sub-agent decoration - same as the paired view
            parent = payload.get("parent_session_id") if isinstance(payload, dict) else ""
            sid = str(evt.get("session_id", ""))
            if parent and sid in sub_labels:
                tool_cell = f"[magenta]↳ {sub_labels[sid]}[/magenta]  [dim]{tool}[/dim]"
            elif parent:
                tool_cell = f"[magenta]↳ sub[/magenta]  [dim]{tool}[/dim]"
            else:
                tool_cell = tool

            table.add_row(
                str(evt.get("ts", ""))[11:19],
                f"[{rcolor}]{risk}[/{rcolor}]",
                f"[{tcolor}]{tlabel}[/{tcolor}]",
                tool_cell,
                text,
            )
        legend_bits = [
            "[green]✓ allow[/green]",
            "[yellow]? ask[/yellow]",
            "[bold red]✗ block[/bold red]",
            "[magenta]✗ scope[/magenta]",
            "[magenta]↳ sub-agent[/magenta]",
        ]
        out.print("[dim]legend:[/dim]  " + "   ".join(legend_bits))
        out.print()
        out.print(table)
        return

    # Paired view (default): one row per tool call, attempt + verdict joined.
    # Compact mode by default - single line per row, truncate. Use --full
    # for the wrapped multi-line view if you actually want all the prose.
    table.add_column("time", style="dim", no_wrap=True, width=8)
    table.add_column("verdict", no_wrap=True, width=8)
    table.add_column("risk", no_wrap=True, width=8)
    table.add_column("tool", no_wrap=True, max_width=18)
    if full:
        table.add_column("what was tried", no_wrap=False, ratio=2)
        table.add_column("why", style="dim italic", no_wrap=False, ratio=2)
    else:
        table.add_column("what was tried", no_wrap=True, max_width=44, overflow="ellipsis")
        table.add_column("why", style="dim italic", no_wrap=True, max_width=60, overflow="ellipsis")

    # Build a session_id → short label map so sub-agents have a readable
    # identity in the rendered table. ses-foo-1234 → "sub·1234".
    session_labels: dict[str, str] = {}
    spawn_count = 0
    for evt in events:
        if evt.get("type") == "agent.spawned":
            sid = str(evt.get("session_id", ""))
            spawn_count += 1
            session_labels[sid] = f"sub·{spawn_count}"

    pairs: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None
    for evt in events:
        etype = str(evt.get("type", ""))
        if etype == "tool.attempted":
            pending = evt
            continue
        if etype.startswith("verdict."):
            row = {
                "ts": evt.get("ts", ""),
                "verdict": etype,
                "risk": evt.get("risk", "low"),
                "session_id": evt.get("session_id", ""),
                "agent_id": evt.get("agent_id", ""),
                "payload_attempt": (pending or {}).get("payload") or {},
                "payload_verdict": evt.get("payload") or {},
            }
            pairs.append(row)
            pending = None

    if only:
        pairs = [r for r in pairs if only in r["verdict"]]

    rows = pairs[-last:]
    if not rows:
        out.print(f"[dim]no tool calls match.[/dim] log: {p}")
        return

    has_subs = any(
        (
            r["payload_verdict"].get("parent_session_id")
            or r["payload_attempt"].get("parent_session_id")
        )
        for r in rows
    )

    # Steel-blue accent for the "try instead" hint lane (delta convention,
    # matches every popular delta theme: Arctic Fox / Mantis Shrimp /
    # Tangara-chilensis). Distinct from coral block + amber ask.
    HINT = "#5E81AC"

    for r in rows:
        risk = str(r["risk"])
        rcolor = risk_style.get(risk, "white")
        vcolor, vlabel = verdict_glyph.get(str(r["verdict"]), ("white", str(r["verdict"])))
        attempt = r["payload_attempt"] or {}
        verdict = r["payload_verdict"] or {}
        tool = str(attempt.get("tool_name") or verdict.get("tool_name") or "-")
        ap = attempt.get("args_preview") or {}
        what = ""
        if isinstance(ap, dict):
            v = ap.get("command") or ap.get("path") or ap.get("file_path") or ""
            if isinstance(v, str):
                what = v.replace("\n", " ")
                if not full:
                    what = what[:80]

        # Split the new "<reason> · try instead: <suggestion>" format so the
        # suggestion can render on its own row underneath, in steel-blue.
        raw_reason = str(
            verdict.get("reason") or verdict.get("risk_reason") or attempt.get("risk_reason") or ""
        )
        suggestion = ""
        if " · try instead: " in raw_reason:
            short_reason, suggestion = raw_reason.split(" · try instead: ", 1)
        else:
            short_reason = raw_reason
        if not full:
            short_reason = short_reason[:60]

        # sub-agent decoration - visible by default
        parent = verdict.get("parent_session_id") or attempt.get("parent_session_id") or ""
        sub_label = session_labels.get(str(r["session_id"]), "")
        if parent and sub_label:
            tool_cell = f"[magenta]↳ {sub_label}[/magenta]  [dim]{tool}[/dim]"
        elif parent:
            tool_cell = f"[magenta]↳ sub[/magenta]  [dim]{tool}[/dim]"
        else:
            tool_cell = tool

        table.add_row(
            str(r["ts"])[11:19],
            f"[{vcolor}]{vlabel}[/{vcolor}]",
            f"[{rcolor}]{risk}[/{rcolor}]",
            tool_cell,
            what,
            short_reason,
        )
        # Conditional hint-lane row underneath. Only renders for blocked /
        # ask events that carry a paste-able suggestion. Steel-blue accent
        # (delta convention) makes the action visually distinct from the
        # event row's verdict color.
        if suggestion:
            sugg_text = suggestion if full else suggestion[:90]
            table.add_row(
                "",
                "",
                "",
                "",
                f"[#{HINT[1:]}]↪ try[/]",
                f"[#{HINT[1:]}]{sugg_text}[/]",
            )

    # legend printed ABOVE the table so the symbols are obvious
    legend_bits = [
        "[green]✓ allow[/green]",
        "[yellow]? ask[/yellow]",
        "[bold red]✗ block[/bold red]",
        "[magenta]✗ scope[/magenta]",
        f"[#{HINT[1:]}]↪ try[/]",
    ]
    if has_subs:
        legend_bits.append("[magenta]↳[/magenta] sub-agent (Task)")
    out.print("[dim]legend:[/dim]  " + "   ".join(legend_bits))
    out.print()
    out.print(table)

    counts = {"allow": 0, "block": 0, "ask  ": 0, "scope": 0}
    for r in rows:
        v = str(r["verdict"])
        if v == "verdict.allowed":
            counts["allow"] += 1
        elif v == "verdict.blocked":
            counts["block"] += 1
        elif v == "verdict.ask":
            counts["ask  "] += 1
        elif v == "verdict.scope_violation":
            counts["scope"] += 1
    sub_n = sum(
        1
        for r in rows
        if (
            r["payload_verdict"].get("parent_session_id")
            or r["payload_attempt"].get("parent_session_id")
        )
    )
    parts = [f"{k.strip()}={v}" for k, v in counts.items() if v]
    if sub_n:
        parts.append(f"sub-agent={sub_n}")
    summary = "  ".join(parts)
    out.print(f"[dim]{len(rows)} tool call(s) · {summary} · log: {p}[/dim]")


@audit_app.command("summary")
def audit_summary(
    since: Annotated[
        str,
        typer.Option(
            "--since",
            "-s",
            help="window to recap. Examples: 12h, 1d, 7d, 30m, 2h30m. Units: s/m/h/d/w.",
        ),
    ] = "12h",
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="output format: markdown (default, Substack-ready), "
            "json (raw data), or table (rich terminal).",
        ),
    ] = "markdown",
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="audit log path (default: $QUILL_HOME/audit.log.jsonl)"),
    ] = None,
    cwd_filter: Annotated[
        Path | None,
        typer.Option(
            "--cwd",
            help="scope the recap to events whose cwd is inside this directory.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="write the rendered report to this file instead of stdout.",
        ),
    ] = None,
) -> None:
    """Morning recap: aggregate overnight auto-approvals into a report.

    Reads the audit log, filters to events in the requested window, and
    prints a paste-ready markdown summary (or JSON / a rich table) of what
    happened. The default window is the last 12 hours, which is the same
    duration `quill night` defaults to. The markdown format is Substack-
    ready: paste it into a daily note or post and it lays out cleanly.

    Example:

        quill audit summary --since 12h
        quill audit summary --since 7d --format json --out recap.json
        quill audit summary --since 1d --cwd ~/quill --format table
    """
    from quill.audit_summary import (
        compute_summary,
        load_events,
        parse_duration,
        render_json,
        render_markdown,
        render_table,
    )

    fmt_norm = (fmt or "markdown").strip().lower()
    if fmt_norm not in ("markdown", "md", "json", "table"):
        console.print(
            f"[red]unknown --format[/red] {fmt!r}; expected one of: markdown, json, table",
        )
        raise typer.Exit(code=2)

    try:
        window = parse_duration(since)
    except ValueError as e:
        console.print(f"[red]bad --since value:[/red] {e}")
        raise typer.Exit(code=2) from e

    p = log_path or default_audit_path()
    events = load_events(p)
    cwd_str = str(cwd_filter) if cwd_filter is not None else None

    stats = compute_summary(
        events,
        since_label=since,
        window=window,
        cwd_filter=cwd_str,
        log_path=p,
    )

    # rendering surface picks the output device. table goes to stdout via a
    # fresh Console; markdown/json go to stdout as plain text so it pipes
    # cleanly into pbcopy, jq, or a Substack draft. The module-level
    # `console` (stderr) is reserved for error / status reporting.
    if fmt_norm == "json":
        text = render_json(stats)
        if output is not None:
            output.write_text(text + "\n")
            console.print(f"[green]wrote[/green] {output}")
        else:
            print(text)
        return

    if fmt_norm == "table":
        out = Console()
        table = render_table(stats)
        if output is not None:
            # rich Table -> plain text via a temporary console; useful for
            # piping into a file even though markdown is the better choice
            # for files.
            from io import StringIO

            buf = StringIO()
            tmp = Console(file=buf, force_terminal=False, width=120)
            tmp.print(table)
            output.write_text(buf.getvalue())
            console.print(f"[green]wrote[/green] {output}")
        else:
            out.print(table)
        if stats.total_events == 0:
            console.print(f"[dim]no events in window. log: {p}[/dim]")
        return

    # markdown (default)
    text = render_markdown(stats)
    if output is not None:
        output.write_text(text)
        console.print(f"[green]wrote[/green] {output}")
    else:
        print(text)


# --------------------------------------------------------------------------
# doctor - install diagnostic
# --------------------------------------------------------------------------


@app.command()
def doctor(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="path to quill config"),
    ] = None,
) -> None:
    """Verify the install: config, audit log, key, hook, upstreams.

    Prints one line per check (PASS / WARN / FAIL) with a remediation
    hint for anything that needs attention. Exits 1 if any FAIL was hit
    so this can be used in scripts.
    """
    out = Console()  # use stdout, not stderr - script-friendly

    # The legacy live-dashboard daemon was removed in the change-control
    # pivot; there are no orphan watcher/tree processes to sweep anymore.
    report = run_doctor(config_path=config_path)
    out.print()
    out.print("[bold]quill doctor[/bold]")
    out.print()
    name_width = max(len(r.name) for r in report.results) + 2
    for r in report.results:
        out.print(f"  {r.status}  [bold]{r.name:<{name_width}}[/bold] {r.detail}")
        if r.fix and r.status != "[green]PASS[/green]":
            out.print(f"        [dim]→ {r.fix}[/dim]")
    out.print()
    if report.has_failures:
        out.print("[red]some checks failed.[/red]  fix the FAILs above and re-run.")
        raise typer.Exit(code=1)
    if report.has_warnings:
        out.print("[yellow]all checks passed (with warnings).[/yellow]  see hints above.")
    else:
        out.print("[green]all checks passed.[/green]")


# --------------------------------------------------------------------------
# claude-hook  (Claude Code PreToolUse adapter)
# --------------------------------------------------------------------------


@app.command("claude-hook", hidden=True)
def claude_hook() -> None:
    """Run as Claude Code's PreToolUse hook.

    Wired into ~/.claude/settings.json so every Claude Code tool call
    (Bash, Edit, Write, ...) is gated by Quill before it executes.
    Reads JSON on stdin, writes JSON on stdout, exits 0.

    Install with:  quill claude-hook-install
    """
    raise typer.Exit(code=cc_adapter.main())


@app.command("claude-hook-install", hidden=True)
def claude_hook_install(
    settings_path: Annotated[
        Path | None,
        typer.Option(
            "--settings",
            help="path to Claude Code settings.json (default: ~/.claude/settings.json)",
        ),
    ] = None,
    matcher: Annotated[
        str,
        typer.Option(
            "--matcher",
            help="which built-in tools to gate (Claude Code matcher syntax)",
        ),
    ] = "Bash|Edit|Write|NotebookEdit",
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="hook timeout in seconds"),
    ] = 10,
) -> None:
    """Idempotently merge the Quill hook into Claude Code's settings.json.

    Safe to re-run; if Quill is already installed at this matcher, it does
    nothing.
    """
    p, already = cc_adapter.install_into_settings(
        settings_path,
        matcher=matcher,
        timeout=timeout,
    )
    if already:
        console.print(f"[dim]already installed in[/dim] {p}")
    else:
        console.print(f"[green]installed[/green] in {p}")
        console.print("  Restart Claude Code to pick up the new hook.")


# --------------------------------------------------------------------------
# cursor-hook  (Cursor 1.7+ pre-tool-call adapter)
# --------------------------------------------------------------------------


@app.command("cursor-hook", hidden=True)
def cursor_hook() -> None:
    """Run as Cursor's pre-tool-call hook.

    Wired into ~/.cursor/hooks.json so every Cursor shell / MCP / file-read
    call is gated by Quill before it executes. Reads JSON on stdin, writes
    JSON on stdout (Cursor's `permission` shape, NOT Claude Code's).

    Install with:  quill cursor-hook-install
    """
    from quill.adapters import cursor as cursor_adapter

    raise typer.Exit(code=cursor_adapter.main())


@app.command("cursor-hook-install", hidden=True)
def cursor_hook_install(
    settings_path: Annotated[
        Path | None,
        typer.Option(
            "--settings",
            help="path to Cursor hooks.json (default: ~/.cursor/hooks.json)",
        ),
    ] = None,
) -> None:
    """Idempotently merge the Quill hook into Cursor's hooks.json.

    Wires beforeShellExecution + beforeMCPExecution + beforeReadFile to
    `quill cursor-hook`. Safe to re-run; if Quill is already wired, no-op.
    Requires Cursor 1.7+.
    """
    from quill.adapters import cursor as cursor_adapter

    p, already = cursor_adapter.install_into_settings(settings_path)
    if already:
        console.print(f"[dim]already installed in[/dim] {p}")
    else:
        console.print(f"[green]installed[/green] in {p}")
        console.print("  Restart Cursor to pick up the new hook.")


# --------------------------------------------------------------------------
# telemetry - opt-in anonymous aggregate usage
# --------------------------------------------------------------------------


@telemetry_app.command("status")
def telemetry_status() -> None:
    """Show whether telemetry is opted-in, and where state lives."""
    s = tel.TelemetryState.load()
    out = Console()
    out.print(f"  install_id : [dim]{s.install_id}[/dim]")
    out.print(f"  opted_in   : [{'green' if s.opted_in else 'yellow'}]{s.opted_in}[/]")
    out.print(f"  asked      : {s.asked} {('@ ' + s.asked_at) if s.asked_at else ''}")
    out.print(f"  endpoint   : {s.endpoint}")
    out.print(f"  state file : {tel._state_path()}")


@telemetry_app.command("on")
def telemetry_on() -> None:
    """Opt in to anonymous aggregate telemetry."""
    s = tel.opt_in()
    Console().print(
        f"[green]telemetry on[/green]. install_id: [dim]{s.install_id}[/dim]\n"
        "  Inspect what gets sent at any time:  quill telemetry show\n"
        "  Turn off:                            quill telemetry off",
    )


@telemetry_app.command("off")
def telemetry_off() -> None:
    """Opt out of telemetry (or stay opted-out)."""
    tel.opt_out()
    Console().print("[yellow]telemetry off.[/yellow]  no events will be sent.")


@telemetry_app.command("show")
def telemetry_show(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="audit log to summarise"),
    ] = None,
) -> None:
    """Print the JSON Quill *would* send.

    This is the only thing that ever leaves your machine. Inspect it
    before opting in if you want to verify the privacy contract holds.
    """
    s = tel.TelemetryState.load()
    p = log_path or default_audit_path()
    aggregate: dict[str, object] = {}
    if p.exists():
        events = []
        with p.open() as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        aggregate = tel.aggregate_events(events)
    out = Console()
    out.print(tel.preview_event_for_user(s, aggregate))


# --------------------------------------------------------------------------
# journal - write a session log to the AgentOS vault
# --------------------------------------------------------------------------


@journal_app.command("save")
def journal_save(
    transcript: Annotated[
        Path | None,
        typer.Option(
            "--transcript",
            help="path to the Claude Code transcript JSONL (read from "
            "stdin's transcript_path if not given)",
        ),
    ] = None,
    sessions_dir: Annotated[
        Path | None,
        typer.Option(
            "--out",
            help="vault Sessions/ directory (default: "
            "~/agentbrain/AgentOS-Vault/ClaudeCode/Sessions/)",
        ),
    ] = None,
) -> None:
    """Render an auto-summary of a Claude Code transcript to the vault.

    Designed to be called from a SessionEnd hook. When called by the
    hook, Claude Code passes session_id / transcript_path / cwd / reason
    on stdin as JSON. The session.close audit emission and drift check
    fire unconditionally so receipts derive from clean session boundaries
    even when no transcript is available; the journal markdown write is
    skipped (with a friendly message) when transcript is missing.
    """
    payload: dict[str, Any] = {}
    if transcript is None:
        try:
            raw = json.loads(sys.stdin.read() or "{}")
            if isinstance(raw, dict):
                payload = raw
        except json.JSONDecodeError:
            payload = {}
        tp = payload.get("transcript_path")
        if isinstance(tp, str) and tp:
            transcript = Path(tp).expanduser()

    session_id = str(payload.get("session_id") or "")
    cwd = str(payload.get("cwd") or "")
    reason = str(payload.get("reason") or "transcript_end")
    if session_id:
        from quill.journal import _check_session_drift, _emit_session_close

        _emit_session_close(session_id, cwd, reason)
        _check_session_drift(session_id, cwd)

    if transcript is None:
        Console(stderr=True).print(
            "[dim]quill journal save: no transcript provided; "
            "session.close emitted, journal markdown skipped.[/dim]",
        )
        return

    written = journal_mod.save_from_transcript(transcript, sessions_dir=sessions_dir)
    Console().print(f"[green]wrote[/green] {written}")


# --------------------------------------------------------------------------
# decay - Permission Decay framework
# --------------------------------------------------------------------------


@decay_app.command("show")
def decay_show(
    all_: Annotated[
        bool,
        typer.Option("--all", help="show healthy permissions too, not just decayed/approaching"),
    ] = False,
) -> None:
    """List tracked permissions with decay status.

    A permission decays when it has not been used in
    `decay_after_days`. Decayed permissions are ignored at the gate
    (the default risk fires) until you run `quill decay reaffirm`.
    """
    out = Console()
    store = decay_mod.DecayStore.load()
    perms = store.all()
    if not perms:
        out.print("[dim]no tracked permissions yet.[/dim]")
        out.print(
            "  permissions register the first time a config policy "
            "override fires; check back after running Claude Code."
        )
        return

    decayed = sorted(store.decayed(), key=lambda p: p.age_days, reverse=True)
    approaching = sorted(store.approaching(), key=lambda p: p.days_left)
    healthy = [p for p in perms if not p.is_decayed and p not in approaching]

    if decayed:
        out.print(f"[bold red]decayed ({len(decayed)})[/bold red] [dim]- action required[/dim]")
        t = Table(box=None, pad_edge=False, show_header=True, header_style="dim")
        t.add_column("kind", style="dim")
        t.add_column("pattern")
        t.add_column("age (d)", justify="right")
        t.add_column("window", justify="right")
        t.add_column("uses", justify="right")
        t.add_column("decay_action")
        for p in decayed:
            t.add_row(
                p.kind,
                p.pattern,
                f"[red]{p.age_days}[/red]",
                str(p.decay_after_days),
                str(p.use_count),
                p.decay_action,
            )
        out.print(t)
        out.print()

    if approaching:
        out.print(f"[yellow]approaching decay ({len(approaching)})[/yellow]")
        t = Table(box=None, pad_edge=False, show_header=True, header_style="dim")
        t.add_column("kind", style="dim")
        t.add_column("pattern")
        t.add_column("days left", justify="right")
        t.add_column("uses", justify="right")
        for p in approaching:
            t.add_row(p.kind, p.pattern, f"[yellow]{p.days_left}[/yellow]", str(p.use_count))
        out.print(t)
        out.print()

    if all_ and healthy:
        out.print(f"[green]healthy ({len(healthy)})[/green]")
        t = Table(box=None, pad_edge=False, show_header=True, header_style="dim")
        t.add_column("kind", style="dim")
        t.add_column("pattern")
        t.add_column("days left", justify="right")
        t.add_column("uses", justify="right")
        t.add_column("last use", style="dim")
        for p in healthy:
            t.add_row(
                p.kind,
                p.pattern,
                f"[green]{p.days_left}[/green]",
                str(p.use_count),
                str(p.last_use)[:19],
            )
        out.print(t)
    elif healthy and not all_:
        out.print(
            f"[dim]+ {len(healthy)} healthy permission(s) (quill decay show --all to see)[/dim]"
        )


@decay_app.command("reaffirm")
def decay_reaffirm(
    pattern: Annotated[str, typer.Argument(help="tool pattern to reaffirm")],
    kind: Annotated[
        str,
        typer.Option("--kind", help="permission kind (default: best-match policy)"),
    ] = "",
) -> None:
    """Bump a permission's last_reaffirmed timestamp without using it."""
    store = decay_mod.DecayStore.load()
    out = Console()
    if kind:
        p = store.reaffirm(kind, pattern)
        if p is None:
            out.print(f"[yellow]no permission found at {kind}:{pattern}[/yellow]")
            raise typer.Exit(code=1)
        out.print(
            f"[green]reaffirmed[/green] {p.key}  [dim](age 0d, {p.decay_after_days}d window)[/dim]"
        )
        return
    # best-match: any kind matching the pattern
    matches = [p for p in store.all() if p.pattern == pattern]
    if not matches:
        out.print(f"[yellow]no permission found for pattern '{pattern}'[/yellow]")
        raise typer.Exit(code=1)
    for m in matches:
        store.reaffirm(m.kind, m.pattern)
    out.print(
        f"[green]reaffirmed[/green] {len(matches)} permission(s) matching pattern '{pattern}'"
    )


@decay_app.command("forget")
def decay_forget(
    pattern: Annotated[str, typer.Argument(help="tool pattern to drop")],
    kind: Annotated[str, typer.Option("--kind")] = "",
) -> None:
    """Drop a tracked permission entirely (re-registers on next use)."""
    store = decay_mod.DecayStore.load()
    out = Console()
    if kind:
        if store.forget(kind, pattern):
            out.print(f"[green]dropped[/green] {kind}:{pattern}")
        else:
            out.print(f"[yellow]no permission at {kind}:{pattern}[/yellow]")
            raise typer.Exit(code=1)
        return
    matches = [p for p in store.all() if p.pattern == pattern]
    for m in matches:
        store.forget(m.kind, m.pattern)
    out.print(f"[green]dropped[/green] {len(matches)} permission(s)")


# --------------------------------------------------------------------------
# version
# --------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the quill version."""
    console.print(f"quill {__version__}")


# --------------------------------------------------------------------------
# receipts - derive Agent Receipts from the audit log


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _is_test_session_id(sid: str) -> bool:
    """Heuristic: real Claude Code / Cursor session_ids are UUIDs. Anything
    else is a unit-test fixture or a manual smoke test that leaked into
    the audit log. Used by `bridge show`, `trifecta show`, and `receipts
    list` to keep test pollution out of default views; pass
    `--include-test-sessions` to see everything."""
    return not bool(_UUID_RE.match(sid or ""))


@receipts_app.command("list")
def receipts_list(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="audit log to derive from"),
    ] = None,
    last: Annotated[int, typer.Option("--last", help="show only last N sessions")] = 10,
    include_test_sessions: Annotated[
        bool,
        typer.Option(
            "--include-test-sessions",
            help="include sessions whose IDs aren't UUID-shaped (test fixtures)",
        ),
    ] = False,
) -> None:
    """List one Receipt per session in reverse chronological order."""
    from quill.receipt import derive_from_events, load_audit_events

    events = load_audit_events(log_path)
    if not events:
        console.print("[yellow]no audit events yet[/yellow]")
        raise typer.Exit(code=1)
    receipts = derive_from_events(events)
    ordered = sorted(
        (
            r
            for r in receipts.values()
            if include_test_sessions or not _is_test_session_id(r.session_id)
        ),
        key=lambda r: r.opened_at or r.closed_at or "",
        reverse=True,
    )[:last]

    table = Table(title="agent receipts", show_lines=False)
    table.add_column("session", style="dim", no_wrap=True, width=10)
    table.add_column("opened", style="dim", no_wrap=True, width=20)
    table.add_column("calls", justify="right", width=6)
    table.add_column("interv.", justify="right", width=7)
    table.add_column("TDR", justify="right", width=5)
    table.add_column("intent / first did", overflow="fold")
    for r in ordered:
        first_did = r.intent or (r.did[0] if r.did else "")
        table.add_row(
            r.session_id[:8],
            (r.opened_at or "")[:19],
            str(r.tool_call_count),
            str(r.intervention_count),
            f"{r.tdr_contribution:.2f}",
            first_did[:60],
        )
    Console().print(table)


@receipts_app.command("show")
def receipts_show(
    session_id: Annotated[str, typer.Argument(help="session_id (or first 8 chars)")],
    log_path: Annotated[Path | None, typer.Option("--log", "-l")] = None,
    prose_only: Annotated[
        bool,
        typer.Option(
            "--prose",
            help="only the plain-English paragraph; suppress the structured detail",
        ),
    ] = False,
) -> None:
    """Print one full Receipt: plain-English paragraph + structured detail."""
    from quill.receipt import derive_from_events, load_audit_events, narrate

    events = load_audit_events(log_path)
    receipts = derive_from_events(events)
    matches = [r for r in receipts.values() if r.session_id.startswith(session_id)]
    if not matches:
        console.print(f"[red]no session matching[/red] {session_id}")
        raise typer.Exit(code=1)
    r = matches[0]
    out = Console()
    # Headline: plain-English paragraph always prints first.
    out.print(f"[bold]session[/bold] {r.session_id}")
    out.print()
    out.print(narrate(r))
    if prose_only:
        return
    out.print()
    out.print(f"  opened: {r.opened_at or '(unknown)'}")
    out.print(f"  closed: {r.closed_at or '(open)'}")
    if r.intent:
        out.print(f"  intent: {r.intent}")
    out.print(
        f"  TDR={r.tdr_contribution:.2f}  trust_delta={r.trust_delta:+.2f}  "
        f"calls={r.tool_call_count}  interventions={r.intervention_count}"
    )
    if r.did:
        out.print(f"\n[bold]did[/bold] ({len(r.did)})")
        for d in r.did:
            out.print(f"  ✓ {d}")
    if r.changed:
        out.print(f"\n[bold]changed[/bold] ({len(r.changed)})")
        for c in r.changed:
            out.print(f"  · {c}")
    if r.uncertain:
        out.print(f"\n[bold yellow]uncertain[/bold yellow] ({len(r.uncertain)})")
        for u in r.uncertain:
            out.print(f"  ? {u}")
    if r.to_verify:
        out.print(f"\n[bold red]to verify[/bold red] ({len(r.to_verify)})")
        for v in r.to_verify:
            out.print(f"  ! {v}")


# --------------------------------------------------------------------------
# bridge - A2A handoff edges


@bridge_app.command("show")
def bridge_show(
    log_path: Annotated[Path | None, typer.Option("--log", "-l")] = None,
    orphans_only: Annotated[
        bool, typer.Option("--orphans", help="show only unmatched handoffs")
    ] = False,
    include_test_sessions: Annotated[
        bool,
        typer.Option(
            "--include-test-sessions",
            help="include handoffs whose session_ids aren't UUID-shaped (test fixtures)",
        ),
    ] = False,
) -> None:
    """List A2A handoff edges (out, in, orphan, cascade)."""
    from quill.bridge import fold_handoffs
    from quill.receipt import load_audit_events

    events = load_audit_events(log_path)
    handoffs = fold_handoffs(events)
    if not handoffs:
        console.print("[dim]no handoff events yet[/dim]")
        return
    table = Table(title="A2A bridge")
    table.add_column("payload_hash", style="dim", no_wrap=True, width=12)
    table.add_column("out → in", width=10)
    table.add_column("status", width=10)
    table.add_column("contract", overflow="fold")
    rendered = 0
    for h in handoffs.values():
        if orphans_only and not h.is_orphan:
            continue
        if not include_test_sessions:
            sid = ""
            if h.out_event:
                sid = str(h.out_event.get("session_id") or "")
            elif h.in_events:
                sid = str(h.in_events[0].get("session_id") or "")
            if _is_test_session_id(sid):
                continue
        out_seen = "✓" if h.out_event else "·"
        in_count = len(h.in_events)
        status = "orphan" if h.is_orphan else ("cascade" if h.is_cascade else "ok")
        contract = ""
        if h.out_event:
            contract = str((h.out_event.get("payload") or {}).get("contract") or "")
        table.add_row(
            h.payload_hash[:12],
            f"{out_seen} → {in_count}",
            status,
            contract,
        )
        rendered += 1
    if rendered == 0:
        console.print(
            "[dim]no real handoff events yet (use --include-test-sessions to see fixtures)[/dim]",
        )
        return
    Console().print(table)


# --------------------------------------------------------------------------
# trifecta - has this session seen untrusted input + private data + an exfil
# vector all together? Internally called "taint" (security term-of-art); the
# public surface uses plain English.


@trifecta_app.command("show")
def trifecta_show(
    log_path: Annotated[Path | None, typer.Option("--log", "-l")] = None,
    closed_only: Annotated[
        bool, typer.Option("--closed", help="only sessions that crossed all three lines")
    ] = False,
    include_test_sessions: Annotated[
        bool,
        typer.Option(
            "--include-test-sessions",
            help="include sessions whose IDs aren't UUID-shaped (test fixtures)",
        ),
    ] = False,
) -> None:
    """Per-session exposure: did the agent see untrusted input + private data
    + an exfiltration vector all in the same session? That's the worst-case
    prompt-injection scenario; two of three is recoverable.
    """
    from quill.receipt import load_audit_events
    from quill.taint import fold_audit_events

    events = load_audit_events(log_path)
    states = fold_audit_events(events)
    if not states:
        console.print("[dim]no exposure observations yet[/dim]")
        return
    table = Table(title="session exposure (untrusted input · private data · exfil vector)")
    table.add_column("session", style="dim", no_wrap=True, width=10)
    table.add_column("untrusted input", justify="center", width=15)
    table.add_column("private data", justify="center", width=14)
    table.add_column("exfil vector", justify="center", width=14)
    table.add_column("verdict")
    rendered = 0
    for sid, state in states.items():
        if closed_only and not state.trifecta_closed:
            continue
        if not include_test_sessions and _is_test_session_id(sid):
            continue
        flag_count = sum(
            [
                state.has_seen_untrusted,
                state.has_accessed_private,
                state.can_exfiltrate,
            ]
        )
        verdict = (
            "[red]all three[/red]"
            if state.trifecta_closed
            else f"[yellow]{flag_count}-of-3[/yellow]"
            if flag_count == 2
            else "[green]safe[/green]"
        )
        table.add_row(
            sid[:8],
            "yes" if state.has_seen_untrusted else "-",
            "yes" if state.has_accessed_private else "-",
            "yes" if state.can_exfiltrate else "-",
            verdict,
        )
        rendered += 1
    if rendered == 0:
        console.print(
            "[dim]no real session exposure yet (use --include-test-sessions to see fixtures)[/dim]",
        )
        return
    Console().print(table)


# --------------------------------------------------------------------------
# pins - tool description pinning (anti-tool-poisoning, anti-rug-pull)


@pins_app.command("list")
def pins_list(
    upstream: Annotated[str | None, typer.Option("--upstream", "-u")] = None,
) -> None:
    """List pinned tools. Pins are auto-recorded on first sight; new digests
    require explicit approval before the tool is re-advertised to the client.
    """
    from quill.pinning import PinStore

    store = PinStore.load()
    if not store.pins:
        console.print("[dim]no pins yet - pins are recorded on first sight of each tool[/dim]")
        return
    table = Table(title="tool pins")
    table.add_column("upstream", style="dim", no_wrap=True, width=14)
    table.add_column("tool", no_wrap=True, width=24)
    table.add_column("digest", style="dim", width=14)
    table.add_column("first seen", style="dim", width=20)
    table.add_column("approved by", width=16)
    table.add_column("status")
    for (up, name), pin in sorted(store.pins.items()):
        if upstream and up != upstream:
            continue
        status = "[red]revoked[/red]" if pin.revoked_at else "[green]active[/green]"
        table.add_row(
            up,
            name,
            pin.digest[:12] + "…",
            pin.first_seen[:19],
            pin.approved_by,
            status,
        )
    Console().print(table)


@pins_app.command("approve")
def pins_approve(
    upstream: Annotated[str, typer.Argument(help="upstream name (e.g. filesystem)")],
    tool_name: Annotated[str, typer.Argument(help="tool name (e.g. read_file)")],
    digest: Annotated[str, typer.Argument(help="full SHA-256 digest from the refusal message")],
) -> None:
    """Approve a new digest for a tool. Use after a legitimate upstream update
    or after manually inspecting a description change.
    """
    from quill.pinning import PinStore

    store = PinStore.load()
    store.approve(upstream, tool_name, digest, by=f"user:{os.environ.get('USER', 'cli')}")
    console.print(
        f"[green]approved[/green] {upstream}.{tool_name} digest={digest[:12]}…",
    )


@pins_app.command("revoke")
def pins_revoke(
    upstream: Annotated[str, typer.Argument()],
    tool_name: Annotated[str, typer.Argument()],
) -> None:
    """Revoke a pinned tool. Future verify() refuses; tool is hidden from the
    client until re-approved with a new digest.
    """
    from quill.pinning import PinStore

    store = PinStore.load()
    store.revoke(upstream, tool_name)
    console.print(f"[yellow]revoked[/yellow] {upstream}.{tool_name}")


# --------------------------------------------------------------------------
# approve - the "go ahead" path, called from a notification


@app.command("approve")
def approve_token(
    token: Annotated[
        str | None,
        typer.Argument(
            help="approval token from a Quill notification "
            "(omit and use --latest to approve the most recent block)"
        ),
    ] = None,
    latest: Annotated[
        bool,
        typer.Option(
            "--latest",
            help="approve the most recently blocked call without copying its token",
        ),
    ] = False,
    no_biometric: Annotated[
        bool,
        typer.Option(
            "--no-biometric",
            help="skip the Touch ID prompt even if available (typed-token-only)",
        ),
    ] = False,
    require_biometric: Annotated[
        bool,
        typer.Option(
            "--require-biometric",
            help="refuse to approve if Touch ID is unavailable",
        ),
    ] = False,
) -> None:
    """Confirm a pending one-shot approval token.

    When Quill blocks a tool call, the user gets a notification with a
    short token. Running `quill approve <token>` marks that exact
    (tool_name, args) pair as approved for the next ~10 minutes; the
    next time the agent retries that exact call, the gate consumes the
    approval and lets it through.

    On macOS with Touch ID available, this command requires a fingerprint
    match before persisting the approval - so a compromised terminal that
    can type the token still can't release the call. Pass --no-biometric
    to skip the prompt (useful in headless / SSH sessions); pass
    --require-biometric to refuse approval when Touch ID isn't available.

    One-shot by design: an attacker who hijacks the agent mid-session
    can't reuse the token for a different command.
    """
    from quill import events as ev
    from quill.approvals import ApprovalStore

    store = ApprovalStore.load()

    # --latest (or a bare `quill approve`) resolves to the most recently issued
    # pending block, so the operator never has to copy the exact token string -
    # they just confirm "yes, the thing I was just asked about" with Touch ID.
    if latest or token is None:
        chosen = store.latest_pending()
        if chosen is None:
            console.print(
                "[red]no pending approvals to confirm.[/red]\n"
                "  nothing is currently blocked and awaiting your go-ahead."
            )
            raise typer.Exit(code=1)
        token = chosen.token
        console.print(
            f"  [dim]approving the most recent block: "
            f"[bold]{chosen.tool_name}[/bold] · "
            f"{chosen.reason or 'tool call'}[/dim]"
        )

    ap = store.approve(token)
    if ap is None:
        console.print(
            f"[red]no active approval matching[/red] [bold]{token}[/bold]\n"
            "  it may have expired (TTL is 10 minutes), already been "
            "consumed, or never existed.",
        )
        raise typer.Exit(code=1)

    biometric_reason = ""
    biometric_event: str | None = None
    # --require-biometric overrides --no-biometric (paranoid mode): you may opt
    # out of Touch ID, but not while also demanding it. Default (neither flag):
    # biometric is attempted, and an unavailable sensor REFUSES (see below).
    skip_biometric = no_biometric and not require_biometric
    if not skip_biometric:
        from quill import touchid

        if touchid.is_available():
            console.print(
                f"  [dim]Touch ID required to approve "
                f"[bold]{ap.tool_name}[/bold] · check the sensor[/dim]",
            )
            res = touchid.authenticate(
                f"approve {ap.tool_name} (token {token[:8]})",
            )
            if res.success:
                biometric_event = ev.APPROVE_BIOMETRIC_OK
                biometric_reason = "ok"
            else:
                # Failure: revoke the just-issued approval state and refuse.
                store.revoke(token)
                biometric_event = ev.APPROVE_BIOMETRIC_DENY
                biometric_reason = res.reason
                console.print(
                    f"[red]biometric refused[/red]: {res.reason}\n"
                    "  approval REVOKED. agent retry will not be allowed.",
                )
                _emit_approve_audit(
                    biometric_event,
                    token,
                    ap.tool_name,
                    biometric_reason,
                )
                raise typer.Exit(code=2)
        else:
            # Touch ID unavailable in THIS context (the agent's own process has
            # no GUI/Secure-Enclave session; SSH and headless daemons too).
            # REFUSE by default - this is load-bearing. Allowing a no-biometric
            # approval when the sensor can't fire is exactly the self-approval
            # hole an agent walks through: it can read the token from
            # `quill approvals list` and run `quill approve` in its own context,
            # which has no Touch ID, so a skip-on-unavailable default lets it
            # release its own blocked call with zero human involvement. The
            # operator must approve from a session where Touch ID works, or pass
            # --no-biometric to explicitly opt into typed-token-only approval.
            store.revoke(token)
            console.print(
                "[red]Touch ID unavailable in this context - approval REFUSED.[/red]\n"
                "  An agent's own process can't reach the sensor, so approving\n"
                "  here would let it self-approve. Approve from a Terminal in\n"
                "  your GUI login session (where Touch ID works), or pass\n"
                "  --no-biometric to opt into typed-token-only approval.",
            )
            _emit_approve_audit(
                ev.APPROVE_BIOMETRIC_DENY,
                token,
                ap.tool_name,
                "not_available",
            )
            raise typer.Exit(code=2)
    else:
        biometric_event = ev.APPROVE_BIOMETRIC_SKIPPED
        biometric_reason = "user_opted_out"

    if biometric_event is not None:
        _emit_approve_audit(biometric_event, token, ap.tool_name, biometric_reason)

    console.print(
        f"[green]approved[/green] [bold]{ap.tool_name}[/bold] for one call · "
        f"expires {ap.expires_at[:19]}",
    )
    if ap.reason:
        console.print(f"  reason: [dim]{ap.reason}[/dim]")
    if biometric_reason == "ok":
        console.print("  [dim]Touch ID confirmed[/dim]")
    console.print(
        "  the agent's next attempt of this exact call will go through.",
    )


def _emit_approve_audit(
    event_type: str,
    token: str,
    tool_name: str,
    reason: str,
) -> None:
    """Best-effort emit a Touch ID outcome to the chained audit log."""
    from quill.audit import AuditLog

    try:
        key = _hmac_key()
        with AuditLog(path=default_audit_path(), hmac_key=key) as audit:
            audit.emit(
                event_type=event_type,
                session_id="quill-approve-cli",
                agent_id="quill.approve",
                risk="high",
                payload={
                    "token_prefix": token[:8],
                    "tool_name": tool_name,
                    "reason": reason,
                },
                force_fsync=True,
            )
    except Exception:
        # Approve must succeed even if audit-emit fails; the approval
        # itself is already persisted to approvals.json.
        pass


@approvals_app.command("list")
def approvals_list() -> None:
    """List pending one-shot approval tokens (issued, unconsumed, unexpired)."""
    import hashlib

    from quill.approvals import ApprovalStore

    store = ApprovalStore.load()
    active = store.active()
    if not active:
        console.print("[dim]no pending approvals[/dim]")
        return
    # SECURITY: show a HASHED id, never the raw token. The raw token is what
    # `quill approve <token>` consumes; printing it here let an agent read its
    # own pending token and self-approve (esp. with --no-biometric). The
    # operator confirms with `quill approve --latest` (Touch-ID gated) and never
    # needs to copy a token string.
    table = Table(title="pending approvals")
    table.add_column("id (hashed)", no_wrap=True, width=14)
    table.add_column("tool", no_wrap=True, width=18)
    table.add_column("issued", style="dim", width=20)
    table.add_column("expires", style="dim", width=20)
    table.add_column("reason", overflow="fold")
    for ap in active:
        table.add_row(
            hashlib.sha256(ap.token.encode()).hexdigest()[:12],
            ap.tool_name,
            ap.issued_at[:19],
            ap.expires_at[:19],
            ap.reason[:80],
        )
    Console().print(table)
    Console().print(
        "[dim]approve the most recent with [bold]quill approve --latest[/bold] "
        "(Touch ID); raw tokens are no longer printed.[/dim]"
    )


@approvals_app.command("revoke")
def approvals_revoke(
    token: Annotated[str, typer.Argument()],
) -> None:
    """Drop a token without consuming it. Useful if the notification was
    surprising and you DON'T want the agent to retry."""
    from quill.approvals import ApprovalStore

    store = ApprovalStore.load()
    if store.revoke(token):
        console.print(f"[yellow]revoked[/yellow] {token}")
    else:
        console.print(f"[dim]no token[/dim] {token}")
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# trust - per-directory trust scopes. The fix for approval fatigue.
# Edit/Write inside a trusted path auto-allows; everything else still gates.


def _load_or_init_config_toml() -> tuple[Path, dict[str, object]]:
    """Read ~/.quill/config.toml as a mutable dict; init a minimal one if missing.

    Returns (path, data). Caller mutates data and writes it back. Keeps the
    starter `[session] intent = "..."` line so future `load_config()` calls
    still pass Pydantic validation - QuillConfig requires SessionConfig.
    """
    import sys as _sys

    if _sys.version_info >= (3, 11):
        import tomllib as _tomllib
    else:
        import tomli as _tomllib  # type: ignore[no-redef]
    from quill.config import default_config_path

    p = default_config_path()
    data: dict[str, object] = {}
    if p.exists():
        with contextlib.suppress(OSError, _tomllib.TOMLDecodeError), p.open("rb") as f:
            data = _tomllib.load(f) or {}
    if "session" not in data:
        # Minimum viable session block so load_config() validation passes
        # after our write. Operator can edit the intent later.
        data["session"] = {"intent": "(autocreated by quill trust)", "scope": []}
    return p, data


def _write_config_toml(path: Path, data: dict[str, object]) -> None:
    """Write the config dict back as TOML. Stdlib has no toml writer, so we
    hand-format - simple key/value, [section], [[upstream]] arrays. Good
    enough for the small surface quill writes (trust / policy / [session])."""
    out: list[str] = []
    # Order: session, audit, trust, policy, telemetry, upstream, then anything else
    section_order = ["session", "audit", "trust", "policy", "telemetry"]
    written: set[str] = set()

    def fmt_value(v: object) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, str):
            # TOML basic string with backslash + dquote escaping
            return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
        if isinstance(v, list):
            return "[" + ", ".join(fmt_value(x) for x in v) + "]"
        return '"' + str(v).replace('"', '\\"') + '"'

    def emit_section(name: str, body: object) -> None:
        if not isinstance(body, dict):
            return
        out.append(f"[{name}]")
        for k, v in body.items():
            out.append(f"{k} = {fmt_value(v)}")
        out.append("")

    for name in section_order:
        if name in data:
            emit_section(name, data[name])
            written.add(name)
    # Pass through any other top-level dict sections (e.g. [bash], [notify]).
    for name, body in data.items():
        if name in written:
            continue
        if name == "upstream" and isinstance(body, list):
            for item in body:
                if isinstance(item, dict):
                    out.append("[[upstream]]")
                    for k, v in item.items():
                        out.append(f"{k} = {fmt_value(v)}")
                    out.append("")
            written.add(name)
            continue
        if isinstance(body, dict):
            emit_section(name, body)
        written.add(name)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out).rstrip() + "\n")
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def _normalize_trust_path(raw: str) -> str:
    """Operator-facing: take a path, return its resolved absolute form.

    `~/foo` -> `/Users/.../foo`. Non-existent paths are still returned
    (operator might be pre-adding a path they're about to create).
    """
    return str(Path(raw).expanduser().resolve(strict=False))


@trust_app.command("add")
def trust_add(
    path: Annotated[
        str,
        typer.Argument(help="directory to trust. Edit/Write inside it auto-allows."),
    ],
) -> None:
    """Add a directory to the trust list.

    After this runs, every default-HIGH-risk Edit/Write/MultiEdit/NotebookEdit
    inside that directory (or any subdirectory) auto-allows instead of
    asking for approval. Pattern-matched HIGHs (vercel --prod, curl, rm -rf)
    and CRITICAL events still fire regardless of trust.
    """
    resolved = _normalize_trust_path(path)
    cfg_path, data = _load_or_init_config_toml()
    trust_block = data.get("trust") or {}
    if not isinstance(trust_block, dict):
        trust_block = {}
    paths = list(trust_block.get("paths") or [])
    if resolved in paths:
        console.print(f"  [dim]already trusted:[/dim] {resolved}")
        return
    paths.append(resolved)
    trust_block["paths"] = paths
    data["trust"] = trust_block
    _write_config_toml(cfg_path, data)
    console.print(f"  [green]trusted[/green] {resolved}")
    console.print(f"  [dim]config:[/dim] {cfg_path}")


@trust_app.command("remove")
def trust_remove(
    path: Annotated[
        str,
        typer.Argument(help="directory to untrust. Future Edit/Write will gate again."),
    ],
) -> None:
    """Remove a directory from the trust list."""
    resolved = _normalize_trust_path(path)
    cfg_path, data = _load_or_init_config_toml()
    trust_block = data.get("trust") or {}
    if not isinstance(trust_block, dict):
        trust_block = {}
    paths = list(trust_block.get("paths") or [])
    if resolved not in paths:
        console.print(f"  [yellow]not in trust list:[/yellow] {resolved}")
        raise typer.Exit(code=1)
    paths = [p for p in paths if p != resolved]
    trust_block["paths"] = paths
    data["trust"] = trust_block
    _write_config_toml(cfg_path, data)
    console.print(f"  [red]untrusted[/red] {resolved}")


@trust_app.command("list")
def trust_list() -> None:
    """Show every trusted directory."""
    cfg_path, data = _load_or_init_config_toml()
    trust_block = data.get("trust") or {}
    if not isinstance(trust_block, dict):
        trust_block = {}
    paths = list(trust_block.get("paths") or [])
    if not paths:
        console.print("[dim]no trusted directories yet.[/dim]")
        console.print(f"[dim]add with: quill trust add <path>  ({cfg_path})[/dim]")
        return
    console.print(f"[bold]trusted directories[/bold]  ({cfg_path})")
    for p in paths:
        exists_tag = "" if Path(p).exists() else "  [yellow](missing on disk)[/yellow]"
        console.print(f"  {p}{exists_tag}")


@trust_app.command("check")
def trust_check(
    cwd: Annotated[
        str | None,
        typer.Argument(help="directory to test (defaults to current cwd)"),
    ] = None,
) -> None:
    """Test whether a given directory is currently trusted."""
    from quill.paths import is_trusted_cwd

    target = cwd or str(Path.cwd())
    resolved = str(Path(target).expanduser().resolve(strict=False))
    if is_trusted_cwd(resolved):
        console.print(f"  [green]trusted[/green] {resolved}")
    else:
        console.print(f"  [dim]not trusted[/dim] {resolved}")
        console.print(f"  [dim]add with: quill trust add {resolved}[/dim]")
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# suggestions - the operator-facing surface for the learner's
# loosening candidates + drift detections + operator-anomaly events.
# Auto-tightenings are recorded too (for transparency) but already
# applied.


def _suggestion_key(s: dict[str, Any]) -> str:
    """Stable key for a suggestion: pattern_id + type. Used to dedup
    multiple firings of the same suggestion across days."""
    pid = s.get("pattern_id") or s.get("session_id") or "(global)"
    return f"{s.get('type', '?')}:{pid}"


@suggestions_app.command("list")
def suggestions_list(
    only: Annotated[
        str | None,
        typer.Option(
            "--only",
            help="filter by type: tightening_auto_applied | loosening_candidate | operator_anomaly | drift_detected",
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="max suggestions to show"),
    ] = 50,
) -> None:
    """List learner-surfaced suggestions, newest first. Dedup by
    (type, pattern_id) so a streak of the same suggestion shows once."""
    from quill.learning import read_suggestions

    raw = read_suggestions(limit=limit * 5)
    raw.sort(key=lambda s: s.get("ts", 0), reverse=True)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for s in raw:
        if only and s.get("type") != only:
            continue
        key = _suggestion_key(s)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
        if len(out) >= limit:
            break
    if not out:
        console.print("[dim]no suggestions in the queue.[/dim]")
        return
    sev_color = {
        "tightening_auto_applied": "yellow",
        "loosening_candidate": "cyan",
        "operator_anomaly": "red",
        "drift_detected": "magenta",
    }
    for s in out:
        color = sev_color.get(s.get("type", ""), "white")
        ts = s.get("ts", 0)
        try:
            ts_label = datetime.fromtimestamp(float(ts)).strftime("%m-%d %H:%M")
        except (ValueError, TypeError):
            ts_label = "?"
        console.print(
            f"  [dim]{ts_label}[/dim]  [{color}]{s.get('type', '?')}[/{color}]  "
            f"[bold]{s.get('pattern_id') or s.get('session_id') or ''}[/bold]"
        )
        ev = s.get("evidence", "")
        if ev:
            console.print(f"          [dim]{ev[:140]}[/dim]")
        if s.get("type") == "loosening_candidate":
            console.print(
                f'          [bold]apply:[/bold] quill suggestions promote "{_suggestion_key(s)}"'
            )


@suggestions_app.command("show")
def suggestions_show(
    key: Annotated[
        str,
        typer.Argument(help="suggestion key from `quill suggestions list` (type:pattern)"),
    ],
) -> None:
    """Show full detail for one suggestion."""
    from quill.learning import read_suggestions

    raw = read_suggestions(limit=1000)
    matching = [s for s in raw if _suggestion_key(s) == key]
    if not matching:
        console.print(f"[yellow]no suggestion matching key:[/yellow] {key}")
        raise typer.Exit(code=1)
    s = matching[-1]
    console.print(json.dumps(s, indent=2))


@suggestions_app.command("promote")
def suggestions_promote(
    key: Annotated[
        str,
        typer.Argument(help="suggestion key (type:pattern)"),
    ],
    ttl_days: Annotated[
        int,
        typer.Option("--ttl-days", help="how long the override lives"),
    ] = 30,
) -> None:
    """Promote a loosening_candidate to a real override. Writes to
    `~/.quill/overrides.toml` with the given TTL. The operator's
    explicit approval lives here - the learner never wrote it itself.
    """
    from quill.learning import read_suggestions

    raw = read_suggestions(limit=1000)
    matching = [
        s for s in raw if _suggestion_key(s) == key and s.get("type") == "loosening_candidate"
    ]
    if not matching:
        console.print(f"[yellow]no loosening_candidate matching key:[/yellow] {key}")
        raise typer.Exit(code=1)
    s = matching[-1]

    overrides_path = Path(
        os.environ.get(
            "QUILL_OVERRIDES",
            str(Path.home() / ".quill" / "overrides.toml"),
        )
    ).expanduser()
    overrides_path.parent.mkdir(parents=True, exist_ok=True)

    pattern_id = str(s.get("pattern_id") or "")
    # Make a TOML-safe section name
    section = "".join(c if c.isalnum() or c in "_-" else "_" for c in pattern_id)[:60]
    existing = overrides_path.read_text() if overrides_path.exists() else ""
    block = (
        f"\n[overrides.{section}]\n"
        f'pattern_id = "{pattern_id}"\n'
        f'promoted_at = "{datetime.now(UTC).isoformat()}"\n'
        f"ttl_days = {ttl_days}\n"
        f'evidence = "{s.get("evidence", "")[:200].replace(chr(34), chr(39))}"\n'
    )
    overrides_path.write_text(existing + block)
    with contextlib.suppress(OSError):
        overrides_path.chmod(0o600)

    # Append a tracking entry to suggestions.jsonl
    from quill.learning import append_suggestion, log_event

    promo = {
        "ts": time.time(),
        "type": "loosening_promoted",
        "pattern_id": pattern_id,
        "ttl_days": ttl_days,
        "promoted_via": "quill suggestions promote",
        "evidence_source": s.get("evidence", ""),
    }
    append_suggestion(promo)
    log_event(f"promoted pattern={pattern_id} ttl_days={ttl_days}")
    console.print(
        f"  [green]promoted[/green] {pattern_id}  "
        f"[dim](ttl {ttl_days}d, written to {overrides_path})[/dim]"
    )


@suggestions_app.command("cleanup")
def suggestions_cleanup(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="show what would be removed, don't change anything"),
    ] = False,
) -> None:
    """Remove stale per-token pattern rows from pattern_stats.json.

    A pre-rc5 bug derived the pattern_id from the FLIPPED decision
    reason after a token consume, producing one dead row per token
    (e.g. `Bash:approved one-shot via quill approve aBc12`). This
    command cleans those up. Real patterns are untouched.

    Idempotent: a second invocation after the first removes nothing.
    """
    from quill.learning import cleanup_stale_patterns, find_stale_patterns

    if dry_run:
        stale = find_stale_patterns()
        if not stale:
            console.print("[dim]no stale rows to clean up.[/dim]")
            return
        console.print(f"would remove [yellow]{len(stale)}[/yellow] stale row(s):")
        for pid in stale[:20]:
            console.print(f"  [dim]{pid}[/dim]")
        if len(stale) > 20:
            console.print(f"  [dim]... and {len(stale) - 20} more[/dim]")
        return
    n, removed = cleanup_stale_patterns()
    if n == 0:
        console.print("[dim]nothing to clean up.[/dim]")
        return
    console.print(f"[green]removed[/green] {n} stale pattern row(s).")
    for pid in removed[:10]:
        console.print(f"  [dim]{pid}[/dim]")
    if len(removed) > 10:
        console.print(f"  [dim]... and {len(removed) - 10} more[/dim]")


@suggestions_app.command("dismiss")
def suggestions_dismiss(
    key: Annotated[
        str,
        typer.Argument(help="suggestion key to dismiss"),
    ],
) -> None:
    """Dismiss a suggestion. Appends a `dismissed` entry to
    suggestions.jsonl so subsequent `list` calls hide it. Append-only;
    no in-place edits."""
    from quill.learning import append_suggestion, log_event

    entry = {
        "ts": time.time(),
        "type": "dismissed",
        "dismissed_key": key,
    }
    append_suggestion(entry)
    log_event(f"dismissed key={key}")
    console.print(f"  [red]dismissed[/red] {key}")


# --------------------------------------------------------------------------
# log - tail the learner's append-only logs in real time so the
# operator can SEE what Quill is doing as it does it.

import time as _time  # noqa: E402 - placement next to its sole user


@app.command("log")
def log_cmd(
    follow: Annotated[
        bool,
        typer.Option("--follow", "-f", help="stream new entries as they arrive"),
    ] = False,
    n: Annotated[
        int,
        typer.Option("--lines", "-n", help="how many trailing lines to show"),
    ] = 30,
    show_suggestions: Annotated[
        bool,
        typer.Option(
            "--suggestions/--no-suggestions",
            help="also tail ~/.quill/suggestions.jsonl",
        ),
    ] = True,
) -> None:
    """Show the learner's recent activity. With --follow, streams new
    entries in real time so you can watch Quill update itself.
    """
    from quill.learning import _log_path, _suggestions_path

    log_path = _log_path()
    sug_path = _suggestions_path()

    if not log_path.exists() and not sug_path.exists():
        console.print(f"[dim]no learner activity yet. The log lives at {log_path}.[/dim]")
        return

    def _print_recent() -> None:
        if log_path.exists():
            lines = log_path.read_text().splitlines()[-n:]
            for line in lines:
                console.print(line)
        if show_suggestions and sug_path.exists():
            sugs = sug_path.read_text().splitlines()[-n:]
            for raw in sugs:
                try:
                    s = json.loads(raw)
                    console.print(
                        f"[dim](suggestion)[/dim] "
                        f"[cyan]{s.get('type')}[/cyan] "
                        f"{s.get('pattern_id') or s.get('session_id') or ''} "
                        f"[dim]{s.get('evidence', '')[:100]}[/dim]"
                    )
                except json.JSONDecodeError:
                    continue

    _print_recent()
    if not follow:
        return

    # Follow mode: poll for size changes. Sub-second granularity.
    last_log_size = log_path.stat().st_size if log_path.exists() else 0
    last_sug_size = sug_path.stat().st_size if sug_path.exists() else 0
    try:
        while True:
            _time.sleep(0.4)
            if log_path.exists():
                sz = log_path.stat().st_size
                if sz > last_log_size:
                    with log_path.open() as f:
                        f.seek(last_log_size)
                        new = f.read()
                    last_log_size = sz
                    for line in new.splitlines():
                        if line.strip():
                            console.print(line)
            if show_suggestions and sug_path.exists():
                sz = sug_path.stat().st_size
                if sz > last_sug_size:
                    with sug_path.open() as f:
                        f.seek(last_sug_size)
                        new = f.read()
                    last_sug_size = sz
                    for raw in new.splitlines():
                        if not raw.strip():
                            continue
                        try:
                            s = json.loads(raw)
                            console.print(
                                f"[dim](suggestion)[/dim] "
                                f"[cyan]{s.get('type')}[/cyan] "
                                f"{s.get('pattern_id') or s.get('session_id') or ''}"
                            )
                        except json.JSONDecodeError:
                            continue
    except KeyboardInterrupt:
        console.print("[dim]\n(stopped)[/dim]")


def main() -> None:  # entry point for the [project.scripts] hook
    app()


if __name__ == "__main__":
    main()
