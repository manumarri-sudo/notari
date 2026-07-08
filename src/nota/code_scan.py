"""Pre-execution AST scan for the write-then-run loophole.

The classifier (``policy.py``) sees a *command string* and the secret
scanner (``secrets.py``) sees *credential shapes*. Neither sees the
*semantics* of a Python file an agent is about to write and then execute
in a later, already-allowed ``python foo.py`` call - the write-then-run
hole (SECURITY-MODEL.md limit 3).

This module closes part of that hole at write time: when the agent writes
a ``.py`` file (or a payload that parses as Python), we parse it with the
stdlib ``ast`` module and walk it for destructive shapes - ``shutil.rmtree``,
``os.system``, ``subprocess`` spawns, and the classic
``exec(base64.b64decode(...))`` obfuscated-payload pattern. A hit escalates
the write to CRITICAL with a precise, line-numbered reason, exactly like a
secret hit does.

Design constraints (mirrors the rest of the gate):
  * Deterministic. Pure AST structure matching, no LLM, no heuristics that
    vary by run.
  * Fail-open on its OWN errors, never fail-open on a detection. A file we
    cannot parse (syntax error, not Python) yields NO findings - we do not
    block valid non-Python writes - but a parse we *can* do and that
    contains a destructive shape always reports it.
  * No execution. We never import, compile-to-code-object, or run the
    scanned source. ``ast.parse`` does not execute.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

# Attribute-call shapes that are destructive on their face. Keyed by the
# (module, attr) pair the call resolves to; value is (rule, critical, why).
_DESTRUCTIVE_CALLS: dict[tuple[str, str], tuple[str, bool, str]] = {
    ("shutil", "rmtree"): ("shutil-rmtree", True, "recursive tree delete"),
    ("os", "system"): ("os-system", True, "shells out to an arbitrary command"),
    ("os", "popen"): ("os-popen", True, "shells out to an arbitrary command"),
    ("os", "remove"): ("os-remove", False, "deletes a file"),
    ("os", "unlink"): ("os-unlink", False, "deletes a file"),
    ("os", "rmdir"): ("os-rmdir", False, "removes a directory"),
    ("os", "removedirs"): ("os-removedirs", True, "removes a directory tree"),
    ("os", "truncate"): ("os-truncate", False, "truncates a file"),
    ("marshal", "loads"): ("marshal-loads", True, "deserializes executable bytecode"),
    ("pickle", "loads"): ("pickle-loads", True, "pickle deserialization is code execution"),
    ("pickle", "load"): ("pickle-load", True, "pickle deserialization is code execution"),
}

# Whole module prefixes whose any-call is a subprocess spawn.
_SUBPROCESS_MODULES = {"subprocess"}

# os.exec* / os.spawn* families - matched by prefix on the attribute name.
_OS_EXEC_PREFIXES = ("exec", "spawn", "posix_spawn")

# Builtins that execute a string/code object.
_EXEC_BUILTINS = {"exec", "eval", "compile"}

# Calls that turn opaque data back into a string/bytes payload - the decode
# half of a decode-to-exec. A hit is only CRITICAL when nested inside an
# exec/eval/compile; on its own it is reported as a (non-critical) signal.
_DECODERS = {
    ("base64", "b64decode"),
    ("base64", "b64encode"),  # encode appears in round-trip obfuscation too
    ("base64", "b32decode"),
    ("base64", "a85decode"),
    ("base64", "urlsafe_b64decode"),
    ("codecs", "decode"),
    ("bytes", "fromhex"),
    ("binascii", "unhexlify"),
    ("binascii", "a2b_base64"),
}


@dataclass(frozen=True, slots=True)
class CodeFinding:
    """One destructive shape located in a scanned source file."""

    lineno: int
    col: int
    rule: str
    message: str
    critical: bool

    def as_reason(self) -> str:
        """One-line, line-numbered reason for the gate's block message."""
        return f"{self.message} (`{self.rule}` at line {self.lineno})"


def _attr_chain(node: ast.AST) -> tuple[str, str] | None:
    """Resolve a call's func to a (root, attr) pair, e.g. ``shutil.rmtree``.

    Returns the leftmost Name and the immediate attribute, so
    ``os.path.join`` -> ("path", "join") and ``shutil.rmtree`` ->
    ("shutil", "rmtree"). Only handles ``Name.attr`` and
    ``Name.x.attr``; deeper chains resolve on their nearest Name.
    """
    if isinstance(node, ast.Attribute):
        value = node.value
        if isinstance(value, ast.Name):
            return value.id, node.attr
        if isinstance(value, ast.Attribute):
            return value.attr, node.attr
    return None


def _subtree_has_decoder(node: ast.AST) -> bool:
    """True if any decode-to-string call lives anywhere under ``node``."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            pair = _attr_chain(child.func)
            if pair is not None and pair in _DECODERS:
                return True
            # bare fromhex()/decode() with no module is ambiguous; ignore.
    return False


class _DestructiveVisitor(ast.NodeVisitor):
    """Walks a parsed module collecting destructive-shape findings."""

    def __init__(self) -> None:
        self.findings: list[CodeFinding] = []

    def _add(self, node: ast.AST, rule: str, message: str, *, critical: bool) -> None:
        self.findings.append(
            CodeFinding(
                lineno=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                rule=rule,
                message=message,
                critical=critical,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # 1. exec / eval / compile - critical, and doubly so when fed a decoder.
        if isinstance(func, ast.Name) and func.id in _EXEC_BUILTINS:
            if any(_subtree_has_decoder(arg) for arg in node.args):
                self._add(
                    node,
                    "exec-decoded-payload",
                    f"{func.id}() of a decoded (base64/hex) payload - obfuscated code execution",
                    critical=True,
                )
            else:
                self._add(
                    node,
                    f"{func.id}-call",
                    f"{func.id}() executes a dynamically-built string",
                    critical=True,
                )

        # 2. __import__('os') and friends - dynamic import to dodge static scan.
        if isinstance(func, ast.Name) and func.id == "__import__":
            self._add(
                node,
                "dynamic-import",
                "__import__() resolves a module name at runtime",
                critical=False,
            )

        pair = _attr_chain(func)
        if pair is not None:
            root, attr = pair
            # 3. Known destructive attribute calls (shutil.rmtree, os.system, ...).
            if pair in _DESTRUCTIVE_CALLS:
                rule, critical, why = _DESTRUCTIVE_CALLS[pair]
                self._add(node, rule, f"{root}.{attr}() {why}", critical=critical)
            # 4. subprocess.* - any spawn.
            elif root in _SUBPROCESS_MODULES:
                shell = _has_shell_true(node)
                self._add(
                    node,
                    "subprocess-shell" if shell else "subprocess",
                    f"subprocess.{attr}() spawns a process"
                    + (" with shell=True (command injection surface)" if shell else ""),
                    critical=shell,
                )
            # 5. os.exec*/os.spawn* process-replacement family.
            elif root == "os" and attr.startswith(_OS_EXEC_PREFIXES):
                self._add(
                    node,
                    "os-exec",
                    f"os.{attr}() replaces/forks the process image",
                    critical=True,
                )

        self.generic_visit(node)


def _has_shell_true(node: ast.Call) -> bool:
    """True if the call passes ``shell=True``."""
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def scan_source(source: str, *, filename: str = "<write>") -> list[CodeFinding]:
    """Parse ``source`` as Python and return destructive-shape findings.

    Non-Python or syntactically-invalid input yields ``[]`` - we never
    block a write we cannot prove is destructive. Findings are sorted by
    line so the first one is the most useful to surface.
    """
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError):
        return []
    visitor = _DestructiveVisitor()
    visitor.visit(tree)
    return sorted(visitor.findings, key=lambda f: (f.lineno, f.col))


# File extensions we attempt to parse as Python. A payload with no extension
# is still scanned if it begins with a python shebang.
_PY_SUFFIXES = (".py", ".pyw", ".pyi")


def looks_like_python(path: str, content: str) -> bool:
    """Heuristic: should we even try to AST-parse this write as Python?"""
    lowered = path.lower()
    if lowered.endswith(_PY_SUFFIXES):
        return True
    head = content.lstrip()[:64]
    return head.startswith("#!") and "python" in head


def scan_write(path: str, content: str) -> list[CodeFinding]:
    """Scan a file-write payload, gated on it looking like Python.

    This is the integration entry point the file-write tools call.
    """
    if not looks_like_python(path, content):
        return []
    return scan_source(content, filename=path or "<write>")


def critical_findings(findings: list[CodeFinding]) -> list[CodeFinding]:
    """Filter to the findings that should escalate a write to CRITICAL."""
    return [f for f in findings if f.critical]
