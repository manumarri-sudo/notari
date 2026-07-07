"""Tests for the pre-execution AST scanner (quill.code_scan)."""

from __future__ import annotations

from quill import code_scan as cs


def _rules(source: str) -> set[str]:
    return {f.rule for f in cs.scan_source(source)}


def test_shutil_rmtree_is_critical() -> None:
    findings = cs.scan_source("import shutil\nshutil.rmtree('/important')\n")
    assert any(f.rule == "shutil-rmtree" and f.critical for f in findings)
    assert findings[0].lineno == 2


def test_os_system_is_critical() -> None:
    findings = cs.scan_source("import os\nos.system('rm -rf ~')\n")
    assert any(f.rule == "os-system" and f.critical for f in findings)


def test_subprocess_plain_vs_shell() -> None:
    plain = cs.scan_source("import subprocess\nsubprocess.run(['ls'])\n")
    assert any(f.rule == "subprocess" and not f.critical for f in plain)

    shell = cs.scan_source("import subprocess\nsubprocess.run('ls', shell=True)\n")
    assert any(f.rule == "subprocess-shell" and f.critical for f in shell)


def test_exec_of_base64_payload_is_critical() -> None:
    src = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
    findings = cs.scan_source(src)
    assert any(f.rule == "exec-decoded-payload" and f.critical for f in findings)


def test_plain_exec_is_critical() -> None:
    findings = cs.scan_source("exec('print(1)')\n")
    assert any(f.rule == "exec-call" and f.critical for f in findings)


def test_eval_hex_decoded_payload() -> None:
    src = "import binascii\neval(binascii.unhexlify('7072696e7428312900'))\n"
    assert "exec-decoded-payload" in _rules(src)


def test_os_exec_family() -> None:
    findings = cs.scan_source("import os\nos.execv('/bin/sh', ['sh'])\n")
    assert any(f.rule == "os-exec" and f.critical for f in findings)


def test_pickle_loads_is_critical() -> None:
    findings = cs.scan_source("import pickle\npickle.loads(b'...')\n")
    assert any(f.rule == "pickle-loads" and f.critical for f in findings)


def test_dynamic_import_flagged_noncritical() -> None:
    findings = cs.scan_source("m = __import__('os')\n")
    assert any(f.rule == "dynamic-import" and not f.critical for f in findings)


def test_benign_code_has_no_findings() -> None:
    src = "import json\nx = {'a': 1}\nprint(json.dumps(x))\n"
    assert cs.scan_source(src) == []


def test_non_python_payload_is_ignored() -> None:
    # Looks like a write of prose / JSON, not Python - never blocked.
    assert cs.scan_write("notes.md", "shutil.rmtree is a function in Python.") == []
    assert cs.scan_write("data.json", '{"cmd": "os.system"}') == []


def test_syntax_error_fails_open() -> None:
    # We cannot parse it, so we report nothing rather than false-blocking.
    assert cs.scan_source("def (((") == []


def test_scan_write_only_scans_python_by_extension() -> None:
    payload = "import os\nos.system('id')\n"
    assert cs.scan_write("evil.py", payload)  # scanned
    assert cs.scan_write("evil.txt", payload) == []  # skipped


def test_scan_write_honors_python_shebang() -> None:
    payload = "#!/usr/bin/env python3\nimport shutil\nshutil.rmtree('/x')\n"
    findings = cs.scan_write("noext", payload)
    assert any(f.rule == "shutil-rmtree" for f in findings)


def test_critical_findings_filter() -> None:
    findings = cs.scan_source(
        "import os, subprocess\nos.remove('a')\nsubprocess.run('x', shell=True)\n"
    )
    crit = cs.critical_findings(findings)
    assert all(f.critical for f in crit)
    assert any(f.rule == "subprocess-shell" for f in crit)
    assert not any(f.rule == "os-remove" for f in crit)  # os.remove is non-critical


def test_as_reason_is_line_numbered() -> None:
    finding = cs.scan_source("import shutil\nshutil.rmtree('/x')\n")[0]
    reason = finding.as_reason()
    assert "line 2" in reason and "shutil-rmtree" in reason
