"""Self-contained HTML rendering of `nota explain`.

The surface a non-technical reader actually looks at: a verdict banner, the
approved task, then one card per finding with the plain-English reason, the
self-fix (copy button on the command), and the paste-ready agent prompt
(copy button). Honest by design: it is a fix-it view, never a certification,
so no "compliant" badges — the strongest thing it says is the verdict.
"""

from __future__ import annotations

import html
from typing import Any

from nota.explain import PASS_LINE, explain_dict

_VERDICT_STYLE = {
    "PASS": ("#1a7f37", "#dafbe1", "✅ PASS — inside what was approved"),
    "NEEDS_REVIEW": ("#9a6700", "#fff8c5", "⚠️ NEEDS REVIEW — a human has to look first"),
    "BLOCK": ("#cf222e", "#ffebe9", "⛔ BLOCK — can't merge until these are fixed"),
}

_CSS = """
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,
sans-serif;color:#1f2328;background:#ffffff;margin:0;padding:32px 16px;}
main{max-width:760px;margin:0 auto;}
.banner{border-radius:8px;padding:16px 20px;font-size:18px;font-weight:600;
border:1px solid;}
.task{color:#656d76;margin:16px 4px 28px;font-size:14px;line-height:1.5;}
.card{border:1px solid #d0d7de;border-radius:8px;padding:16px 20px;
margin-bottom:16px;background:#f6f8fa;}
.card h3{margin:0 0 8px;font-size:15px;}
.where{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:12.5px;color:#656d76;margin-bottom:12px;}
.label{font-size:11px;font-weight:700;letter-spacing:.04em;color:#656d76;
text-transform:uppercase;margin:12px 0 4px;}
.copyable{display:flex;gap:8px;align-items:flex-start;}
.copyable pre{flex:1;margin:0;padding:10px 12px;background:#ffffff;
border:1px solid #d0d7de;border-radius:6px;font-size:12.5px;white-space:
pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,
Consolas,monospace;}
button{border:1px solid #d0d7de;background:#ffffff;border-radius:6px;
padding:6px 12px;font-size:12px;cursor:pointer;color:#1f2328;}
button:hover{background:#f3f4f6;}
.rollup{font-size:14px;font-weight:600;color:#1f2328;margin:12px 4px 0;}
.closer{color:#656d76;font-size:14px;margin-top:24px;}
.disclaimer{color:#8b949e;font-size:12px;line-height:1.5;margin-top:24px;
padding-top:16px;border-top:1px solid #d0d7de;}
"""

_COPY_JS = """
function cp(btn){
  const pre = btn.parentElement.querySelector('pre');
  navigator.clipboard.writeText(pre.textContent).then(()=>{
    const old = btn.textContent; btn.textContent = 'Copied';
    setTimeout(()=>{ btn.textContent = old; }, 1200);
  });
}
"""


def _copy_block(label: str, content: str) -> str:
    return (
        f'<div class="label">{html.escape(label)}</div>'
        f'<div class="copyable"><pre>{html.escape(content)}</pre>'
        f'<button onclick="cp(this)">Copy</button></div>'
    )


def render_html(passport: dict[str, Any]) -> str:
    """Render the full self-contained explain page."""
    verdict = passport.get("verdict", "BLOCK")
    color, bg, banner = _VERDICT_STYLE.get(verdict, _VERDICT_STYLE["BLOCK"])
    d = explain_dict(passport)

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Nota — what to fix</title>",
        f"<style>{_CSS}</style></head><body><main>",
        f'<div class="banner" style="color:{color};background:{bg};'
        f'border-color:{color}">{html.escape(banner)}</div>',
    ]
    if d.get("rollup"):
        parts.append(f'<p class="rollup">{html.escape(d["rollup"])}</p>')

    task_bits = []
    if d["task"]:
        task_bits.append(f"Approved task: &ldquo;{html.escape(d['task'])}&rdquo;")
    if d["allowed_paths"]:
        task_bits.append("Approved area: " + html.escape(", ".join(d["allowed_paths"])))
    if task_bits:
        parts.append(f'<p class="task">{"<br>".join(task_bits)}</p>')

    if verdict == "PASS":
        parts.append(f'<p class="closer">{html.escape(PASS_LINE)}</p>')
    else:
        for n, r in enumerate(d["remediations"], start=1):
            parts.append('<div class="card">')
            parts.append(f"<h3>Issue {n}: {html.escape(r['plain'])}</h3>")
            if r["where"]:
                parts.append(f'<div class="where">{html.escape(r["where"])}</div>')
            parts.append(_copy_block("Fix it yourself", r["self_fix"]))
            if r["cc_prompt"]:
                parts.append(_copy_block("Or paste this to your coding agent", r["cc_prompt"]))
            parts.append("</div>")
        parts.append(f'<p class="closer">{html.escape(d["closer"])}</p>')

    parts.append(f'<p class="disclaimer">{html.escape(d["does_not_prove"])}</p>')
    parts.append(f"</main><script>{_COPY_JS}</script></body></html>")
    return "".join(parts)
