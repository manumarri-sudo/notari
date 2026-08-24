# Phase 1 plan: extract the loop surface

Produced against `notari-secfix-wave2-20260724` at baseline **1548 passed, 4 xfailed**.
All import analysis in this document comes from an AST pass over 150 `.py` files
(`ast.NodeVisitor`, alias-tracking through `import x`, `from notari.x import y`,
`from notari import x`, and `as` renames), so no grep was used to establish a call site.

---

## 0. Three findings that change the scope before any code moves

The handoff asks me to stop and say so rather than proceed when the plan appears to
require something it ruled out, and three items qualify: two are hard stops, and one is a
judgment call I want confirmed.

### 0.1 HARD STOP: `notari night` is gate machinery, not loop machinery

The handoff says to remove "the hidden CLI commands they back: `learn`, `insights`,
`saves`, `roster`, `night`", but `night` is not backed by any of the seven modules. It is
backed by `overnight.py` (304 lines, not in the removal list), and `overnight.py` is
consumed directly by the gate:

| site | what it does |
|---|---|
| `adapters/claude_code.py:593-598` | on every CRITICAL deny, `_ovn.record_event("critical")` |
| `adapters/claude_code.py:618-628` | on every HIGH, `is_active_from_config()` can flip deny to `verdict.allowed.overnight` |
| `adapters/claude_code.py:375-388` | the `_GATE_STATE_DIRS` self-tamper comment cites `notari night` and `overnight.json` as the reasoning for protecting `.notari/` wholesale |

Removing the `night` and `day` commands would leave overnight mode fully reachable
through `[overnight] enabled = true` in `config.toml` plus `overnight.json`, while
deleting the operator's only way to turn it off, inspect it, or read the morning recap,
and `notari day` is the documented kill switch for a mode that auto-approves HIGH risk.

**I am not removing `night`, `day`, or `overnight.py`.** If you want them gone that is a
separate decision about the gate rather than part of the loop extraction, and it needs its
own review because it touches the file hardened against the gate bypass.

### 0.2 HARD STOP: `journal._emit_session_close` is audit-chain machinery

`journal.py` is on the deletion list, but it contains the **sole producer** of the
`session.close` audit event, and four surfaces that survive consume it:

| consumer | line | why it matters |
|---|---|---|
| `events.py` | 42, 84 | `SESSION_CLOSE` is a declared canonical frame boundary |
| `receipt.py` | 143 | derives `closed_at` on every Receipt |
| `githook.py` | 32, `find_active_session` | freshness window for the commit-message summary reads `closed_at` |
| `roster.py` | 87 | folds closes into agent/session rows |

Deleting `journal.py` wholesale would leave `session.open` events that never close, would
silently degrade `find_active_session` to "no active session", and would break the
commit-hook summary, which is why two gate tests already depend on it
(`test_claude_hook.py:602` and `:642`, covering idempotence and duration/tool-count
derivation).

**Plan: `_emit_session_close` is category-2 shared machinery and moves to `receipt.py`
unchanged, with its two gate tests repointed**, preserving both its behaviour and its
signature exactly as they are today. Everything else in `journal.py` (the markdown
session-journal writer, `_check_session_drift`, and the Page-Hinkley drift call into
`learning`) is genuine loop surface and goes, so that is 435 lines minus roughly 60 kept,
or about 375 removed.

`roster.py` is a pure read-only fold over the audit chain with no loop imports at all, so
removing the `roster` command is safe, though I should note it is audit surface being
removed for tidiness rather than loop surface, and I will keep it if you prefer.

### 0.3 JUDGMENT CALL: removing `decay.py` is a real loosening of the risk classifier

`adapters/claude_code.py:311-344`, inside `classify_event`, is the only place a user
policy override can be refused, because today a stale override falls back to the tool's
natural risk and tells the operator to reaffirm. With `decay.py` gone, `classify_event`
becomes `return user_override, "user policy override", ""` unconditionally, so a
`["Bash"] = "low"` written into `config.toml` a year ago would stay low forever.

This contradicts the handoff's own request in Phase 1 item 4 to show that the risk
classification is unchanged, since it will not be unchanged on that path.

Two facts inform the call. First, **nothing tests this branch**: `tests/test_decay.py`
exercises `decay.py` in isolation (`policy_kind`, `record_use`, windows, chmod) while no
test anywhere asserts the decayed-override fallback inside the gate. Second, Permission
Decay is one of your named frameworks, which makes this a product decision rather than a
cleanup.

**My recommendation: remove it as specified**, because the narrowing thesis says the gate
is a bundled on-ramp and this is an unexercised refinement of it, but I want that said out
loud and approved rather than buried in a diff, and I will record the behaviour change in
the commit message and in `docs/SECURITY-MODEL.md`.

**Alternative if you prefer:** keep roughly 40 lines of staleness check inline in
`claude_code.py` and delete the other 267 lines of `decay.py` along with the
`notari decay` commands, which costs complexity but preserves the control.

---

## 1. Call graph (AST-derived)

150 files scanned, covering every call site of the seven modules in source, with tests
listed separately in section 5.

### `decay.py` (307 lines)

| file | line | symbol | in function | class |
|---|---|---|---|---|
| `adapters/claude_code.py` | 326 | `_decay.DecayStore.load` | `classify_event` | **seam, see 0.3** |
| `adapters/claude_code.py` | 331 | `_decay.policy_kind` | `classify_event` | **seam, see 0.3** |
| `cli.py` | 4146 | `decay_mod.DecayStore` | `decay_show` | delete command |
| `cli.py` | 4225 | `decay_mod.DecayStore` | `decay_reaffirm` | delete command |
| `cli.py` | 4254 | `decay_mod.DecayStore` | `decay_forget` | delete command |
| `doctor.py` | 473 | `_decay.DecayStore.load` | `check_permission_decay` | delete check |
| `learn.py` | 251 | `_decay.DecayStore` | `analyze_decayed_permissions` | dies with `learn.py` |

### `learn.py` (516 lines)

| file | line | symbol | in function | class |
|---|---|---|---|---|
| `adapters/claude_code.py` | 1023 | `_normalize_block_reason` | `run_hook` | seam, delete whole block |
| `cli.py` | 2082 | `analyze` | `learn_cmd` | delete command |
| `cli.py` | 2160 | `analyze` | `kpis_cmd` | **seam, see 4.3** |
| `doctor.py` | 416 | `analyze` | `check_self_improvement_signals` | delete check |
| `learning.py` | 602 | `_normalize_block_reason` | `record_decision_learning` | dies with `learning.py` |

### `learning.py` (893 lines)

| file | line | symbol | in function | class |
|---|---|---|---|---|
| `adapters/claude_code.py` | 1025 | `load_active_overrides` | `run_hook` | seam, delete whole block |
| `adapters/claude_code.py` | 1363, 1368 | `record_decision_learning` | `run_hook` | seam, delete whole block |
| `adapters/cursor.py` | 416 | `record_decision_learning` | `run_hook` | seam, delete whole block |
| `cli.py` | 5103, 5156, 5182 | `read_suggestions` | `suggestions_list/show/promote` | delete sub-app |
| `cli.py` | 5225, 5290 | `append_suggestion` | `suggestions_promote/dismiss` | delete sub-app |
| `cli.py` | 5226, 5291 | `log_event` | `suggestions_promote/dismiss` | delete sub-app |
| `cli.py` | 5252 | `find_stale_patterns` | `suggestions_cleanup` | delete sub-app |
| `cli.py` | 5262 | `cleanup_stale_patterns` | `suggestions_cleanup` | delete sub-app |
| `cli.py` | 5325, 5326 | `_log_path`, `_suggestions_path` | `log_cmd` | delete command |
| `doctor.py` | 390 | `find_stale_patterns` | `check_stale_pattern_stats` | delete check |
| `journal.py` | 400 | `check_drift_for_session` | `_check_session_drift` | dies with journal loop half |

### `journal.py` (435 lines)

| file | line | symbol | in function | class |
|---|---|---|---|---|
| `cli.py` | 4113 | `_emit_session_close` | `journal_save` | **preserve and move, see 0.2** |
| `cli.py` | 4114 | `_check_session_drift` | `journal_save` | delete |
| `cli.py` | 4123 | `journal_mod.save_from_transcript` | `journal_save` | delete |

### `insights.py` (364 lines)

| file | line | symbol | in function | class |
|---|---|---|---|---|
| `cli.py` | 1669 | `compute_insights` | `insights_cmd` | delete command |
| `cli.py` | 1670 | `format_insights` | `insights_cmd` | delete command |

### `saves.py` (456 lines)

| file | line | symbol | in function | class |
|---|---|---|---|---|
| `cli.py` | 1662 | `parse_window` | `insights_cmd` | delete with command |
| `cli.py` | 1825 | `parse_window` | `saves_cmd` | delete command |
| `cli.py` | 1832 | `compute_saves` | `saves_cmd` | delete command |
| `cli.py` | 1833 | `format_saves` | `saves_cmd` | delete command |
| `insights.py` | 164, 166, 167, 181, 235 | `_iter_events`, `_parse_ts`, `_in_window`, `canonicalize_pattern` | `compute_insights` | dies with `insights.py` |

### `lessons.py` (360 lines)

| file | line | symbol | in function | class |
|---|---|---|---|---|
| `cli.py` | 466 | `lessons_mod.record_mistakes` | `verify_cmd` | **seam into the product, see 2** |
| `cli.py` | 984, 987, 996 | `suggest`, `load_events`, `load_promoted` | `lessons_main` | delete sub-app |
| `cli.py` | 1022 | `promote` | `lessons_promote_cmd` | delete sub-app |
| `cli.py` | 1104 | `lessons_mod.load_promoted` | `_emit_agent_brief` | seam, drop the argument |
| `teach.py` | 87 | `lessons_mod.load_promoted` | `teach` | **see 4.4** |

---

## 2. Classification of every call site

**Category 1, pure loop, delete outright** (33 of 42 source call sites): every
`cli.py` command body listed above except `verify_cmd:466` and `kpis_cmd:2160`, all
three `doctor.py` checks, `insights.py` into `saves.py`, `journal.py:400` into `learning`,
`learn.py:251` into `decay`, and `learning.py:602` into `learn`.

**Category 2, shared machinery, preserve and move** (1 site):
`journal._emit_session_close` moves verbatim to `receipt.py`, which already owns
`SESSION_CLOSE` consumption, so `cli.py:4113` repoints and the `notari journal save`
command becomes a thin `session-close` emitter folded into the SessionEnd path, with the
function's behaviour and signature both untouched.

**Category 3, seams needing a small replacement** (8 sites):

| seam | replacement |
|---|---|
| `claude_code.py:324-343` | delete the decay block so `classify_event` returns the override directly, which is the behaviour change described in section 0.3 |
| `claude_code.py:1018-1038` | delete the whole `if decision.permission == "ask" and ...` override-downshift block, which removes a path that turns ask into allow and is therefore strictly tightening |
| `claude_code.py:1359-1370` | delete the whole `if decision.permission != "allow" or approval_token_used:` recording block, which runs after the verdict is final and cannot affect it |
| `cursor.py:416` | delete the equivalent recording block |
| `cli.py:463-468` | delete the `try: ... record_mistakes(...) except: pass` block in `verify_cmd`, which is already a no-op on the verdict by construction |
| `cli.py:1104` | drop `promoted=` from the `teach_mod.agent_brief(...)` call |
| `teach.py:140-159` | drop the `promoted` parameter and its two-line render branch from `agent_brief` |
| `doctor.py` | remove three `CheckResult` producers along with their registrations in the orchestrator |

---

## 3. Ordering, and why

Callers come before callees, so that every commit leaves the tree importable and the suite
green, and so a bisect lands on exactly one removal.

1. **`insights.py`** plus `notari insights`, since only `cli.py` imports it, which then
   frees `saves.py` to be removed on its own.
2. **`saves.py`** plus `notari saves`, which by this point is a true leaf with no
   remaining consumers.
3. **`journal.py` loop half** plus `notari journal`, after moving `_emit_session_close`
   to `receipt.py` in its own preceding commit so that the move and the deletion bisect
   apart cleanly.
4. **`teach.py` lessons surface**, then **`lessons.py`** plus `notari lessons`, the
   `verify_cmd` recorder, and the `agent_brief` argument, all of which depend on nothing
   else in the set.
5. **`learning.py`** plus `notari suggestions`, `notari log`, the `doctor` stale-pattern
   check, and the two adapter seams, which together free `learn.py`.
6. **`learn.py`** plus `notari learn`, the `doctor` self-improvement check, and whatever
   the section 4.3 decision settles for `kpis_cmd`, which then frees `decay.py`.
7. **`decay.py`** plus `notari decay`, the `doctor` decay check, and the `classify_event`
   seam, going last because it is the only one that changes a gate verdict and so it
   should land alone on top of an otherwise-green tree.

That is nine commits in total, being the seven above plus the `_emit_session_close` move
and a closing docs pass.

---

## 4. Blast radius on `adapters/claude_code.py`

### 4.1 Exact lines

Three hunks totalling **53 lines, all deletions, with no rewrites**:

| lines | commit | net |
|---|---|---|
| 1359-1370 | step 5 | -12 |
| 1018-1038 | step 5 | -21 |
| 324-343 | step 7 | -20 |

Nothing else in the file is touched, and specifically **not** touched are
`_GATE_STATE_DIRS` (375-388), `_SENSITIVE_DIRS` and `_sensitive_path_hit`, `_WRITE_VERBS`,
`classify_command`, the overnight blocks at 588-640, the approval-token path, or anything
else in the self-tamper surface. `cursor.py` loses one hunk of roughly 8 lines on the same
pattern.

### 4.2 How I will prove the gate is unchanged

These assert properties rather than mechanisms, per rule 1:

1. **Golden characterization harness, written and captured before any deletion**, running
   a matrix over `classify_event(tool_name, bypass_mode, config_override)` across every
   key in `DEFAULT_BUILTIN_RISK`, both bypass states, and the override cases, serialized
   to JSON on the pre-change tree. After each commit I regenerate and diff it, and the
   only permitted difference in the whole refactor is the decayed-override row in step 7,
   whose diff gets pasted into the commit message. This catches a classifier change that
   no named test covers, which is exactly the failure mode of
   `test_pause_json_is_in_adapter_gate_surface`.
2. **`tests/test_gate_self_tamper.py` and `tests/test_disable_auth.py` run explicitly**
   after every one of the nine commits rather than only at the end, with counts reported
   each time.
3. **`git diff -- src/notari/adapters/claude_code.py` must show deletions only**, so I
   will report `--numstat` per commit, and any nonzero addition count on that file is a
   red flag I will explain rather than gloss over.
4. **A direction-of-safety argument stated per hunk**, since hunk 1018-1038 removes an
   ask-to-allow downshift and can therefore only make behaviour more restrictive, hunk
   1359-1370 executes after `decision` is final and returns nothing into it, and hunk
   324-343 is the one genuine loosening, which is why it is isolated in its own commit.
5. **Rule 2 discipline on every test I write or change**, meaning I stash the source,
   watch it fail, restore, watch it pass, and report both counts.

### 4.3 Open seam: `notari kpis` (resolved, and my first recommendation was wrong)

An earlier draft of this plan called `notari kpis` loop telemetry and recommended deleting
it, which reading `learn.py` disproved. `derive_kpis` (lines 431-486) is a **pure fold over
`events.py` constants** (`VERDICT_ASK`, `VERDICT_BLOCKED`, `VERDICT_ALLOWED`,
`SESSION_TAINT_UPDATE`, `AGENT_CASCADE_AFFECTED`) with exactly one internal dependency,
the 25-line `_normalize_block_reason`. It touches no lesson, no suggestion, no override,
and no decay record. Its only tie to the loop is that `analyze()` happens to bundle
suggestions and KPIs into a single return tuple.

So `kpis` is audit surface wearing a loop module's file, in the same category as
`roster.py` and `_emit_session_close`, and the split inside `learn.py` is clean:

| half | lines | fate |
|---|---|---|
| `Suggestion`, `SuggestionCategory` | 20 | loop, delete |
| the five `analyze_*` generators | 241 | loop, delete |
| `analyze()` | 28 | loop, delete |
| `KPIReport` | 42 | audit, move |
| `derive_kpis` | 56 | audit, move |
| `_normalize_block_reason` | 25 | audit, move |
| `_iter_audit_events`, `_parse_ts`, `_in_window` | 30 | already duplicated in `audit_summary.py` |

**Recommendation: keep the metric, delete the module.** `KPIReport`, `derive_kpis`, and
`_normalize_block_reason` move into `audit_summary.py`, which already owns `load_events`,
`_parse_ts`, and `filter_events`, so the three event helpers dedupe against what is there
rather than moving. `learn.py` still deletes in full, the definition of done still holds,
and roughly 100 net lines survive out of 516. This is the same category-2 move as
`_emit_session_close` and it lands in its own commit ahead of the `learn.py` deletion.

The reason to keep it is that `noise_ratio` (asks per real block) is Intervention Rate from
the Trust Infrastructure framework, and it is the only quantitative instrument anywhere in
the codebase that can say whether the gate is training approve-fatigue. The reason someone
might still cut it is that it is hidden and unrequested, and if you would rather be ruthless
then 56 lines are recoverable from git history whenever a gate dashboard is actually wanted.

### 4.4 Open seam: `notari teach` (resolved)

`teach.py` splits along an unusually clean line, because the two halves have entirely
different inputs:

| function | input | fate |
|---|---|---|
| `render_block` | `promoted` only | loop, delete |
| `update_file` | `promoted` only | loop, delete |
| `teach` | `lessons_mod.load_promoted(root)` only | loop, delete |
| `BLOCK_START` / `BLOCK_END` markers | the above | loop, delete |
| `fix_prompt` | a passport dict | **product, keep untouched** |
| `agent_brief` | contract task, allowed paths, perimeter | **product, keep minus `promoted`** |

**Recommendation: remove the `notari teach` command and the four managed-block symbols,
keep `fix_prompt` and `agent_brief`.** The first three functions take `promoted` as their
only argument, so with `lessons.py` gone they would write an empty managed block into the
user's `CLAUDE.md`, which is worse than absent. The other two render the contract and the
verdict for a coding agent, they back `notari agent-brief` and `notari fix-prompt`, and
they are Change Passport surface rather than loop surface, so they stay. `teach.py` drops
from 164 lines to roughly 100, and its module docstring gets rewritten because "Write
promoted Notari lessons into agent instruction files" stops being true of it.

Worth saying on its own merits: the managed-block machinery is the loop's most invasive
surface, since it is the one feature that writes into the operator's own instruction files.
Removing it is a gain independent of the narrowing argument.

**Documentation consequence to schedule, not to silently absorb:** `README.md` documents
`notari teach` at lines 79, 351, and 507, and the demo GIF caption at line 142 explicitly
advertises "the lessons loop writing a promoted rule into CLAUDE.md". The prose is a text
edit in the docs commit, but the GIF itself becomes inaccurate and needs re-recording. I
will flag that as a follow-up rather than leave a caption describing a feature that no
longer exists.

---

## 5. Test inventory

**Deleted outright, 16 files, 3,905 lines:**

| file | lines | file | lines |
|---|---|---|---|
| `test_saves.py` | 428 | `test_learn.py` | 257 |
| `test_learning_overrides.py` | 344 | `test_learning_concurrency.py` | 213 |
| `test_learning_cleanup.py` | 342 | `test_journal.py` | 178 |
| `test_lessons.py` | 312 | `test_learning_real_log_replay.py` | 179 |
| `test_insights.py` | 292 | `test_learning_drift.py` | 163 |
| `test_learning_hook_integration.py` | 284 | `test_learning_self_test.py` | 149 |
| `test_learning_cli.py` | 271 | `test_decay.py` | 146 |
| `test_learning_core.py` | 262 | `test_auto_promote.py` | 85 |

Add `test_roster.py` (67) if `roster` goes, while `test_overnight.py` (520) **stays**, per
section 0.1.

**Rewritten rather than deleted:**

- `tests/test_claude_hook.py`, where the two tests at 602 and 642 repoint their
  `from notari.journal import _emit_session_close` to the new home in `receipt.py`, and
  the assertions (idempotence, `duration_seconds >= 0`, `tool_call_count == 2`) are
  properties that survive verbatim.
- `tests/test_launch_smoke.py`, which drops the three lessons lines (17, 85, 90), though
  the property it was protecting, that a post-verify side effect never changes the
  verdict, is worth keeping, so I will re-anchor it on the passport build rather than
  delete it.
- `tests/test_doc_counts.py`, which I will check for any pinned count that moves once
  `README.md` loses its lessons lines.

**Coverage genuinely lost, stated plainly:**

- Permission-decay windows, chmod-600 on `permissions.json`, and the reaffirm and forget
  semantics, all accepted because the feature is going.
- Learning-store concurrency (file locking under parallel writes), which is the one
  deletion I am slightly uneasy about, because the locking idiom may be shared with other
  state files, so I will check whether `learning.py`'s locking is its own or shared before
  deleting `test_learning_concurrency.py`, and if it turns out to be shared then the lock
  test moves to whichever module owns it.
- The Page-Hinkley drift detector, which no other surface uses.

**Coverage that must survive, and where it lands:** `session.close` idempotence and
derivation move with the function onto `receipt.py`'s test surface, and the gate's ask-path
behaviour after the override block is removed gets a new property test asserting that a
default-classified `ask` stays `ask` when no config is present.

---

## 6. What I will NOT do

- **Not touching** `secrets.py`, `verify.py`, `contract.py`, `perimeter.py`,
  `passport.py`, `attest.py`, `audit.py`, `provenance.py`, or
  `scripts/notari-passport.sh`, since nothing in the plan requires it, and the only
  near-miss is `verify_cmd` in `cli.py:463-468`, which is CLI glue rather than `verify.py`.
- **Not removing** `notari night`, `notari day`, or `overnight.py`, per section 0.1.
- **Not deleting** `journal._emit_session_close`, per section 0.2.
- **Not batching** deletions, since the plan is nine commits with the full suite between
  each.
- **Not writing** new features, because the only new code is the golden classifier harness
  and two replacement property tests.
- **Not trusting** a subagent report or a green suite as proof, so every claim in the
  Phase 2 report will carry the literal command and its real output.

## Files I expect to modify

`src/notari/cli.py`, `src/notari/doctor.py`, `src/notari/teach.py`,
`src/notari/receipt.py`, `src/notari/adapters/claude_code.py`, and
`src/notari/adapters/cursor.py`, alongside deletion of the seven modules, the test changes
above, `README.md`, and `docs/SECURITY-MODEL.md`. All of these sit inside the signed
contract scope (`src/**`, `tests/**`, `docs/**`, `README.md`), so `notari verify` should
stay PASS throughout.

## Decision log

| # | question | status |
|---|---|---|
| 1 | Section 0.3, remove `decay.py` fully and accept that policy overrides stop expiring | **APPROVED** by Manu. The classifier loosening is deliberate, lands alone in commit 7, and gets recorded in the commit message and `docs/SECURITY-MODEL.md`. |
| 2 | Section 4.3, `notari kpis` | Recommendation revised after reading the source: move `derive_kpis` to `audit_summary.py`, delete `learn.py` in full. Awaiting your yes. |
| 3 | Section 4.4, `notari teach` | Recommendation: delete the managed-block half, keep `fix_prompt` and `agent_brief`. Awaiting your yes. |
| 4 | Sections 0.1 and 0.2, `night`/`day`/`overnight.py` stay and `_emit_session_close` is preserved | Treating as accepted unless you object, since both are gate and audit machinery rather than loop machinery. |
| 5 | `roster` is audit surface, so remove it anyway or keep it | Open, and low stakes either way. |

## Commit sequence after the above

Eleven commits rather than nine, because two category-2 moves now land ahead of their
deletions so that a move and a removal never share a bisect step:

1. move `_emit_session_close` into `receipt.py`, repoint two gate tests
2. capture the golden `classify_event` characterization matrix
3. `insights.py` plus `notari insights`
4. `saves.py` plus `notari saves`
5. `journal.py` loop half plus `notari journal`
6. `teach.py` managed-block half plus `notari teach`
7. `lessons.py` plus `notari lessons`, the `verify_cmd` recorder, the `agent_brief` argument
8. `learning.py` plus `notari suggestions`, `notari log`, the doctor check, both adapter seams
9. move `KPIReport`, `derive_kpis`, `_normalize_block_reason` into `audit_summary.py`
10. `learn.py` plus `notari learn` and the doctor self-improvement check
11. `decay.py` plus `notari decay`, the doctor decay check, and the `classify_event` seam
