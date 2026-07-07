#!/usr/bin/env bash
#
# Quill Change Control — drop it in front of an agent that knows NOTHING about it.
#
# A human does setup ONCE (sign the perimeter). After that the "agent" only ever
# writes files and commits — it never runs a quill command — and Quill judges
# each diff. Run it and watch the verdicts:
#
#   QUILL=/path/to/.venv/bin/quill ./examples/change_control_demo.sh
#   (defaults to `quill` on PATH)
#
set -uo pipefail
Q="${QUILL:-quill}"
W="$(mktemp -d)"
OUT="$(mktemp -d)"
FAKE_KEY="AKIA""IOSFODNN7EXAMPLE"   # assembled so this file holds no real secret
cd "$W"

line(){ printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }

# ---- the app, before any agent touches it ----
git init -q && git config user.email demo@local && git config user.name demo
mkdir -p src/checkout src/auth migrations .github/workflows
echo "def total(cart): return sum(cart)" > src/checkout/cart.py
echo "def login(u,p): ..."                > src/auth/login.py
echo "-- base schema"                     > migrations/001_init.sql
printf 'name: ci\non: [push]\n'           > .github/workflows/ci.yml
echo "# MyApp"                            > README.md
git add -A && git commit -qm "app: initial state"

line "HUMAN setup, done ONCE (the agent never sees this)"
"$Q" keygen --out "$W/approver.pem" >/dev/null   # human key — keep the private half off the box
"$Q" keygen --out "$W/gate.pem"     >/dev/null   # CI key that signs the verdict
mkdir -p .quill/approvers && cp "$W/approver.pem.pub" .quill/approvers/human.pub
# Agents may work in src/** but NEVER touch auth, migrations, or CI; secrets always blocked.
"$Q" guard --key "$W/approver.pem" \
  --allow 'src/**' --allow 'README.md' \
  --forbid 'src/auth/**' --forbid 'migrations/**' --approved-by alice | sed 's/^/  /'
git add -A && git commit -qm "quill: sign perimeter"
# Sign the contract with the approver key so `verify --strict` can prove a human
# (not the agent) authored the base commit and scope.
"$Q" begin "sprint: ship the checkout flow" --scope 'src/**' --scope 'README.md' \
  --key "$W/approver.pem" --repo demo/app >/dev/null
git add -A && git commit -qm "quill: open contract"
MAIN="$(git rev-parse HEAD)"
# The three things that make strict mode a real boundary, exactly as a CI setup
# would provide them (see docs/SECURITY-MODEL.md "Deployment checklist"):
#   1. the gate signing key,
#   2. the approver PUBLIC key as the EXTERNAL trust root — strict mode ignores
#      the committed .quill/approvers/*.pub on purpose (an agent could plant one),
#      so without this every verdict fails closed with "provenance not established",
#   3. the repo identity the contract is bound to (here via --repo above +
#      GITHUB_REPOSITORY, which CI sets for you).
export QUILL_GATE_KEY="$(cat "$W/gate.pem")"
export QUILL_APPROVER_PUBKEYS="$(cat "$W/approver.pem.pub")"
export GITHUB_REPOSITORY="demo/app"

agent_pr(){
  local name="$1"; shift
  git checkout -q "$MAIN"; git checkout -qB "pr/$name" >/dev/null 2>&1
  "$@"                                   # the oblivious agent edits files + commits
  git add -A && git commit -qm "agent: $name" >/dev/null
  line "AGENT PR: $name"
  "$Q" verify --strict --passport-dir "$OUT" >/dev/null 2>&1
  local code=$?
  python3 - "$OUT/passport.json" "$code" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); code=sys.argv[2]
m={"PASS":"\033[32m✅","NEEDS_REVIEW":"\033[33m⚠️ ","BLOCK":"\033[31m⛔"}[d["verdict"]]
print(f"  verdict: {m} {d['verdict']}\033[0m   (CI exit {code})")
print(f"  provenance: {d['trust']['provenance']} · strict={d['trust']['strict']}")
for r in d["reasons"]: print(f"    - {r}")
PY
}

agent_pr "legit-feature"    bash -c 'echo "def apply_coupon(c): ..." >> src/checkout/cart.py'
agent_pr "hardcoded-secret" bash -c 'echo "AWS=\"'"$FAKE_KEY"'\"" >> src/checkout/cart.py'
agent_pr "touch-auth"       bash -c 'echo "# backdoor" >> src/auth/login.py'
agent_pr "edit-migration"   bash -c 'echo "DROP TABLE users;" >> migrations/001_init.sql'
agent_pr "disable-the-gate" bash -c 'printf "  steps: [evil]\n" >> .github/workflows/ci.yml'
agent_pr "scope-escape"     bash -c 'mkdir -p ops && echo x > ops/prod.cfg'
# In-scope symlink pointing OUT of scope: the diff shows only an in-scope path
# whose "content" is the target string, so it can't be blocked on scope alone —
# it surfaces as NEEDS_REVIEW with the target recorded for the reviewer.
agent_pr "in-scope-symlink" bash -c 'ln -s ../auth/login.py src/checkout/alias.py'

line "A reviewer independently re-checks a BLOCK verdict (doesn't trust the repo)"
git checkout -q pr/touch-auth
"$Q" verify --strict --passport-dir "$OUT" >/dev/null 2>&1
"$Q" verify-passport "$OUT/passport.json" --gate-key "$W/gate.pem.pub" | sed 's/^/  /'

line "Agent forges the signed verdict BLOCK -> PASS"
python3 -c "import json,pathlib; p=pathlib.Path('$OUT/passport.json'); d=json.loads(p.read_text()); d['verdict']='PASS'; p.write_text(json.dumps(d))"
"$Q" verify-passport "$OUT/passport.json" --gate-key "$W/gate.pem.pub" | sed 's/^/  /' || true

echo; echo "demo repo: $W"
