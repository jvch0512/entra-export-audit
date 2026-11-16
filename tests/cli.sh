#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 2
BIN=bin/entra-export-audit
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
exp() { local name=$1 want=$2; shift 2; "$BIN" "$@" >/dev/null 2>&1; local got=$?; [ "$got" = "$want" ] && ok "$name" || bad "$name (got $got, want $want)"; }
D="--today 2026-11-16"
exp "default exit 0" 0 examples $D
exp "fail-on medium" 1 examples $D --fail-on medium
exp "fail-on high" 1 examples $D --fail-on high
exp "fail-on critical" 1 examples $D --fail-on critical
exp "missing path" 2 "$T/none"
exp "bad flag" 2 --bogus
exp "no args" 2
exp "bad fail-on" 2 examples --fail-on low
exp "bad date" 2 examples --today 2026-13-40
exp "two paths" 2 examples examples
"$BIN" examples $D --tsv | head -1 | grep -q '^# 3 files, 8 findings$' && ok "tsv header" || bad "tsv header"
"$BIN" examples $D --tsv | sed -n 2p | awk -F'\t' 'NF==4{exit 0} {exit 1}' && ok "tsv columns" || bad "tsv columns"
"$BIN" examples $D | head -1 | grep -q '^3 files, 8 findings$' && ok "human header" || bad "human header"
"$BIN" examples --today 2026-01-01 --tsv | grep -q ENT004 && bad "today moves stale check" || ok "today moves stale check"
printf '{"users":[{"id":"a","userPrincipalName":"a@x.com","isMfaRegistered":false}]}' > "$T/one.json"
"$BIN" "$T/one.json" --tsv | grep -q $'\tENT005\tone.json#a@x.com\t' && ok "single file label" || bad "single file label"
head -c 2000 /dev/urandom > "$T/bin.json"
"$BIN" "$T/bin.json" >/dev/null 2>&1; [ $? -le 1 ] && ok "binary input survives" || bad "binary input"
exit $fail
