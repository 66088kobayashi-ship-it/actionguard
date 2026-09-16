#!/bin/bash
# Corpus construction for the actionguard study.
#
# The resolved list of 259 repositories is deliberately NOT published: one of them
# contains a vulnerability that was disclosed privately, and publishing the list
# alongside the scanner would identify it. This script reproduces an equivalent
# corpus from scratch. It will not reproduce the exact same set — GitHub search is
# ranked by recent update — so expect the aggregate numbers to shift.
#
# Requires: git, curl, python3, node. No GitHub token needed (unauthenticated
# repository search is 10 req/min; code search would need auth and is not used).

set -u
OUT=${1:-corpus}
QUERIES=(
  "supabase+nextjs"
  "supabase+next.js+app+router"
  "next.js+supabase+server+actions"
  "supabase+auth+nextjs+app"
  "nextjs+supabase+saas"
  "supabase+nextjs+dashboard"
)

echo "[1/3] collecting candidates"
: > candidates_raw.tsv
for q in "${QUERIES[@]}"; do
  for page in 1 2 3; do
    curl -s "https://api.github.com/search/repositories?q=${q}+language:TypeScript&sort=updated&per_page=100&page=${page}" \
    | python3 -c '
import sys, json
try:
    for i in json.load(sys.stdin).get("items", []):
        print(i["full_name"], i["size"], sep="\t")
except Exception:
    pass
' >> candidates_raw.tsv
    sleep 7   # unauthenticated search rate limit
  done
done
# drop very large repositories (monorepos, vendored trees)
awk -F'\t' '$2<80000{print $1}' candidates_raw.tsv | sort -u > candidates.txt
echo "  candidates: $(wc -l < candidates.txt)"

echo "[2/3] shallow cloning"
mkdir -p "$OUT"
clone_one() {
  d="$2/$(echo "$1" | tr '/' '__')"
  [ -d "$d" ] && return 0
  timeout 60 git clone --depth 1 --quiet "https://github.com/$1.git" "$d" 2>/dev/null
  return 0
}
export -f clone_one
xargs -a candidates.txt -P 10 -I{} bash -c 'clone_one "$@"' _ {} "$OUT"

echo "[3/3] filtering to Supabase + Server Actions projects"
: > valid.txt
for d in "$OUT"/*/; do
  [ -f "$d/package.json" ] || continue
  grep -q '@supabase/supabase-js' "$d/package.json" 2>/dev/null || continue
  grep -rlE "^[[:space:]]*['\"]use server['\"]" \
       --include='*.ts' --include='*.tsx' "$d" 2>/dev/null \
    | grep -qv node_modules || continue
  echo "$d" >> valid.txt
done
echo "  valid: $(wc -l < valid.txt)  (roughly a third of clones, in our run)"

echo
echo "Next:  while read -r d; do node dist/cli.js \"\$(realpath \"\$d\")\"; done < valid.txt"
