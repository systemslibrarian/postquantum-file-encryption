#!/usr/bin/env bash
# Continuous documentation-consistency guard.
#
# The release workflow already fails a *tag* if the README status line or an install snippet
# lags the version being published. That check only runs at release time, so drift can still
# accumulate on main between releases — which is exactly how the "Last reviewed against 1.2.0",
# "1.5.0", and "Now — 1.0.1" markers went stale while the code shipped 1.6.0. This script runs
# on every push and pull request (see .github/workflows/docs-consistency.yml) and enforces:
#
#   1. Current-version markers match the core package <Version>:
#        * the root README **Status:** line,
#        * the ROADMAP "## Now — `X`" heading,
#        * every "Last reviewed against: **`X`**" marker in any tracked Markdown file.
#   2. Every relative Markdown link resolves to a file that exists — no dead internal links.
#
# Historical version mentions (CHANGELOG entries, "shipped 1.3.0" prose, the compare-link
# footer) are deliberately NOT matched: they are facts about earlier releases, not the current
# version. See CLAUDE.md, "When you bump the package version".
#
# Run locally:  bash scripts/check-docs-consistency.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

core_csproj="src/PostQuantum.FileEncryption/PostQuantum.FileEncryption.csproj"
version="$(grep -oP '(?<=<Version>)[^<]+' "$core_csproj" | head -n1)"
if [ -z "${version:-}" ]; then
  echo "::error file=$core_csproj::could not read <Version>" >&2
  exit 1
fi
echo "Canonical package version: $version"

# fail flag lives in a file so it survives the subshells created by `... | while`.
fail_marker="$(mktemp)"
trap 'rm -f "$fail_marker"' EXIT
mark_fail() { printf 'x' >> "$fail_marker"; }

# ------------------------------------------------------------------ 1. version markers

# Explicit single-line markers that must name the current version.
if ! grep -qP "Status:\s*\`${version}\`" README.md; then
  echo "::error file=README.md::the **Status:** line does not name the current version \`${version}\`" >&2
  mark_fail
fi
if ! grep -qP "## Now — \`${version}\`" ROADMAP.md; then
  echo "::error file=ROADMAP.md::the \"## Now —\" heading does not name the current version \`${version}\`" >&2
  mark_fail
fi

# Generic: every "Last reviewed against: **`X`**" marker in any Markdown file must equal it.
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  f="${hit%%:*}"
  found="$(printf '%s' "$hit" | grep -oP 'Last reviewed against: \*\*`\K[^`]+')"
  if [ "$found" != "$version" ]; then
    echo "::error file=$f::stale marker 'Last reviewed against \`$found\`'; the current version is \`$version\`" >&2
    mark_fail
  fi
done < <(git grep -nP 'Last reviewed against: \*\*`[^`]+`\*\*' -- '*.md' || true)

# ------------------------------------------------------------------ 2. dead internal links

while IFS= read -r mdfile; do
  dir="$(dirname "$mdfile")"
  # Inline-link targets: the (...) in ](...). `-n` gives the line, `\K` drops the ]( prefix.
  while IFS= read -r m; do
    [ -z "$m" ] && continue
    lineno="${m%%:*}"
    target="${m#*:}"
    case "$target" in
      http://*|https://*|mailto:*|tel:*|\#*) continue ;;  # external or same-page anchor
    esac
    path="${target%%#*}"   # drop #fragment
    path="${path%%\?*}"    # drop ?query
    [ -z "$path" ] && continue
    if [ ! -e "$dir/$path" ]; then
      echo "::error file=$mdfile,line=$lineno::dead internal link '$target' (no file at '$dir/$path')" >&2
      mark_fail
    fi
  done < <(grep -noP '\]\(\K[^)]+' "$mdfile" 2>/dev/null || true)
done < <(git ls-files '*.md')

# ------------------------------------------------------------------ verdict

if [ -s "$fail_marker" ]; then
  echo "Documentation consistency check FAILED — see the annotations above." >&2
  exit 1
fi
echo "Documentation consistency check passed."
