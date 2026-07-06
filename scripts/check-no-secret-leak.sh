#!/usr/bin/env bash
# Fails the build if identity_signature / vault_signature / identitySignature
# / vaultSignature appear anywhere near a fetch/axios/console.log/storage
# call. Per CODEX_PROMPT.md deliverable 1 and docs/09-security-model.md.
#
# This is a coarse grep-based guard, not a full data-flow analysis — it
# catches the obvious mistake (passing a secret directly into a network
# or logging call) but is not a substitute for a real audit before
# production deployment.

set -euo pipefail

SECRET_PATTERNS="identitySignature|vaultSignature|identity_signature|vault_signature"
SINK_PATTERNS="fetch\(|axios\.|console\.log\(|localStorage\.|sessionStorage\.|writeFile"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VIOLATIONS=0

while IFS= read -r -d '' file; do
  while IFS= read -r line; do
    line_no=$(echo "$line" | cut -d: -f1)
    content=$(echo "$line" | cut -d: -f2-)
    # Look a few lines around the sink for the secret pattern.
    context=$(sed -n "$((line_no > 3 ? line_no - 3 : 1)),$((line_no + 3))p" "$file")
    if echo "$context" | grep -qE "$SECRET_PATTERNS"; then
      echo "POTENTIAL LEAK: $file:$line_no -> $content"
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  done < <(grep -nE "$SINK_PATTERNS" "$file" || true)
done < <(find "$REPO_ROOT/sdk" "$REPO_ROOT/registry" -type f -name '*.ts' -print0)

if [ "$VIOLATIONS" -gt 0 ]; then
  echo ""
  echo "$VIOLATIONS potential secret-leak violation(s) found. Failing build."
  exit 1
fi

echo "No secret-leak violations found."
