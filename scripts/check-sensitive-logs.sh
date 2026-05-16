#!/usr/bin/env bash
set -euo pipefail

# Fails when likely sensitive field names are used directly in logging statements.
# This is intentionally conservative: it scans only active source files and only
# lines that contain a logging macro/console call.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_PATTERN='(println!|eprintln!|dbg!|tracing::(trace|debug|info|warn|error)!|log::(trace|debug|info|warn|error)!|console\.(log|debug|info|warn|error))'
SENSITIVE_PATTERN='(mnemonic|seed phrase|seed|private[_ -]?key|secret|password|passphrase|refresh[_ -]?token|access[_ -]?token|file[_ -]?key|aes[_ -]?key|encrypted_aes_key|encrypted_file_key|plaintext|plain[_ -]?text|decrypted|content|title|filename|file_info|upload_result|output_path)'
ALLOWLIST_PATTERN='(tests/|test_|tests::|src/bin/test_|examples/|validate_vaulted_seed|SecretBytes|DEFAULT_MNEMONIC_WORDS|ADVANCED_MNEMONIC_WORDS|MIN_MNEMONIC_WORDS|EncryptedData|encrypted payload|encrypted file|encrypted note|encrypted metadata|redacted|selected output path|Access token expired|session refresh|Token refreshed|auth credential|wallet material|content key|payload decrypted)'

matches="$({
  grep -RInE "$LOG_PATTERN" crates scripts \
    --include='*.rs' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
    --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=target || true
} | grep -Ei "$SENSITIVE_PATTERN" | grep -Eiv "$ALLOWLIST_PATTERN" || true)"

if [[ -n "$matches" ]]; then
  echo "Potential sensitive logging found:" >&2
  echo "$matches" >&2
  echo >&2
  echo "Review each line. Remove the value, redact it, or extend the allowlist only for a safe false positive." >&2
  exit 1
fi

echo "Sensitive logging check passed."
