#!/bin/sh
set -eu

: "${DATABASE_URL_FILE:?set DATABASE_URL_FILE}"
: "${OUTPUT_DIRECTORY:?set OUTPUT_DIRECTORY}"
: "${BACKUP_ID:?set BACKUP_ID}"
: "${RETAIN_UNTIL:?set RETAIN_UNTIL}"
: "${KEY_IDS:?set KEY_IDS to comma-separated key IDs from key-status}"

umask 077
test -f "$DATABASE_URL_FILE"
mkdir -p "$OUTPUT_DIRECTORY"
dump="$OUTPUT_DIRECTORY/$BACKUP_ID.dump"
manifest="$OUTPUT_DIRECTORY/$BACKUP_ID.manifest"
pg_dump --format=custom --file="$dump" "$(cat "$DATABASE_URL_FILE")"
digest=$(sha256sum "$dump" | awk '{print $1}')
created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf 'backup_id=%s\nartifact_sha256=%s\nkey_ids=%s\ncreated_at=%s\nretain_until=%s\n' \
  "$BACKUP_ID" "$digest" "$KEY_IDS" "$created" "$RETAIN_UNTIL" > "$manifest"
printf '%s\n' "$manifest"
