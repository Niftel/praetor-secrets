#!/bin/sh
set -eu

: "${ADMIN_DATABASE_URL_FILE:?set ADMIN_DATABASE_URL_FILE}"
: "${RESTORE_DATABASE_URL_FILE:?set RESTORE_DATABASE_URL_FILE}"
: "${BACKUP_DUMP:?set BACKUP_DUMP}"
: "${EXPECTED_SHA256:?set EXPECTED_SHA256}"
test "$#" -gt 0 || {
  printf '%s\n' "usage: $0 VALIDATOR [ARG...]" >&2
  exit 2
}

actual=$(sha256sum "$BACKUP_DUMP" | awk '{print $1}')
test "$actual" = "$EXPECTED_SHA256"
dropdb --if-exists --force --dbname="$(cat "$ADMIN_DATABASE_URL_FILE")" praetor_secrets_restore
createdb --dbname="$(cat "$ADMIN_DATABASE_URL_FILE")" praetor_secrets_restore
pg_restore --exit-on-error --no-owner --dbname="$(cat "$RESTORE_DATABASE_URL_FILE")" "$BACKUP_DUMP"
"$@"
