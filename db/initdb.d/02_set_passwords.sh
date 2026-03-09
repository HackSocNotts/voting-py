#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -c "ALTER ROLE registration_svc WITH PASSWORD '$REG_DB_PASSWORD';" \
    -c "ALTER ROLE ballot_svc       WITH PASSWORD '$BALLOT_DB_PASSWORD';" \
    -c "ALTER ROLE tally_svc        WITH PASSWORD '$TALLY_DB_PASSWORD';"
