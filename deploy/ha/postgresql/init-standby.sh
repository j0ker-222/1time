#!/bin/bash
# Turn this node into a hot standby of PRIMARY (also used to bring a former
# primary back after a failover when pg_rewind is not possible).
# Usage (as root on the standby): ./init-standby.sh 10.10.0.21 app2
set -euo pipefail
PRIMARY=${1:?primary address}
NAME=${2:?this node name: app1 or app2}
PGVER=$(ls /usr/lib/postgresql | sort -n | tail -1)
DATA=/var/lib/postgresql/$PGVER/main
SLOT=${NAME}

systemctl stop postgresql
rm -rf "${DATA:?}"/*
# Password for "replicator" from ~postgres/.pgpass:
#   10.10.0.21:5432:replication:replicator:SECRET
#   10.10.0.22:5432:replication:replicator:SECRET
sudo -u postgres pg_basebackup -h "$PRIMARY" -U replicator -D "$DATA" \
    -X stream -R -C -S "$SLOT" -c fast -P
# -R writes primary_conninfo + standby.signal, application_name = NAME so
# that synchronous_standby_names matches.
sudo -u postgres sed -i "s/^primary_conninfo = '/primary_conninfo = 'application_name=${NAME} /" \
    "$DATA/postgresql.auto.conf"
systemctl start postgresql
sudo -u postgres psql -Atc "SELECT pg_is_in_recovery()"
