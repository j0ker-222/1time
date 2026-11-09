#!/bin/sh
# keepalived health check: nginx process is up and answers locally.
# /etc/keepalived/check_nginx.sh, chmod 755, owner root.
pidof nginx >/dev/null 2>&1 || exit 1
# The status location is defined in onetime-lb.conf (127.0.0.1:8081/lb-health).
curl -fsS -m 1 -o /dev/null http://127.0.0.1:8081/lb-health || exit 1
exit 0
