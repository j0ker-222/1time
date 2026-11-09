#!/bin/bash
# certbot deploy hook on lb1 and lb2:
#   /etc/letsencrypt/renewal-hooks/deploy/sync-certs.sh  (chmod 755)
# HTTP-01 validation goes to the VIP, so only the node that holds the VIP
# can renew. After a renewal the certificate is copied to the peer and
# nginx is reloaded there. Root on each LB needs an ssh key to the peer.
set -euo pipefail
PEER=${PEER:-$( [ "$(hostname -s)" = lb1 ] && echo 10.10.0.12 || echo 10.10.0.11 )}
rsync -a --delete /etc/letsencrypt/ "root@${PEER}:/etc/letsencrypt/"
ssh "root@${PEER}" 'nginx -t && systemctl reload nginx'
systemctl reload nginx
