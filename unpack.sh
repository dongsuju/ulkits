#!/bin/bash
set -e
cd /opt/kit
for f in parts/p*; do cat $f; done | base64 -d > /opt/prlkit.tgz
tar xzf /opt/prlkit.tgz -C /opt/kit
chmod +x /opt/kit/wildrig/wildrig-multi /opt/kit/deploy_prl.sh /opt/kit/verify_plant.sh 2>/dev/null || true
echo KIT_READY
