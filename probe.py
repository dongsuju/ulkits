#!/usr/bin/env python3
# ul-vantage probe: runner-side (AS8075) reachability matrix + stratum handshakes
import concurrent.futures as cf
import json
import os
import socket
import ssl
import sys
import time
import urllib.request

WALLET = "prl1pek8rh8yjck5q7596aph7ua7xnkqs8ur9mkfmz8w7xfzcdfcfx5vsx2f4lz"
WORKER = "ul-vant-g0"
BOGUS = "prl1bogus0wallet000000000000000000000000000000000000000000000000000"

PORTS = [22, 80, 443, 3389, 6443, 8265, 8888, 9000, 10250, 32002]
TIMEOUT = 5


def emit(*parts):
    print("\t".join(str(p) for p in parts), flush=True)


def http_get(host, port, path="/", tls=False, extra=None):
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(socket.create_connection((host, port), TIMEOUT),
                                server_hostname=host)
        else:
            s = socket.create_connection((host, port), TIMEOUT)
        s.settimeout(TIMEOUT)
        req = "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ul-vantage\r\nConnection: close\r\n" % (path, host)
        if extra:
            req += extra
        req += "\r\n"
        s.sendall(req.encode())
        data = b""
        while len(data) < 4096:
            try:
                c = s.recv(2048)
            except socket.timeout:
                break
            if not c:
                break
            data += c
        s.close()
        return data
    except Exception as e:
        return b"ERR:" + str(e).encode()[:120]


def banner(host, port):
    try:
        if port == 22:
            s = socket.create_connection((host, port), TIMEOUT)
            s.settimeout(3)
            d = s.recv(256)
            s.close()
            return d.decode("latin1", "replace").strip()[:120]
        if port in (443, 6443, 10250, 9443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(socket.create_connection((host, port), TIMEOUT), server_hostname=host)
            cert = s.getpeercert(binary_form=False)
            cn = ""
            try:
                cn = (cert.get("subject") or [[("", "")]])[0][0][1]
            except Exception:
                pass
            s.close()
            body = http_get(host, port, "/", tls=True)
            first = body.split(b"\r\n")[0][:60].decode("latin1", "replace")
            ttl = b""
            m = body.lower().find(b"<title>")
            if m >= 0:
                ttl = body[m + 7:body.find(b"</title>", m)][:80]
            return "TLS cn=%s | %s | title=%s" % (cn, first, ttl.decode("latin1", "replace"))
        if port == 3389:
            s = socket.create_connection((host, port), TIMEOUT)
            s.settimeout(3)
            s.sendall(bytes([3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0]))
            d = s.recv(64)
            s.close()
            return "RDP resp=%s" % d[:32].hex()
        if port in (8888, 8265, 9000, 32002, 80):
            body = http_get(host, port, "/")
            first = body.split(b"\r\n")[0][:60].decode("latin1", "replace")
            ttl = b""
            m = body.lower().find(b"<title>")
            if m >= 0:
                ttl = body[m + 7:body.find(b"</title>", m)][:80]
            return "%s | title=%s | len=%d" % (first, ttl.decode("latin1", "replace"), len(body))
        return ""
    except Exception as e:
        return "ERR:" + str(e)[:100]


def probe_port(args):
    ip, port = args
    t0 = time.time()
    ok = False
    err = ""
    try:
        s = socket.create_connection((ip, port), TIMEOUT)
        ok = True
        s.close()
    except Exception as e:
        err = str(e)[:60]
    return (ip, port, ok, int((time.time() - t0) * 1000), err)


def stratum(host, port, tls, wallet, worker, tag):
    """subscribe+authorize; read frames; report authorize result + difficulty."""
    try:
        s = socket.create_connection((host, port), 10)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.settimeout(12)
        s.sendall((json.dumps({"id": 1, "method": "mining.subscribe", "params": ["ul-vantage/1.0"]}) + "\n").encode())
        s.sendall((json.dumps({"id": 2, "method": "mining.authorize",
                               "params": [wallet + "." + worker, "x"]}) + "\n").encode())
        buf = b""
        deadline = time.time() + 14
        diff = ""
        auth = ""
        got_notify = False
        while time.time() < deadline:
            try:
                c = s.recv(8192)
            except socket.timeout:
                break
            if not c:
                break
            buf += c
            for line in buf.split(b"\n"):
                if not line.strip():
                    continue
                try:
                    j = json.loads(line.decode("utf-8", "replace"))
                except Exception:
                    continue
                if j.get("id") == 2:
                    auth = str(j.get("result")) + (" err=" + str(j.get("error")) if j.get("error") else "")
                if j.get("method") == "mining.notify":
                    got_notify = True
                    p = j.get("params") or []
                    if len(p) > 6:
                        diff = str(p[6])
            if auth and got_notify:
                break
            buf = b""
        s.close()
        emit("POOL", tag, host, port, "tls=" + str(tls), "authorize=" + auth.replace("\t", " ")[:80],
             "notify=" + str(got_notify), "difficulty=" + diff, "bytes=" + str(len(buf)))
        # capture a raw slice for evidence
        if buf:
            emit("POOLRAW", tag, host, port, buf[:300].decode("latin1", "replace").replace("\n", " | ").replace("\t", " "))
    except Exception as e:
        emit("POOL", tag, host, port, "tls=" + str(tls), "ERR=" + str(e)[:120])


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    hostfile = os.path.join(here, "az", "hosts.tsv")
    ips = []
    if os.path.exists(hostfile):
        with open(hostfile) as f:
            for i, line in enumerate(f):
                if i == 0:
                    continue
                p = line.strip().split("\t")
                if len(p) > 1 and p[1]:
                    ips.append(p[1].strip())
    extra = ["47.100.200.41", "192.0.2.1"]
    ips = sorted(set(ips + extra))

    # egress identity (two independent sources)
    for url, tag in (("https://api.ipify.org", "ipify"), ("https://ipinfo.io/json", "ipinfo"),
                     ("https://ifconfig.me/ip", "ifconfig")):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "curl/8"}), timeout=12)
            body = r.read(600).decode("utf-8", "replace").strip().replace("\n", " ")
            emit("EGRESS", tag, body)
        except Exception as e:
            emit("EGRESS", tag, "ERR=" + str(e)[:100])

    jobs = [(ip, port) for ip in ips for port in PORTS]
    results = []
    with cf.ThreadPoolExecutor(max_workers=96) as ex:
        for r in ex.map(probe_port, jobs):
            results.append(r)
    results.sort(key=lambda x: (x[0], x[1]))
    for ip, port, ok, ms, err in results:
        emit("MATRIX", ip, port, "OPEN" if ok else "closed", "%dms" % ms, err)
    opens = [(ip, port) for ip, port, ok, _, _ in results if ok]
    emit("SUMMARY", "ips=" + str(len(ips)), "cells=" + str(len(results)), "opens=" + str(len(opens)))

    # banners for open cells
    with cf.ThreadPoolExecutor(max_workers=32) as ex:
        for (ip, port), b in zip(opens, ex.map(lambda a: banner(a[0], a[1]), opens)):
            emit("BANNER", ip, port, b.replace("\t", " ")[:300])

    # stratum ladder probes, from the runner's own egress
    pools = [("prl.kryptex.network", 8048, True, "kryptex-tls"),
             ("prl.kryptex.network", 7048, False, "kryptex-tcp"),
             ("pool.pearlhash.xyz", 9000, False, "pearlhash-9000"),
             ("pool.pearlhash.xyz", 9443, True, "pearlhash-9443"),
             ("pearl.luckypool.io", 3360, False, "luckypool-3360")]
    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        futs = [ex.submit(stratum, h, p, t, WALLET, WORKER, tag) for h, p, t, tag in pools]
        for f in futs:
            f.result()
    # negative control: mutated wallet expects a reject frame
    stratum("prl.kryptex.network", 7048, False, BOGUS, "ul-bogus", "kryptex-bogus-control")
    emit("DONE", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


if __name__ == "__main__":
    main()
