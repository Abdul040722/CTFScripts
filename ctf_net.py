#!/usr/bin/env python3
"""
CTF NETWORKING SKELETON  (CyberSci)
===================================
CHEAT SHEET
-----------
Install   : pip install requests pwntools scapy      (all optional; missing ones are skipped)
Help      : python3 ctf_net.py <cmd> -h
Flag hunt : every command auto-searches output (raw + base64/hex/rot13/xor/url/reverse)
            for --flag-regex. Confirm the flag format in the challenge text, then
            change DEFAULT_FLAG_RE below.

Subcommands
-----------
scan   -t 10.0.0.5 -p 1-10000 --threads 200        TCP connect scan + banner grab
tcp    -t 10.0.0.5 -p 9001 -d 'HELP\\n'             raw socket session -> edit session_logic()
tcp    -t 10.0.0.5 -p 9001 --hex 414243            payload from hex
tcp    -t 10.0.0.5 -p 9001 -f payload.bin          payload from file
udp    -t 10.0.0.5 -p 53 --hex <bytes>             one UDP datagram + reply
pwn    -t 10.0.0.5 -p 9001                         pwntools session -> edit pwn_logic()
http   -t http://10.0.0.5:8080/ -X POST -d 'a=1' -H 'X-Foo: bar' -c 'sid=abc'
http   -t 'http://10.0.0.5/?id=FUZZ' --fuzz words.txt      replace FUZZ from wordlist
http   -t http://10.0.0.5/ --proxy http://127.0.0.1:8080   send through Burp
pcap   -f capture.pcapng --strings --dump out/     per-flow payloads, strings, flag hunt
decode -d 'ZmxhZ3t0ZXN0fQ=='                       try common decodings (or -f file, or stdin)

Global flags: --timeout 5  --flag-regex 'regex'  -v (debug + tracebacks)

Fallbacks when this script is too slow to adapt:
  nmap -sC -sV -p- -T4 TARGET        tshark -r f.pcap -q -z follow,tcp,ascii,0
  nc TARGET PORT                     strings -n 6 f.pcap | grep -i flag
"""

import argparse
import base64
import binascii
import codecs
import logging
import operator
import os
import re
import socket
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------------------- #
# Optional dependencies: script still runs without them (only that cmd fails)
# --------------------------------------------------------------------------- #
try:
    import requests
except ImportError:
    requests = None
try:
    from pwn import remote as pwn_remote, context as pwn_context
except ImportError:
    pwn_remote = pwn_context = None
try:
    from scapy.all import PcapReader, IP, TCP, UDP, Raw
except ImportError:
    PcapReader = None

log = logging.getLogger("ctf")

# EDIT HERE: confirm the real flag format from the CyberSci rules / challenge text
DEFAULT_FLAG_RE = r"(?:CTF|FLAG|flag|CYBERSCI|cybersci)\{[^}\n]{1,200}\}"


# =========================================================================== #
# Helpers
# =========================================================================== #
def need(mod, pip_name):
    """Abort one command cleanly if an optional dependency is missing."""
    if mod is None:
        raise SystemExit(f"[!] missing dependency -> pip install {pip_name}")


def need_target(a):
    if not a.target:
        raise SystemExit("[!] -t/--target is required for this command")
    return a.target


def port_of(a, default=None):
    p = a.port or default
    if p is None:
        raise SystemExit("[!] -p/--port is required for this command")
    return int(p)


def parse_ports(spec):
    """'22,80,1000-1100' -> [22, 80, 1000, ..., 1100]"""
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.update(range(int(lo), int(hi) + 1))
        elif part:
            out.add(int(part))
    return sorted(p for p in out if 0 < p < 65536)


def to_bytes(x):
    return x if isinstance(x, (bytes, bytearray)) else str(x).encode("utf-8", "replace")


def show(direction, data):
    """Pretty-print bytes: '<<' = received, '>>' = sent."""
    print(f"{direction} {len(data)}B {data[:2000]!r}")


def build_payload(a):
    """
    Build the bytes you send. Priority: --hex > --file > --data.
    EDIT HERE: replace with struct.pack(...), crafted headers, etc. when needed.
    """
    if a.hex:
        return binascii.unhexlify(a.hex.replace(" ", ""))
    if a.file and a.cmd != "pcap":
        with open(a.file, "rb") as f:
            return f.read()
    if a.data:
        # lets you type \n \r\n \x41 in the shell
        return a.data.encode().decode("unicode_escape").encode("latin-1", "replace")
    return b""


_XOR_TABLES = {k: bytes(b ^ k for b in range(256)) for k in range(1, 256)}


def try_decodings(blob):
    """Yield (name, decoded_bytes) for each cheap decoding that succeeds."""
    t = bytes(blob).strip()
    attempts = {
        # TODO: add custom decodings here (e.g. base85, zlib, gzip, custom alphabet)
        "base64": lambda: base64.b64decode(t + b"=" * (-len(t) % 4)),
        "base64url": lambda: base64.urlsafe_b64decode(t + b"=" * (-len(t) % 4)),
        "base32": lambda: base64.b32decode(t + b"=" * (-len(t) % 8)),
        "hex": lambda: binascii.unhexlify(re.sub(rb"[^0-9a-fA-F]", b"", t)),
        "rot13": lambda: codecs.decode(t.decode("latin-1"), "rot_13").encode("latin-1"),
        "urldecode": lambda: urllib.parse.unquote_to_bytes(t),
        "reverse": lambda: t[::-1],
    }
    for name, fn in attempts.items():
        try:
            out = fn()
            if out and out != t:
                yield name, out
                if len(out) <= 1 << 16:  # chain one level: decode -> XOR (e.g. hex then XOR)
                    for k in range(1, 256):
                        yield f"{name}>xor_0x{k:02x}", out.translate(_XOR_TABLES[k])
        except Exception:
            continue
    if len(t) <= 1 << 20:  # single-byte XOR on the input itself (translate = fast C loop)
        for k in range(1, 256):
            yield f"xor_0x{k:02x}", t.translate(_XOR_TABLES[k])


def hunt(data, flag_re, label=""):
    """Search data and its common decodings for the flag regex. Prints hits."""
    blob = to_bytes(data)
    if not blob:
        return
    pat = re.compile(to_bytes(flag_re))
    seen = set()
    for name, buf in [("raw", blob), *try_decodings(blob)]:
        for m in pat.finditer(buf):
            hit = (name, m.group(0))
            if hit not in seen:
                seen.add(hit)
                print(f"\033[92m[FLAG?] {label} via {name}: {m.group(0).decode(errors='replace')}\033[0m")


def recv_until(sock, delim=b"\n", timeout=5.0, maxlen=1 << 20):
    """Read until delim appears, peer closes, or timeout. Returns what we have."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while delim not in buf and len(buf) < maxlen:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf


def recv_all(sock, timeout=2.0):
    """Read until the peer closes or goes quiet for `timeout` seconds."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf


_OPS = {"+": operator.add, "-": operator.sub, "*": operator.mul, "/": operator.floordiv}


def solve_arith(text):
    """Find 'a <op> b' in text and compute it (for 'solve 100 sums fast' challenges)."""
    m = re.search(rb"(-?\d+)\s*([+\-*/])\s*(-?\d+)", to_bytes(text))
    if not m:
        return None
    return _OPS[m.group(2).decode()](int(m.group(1)), int(m.group(3)))


# =========================================================================== #
# Commands
# =========================================================================== #
def cmd_scan(a):
    """TCP connect scan with banner grab. Threaded, no root needed."""
    host = need_target(a)
    ports = parse_ports(a.port or "1-1024")
    log.info("scanning %s (%d ports)", host, len(ports))

    def probe(p):
        try:
            with socket.socket() as s:
                s.settimeout(a.timeout)
                if s.connect_ex((host, p)) != 0:
                    return None
                s.settimeout(1.0)
                try:
                    return p, s.recv(256)
                except OSError:
                    return p, b""
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        for res in ex.map(probe, ports):
            if res:
                print(f"[open] {res[0]:<6} {res[1][:80]!r}")
                hunt(res[1], a.flag_re, f"port {res[0]}")


def session_logic(sock, a):
    """
    EDIT HERE: the scripted TCP conversation. Default = read banner, send payload, read reply.
    """
    banner = recv_until(sock, b"\n", a.timeout)
    show("<<", banner)
    hunt(banner, a.flag_re, "banner")

    # TODO: menu / prompt-driven service -> wait for prompt, then answer
    # recv_until(sock, b"> ", a.timeout); sock.sendall(b"1\n")

    # TODO: "solve N math questions" style challenge (adjust N and delimiters)
    # for _ in range(100):
    #     q = recv_until(sock, b"=", a.timeout)
    #     ans = solve_arith(q)                     # EDIT HERE: custom parsing if format differs
    #     if ans is None: break
    #     sock.sendall(f"{ans}\n".encode())

    payload = build_payload(a)  # EDIT HERE: payload logic lives in build_payload()
    if payload:
        sock.sendall(payload)
        show(">>", payload)

    reply = recv_all(sock, a.timeout)
    show("<<", reply)
    hunt(reply, a.flag_re, "reply")


def cmd_tcp(a):
    """Raw TCP session with plain sockets (no extra deps)."""
    host, port = need_target(a), port_of(a)
    with socket.create_connection((host, port), timeout=a.timeout) as s:
        log.info("connected %s:%d", host, port)
        session_logic(s, a)


def cmd_udp(a):
    """Send one UDP datagram and print the reply."""
    host, port = need_target(a), port_of(a)
    payload = build_payload(a) or b"\n"  # EDIT HERE: protocol-specific probe
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(a.timeout)
        s.sendto(payload, (host, port))
        show(">>", payload)
        data, addr = s.recvfrom(65535)
        show(f"<< {addr}", data)
        hunt(data, a.flag_re, "udp")


def pwn_logic(io, a):
    """EDIT HERE: pwntools-style conversation (recvuntil / sendlineafter / interactive)."""
    banner = io.recvrepeat(1)  # TODO: replace with io.recvuntil(b"prompt: ")
    show("<<", banner)
    hunt(banner, a.flag_re, "banner")
    # TODO: io.sendlineafter(b"> ", b"1")
    # TODO: io.sendline(build_payload(a))
    io.interactive()  # drop to a shell-like prompt; remove if fully scripted


def cmd_pwn(a):
    """Same idea as tcp, but with pwntools helpers."""
    need(pwn_remote, "pwntools")
    host, port = need_target(a), port_of(a)
    pwn_context.log_level = "debug" if a.verbose else "info"
    io = pwn_remote(host, port, timeout=a.timeout)
    try:
        pwn_logic(io, a)
    finally:
        io.close()


def fz(x, word):
    """Substitute the FUZZ marker (works on str only)."""
    return x.replace("FUZZ", word) if (word and isinstance(x, str)) else x


def cmd_http(a):
    """HTTP request(s) via requests. Supports custom headers/cookies/proxy and FUZZ wordlist."""
    need(requests, "requests")
    import urllib3
    urllib3.disable_warnings()

    url = need_target(a)
    if "://" not in url:
        url = f"http://{url}" + (f":{a.port}" if a.port else "")

    # EDIT HERE: default headers / auth tokens
    headers = {"User-Agent": "Mozilla/5.0"}
    for h in a.header or []:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    if a.cookie:
        headers["Cookie"] = a.cookie

    body = (build_payload(a) or b"").decode("latin-1") or None
    words = [None]
    if a.fuzz:
        with open(a.fuzz, errors="ignore") as f:
            words = [ln.strip() for ln in f if ln.strip()]

    s = requests.Session()
    s.verify = False
    if a.proxy:
        s.proxies = {"http": a.proxy, "https": a.proxy}

    for w in words:
        try:
            r = s.request(
                a.method,
                fz(url, w),
                headers={k: fz(v, w) for k, v in headers.items()},
                data=fz(body, w),
                timeout=a.timeout,
                allow_redirects=a.redirects,
            )
        except requests.RequestException as e:
            log.error("request failed (%s): %s", w, e)
            continue

        if w is None:  # single request -> full output
            print(f"[{r.status_code}] {r.reason}  {len(r.content)}B  {r.url}")
            for k, v in r.headers.items():
                print(f"  {k}: {v}")
            print("\n" + r.text[: a.max_body])
        else:  # fuzzing -> one line per word
            print(f"{r.status_code:<4} {len(r.content):<8} {w}")

        # TODO: add logic here (e.g. compare to baseline length, check for 'success' marker)
        hunt(r.content, a.flag_re, f"body[{w}]")
        hunt("\n".join(f"{k}: {v}" for k, v in r.headers.items()), a.flag_re, f"headers[{w}]")


def cmd_pcap(a):
    """Summarise a capture: per-flow payloads, strings, flag hunt. Streams the file (low RAM)."""
    need(PcapReader, "scapy")
    if not a.file:
        raise SystemExit("[!] -f/--file <capture> is required")
    flows, count = {}, 0
    with PcapReader(a.file) as rd:
        for p in rd:
            count += 1
            if IP in p and Raw in p and (TCP in p or UDP in p):
                l4 = p[TCP] if TCP in p else p[UDP]
                key = (p[IP].src, l4.sport, p[IP].dst, l4.dport, "tcp" if TCP in p else "udp")
                flows.setdefault(key, bytearray()).extend(bytes(p[Raw].load))
            # TODO: add DNS / ICMP / non-IP extraction here (exfil via DNS names, ICMP payloads)
    print(f"[pcap] {count} packets, {len(flows)} payload flows (arrival order, not seq-sorted)")

    if a.dump:
        os.makedirs(a.dump, exist_ok=True)
    for i, (key, buf) in enumerate(sorted(flows.items(), key=lambda kv: -len(kv[1]))):
        src, sp, dst, dp, proto = key
        print(f"  #{i:<3} {proto} {src}:{sp} -> {dst}:{dp}  {len(buf)}B")
        if a.strings:
            for st in re.findall(rb"[ -~]{6,}", bytes(buf))[:15]:
                print(f"        {st[:120]!r}")
        hunt(bytes(buf), a.flag_re, f"flow#{i}")
        if a.dump:
            with open(os.path.join(a.dump, f"flow{i}_{proto}_{sp}-{dp}.bin"), "wb") as f:
                f.write(buf)
    # TODO: for retransmits / out-of-order data, fall back to: tshark -r FILE -q -z follow,tcp,raw,N


def cmd_decode(a):
    """Try common decodings on -d / -f / stdin; auto-hunt flags (incl. XOR)."""
    if a.data:
        blob = to_bytes(a.data)
    elif a.file:
        with open(a.file, "rb") as f:
            blob = f.read()
    else:
        blob = sys.stdin.buffer.read()
    for name, out in try_decodings(blob):
        if "xor" in name:
            continue  # too noisy to print; flag hunt below still covers it
        ratio = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / max(len(out), 1)
        if ratio > 0.9:
            print(f"[{name}] {out[:300]!r}")
    hunt(blob, a.flag_re, "decode")


# =========================================================================== #
# CLI
# =========================================================================== #
def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-t", "--target", help="IP / hostname / URL")
    common.add_argument("-p", "--port", help="port (scan accepts 22,80,1-1024)")
    common.add_argument("-f", "--file", help="input file: pcap, payload bytes, etc.")
    common.add_argument("-d", "--data", help="payload string; escapes ok: 'GET / HTTP/1.0\\r\\n\\r\\n'")
    common.add_argument("--hex", help="payload as hex string")
    common.add_argument("--timeout", type=float, default=5.0)
    common.add_argument("--flag-regex", dest="flag_re", default=DEFAULT_FLAG_RE, help="regex for the flag format")
    common.add_argument("-v", "--verbose", action="store_true", help="debug logs + tracebacks")

    ap = argparse.ArgumentParser(description="CTF networking skeleton (see file docstring)",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", parents=[common], help="TCP connect scan + banners")
    sp.add_argument("--threads", type=int, default=100)
    sp.set_defaults(func=cmd_scan)

    sub.add_parser("tcp", parents=[common], help="raw TCP session").set_defaults(func=cmd_tcp)
    sub.add_parser("udp", parents=[common], help="single UDP probe").set_defaults(func=cmd_udp)
    sub.add_parser("pwn", parents=[common], help="pwntools session").set_defaults(func=cmd_pwn)

    sp = sub.add_parser("http", parents=[common], help="HTTP request / fuzz")
    sp.add_argument("-X", "--method", default="GET")
    sp.add_argument("-H", "--header", action="append", help="'Key: Value' (repeatable)")
    sp.add_argument("-c", "--cookie", help="'a=b; c=d'")
    sp.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 (Burp)")
    sp.add_argument("--fuzz", help="wordlist; replaces FUZZ in url/headers/body")
    sp.add_argument("--redirects", action="store_true", help="follow redirects")
    sp.add_argument("--max-body", type=int, default=3000, dest="max_body")
    sp.set_defaults(func=cmd_http)

    sp = sub.add_parser("pcap", parents=[common], help="analyse a capture file")
    sp.add_argument("--strings", action="store_true", help="print printable strings per flow")
    sp.add_argument("--dump", metavar="DIR", help="write each flow payload to DIR")
    sp.set_defaults(func=cmd_pcap)

    sub.add_parser("decode", parents=[common], help="try common decodings").set_defaults(func=cmd_decode)
    return ap


def main():
    a = build_parser().parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="[%(levelname).1s] %(message)s")
    try:
        a.func(a)
    except KeyboardInterrupt:
        log.warning("interrupted")
        sys.exit(130)
    except socket.timeout:
        log.error("timed out (raise --timeout or check target/port)")
    except ConnectionRefusedError:
        log.error("connection refused (wrong port, or service down)")
    except socket.gaierror as e:
        log.error("cannot resolve target: %s", e)
    except FileNotFoundError as e:
        log.error("file not found: %s", e.filename)
    except (ValueError, binascii.Error) as e:
        log.error("bad input (port/hex/regex?): %s", e)
    except OSError as e:
        log.error("network/OS error: %s", e)
    except Exception as e:  # last-resort net so the script never dies silently
        log.error("unexpected %s: %s", type(e).__name__, e)
        if a.verbose:
            raise


if __name__ == "__main__":
    main()
