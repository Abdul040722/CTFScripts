#!/usr/bin/env python3
"""
CTF CRYPTOGRAPHY SKELETON  (CyberSci)
========================================
CHEAT SHEET
-----------
Install   : pip install cryptography    (only needed for the `aes` command; everything
            else -- RSA math, classical ciphers, hashing -- is pure stdlib, no deps)
Help      : python3 ctf_crypto.py <cmd> -h
Flag hunt : most commands auto-search their decrypted/decoded output for --flag-regex,
            including base64/hex/rot13/xor/url/reverse decodings of it. Confirm the real
            flag format first, then change DEFAULT_FLAG_RE below.
Numbers   : -n/-e/-c/-p/-q/--priv-d accept plain decimal OR 0x-prefixed hex.

Subcommands
-----------
classical --mode caesar   -d 'Wkh iodj lv khuh'                 brute all 26 shifts, ranked
classical --mode vigenere -d '<ciphertext>'                     guess keylen (IC) + crack
classical --mode vigenere -d '<ciphertext>' --key SECRETKEY     decrypt with a known key
classical --mode xor -d '<hex>' --input-format hex               single-byte XOR brute force
classical --mode xor -d '<hex>' --input-format hex --max-keylen 40
                                                                 repeating-key XOR crack (Cryptopals #6 style)
classical --mode auto -d '<text>'                                 quick "just try everything" pass

modmath --op gcd     --a 462 --b 1071
modmath --op modinv  --a 17 --m 3120
modmath --op crt     --mods 3,5,7 --rems 2,3,2
modmath --op factor  --n 1000000007000000033 --timeout 15
modmath --op dlog    --g 5 --h 8923 --p 104729
modmath --op isprime --n 2305843009213693951

rsa --action decrypt         -n .. -e 65537 -c .. -p .. -q ..      (or --priv-d, or --pem key.pem)
rsa --action factor          -n .. -c .. --timeout 20              trial-div -> Fermat -> Pollard rho
rsa --action wiener          -n .. -e .. -c ..                     low private exponent d
rsa --action common-modulus  -n .. --c1 .. --e1 .. --c2 .. --e2 .. same n, coprime e's, same m
rsa --action batch-gcd       --batch-file moduli.csv               weak-key shared-factor sweep ('n,c' per line)
rsa --action hastad --e 3 --pair n1:c1 --pair n2:c2 --pair n3:c3   broadcast attack, no padding

aes --action ecb-detect  -d '<hex ciphertext>'                     duplicate-block scan
aes --action encrypt/decrypt --mode ecb|cbc --key <hex> [--iv <hex>] -d '<hex>'
aes --action bitflip --data <hex ciphertext> --block-index 2 --known admin=0 --target admin=1
aes --action ecb-oracle                                            byte-at-a-time secret recovery;
                                                                    wire up ecb_oracle_stub() first

hash --action identify -d '<hex digest>'                           guess algo from digest length
hash --action crack -d '<hex digest>' --algo sha256 --wordlist rockyou.txt
hash --action length-extension --known-hash <hex> --known-len 37 --append ';admin=true' --algo sha1

decode -d 'ZmxhZ3t0ZXN0fQ=='                                      try common decodings (or -f file, or stdin)

Fallbacks when this script is too slow to adapt:
  CyberChef (offline copy if allowed)        RsaCtfTool (github.com/RsaCtfTool/RsaCtfTool)
  factordb.com (if internet access is allowed in-comp)   openssl rsa -text -in key.pem
"""

import argparse
import base64
import binascii
import codecs
import hashlib
import logging
import math
import random
import re
import struct
import sys
import time
import urllib.parse
from collections import Counter
from math import isqrt

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    Cipher = algorithms = modes = default_backend = None

log = logging.getLogger("ctfcrypto")

# EDIT HERE: confirm the real flag format from the CyberSci rules / challenge text
DEFAULT_FLAG_RE = r"(?:CTF|FLAG|flag|CYBERSCI|cybersci)\{[^}\n]{1,200}\}"


# =========================================================================== #
# Generic helpers
# =========================================================================== #
def need(mod, pip_name):
    if mod is None:
        raise SystemExit(f"[!] missing dependency -> pip install {pip_name}")


def to_bytes(x):
    return x if isinstance(x, (bytes, bytearray)) else str(x).encode("utf-8", "replace")


def parse_int(s):
    """Accept plain decimal or 0x-prefixed hex for the big-number CLI flags."""
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def i2b(n, length=None):
    if length is None:
        length = max((n.bit_length() + 7) // 8, 1)
    return n.to_bytes(length, "big")


def get_raw_bytes(a):
    if getattr(a, "data", None) is not None:
        return a.data.encode()
    if getattr(a, "file", None):
        with open(a.file, "rb") as f:
            return f.read()
    return sys.stdin.buffer.read()


def decode_input(a):
    """Read -d/-f/stdin and interpret per --input-format (text/hex/base64).
    Only hex/base64 get whitespace stripped (that's just copy-paste formatting); raw
    text is passed through exactly, since trailing bytes/spaces can be meaningful
    (e.g. PKCS7-sensitive AES input built with --no-pad)."""
    raw = get_raw_bytes(a)
    fmt = getattr(a, "input_format", "text")
    if fmt == "hex":
        return bytes.fromhex(re.sub(rb"\s+", b"", raw).decode())
    if fmt == "base64":
        raw = raw.strip()
        return base64.b64decode(raw + b"=" * (-len(raw) % 4))
    return raw


def try_decodings(blob):
    """Yield (name, decoded_bytes) for each cheap decoding that succeeds."""
    t = bytes(blob).strip()
    attempts = {
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
                if len(out) <= 1 << 16:
                    for k in range(1, 256):
                        yield f"{name}>xor_0x{k:02x}", out.translate(_XOR_TABLES[k])
        except Exception:
            continue
    if len(t) <= 1 << 20:
        for k in range(1, 256):
            yield f"xor_0x{k:02x}", t.translate(_XOR_TABLES[k])


_XOR_TABLES = {k: bytes(b ^ k for b in range(256)) for k in range(1, 256)}


def hunt(data, flag_re, label=""):
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
# Number theory (RSA / modmath backbone)
# =========================================================================== #
def ext_gcd(a, b):
    """Iterative extended Euclid: returns (gcd, x, y) with a*x + b*y = gcd. No recursion
    limit issues even for 2048-bit RSA numbers."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def is_prime(n, rounds=40):
    """Miller-Rabin; deterministic for n < 3.3*10^24 via the known witness set."""
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for sp in small:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    def witness_ok(a):
        x = pow(a, d, n)
        if x in (1, n - 1):
            return True
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                return True
        return False

    bases = small if n < 3_317_044_064_679_887_385_961_981 else [random.randrange(2, n - 1) for _ in range(rounds)]
    return all(witness_ok(a) for a in bases if a < n)


_SMALL_PRIMES = None


def small_primes(limit=100_000):
    global _SMALL_PRIMES
    if _SMALL_PRIMES is not None:
        return _SMALL_PRIMES
    sieve = bytearray([1]) * (limit + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    _SMALL_PRIMES = [i for i, v in enumerate(sieve) if v]
    return _SMALL_PRIMES


def trial_division(n):
    for p in small_primes():
        if n % p == 0:
            return p
    return None


def fermat_factor(n, deadline):
    """Fast when p and q are close together."""
    a = isqrt(n)
    if a * a < n:
        a += 1
    while time.time() < deadline:
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def pollard_rho(n, deadline):
    """General-purpose; fine for moduli up to a few hundred bits within a short budget --
    NOT a substitute for factoring a real 2048-bit balanced-prime RSA key."""
    if n % 2 == 0:
        return 2
    while time.time() < deadline:
        x = y = random.randrange(2, n - 1)
        c = random.randrange(1, n - 1)
        d = 1
        while d == 1:
            if time.time() > deadline:
                return None
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d
    return None


def factor_full(n, deadline):
    """Recursive: trial division -> short Fermat slice -> Pollard rho, until `deadline`
    (wall clock). Returns a sorted list of prime factors; a surviving composite means
    the time budget ran out (-> raise --timeout, or this n is just too hard for this script)."""
    if n == 1:
        return []
    if is_prime(n):
        return [n]
    d = trial_division(n)
    if d:
        return sorted(factor_full(d, deadline) + factor_full(n // d, deadline))
    fr = fermat_factor(n, min(deadline, time.time() + 2))  # cheap, try it first
    if fr:
        p0, q0 = fr
        return sorted(factor_full(p0, deadline) + factor_full(q0, deadline))
    d = pollard_rho(n, deadline)
    if d:
        return sorted(factor_full(d, deadline) + factor_full(n // d, deadline))
    return [n]  # gave up -- still composite


def iroot(x, n):
    """Exact integer n-th root of x, or None if x is not a perfect n-th power."""
    if x < 0:
        return None
    if x == 0:
        return 0
    hi = 1
    while hi**n <= x:
        hi *= 2
    lo = hi // 2
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**n <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo if lo**n == x else None


def crt_pair(r1, m1, r2, m2):
    g, p, _ = ext_gcd(m1, m2)
    if (r2 - r1) % g != 0:
        return None
    lcm = m1 // g * m2
    x = (r1 + (r2 - r1) // g * p % (m2 // g) * m1) % lcm
    return x, lcm


def crt(remainders, moduli):
    """General CRT (works even if moduli aren't pairwise coprime; returns None if the
    system is inconsistent). Returns (x, lcm_of_moduli)."""
    r, m = remainders[0], moduli[0]
    for ri, mi in zip(remainders[1:], moduli[1:]):
        res = crt_pair(r, m, ri, mi)
        if res is None:
            return None
        r, m = res
    return r, m


def bsgs(g, h, p, order=None):
    """Baby-step giant-step discrete log: solve g^x = h (mod p). O(sqrt(order)) time
    and memory -- fine up to order ~2^40ish, not realistic for full-size DH primes."""
    order = order or (p - 1)
    m = isqrt(order) + 1
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % p
    factor = pow(g, -m, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


def wiener_attack(e, n):
    """Classic Wiener's attack for small private exponent d (roughly d < n^0.25 / 3).
    Returns (d, p, q) or None."""

    def cf(num, den):
        out = []
        while den:
            q, r = divmod(num, den)
            out.append(q)
            num, den = den, r
        return out

    def convergents(terms):
        n1, n2, d1, d2 = 1, 0, 0, 1
        for a in terms:
            n1, n2 = a * n1 + n2, n1
            d1, d2 = a * d1 + d2, d1
            yield n1, d1

    for k, d in convergents(cf(e, n)):
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        sq = isqrt(disc)
        if sq * sq != disc or (s + sq) % 2:
            continue
        p, q = (s + sq) // 2, (s - sq) // 2
        if p > 1 and q > 1 and p * q == n:
            return d, p, q
    return None


# =========================================================================== #
# classical  (caesar / vigenere / xor, with English-frequency scoring)
# =========================================================================== #
# standard English letter frequency (%), used for chi-squared scoring -- lower = more English-like
ENGLISH_FREQ = {
    "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97, "N": 6.75, "S": 6.33, "H": 6.09,
    "R": 5.99, "D": 4.25, "L": 4.03, "C": 2.78, "U": 2.76, "M": 2.41, "W": 2.36, "F": 2.23,
    "G": 2.02, "Y": 1.97, "P": 1.93, "B": 1.29, "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15,
    "Q": 0.10, "Z": 0.07,
}


def chi_squared_score(text: bytes) -> float:
    """Lower is more English-like. Heavily penalizes non-printable garbage so wrong
    keys sort to the bottom even on short ciphertexts."""
    letters = [c for c in text.upper() if 65 <= c <= 90]
    n = len(letters)
    if n == 0:
        return 1e9
    counts = Counter(chr(c) for c in letters)
    score = sum((counts.get(L, 0) - pct / 100.0 * n) ** 2 / (pct / 100.0 * n) for L, pct in ENGLISH_FREQ.items())
    nonprintable = sum(1 for b in text if b < 9 or 13 < b < 32 or b > 126)
    return score + nonprintable * 50


def caesar_shift(text: bytes, shift: int) -> bytes:
    out = bytearray()
    for b in text:
        if 65 <= b <= 90:
            out.append((b - 65 + shift) % 26 + 65)
        elif 97 <= b <= 122:
            out.append((b - 97 + shift) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)


def crack_vigenere_key(data, klen):
    letters = [chr(b) for b in data.upper() if 65 <= b <= 90]
    key = ""
    for col in range(klen):
        seq = letters[col::klen]
        best = min(range(26), key=lambda k: chi_squared_score(bytes((ord(c) - 65 - k) % 26 + 65 for c in seq)))
        key += chr(best + 65)
    return key


def vigenere_decrypt(text: bytes, key: str) -> bytes:
    out, ki, key = bytearray(), 0, key.upper()
    for b in text:
        if 65 <= b <= 90:
            out.append((b - 65 - (ord(key[ki % len(key)]) - 65)) % 26 + 65)
            ki += 1
        elif 97 <= b <= 122:
            out.append((b - 97 - (ord(key[ki % len(key)]) - 65)) % 26 + 97)
            ki += 1
        else:
            out.append(b)
    return bytes(out)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_xor_keysize(data, max_len=40):
    scored = []
    for klen in range(2, min(max_len, len(data) // 4) + 1):
        # average over up to 20 chunks (not just the first couple) -- too few chunks makes
        # the normalized Hamming distance noisy enough to rank the true keysize low
        nchunks = min(len(data) // klen, 20)
        if nchunks < 4:
            continue
        chunks = [data[i * klen : (i + 1) * klen] for i in range(nchunks)]
        dists = [hamming_distance(chunks[i], chunks[j]) / klen for i in range(nchunks) for j in range(i + 1, nchunks)]
        scored.append((klen, sum(dists) / len(dists)))
    return sorted(scored, key=lambda t: t[1])


# NOTE: repeating-key XOR cracking needs real ciphertext length to work -- each key byte
# is recovered from only every klen-th byte, so a short ciphertext starves every column of
# samples and the frequency analysis gets unreliable. Rule of thumb: want at least ~40-50
# bytes per key byte (i.e. len(ciphertext) >~ 40*keylen) before trusting the result.
def crack_repeating_xor(data, klen):
    key = bytearray()
    for col in range(klen):
        block = data[col::klen]
        key.append(min(range(256), key=lambda k: chi_squared_score(xor_bytes(block, bytes([k])))))
    return bytes(key)


def cmd_classical(a):
    data = decode_input(a)

    if a.mode == "caesar":
        if a.key:
            shift = int(a.key)
            pt = caesar_shift(data, -shift)
            print(f"[shift {shift}] {pt!r}")
            hunt(pt, a.flag_re, "caesar")
        else:
            ranked = sorted(range(26), key=lambda s: chi_squared_score(caesar_shift(data, -s)))
            for s in ranked[: a.top]:
                pt = caesar_shift(data, -s)
                print(f"[shift {s:2d}] score={chi_squared_score(pt):8.1f}  {pt[:150]!r}")
                hunt(pt, a.flag_re, f"caesar shift {s}")

    elif a.mode == "vigenere":
        if a.key:
            pt = vigenere_decrypt(data, a.key)
            print(f"[key={a.key}] {pt[:200]!r}")
            hunt(pt, a.flag_re, "vigenere")
        else:
            # Try every key length up to --max-keylen and rank by how English the fully
            # decrypted result looks. More reliable than index-of-coincidence pre-filtering
            # on short ciphertexts (IC alone is noisy under ~200 letters).
            # EDIT HERE: columns shorter than ~10 letters overfit -- each column has so few
            # samples that per-column chi-squared cracking can fit English by pure chance,
            # so longer wrong keys spuriously outscore the true (shorter) one. Skip those.
            nletters = sum(1 for b in data if 65 <= (b & ~32) <= 90)
            candidates = []
            for klen in range(1, a.max_keylen + 1):
                if nletters // klen < 10:
                    continue
                key = crack_vigenere_key(data, klen)
                pt = vigenere_decrypt(data, key)
                candidates.append((chi_squared_score(pt), klen, key, pt))
            for score, klen, key, pt in sorted(candidates)[: a.top]:
                print(f"[keylen {klen:2d} key={key}] score={score:8.1f}  {pt[:150]!r}")
                hunt(pt, a.flag_re, f"vigenere keylen {klen}")

    elif a.mode == "xor":
        if a.key:
            # EDIT HERE: force one or the other if this guess is wrong
            is_hex = len(a.key) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in a.key)
            key = bytes.fromhex(a.key) if is_hex else a.key.encode()
            pt = xor_bytes(data, key)
            print(f"[key={key!r}] {pt[:200]!r}")
            hunt(pt, a.flag_re, "xor")
        else:
            print("-- single-byte XOR brute force --")
            ranked = sorted(range(256), key=lambda k: chi_squared_score(xor_bytes(data, bytes([k]))))
            for k in ranked[: a.top]:
                pt = xor_bytes(data, bytes([k]))
                print(f"[key 0x{k:02x}] score={chi_squared_score(pt):8.1f}  {pt[:120]!r}")
                hunt(pt, a.flag_re, f"xor single 0x{k:02x}")
            print("-- repeating-key XOR (Hamming-distance keysize guess) --")
            for klen, score in guess_xor_keysize(data, a.max_keylen)[:3]:
                key = crack_repeating_xor(data, klen)
                pt = xor_bytes(data, key)
                print(f"[keylen {klen:2d} dist={score:.3f} key={key!r}] {pt[:150]!r}")
                hunt(pt, a.flag_re, f"xor repeating keylen {klen}")

    elif a.mode == "auto":
        candidates = [(chi_squared_score(caesar_shift(data, -s)), f"caesar shift {s}", caesar_shift(data, -s))
                      for s in range(26)]
        candidates += [(chi_squared_score(xor_bytes(data, bytes([k]))), f"xor 0x{k:02x}", xor_bytes(data, bytes([k])))
                       for k in range(256)]
        for score, name, pt in sorted(candidates)[: a.top]:
            print(f"[{name}] score={score:8.1f}  {pt[:120]!r}")
            hunt(pt, a.flag_re, name)


# =========================================================================== #
# modmath
# =========================================================================== #
def cmd_modmath(a):
    if a.op == "gcd":
        x, y = parse_int(a.a), parse_int(a.b)
        g, s, t = ext_gcd(x, y)
        print(f"gcd({x}, {y}) = {g}")
        print(f"{x}*({s}) + {y}*({t}) = {g}")
    elif a.op == "modinv":
        x, m = parse_int(a.a), parse_int(a.m)
        try:
            print(f"{x}^-1 mod {m} = {pow(x, -1, m)}")
        except ValueError:
            print(f"[-] {x} has no inverse mod {m} (gcd != 1)")
    elif a.op == "crt":
        mods = [parse_int(x) for x in a.mods.split(",")]
        rems = [parse_int(x) for x in a.rems.split(",")]
        res = crt(rems, mods)
        print("[-] no solution (moduli not compatible)" if res is None else f"x = {res[0]} (mod {res[1]})")
    elif a.op == "factor":
        n = parse_int(a.n)
        log.info("factoring %d (timeout %.0fs)...", n, a.timeout)
        print(factor_full(n, time.time() + a.timeout))
    elif a.op == "dlog":
        g, h, p = parse_int(a.g), parse_int(a.h), parse_int(a.p)
        order = parse_int(a.order) if a.order else p - 1
        if order > 2**48:
            log.warning("order %d is large -- bsgs needs ~sqrt(order) time/memory, this may not finish", order)
        x = bsgs(g, h, p, order)
        print(f"x = {x}" if x is not None else "[-] not found in the given order")
    elif a.op == "isprime":
        n = parse_int(a.n)
        print(f"{n} is {'PRIME' if is_prime(n, a.rounds) else 'COMPOSITE'}")


# =========================================================================== #
# rsa
# =========================================================================== #
def load_pem(path):
    need(Cipher, "cryptography")
    from cryptography.hazmat.primitives import serialization

    raw = open(path, "rb").read()
    try:
        key = serialization.load_pem_private_key(raw, password=None)  # TODO: EDIT HERE - password=b"..." if set
        nums, pub = key.private_numbers(), key.private_numbers().public_numbers
        return dict(n=pub.n, e=pub.e, d=nums.d, p=nums.p, q=nums.q)
    except (ValueError, TypeError):
        key = serialization.load_pem_public_key(raw)
        nums = key.public_numbers()
        return dict(n=nums.n, e=nums.e, d=None, p=None, q=None)


def cmd_rsa(a):
    n = parse_int(a.n) if a.n else None
    e = parse_int(a.e) if a.e else 65537
    c = parse_int(a.c) if a.c else None
    p = parse_int(a.p) if a.p else None
    q = parse_int(a.q) if a.q else None
    priv_d = parse_int(a.priv_d) if a.priv_d else None

    if a.pem:
        info = load_pem(a.pem)
        n = n or info["n"]
        e = info["e"] if not a.e else e
        p, q, priv_d = p or info["p"], q or info["q"], priv_d or info["d"]

    if a.action == "info":
        if n is None:
            raise SystemExit("[!] need -n (or --pem)")
        print(f"n = {n}\nbit length = {n.bit_length()}\ne = {e}")
        if p and q:
            print(f"p = {p}\nq = {q}")
        if priv_d:
            print(f"d = {priv_d}")

    elif a.action == "decrypt":
        if n is None or c is None:
            raise SystemExit("[!] need -n and -c")
        if priv_d is None:
            if not (p and q):
                raise SystemExit("[!] need --priv-d, or -p and -q, to decrypt")
            priv_d = pow(e, -1, (p - 1) * (q - 1))
        m = pow(c, priv_d, n)
        mb = i2b(m)
        print(f"m (int)   = {m}\nm (hex)   = {m:x}\nm (bytes) = {mb!r}")
        hunt(mb, a.flag_re, "rsa-decrypt")

    elif a.action == "factor":
        if n is None:
            raise SystemExit("[!] need -n")
        log.info("factoring (trial division -> Fermat -> Pollard rho, timeout %.0fs)...", a.timeout)
        factors = factor_full(n, time.time() + a.timeout)
        print(f"factors: {factors}")
        if len(factors) == 2 and c is not None:
            p0, q0 = factors
            d0 = pow(e, -1, (p0 - 1) * (q0 - 1))
            mb = i2b(pow(c, d0, n))
            print(f"d = {d0}\nm (bytes) = {mb!r}")
            hunt(mb, a.flag_re, "rsa-factor")

    elif a.action == "wiener":
        if n is None:
            raise SystemExit("[!] need -n (and -e, default 65537)")
        res = wiener_attack(e, n)
        if not res:
            print("[-] Wiener's attack failed (d probably isn't small enough)")
            return
        d0, p0, q0 = res
        print(f"d = {d0}\np = {p0}\nq = {q0}")
        if c is not None:
            mb = i2b(pow(c, d0, n))
            print(f"m (bytes) = {mb!r}")
            hunt(mb, a.flag_re, "rsa-wiener")

    elif a.action == "common-modulus":
        if n is None or c is None or a.c2 is None or a.e1 is None or a.e2 is None:
            raise SystemExit("[!] need -n, -c/--c1, --c2, --e1, --e2")
        c1, c2, e1, e2 = c, parse_int(a.c2), parse_int(a.e1), parse_int(a.e2)
        g, x, y = ext_gcd(e1, e2)
        if g != 1:
            raise SystemExit(f"[!] gcd(e1,e2)={g} != 1 -- common modulus attack needs coprime exponents")
        mb = i2b((pow(c1, x, n) * pow(c2, y, n)) % n)
        print(f"m (bytes) = {mb!r}")
        hunt(mb, a.flag_re, "rsa-common-modulus")

    elif a.action == "batch-gcd":
        if not a.batch_file:
            raise SystemExit("[!] need --batch-file ('n' or 'n,c' per line)")
        entries = []
        with open(a.batch_file) as f:
            for line in f:
                parts = line.strip().split(",")
                if not parts or not parts[0]:
                    continue
                entries.append((parse_int(parts[0]), parse_int(parts[1]) if len(parts) > 1 else None))
        hits = 0
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                ni, ci = entries[i]
                nj, cj = entries[j]
                g = math.gcd(ni, nj)
                if g in (1, ni, nj):
                    continue
                hits += 1
                print(f"[+] shared factor between entry {i} and {j}: p = {g}")
                for idx, (nn, cc) in ((i, (ni, ci)), (j, (nj, cj))):
                    if cc is not None:
                        qq = nn // g
                        dd = pow(e, -1, (g - 1) * (qq - 1))
                        mb = i2b(pow(cc, dd, nn))
                        print(f"    entry {idx}: m = {mb!r}")
                        hunt(mb, a.flag_re, f"rsa-batch-gcd entry{idx}")
        if not hits:
            print("[-] no shared factors found across the given moduli")

    elif a.action == "hastad":
        if not a.pair:
            raise SystemExit("[!] give >= e pairs via --pair n:c (repeatable); default e=3 if unset")
        pairs = [tuple(parse_int(x) for x in pr.split(":")) for pr in a.pair]
        ns, cs = [p_[0] for p_ in pairs], [p_[1] for p_ in pairs]
        if len(pairs) < e:
            log.warning("only %d pairs given but e=%d -- CRT result may not be the true m^e", len(pairs), e)
        res = crt(cs, ns)
        if res is None:
            raise SystemExit("[!] CRT failed -- moduli may not be pairwise coprime")
        m = iroot(res[0], e)
        if m is None:
            print("[-] no exact integer e-th root -- message may be padded, or you need more pairs")
            return
        mb = i2b(m)
        print(f"m (bytes) = {mb!r}")
        hunt(mb, a.flag_re, "rsa-hastad")


# =========================================================================== #
# aes
# =========================================================================== #
def pkcs7_pad(data: bytes, block_size=16) -> bytes:
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS7 padding")
    return data[:-n]


def aes_encrypt(key, data, mode="ecb", iv=None, pad=True):
    need(Cipher, "cryptography")
    if pad:
        data = pkcs7_pad(data)
    c = Cipher(algorithms.AES(key), modes.ECB() if mode == "ecb" else modes.CBC(iv), default_backend()).encryptor()
    return c.update(data) + c.finalize()


def aes_decrypt(key, data, mode="ecb", iv=None, unpad=True):
    need(Cipher, "cryptography")
    c = Cipher(algorithms.AES(key), modes.ECB() if mode == "ecb" else modes.CBC(iv), default_backend()).decryptor()
    out = c.update(data) + c.finalize()
    return pkcs7_unpad(out) if unpad else out


def ecb_oracle_stub(prefix: bytes) -> bytes:
    """
    EDIT HERE: point this at the real oracle, e.g.:
        return requests.post(URL, data={"in": prefix.hex()}).json()["ct"].encode()
    Must return ECB(attacker_prefix + secret). Left as-is it refuses to run so you
    don't silently chase garbage output.
    """
    raise NotImplementedError("wire ecb_oracle_stub() up to the real encryption oracle first")


def find_block_size(oracle, max_try=64):
    base = len(oracle(b""))
    for i in range(1, max_try):
        n = len(oracle(b"A" * i))
        if n != base:
            return n - base, base
    return None, base


def ecb_byte_at_a_time(oracle, block_size, max_secret_len=512):
    """Cryptopals-style byte-at-a-time ECB secret recovery."""
    known = b""
    for _ in range(max_secret_len):
        pad_len = (block_size - 1 - len(known) % block_size) % block_size
        pad = b"A" * pad_len
        idx = (len(pad) + len(known)) // block_size
        target = oracle(pad)[idx * block_size : (idx + 1) * block_size]
        found = None
        for byte in range(256):
            g = oracle(pad + known + bytes([byte]))[idx * block_size : (idx + 1) * block_size]
            if g == target:
                found = byte
                break
        if found is None:
            break  # ran out of secret (hit its own PKCS7 padding) -- done
        known += bytes([found])
    return known


def cmd_aes(a):
    if a.action == "ecb-detect":
        data = decode_input(a)
        bs = a.block_size
        blocks = [data[i : i + bs] for i in range(0, len(data), bs)]
        seen, dupes = {}, []
        for i, b in enumerate(blocks):
            if b in seen:
                dupes.append((seen[b], i, b.hex()))
            else:
                seen[b] = i
        if dupes:
            print(f"[!] ECB indicated -- {len(dupes)} duplicate block pair(s):")
            for i, j, bh in dupes:
                print(f"    block {i} == block {j}: {bh}")
        else:
            print("[-] no duplicate blocks -- likely not ECB (or no repeating plaintext blocks)")

    elif a.action in ("encrypt", "decrypt"):
        if not a.key:
            raise SystemExit("[!] need --key (hex)")
        key = bytes.fromhex(a.key)
        iv = bytes.fromhex(a.iv) if a.iv else None
        if a.mode == "cbc" and iv is None:
            raise SystemExit("[!] cbc mode needs --iv")
        data = decode_input(a)
        if a.action == "encrypt":
            out = aes_encrypt(key, data, a.mode, iv, pad=not a.no_pad)
            print(f"ciphertext (hex): {out.hex()}")
        else:
            out = aes_decrypt(key, data, a.mode, iv, unpad=not a.no_pad)
            print(f"plaintext: {out!r}")
            hunt(out, a.flag_re, "aes-decrypt")

    elif a.action == "bitflip":
        ct = decode_input(a)
        known, target = a.known.encode(), a.target.encode()
        if len(known) != len(target):
            raise SystemExit("[!] --known and --target must be the same length")
        bs = a.block_size
        blocks = [bytearray(ct[i : i + bs]) for i in range(0, len(ct), bs)]
        prev = a.block_index - 1
        if prev < 0:
            raise SystemExit("[!] block-index 0 needs the IV flipped instead -- usually sent separately, patch it by hand")
        delta = bytes(k ^ t for k, t in zip(known, target))
        for i, d in enumerate(delta):
            blocks[prev][a.offset + i] ^= d
        print(f"new ciphertext (hex): {b''.join(bytes(b) for b in blocks).hex()}")

    elif a.action == "ecb-oracle":
        bs, base_len = find_block_size(ecb_oracle_stub)
        print(f"[+] block size: {bs}, base ciphertext len: {base_len}")
        probe = ecb_oracle_stub(b"A" * bs * 3)
        blocks = [probe[i : i + bs] for i in range(0, len(probe), bs)]
        print("[+] ECB confirmed (repeated blocks)" if len(set(blocks)) < len(blocks)
              else "[!] doesn't look like ECB -- double-check the oracle before trusting this")
        secret = ecb_byte_at_a_time(ecb_oracle_stub, bs)
        print(f"[+] recovered secret ({len(secret)}B): {secret!r}")
        print("    (the last byte is often a deterministic PKCS7 padding byte, e.g. \\x01 -- "
              "strip it if the tail looks like padding, not secret)")
        hunt(secret, a.flag_re, "ecb-oracle")


# =========================================================================== #
# hash  (identify / crack / length-extension)
# =========================================================================== #
def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


_MD5_K = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
_MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
_SHA1_K = [0x5A827999] * 20 + [0x6ED9EBA1] * 20 + [0x8F1BBCDC] * 20 + [0xCA62C1D6] * 20


def _md5_pad(msg_len):
    pad = b"\x80" + b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    return pad + struct.pack("<Q", (msg_len * 8) & 0xFFFFFFFFFFFFFFFF)


def _md5_compress(state, block):
    a, b, c, d = state
    M = struct.unpack("<16I", block)
    A, B, C, D = a, b, c, d
    for i in range(64):
        if i < 16:
            F, g = (B & C) | (~B & 0xFFFFFFFF & D), i
        elif i < 32:
            F, g = (D & B) | (~D & 0xFFFFFFFF & C), (5 * i + 1) % 16
        elif i < 48:
            F, g = B ^ C ^ D, (3 * i + 5) % 16
        else:
            F, g = C ^ (B | ~D & 0xFFFFFFFF), (7 * i) % 16
        F = (F + A + _MD5_K[i] + M[g]) & 0xFFFFFFFF
        A, D, C, B = D, C, B, (B + _rotl(F, _MD5_S[i])) & 0xFFFFFFFF
    return (a + A) & 0xFFFFFFFF, (b + B) & 0xFFFFFFFF, (c + C) & 0xFFFFFFFF, (d + D) & 0xFFFFFFFF


def _sha1_pad(msg_len):
    pad = b"\x80" + b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    return pad + struct.pack(">Q", msg_len * 8)


def _sha1_compress(state, block):
    a, b, c, d, e = state
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    A, B, C, D, E = a, b, c, d, e
    for i in range(80):
        if i < 20:
            f = (B & C) | (~B & 0xFFFFFFFF & D)
        elif i < 40:
            f = B ^ C ^ D
        elif i < 60:
            f = (B & C) | (B & D) | (C & D)
        else:
            f = B ^ C ^ D
        A, B, C, D, E = (_rotl(A, 5) + f + E + _SHA1_K[i] + w[i]) & 0xFFFFFFFF, A, _rotl(B, 30), C, D
    return (a + A) & 0xFFFFFFFF, (b + B) & 0xFFFFFFFF, (c + C) & 0xFFFFFFFF, (d + D) & 0xFFFFFFFF, (e + E) & 0xFFFFFFFF


_HASHSPEC = {
    "md5": dict(pad=_md5_pad, compress=_md5_compress, iv=(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
                fmt="<4I"),
    "sha1": dict(pad=_sha1_pad, compress=_sha1_compress,
                 iv=(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0), fmt=">5I"),
}
# TODO: EDIT HERE - add sha256 the same way (FIPS 180-4 compression function) if a
#       challenge needs length-extension on it; md5/sha1 cover the overwhelming majority.


def _run_state(message, state, spec):
    for i in range(0, len(message), 64):
        state = spec["compress"](state, message[i : i + 64])
    return state


def length_extend(known_hash_hex, orig_total_len, append, algo="md5"):
    """Forge H(secret||known_msg||glue||append) knowing only H(secret||known_msg) and
    len(secret||known_msg) -- never the secret itself.
    Returns (new_digest_hex, glue_padding). Send known_msg + glue_padding + append as
    the new raw bytes (NOT final_pad -- that's the server's own implicit padding step)."""
    spec = _HASHSPEC[algo]
    state = struct.unpack(spec["fmt"], bytes.fromhex(known_hash_hex))
    glue = spec["pad"](orig_total_len)
    new_total_len = orig_total_len + len(glue) + len(append)
    final_pad = spec["pad"](new_total_len)
    final_state = _run_state(append + final_pad, state, spec)
    return struct.pack(spec["fmt"], *final_state).hex(), glue


_HASH_LEN_GUESS = {16: "md5 / ntlm", 20: "sha1", 28: "sha224", 32: "sha256", 48: "sha384", 64: "sha512"}


def cmd_hash(a):
    if a.action == "identify":
        h = a.data.strip()
        nbytes = len(h) // 2
        print(f"{len(h)} hex chars ({nbytes} bytes) -> likely: {_HASH_LEN_GUESS.get(nbytes, 'unknown')}")

    elif a.action == "crack":
        if not a.wordlist:
            raise SystemExit("[!] --wordlist is required")
        target = a.data.strip().lower()
        algo = a.algo or {16: "md5", 20: "sha1", 32: "sha256", 64: "sha512"}.get(len(target) // 2, "md5")
        hashfn = getattr(hashlib, algo, None)
        if hashfn is None:
            raise SystemExit(f"[!] unknown algo {algo!r} (see hashlib.algorithms_available)")
        prefix, suffix = (a.prefix or "").encode(), (a.suffix or "").encode()
        with open(a.wordlist, errors="ignore") as f:
            for line in f:
                w = line.rstrip("\n")
                if hashfn(prefix + w.encode() + suffix).hexdigest() == target:
                    print(f"[CRACKED] {w!r}")
                    return
        print("[-] not found in wordlist")

    elif a.action == "length-extension":
        if not a.known_hash or a.append is None:
            raise SystemExit("[!] need --known-hash and --append")
        append = a.append.encode()
        if a.known_len is not None:
            digest, glue = length_extend(a.known_hash, a.known_len, append, a.algo)
            print(f"forged digest : {digest}")
            print(f"glue padding  : {glue.hex()}  ({len(glue)}B)")
            print(f"send as (hex) : {(a.known_msg or '').encode().hex()}{glue.hex()}{append.hex()}")
            hunt(digest, a.flag_re, "length-extension")
        elif a.secret_len_range:
            lo, hi = (int(x) for x in a.secret_len_range.split("-"))
            known_msg_len = a.known_msg_len or 0
            print(f"-- {hi - lo + 1} candidates (try each against the real oracle) --")
            for secret_len in range(lo, hi + 1):
                total = secret_len + known_msg_len
                digest, glue = length_extend(a.known_hash, total, append, a.algo)
                print(f"[secret_len={secret_len:3d}] digest={digest}  "
                      f"send=(known_msg)+{glue.hex()}+{append.hex()}")
        else:
            raise SystemExit("[!] need --known-len, or --secret-len-range with --known-msg-len")


# =========================================================================== #
# decode
# =========================================================================== #
def cmd_decode(a):
    if a.data is not None:
        blob = to_bytes(a.data)
    elif a.file:
        with open(a.file, "rb") as f:
            blob = f.read()
    else:
        blob = sys.stdin.buffer.read()
    blob = blob.strip()
    for name, out in try_decodings(blob):
        if "xor" in name:
            continue
        ratio = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / max(len(out), 1)
        if ratio > 0.9:
            print(f"[{name}] {out[:300]!r}")
    hunt(blob, a.flag_re, "decode")


# =========================================================================== #
# CLI
# =========================================================================== #
def build_parser():
    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--flag-regex", dest="flag_re", default=DEFAULT_FLAG_RE)
    base.add_argument("-v", "--verbose", action="store_true", help="debug logs + tracebacks")

    ap = argparse.ArgumentParser(description="CTF cryptography skeleton (see file docstring)",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("classical", parents=[base], help="caesar / vigenere / xor")
    sp.add_argument("-d", "--data")
    sp.add_argument("-f", "--file")
    sp.add_argument("--mode", required=True, choices=["caesar", "vigenere", "xor", "auto"])
    sp.add_argument("--key", help="known key: int shift / vigenere word / xor hex-or-text")
    sp.add_argument("--input-format", dest="input_format", default="text", choices=["text", "hex", "base64"])
    sp.add_argument("--max-keylen", dest="max_keylen", type=int, default=40)
    sp.add_argument("--top", type=int, default=5, help="how many ranked candidates to show")
    sp.set_defaults(func=cmd_classical)

    sp = sub.add_parser("modmath", parents=[base], help="gcd/modinv/crt/factor/dlog/isprime")
    sp.add_argument("--op", required=True, choices=["gcd", "modinv", "crt", "factor", "dlog", "isprime"])
    sp.add_argument("--a"); sp.add_argument("--b"); sp.add_argument("--m")
    sp.add_argument("--mods"); sp.add_argument("--rems")
    sp.add_argument("--n")
    sp.add_argument("--g"); sp.add_argument("--h"); sp.add_argument("--p"); sp.add_argument("--order")
    sp.add_argument("--timeout", type=float, default=15.0)
    sp.add_argument("--rounds", type=int, default=40)
    sp.set_defaults(func=cmd_modmath)

    sp = sub.add_parser("rsa", parents=[base], help="decrypt/factor/wiener/common-modulus/batch-gcd/hastad")
    sp.add_argument("--action", required=True,
                    choices=["decrypt", "factor", "wiener", "common-modulus", "batch-gcd", "hastad", "info"])
    sp.add_argument("-n"); sp.add_argument("-e"); sp.add_argument("-c")
    sp.add_argument("-p"); sp.add_argument("-q")
    sp.add_argument("--priv-d", dest="priv_d", help="known private exponent (avoids clashing with -d elsewhere)")
    sp.add_argument("--pem", help="PEM public or private key file")
    sp.add_argument("--c1", dest="c", help="alias for -c, reads better for common-modulus")
    sp.add_argument("--e1"); sp.add_argument("--c2"); sp.add_argument("--e2")
    sp.add_argument("--batch-file", dest="batch_file")
    sp.add_argument("--pair", action="append", help="'n:c' (repeatable) for hastad")
    sp.add_argument("--timeout", type=float, default=20.0)
    sp.set_defaults(func=cmd_rsa)

    sp = sub.add_parser("aes", parents=[base], help="ecb-detect/encrypt/decrypt/bitflip/ecb-oracle")
    sp.add_argument("--action", required=True,
                    choices=["ecb-detect", "encrypt", "decrypt", "bitflip", "ecb-oracle"])
    sp.add_argument("-d", "--data")
    sp.add_argument("-f", "--file")
    sp.add_argument("--input-format", dest="input_format", default="hex", choices=["text", "hex", "base64"])
    sp.add_argument("--key"); sp.add_argument("--iv")
    sp.add_argument("--mode", default="ecb", choices=["ecb", "cbc"])
    sp.add_argument("--no-pad", dest="no_pad", action="store_true")
    sp.add_argument("--block-size", dest="block_size", type=int, default=16)
    sp.add_argument("--block-index", dest="block_index", type=int)
    sp.add_argument("--offset", type=int, default=0)
    sp.add_argument("--known"); sp.add_argument("--target")
    sp.set_defaults(func=cmd_aes)

    sp = sub.add_parser("hash", parents=[base], help="identify/crack/length-extension")
    sp.add_argument("--action", required=True, choices=["identify", "crack", "length-extension"])
    sp.add_argument("-d", "--data", help="hash hex (identify/crack)")
    sp.add_argument("--algo", default=None)
    sp.add_argument("--wordlist")
    sp.add_argument("--prefix"); sp.add_argument("--suffix")
    sp.add_argument("--known-hash", dest="known_hash")
    sp.add_argument("--known-len", dest="known_len", type=int, help="exact len(secret||known_msg)")
    sp.add_argument("--known-msg", dest="known_msg", default="", help="the message portion you already have")
    sp.add_argument("--known-msg-len", dest="known_msg_len", type=int)
    sp.add_argument("--secret-len-range", dest="secret_len_range", help="'0-32' to brute a range against an oracle")
    sp.add_argument("--append")
    sp.set_defaults(func=cmd_hash)

    sp = sub.add_parser("decode", parents=[base], help="try common decodings")
    sp.add_argument("-d", "--data")
    sp.add_argument("-f", "--file")
    sp.set_defaults(func=cmd_decode)

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
    except FileNotFoundError as e:
        log.error("file not found: %s", e.filename)
    except (ValueError, binascii.Error) as e:
        log.error("bad input (number/hex/padding?): %s", e)
    except Exception as e:  # last-resort net so the script never dies silently
        log.error("unexpected %s: %s", type(e).__name__, e)
        if a.verbose:
            raise


if __name__ == "__main__":
    main()
