#!/usr/bin/env python3
"""
CTF OSINT SKELETON  (CyberSci)
================================
CHEAT SHEET
-----------
Install   : pip install requests dnspython pypdf Pillow
            (requests is the only hard dependency; dnspython enables MX/TXT/NS/SOA/CNAME
            records, pypdf enables PDF metadata, Pillow enables image EXIF/GPS -- each
            degrades gracefully with a one-line "pip install X" message if missing)
Help      : python3 ctf_osint.py <cmd> -h
Flag hunt : most commands auto-search their output for --flag-regex, including
            base64/hex/rot13/xor/url/reverse decodings of it. Confirm the real flag
            format first, then change DEFAULT_FLAG_RE below.
Scope     : everything here only touches data a service already serves to anyone who
            asks (DNS, WHOIS, cert-transparency logs, public profile pages, a file
            you already have) -- no login bypass, no private-data aggregation, no
            scraping of people-search/data-broker sites. Keep it that way when editing.

Subcommands
-----------
domain     -t example.com                          WHOIS (via IANA referral chain) + DNS records
domain     -t example.com --no-whois                DNS only (A/AAAA always; more with dnspython)
subdomains -t example.com                           crt.sh certificate-transparency search
subdomains -t example.com --wordlist sub.txt        + brute-force DNS resolution
username   -u johndoe                               checks a curated multi-site table concurrently
metadata   -f photo.jpg                              auto-detects image/PDF/Office, pulls hidden
                                                      metadata (GPS, author, software, timestamps);
                                                      for a file this misreads, exiftool is the
                                                      far more complete fallback -- it handles
                                                      every format/edge-case this skeleton doesn't
geo        --action exif -f photo.jpg                EXIF GPS -> decimal coords + map link
geo        --action ip -t 8.8.8.8                    IP geolocation; tries ipapi.co (HTTPS) then
                                                      ip-api.com (HTTP) so an HTTPS-only/TLS-
                                                      inspecting network still gets an answer
geo        --action coords --lat 45.4215 --lon -75.6972
                                                      decimal <-> DMS conversion + map links
wayback    -t https://example.com/page               list archive.org snapshots
wayback    -t https://example.com/page --fetch latest fetch a specific snapshot's content
dork       --site example.com --filetype pdf --intitle confidential
                                                      builds a correct dork query + search URLs
                                                      (prints URLs for you to open -- never
                                                      scrapes search results itself)
decode     -d 'ZmxhZ3t0ZXN0fQ=='                      try common decodings (or -f file, or stdin)

Fallbacks when this script is too slow to adapt:
  Sherlock / Maigret (username enum, hundreds of sites)   exiftool photo.jpg
  theHarvester -d example.com (emails/subdomains)         Shodan / Censys (exposed services)
  archive.org/web directly                                 Google/Bing/DuckDuckGo directly
"""

import argparse
import base64
import binascii
import codecs
import logging
import os
import re
import socket
import sys
import urllib.parse
import zipfile
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    requests = None
try:
    import dns.resolver
except ImportError:
    dns = None
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None
try:
    from PIL import Image, ExifTags
except ImportError:
    Image = ExifTags = None

log = logging.getLogger("ctfosint")

# EDIT HERE: confirm the real flag format from the CyberSci rules / challenge text
DEFAULT_FLAG_RE = r"(?:CTF|FLAG|flag|CYBERSCI|cybersci)\{[^}\n]{1,200}\}"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ctf-osint-script/1.0)"}


# =========================================================================== #
# Generic helpers
# =========================================================================== #
def need(mod, pip_name):
    if mod is None:
        raise SystemExit(f"[!] missing dependency -> pip install {pip_name}")


def to_bytes(x):
    return x if isinstance(x, (bytes, bytearray)) else str(x).encode("utf-8", "replace")


_XOR_TABLES = {k: bytes(b ^ k for b in range(256)) for k in range(1, 256)}

# EDIT HERE if a challenge genuinely needs bigger blobs run through this -- but know the
# cost first. The derived buffers below (rot13/urldecode/reverse in particular, which are
# near-full-size copies with no cap of their own) measurably blow up memory well beyond a
# simple multiple of the input size: confirmed in testing that a 25MB input drove this
# process to 2.3GB RSS, and 50MB reliably got OOM-killed. These caps keep flag-hunting
# usable against a real multi-MB file without exhausting memory mid-round.
MAX_DECODE_SIZE = 2 << 20  # 2 MiB -- beyond this, skip ALL derived decodings (rot13,
                            # urldecode, reverse, etc.); hunt() still pattern-matches the
                            # raw bytes directly, so a plaintext/unencoded flag still hits
MAX_XOR_SIZE = 1 << 16      # 64 KiB -- single-byte XOR brute force (255 full-size passes)
                            # stays fast under this; for a bigger suspect blob, carve out
                            # just that region first and XOR-brute-force the smaller piece


def try_decodings(blob):
    t = bytes(blob).strip()
    if len(t) > MAX_DECODE_SIZE:
        return  # too large to safely fan out -- see MAX_DECODE_SIZE above
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
    if len(t) <= MAX_XOR_SIZE:
        for k in range(1, 256):
            yield f"xor_0x{k:02x}", t.translate(_XOR_TABLES[k])


def _hunt_sources(blob):
    yield "raw", blob
    yield from try_decodings(blob)


def hunt(data, flag_re, label=""):
    blob = to_bytes(data)
    if not blob:
        return
    pat = re.compile(to_bytes(flag_re))
    seen = set()
    for name, buf in _hunt_sources(blob):
        for m in pat.finditer(buf):
            hit = (name, m.group(0))
            if hit not in seen:
                seen.add(hit)
                print(f"\033[92m[FLAG?] {label} via {name}: {m.group(0).decode(errors='replace')}\033[0m")


# =========================================================================== #
# domain  (WHOIS via IANA referral chain + DNS records)
# =========================================================================== #
def whois_query(server, query, timeout=10):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode(errors="replace")


def whois_lookup(domain, timeout=10):
    """IANA -> TLD registry -> (sometimes) registrar, the standard WHOIS referral chain.
    Pure stdlib (raw TCP/43), no API key, works for the vast majority of TLDs."""
    tld = domain.rsplit(".", 1)[-1]
    iana_resp = whois_query("whois.iana.org", tld, timeout)
    m = re.search(r"refer:\s*(\S+)", iana_resp, re.I)
    if not m:
        return iana_resp  # unusual TLD -- IANA's own record is all we get
    registry_resp = whois_query(m.group(1), domain, timeout)
    # thin registries (e.g. Verisign for .com/.net) point further at the real registrar
    m2 = re.search(r"Registrar WHOIS Server:\s*(\S+)", registry_resp, re.I)
    if m2 and m2.group(1) and m2.group(1) != m.group(1):
        try:
            deeper = whois_query(m2.group(1), domain, timeout)
            return registry_resp + "\n\n----- referred registrar record -----\n\n" + deeper
        except OSError:
            pass
    return registry_resp


def dns_basic(domain):
    """A/AAAA via getaddrinfo -- always available, zero extra dependencies."""
    out = {"A": [], "AAAA": []}
    try:
        for family, _, _, _, addr in socket.getaddrinfo(domain, None):
            if family == socket.AF_INET and addr[0] not in out["A"]:
                out["A"].append(addr[0])
            elif family == socket.AF_INET6 and addr[0] not in out["AAAA"]:
                out["AAAA"].append(addr[0])
    except socket.gaierror as e:
        out["error"] = str(e)
    return out


def dns_extra(domain, record_types):
    need(dns, "dnspython")
    resolver = dns.resolver.Resolver()
    out = {}
    for rtype in record_types:
        try:
            out[rtype] = [r.to_text() for r in resolver.resolve(domain, rtype)]
        except Exception as e:
            out[rtype] = [f"(none: {type(e).__name__})"]
    return out


def cmd_domain(a):
    if not a.no_dns:
        print("-- DNS: A/AAAA --")
        for k, v in dns_basic(a.target).items():
            print(f"  {k}: {', '.join(v) if v else '(none)'}")
        if dns:
            print("-- DNS: MX/TXT/NS/SOA/CNAME --")
            for rtype, vals in dns_extra(a.target, ["MX", "TXT", "NS", "SOA", "CNAME"]).items():
                for v in vals:
                    print(f"  {rtype}: {v}")
                    hunt(v, a.flag_re, f"dns-{rtype}")
        else:
            print("  (pip install dnspython for MX/TXT/NS/SOA/CNAME)")

    if not a.no_whois:
        print("-- WHOIS --")
        try:
            resp = whois_lookup(a.target, a.timeout)
            print(resp)
            hunt(resp, a.flag_re, "whois")
        except OSError as e:
            log.error("whois lookup failed: %s", e)


# =========================================================================== #
# subdomains  (certificate-transparency search + optional DNS brute force)
# =========================================================================== #
def crtsh_subdomains(domain, timeout=15):
    need(requests, "requests")
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    r = requests.get(url, timeout=timeout, headers=HEADERS)
    r.raise_for_status()
    names = set()
    for entry in r.json():
        for line in entry.get("name_value", "").split("\n"):
            line = line.strip().lstrip("*.")
            if line.endswith(domain):
                names.add(line)
    return sorted(names)


def detect_wildcard_dns(domain):
    """Probe two near-certainly-nonexistent subdomains; if they both resolve anyway (to the
    same address(es)), the zone has a wildcard record -- without this check, every single
    word in the brute-force list would come back as a false 'found', pointed at whatever
    catch-all IP the wildcard sinkholes to. Returns the wildcard's IP set, or None.
    NOTE: socket.gethostbyname_ex() delegates to the OS resolver, which doesn't honor
    Python-side timeouts -- a genuinely unresponsive DNS server blocks for as long as the
    system resolver's own retry/timeout settings allow, same as the brute-force loop below."""
    ip_sets = []
    for _ in range(2):
        probe = f"{os.urandom(8).hex()}-wc-probe.{domain}"
        try:
            _, _, ips = socket.gethostbyname_ex(probe)
            ip_sets.append(set(ips))
        except socket.gaierror:
            return None  # a random name correctly failed to resolve -- no wildcard
    if ip_sets[0] and ip_sets[0] & ip_sets[1]:
        return ip_sets[0] | ip_sets[1]
    return None


def cmd_subdomains(a):
    log.info("querying crt.sh for *.%s ...", a.target)
    try:
        names = crtsh_subdomains(a.target, a.timeout)
        print(f"[+] {len(names)} unique name(s) from certificate-transparency logs:")
        for n in names:
            print(f"  {n}")
            hunt(n, a.flag_re, "crtsh")
    except Exception as e:
        log.error("crt.sh lookup failed: %s", e)

    if a.wordlist:
        print(f"-- brute-forcing subdomains from {a.wordlist} --")
        wildcard_ips = detect_wildcard_dns(a.target)
        if wildcard_ips:
            print(f"[!] wildcard DNS detected ({', '.join(sorted(wildcard_ips))}) -- any "
                  f"word that resolves to ONLY this address is noise, not a real subdomain, "
                  f"and gets suppressed below")

        with open(a.wordlist, errors="ignore") as f:
            words = [w.strip() for w in f if w.strip()]

        def resolve(w):
            fqdn = f"{w}.{a.target}"
            try:
                _, _, ips = socket.gethostbyname_ex(fqdn)
                return fqdn, set(ips)
            except socket.gaierror:
                return None

        suppressed = 0
        with ThreadPoolExecutor(max_workers=a.threads) as ex:
            for res in ex.map(resolve, words):
                if not res:
                    continue
                fqdn, ips = res
                if wildcard_ips and ips and ips <= wildcard_ips:
                    suppressed += 1
                    continue
                print(f"  {fqdn} -> {', '.join(sorted(ips))}")
                hunt(fqdn, a.flag_re, "subdomain-brute")
        if suppressed:
            print(f"  ({suppressed} additional word(s) matched the wildcard catch-all and were suppressed)")


# =========================================================================== #
# username  (Sherlock-style existence check across a small, verified site table)
# =========================================================================== #
# TODO: EDIT HERE - add more sites. Each entry is (name, url_template, check(response)->bool).
# Three check styles, pick whichever fits the target site:
#   status code only : lambda r: r.status_code == 200
#   JSON field        : lambda r: bool(r.json().get("some_field"))
#   body marker        : lambda r: "not found" not in r.text.lower()
#
# NOTE on reliability: PyPI and npm are deliberately NOT here -- both were tested live
# while building this script and BOTH returned the exact same response (PyPI: HTTP 200
# with a "Client Challenge" anti-bot page; npm: HTTP 403) for a real username and a
# randomly-made-up one, which silently makes every lookup report FOUND (PyPI) or every
# lookup error out (npm). Package registries in particular seem to bot-wall this pattern
# now, likely due to scraping/typosquatting abuse. X/Twitter and Instagram are excluded
# for the same underlying reason: they serve the same app-shell HTML either way.
# The entries below check out individually (GitHub verified live; Steam and Hacker News'
# marker text confirmed against real fetched pages), but run one `username -u <a-handle-
# you-know-is-real>` sanity check on your own connection before competition day -- a site
# can silently flip into the PyPI failure mode at any time, and you want to find that out
# before the round, not during it.
SITES = [
    ("GitHub", "https://github.com/{u}", lambda r: r.status_code == 200),
    ("GitLab", "https://gitlab.com/{u}", lambda r: r.status_code == 200),
    ("Docker Hub", "https://hub.docker.com/v2/users/{u}/", lambda r: r.status_code == 200),
    ("Reddit", "https://www.reddit.com/user/{u}/about.json", lambda r: r.status_code == 200 and "data" in r.json()),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?username={u}", lambda r: bool(r.json().get("them"))),
    ("Steam", "https://steamcommunity.com/id/{u}", lambda r: "The specified profile could not be found" not in r.text),
    ("Hacker News", "https://news.ycombinator.com/user?id={u}", lambda r: "No such user" not in r.text),
]


def check_site(username, site, timeout):
    name, url_tmpl, check = site
    url = url_tmpl.format(u=urllib.parse.quote(username))
    try:
        r = requests.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        return name, url, check(r), None
    except Exception as e:
        return name, url, None, str(e)


def cmd_username(a):
    need(requests, "requests")
    print(f"[*] checking {len(SITES)} sites for username {a.username!r} ...")
    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        futures = [ex.submit(check_site, a.username, site, a.timeout) for site in SITES]
        for fut in futures:
            name, url, exists, err = fut.result()
            if err:
                print(f"  [?] {name:12s} error: {err}")
            elif exists:
                print(f"  [+] {name:12s} FOUND   {url}")
            else:
                print(f"  [-] {name:12s} not found")


# =========================================================================== #
# metadata  (auto-detects image / PDF / Office, pulls hidden metadata)
# =========================================================================== #
def gps_to_decimal(coord, ref):
    deg, minutes, seconds = (float(x) for x in coord)
    dec = deg + minutes / 60 + seconds / 3600
    return -dec if ref in ("S", "W") else dec


def extract_image_metadata(path, a):
    need(Image, "Pillow")
    img = Image.open(path)
    print(f"format={img.format} size={img.size}")
    exif = img.getexif()
    if not exif:
        print("[-] no EXIF data")
        return
    for tag_id, value in exif.items():
        tag = ExifTags.TAGS.get(tag_id, tag_id)
        if tag in ("Make", "Model", "Software", "DateTime", "DateTimeOriginal", "Artist", "Copyright"):
            print(f"  {tag}: {value}")
            hunt(str(value), a.flag_re, f"exif:{tag}")
    gps_ifd = exif.get_ifd(0x8825)  # GPS sub-IFD
    if not gps_ifd:
        print("  [-] no GPS data in EXIF")
        return
    gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
    if "GPSLatitude" in gps and "GPSLongitude" in gps:
        lat = gps_to_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
        lon = gps_to_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
        print(f"  GPS: {lat:.6f}, {lon:.6f}")
        print(f"  map: https://www.google.com/maps?q={lat:.6f},{lon:.6f}")
    else:
        print("  [-] GPS IFD present but no lat/lon tags")


def extract_pdf_metadata(path, a):
    need(PdfReader, "pypdf")
    reader = PdfReader(path)
    meta = reader.metadata or {}
    for k, v in meta.items():
        print(f"  {k}: {v}")
        hunt(str(v), a.flag_re, f"pdf:{k}")
    print(f"  pages: {len(reader.pages)}")
    # pypdf's .metadata only reads the classic /Info dict; many modern PDFs also carry
    # richer XMP metadata as an embedded XML stream, so scan the raw bytes for it too.
    raw = open(path, "rb").read()
    for m in re.finditer(rb"<(dc:creator|xmp:CreatorTool|pdf:Producer)[^>]*>(.*?)</\1>", raw, re.S):
        val = m.group(2).decode(errors="replace").strip()
        print(f"  xmp {m.group(1).decode()}: {val}")
        hunt(val, a.flag_re, "pdf-xmp")


def extract_office_metadata(path, a):
    """core.xml/app.xml are simple one-level-deep for most fields (dc:creator,
    cp:lastModifiedBy, Company, ...), but app.xml's HeadingPairs/TitlesOfParts use a
    nested vt:vector/vt:variant wrapper around generic lpstr/i4 leaves, so printing bare
    leaf tags would show several unrelated 'lpstr: ...' lines with no way to tell them
    apart. Walking with one level of parent-tag context disambiguates that case without
    needing a full path (print/hunt still sees every leaf regardless of nesting depth --
    nothing is lost either way, this only affects how it's labeled on screen)."""
    import xml.etree.ElementTree as ET

    def walk(el, parent_tag, part):
        tag = el.tag.split("}")[-1]  # strip the XML namespace for readability
        if el.text and el.text.strip():
            label = f"{parent_tag}.{tag}" if parent_tag else tag
            print(f"  {label}: {el.text.strip()}")
            hunt(el.text, a.flag_re, f"office:{part}:{label}")
        for child in el:
            walk(child, tag, part)

    with zipfile.ZipFile(path) as z:
        for part in ("docProps/core.xml", "docProps/app.xml"):
            if part not in z.namelist():
                continue
            print(f"-- {part} --")
            walk(ET.fromstring(z.read(part)), None, part)


def cmd_metadata(a):
    ext = os.path.splitext(a.file)[1].lower()
    with open(a.file, "rb") as f:
        head = f.read(8)
    if head[:4] == b"PK\x03\x04":
        extract_office_metadata(a.file, a)  # covers docx/xlsx/pptx/odt (docProps/core.xml)
    elif head[:5] == b"%PDF-":
        extract_pdf_metadata(a.file, a)
    elif head[:3] == b"\xff\xd8\xff" or head[:8] == b"\x89PNG\r\n\x1a\n" or ext in (".jpg", ".jpeg", ".png", ".tif", ".tiff", ".heic"):
        extract_image_metadata(a.file, a)
    else:
        print(f"[-] no handler for this file (ext={ext!r}, magic={head[:4].hex()}) -- "
              f"TODO: EDIT HERE to add one, or try the forensics skeleton's `identify`")


# =========================================================================== #
# geo  (exif GPS / IP geolocation / manual coordinate conversion)
# =========================================================================== #
def dms_to_decimal(deg, minutes, seconds, ref):
    dec = deg + minutes / 60 + seconds / 3600
    return -dec if ref.upper() in ("S", "W") else dec


def decimal_to_dms(dec):
    sign = -1 if dec < 0 else 1
    dec = abs(dec)
    deg = int(dec)
    minutes_f = (dec - deg) * 60
    minutes = int(minutes_f)
    seconds = (minutes_f - minutes) * 60
    return sign * deg, minutes, seconds


def _parse_ipapi_co(data):
    # ipapi.co returns HTTP 200 with {"error": true, "reason": "..."} for several failure
    # cases (invalid IP, reserved/private IP), and a 429 with the same shape when rate
    # limited -- the "error" key is the one check that covers all of them.
    if data.get("error"):
        return None
    return {"query": data.get("ip"), "country": data.get("country_name"), "region": data.get("region"),
            "city": data.get("city"), "zip": data.get("postal"), "lat": data.get("latitude"),
            "lon": data.get("longitude"), "isp": data.get("org"), "org": data.get("org"),
            "as": data.get("asn")}


def _parse_ip_api_com(data):
    if data.get("status") != "success":
        return None
    return {"query": data.get("query"), "country": data.get("country"), "region": data.get("regionName"),
            "city": data.get("city"), "zip": data.get("zip"), "lat": data.get("lat"), "lon": data.get("lon"),
            "isp": data.get("isp"), "org": data.get("org"), "as": data.get("as")}


# Tried in order; the first provider that returns a usable result wins.
# ipapi.co goes first: HTTPS, no key, ~1000 lookups/day free -- survives a CTF network that
# blocks plain HTTP or runs TLS inspection. ip-api.com is the fallback: HTTP ONLY on its
# free tier (HTTPS needs a paid plan) but a separate 45/min quota, so it's still worth
# trying if ipapi.co's daily allowance is already spent, or if HTTP happens to be what
# works on a given network and HTTPS doesn't.
# TODO: EDIT HERE - add a third entry for ipinfo.io if you have a free-tier token:
#   ("ipinfo.io", "https://ipinfo.io/{ip}/json?token=YOUR_TOKEN", _parse_your_fn)
IP_GEO_PROVIDERS = [
    ("ipapi.co", "https://ipapi.co/{ip}/json/", _parse_ipapi_co),
    ("ip-api.com", "http://ip-api.com/json/{ip}", _parse_ip_api_com),
]


def geo_ip_lookup(ip, timeout):
    need(requests, "requests")
    for name, url_tmpl, parser in IP_GEO_PROVIDERS:
        try:
            r = requests.get(url_tmpl.format(ip=ip), timeout=timeout, headers=HEADERS)
            result = parser(r.json())
            if result:
                result["_provider"] = name
                return result
            log.debug("%s: no usable result (rate limited / invalid IP?)", name)
        except (requests.RequestException, ValueError) as e:
            log.debug("%s unreachable: %s", name, e)
    return None


def cmd_geo(a):
    if a.action == "exif":
        extract_image_metadata(a.file, a)  # already prints GPS + map link if present

    elif a.action == "ip":
        data = geo_ip_lookup(a.target, a.timeout)
        if not data:
            print("[-] every provider failed or was unreachable -- check connectivity "
                  "(see IP_GEO_PROVIDERS to add one with a token)")
            return
        print(f"  (via {data.pop('_provider')})")
        for k in ("query", "country", "region", "city", "zip", "lat", "lon", "isp", "org", "as"):
            print(f"  {k}: {data.get(k)}")
        if data.get("lat") and data.get("lon"):
            print(f"  map: https://www.google.com/maps?q={data['lat']},{data['lon']}")
        hunt(str(data), a.flag_re, "geoip")

    elif a.action == "coords":
        if a.dms:
            # format: "40 44 54.36 N, 73 59 8.36 W"
            parts = [p.strip() for p in a.dms.split(",")]
            lat_p, lon_p = parts[0].split(), parts[1].split()
            lat = dms_to_decimal(float(lat_p[0]), float(lat_p[1]), float(lat_p[2]), lat_p[3])
            lon = dms_to_decimal(float(lon_p[0]), float(lon_p[1]), float(lon_p[2]), lon_p[3])
        elif a.lat is not None and a.lon is not None:
            lat, lon = a.lat, a.lon
        else:
            raise SystemExit("[!] give --lat/--lon or --dms")
        print(f"decimal: {lat:.6f}, {lon:.6f}")
        dlat, mlat, slat = decimal_to_dms(lat)
        dlon, mlon, slon = decimal_to_dms(lon)
        print(f"dms    : {abs(dlat)}°{mlat}'{slat:.2f}\"{'S' if lat < 0 else 'N'}, "
              f"{abs(dlon)}°{mlon}'{slon:.2f}\"{'W' if lon < 0 else 'E'}")
        print(f"google : https://www.google.com/maps?q={lat:.6f},{lon:.6f}")
        print(f"osm    : https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}&zoom=16")


# =========================================================================== #
# wayback  (archive.org CDX snapshot listing + fetch)
# =========================================================================== #
def cmd_wayback(a):
    need(requests, "requests")
    cdx_url = (f"https://web.archive.org/cdx/server/cdx?url={urllib.parse.quote(a.target)}"
               f"&output=json&collapse=timestamp:8")
    r = requests.get(cdx_url, timeout=a.timeout, headers=HEADERS)
    rows = r.json()
    if len(rows) <= 1:
        print("[-] no snapshots found")
        return
    header, entries = rows[0], rows[1:]
    ts_idx = header.index("timestamp")
    print(f"[+] {len(entries)} snapshot(s) (collapsed to one per day):")
    for e in entries:
        rec = dict(zip(header, e))
        print(f"  {rec['timestamp']}  [{rec['statuscode']}]  {rec['original']}")

    if a.fetch:
        ts = entries[-1][ts_idx] if a.fetch == "latest" else a.fetch
        snap_url = f"https://web.archive.org/web/{ts}/{a.target}"
        rr = requests.get(snap_url, timeout=a.timeout, headers=HEADERS)
        print(f"-- fetched snapshot {ts} ({len(rr.content)}B) --")
        hunt(rr.content, a.flag_re, f"wayback-{ts}")
        print(rr.text[: a.max_body])


# =========================================================================== #
# dork  (builds a correct query + search-engine URLs -- never scrapes results)
# =========================================================================== #
def cmd_dork(a):
    parts = []
    if a.site:
        parts.append(f"site:{a.site}")
    if a.filetype:
        parts.append(f"filetype:{a.filetype}")
    if a.intitle:
        parts.append(f'intitle:"{a.intitle}"')
    if a.inurl:
        parts.append(f"inurl:{a.inurl}")
    for x in a.exclude or []:
        parts.append(f"-{x}")
    parts.extend(a.terms or [])
    if not parts:
        raise SystemExit("[!] give at least one of --site/--filetype/--intitle/--inurl/terms")
    query = " ".join(parts)
    print(f"query : {query}")
    q = urllib.parse.quote(query)
    print(f"google: https://www.google.com/search?q={q}")
    print(f"bing  : https://www.bing.com/search?q={q}")
    print(f"ddg   : https://duckduckgo.com/?q={q}")


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
    base.add_argument("--timeout", type=float, default=10.0)
    base.add_argument("-v", "--verbose", action="store_true", help="debug logs + tracebacks")

    ap = argparse.ArgumentParser(description="CTF OSINT skeleton (see file docstring)",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("domain", parents=[base], help="WHOIS + DNS records")
    sp.add_argument("-t", "--target", required=True, help="domain name")
    sp.add_argument("--no-whois", dest="no_whois", action="store_true")
    sp.add_argument("--no-dns", dest="no_dns", action="store_true")
    sp.set_defaults(func=cmd_domain)

    sp = sub.add_parser("subdomains", parents=[base], help="crt.sh + optional DNS brute force")
    sp.add_argument("-t", "--target", required=True, help="domain name")
    sp.add_argument("--wordlist")
    sp.add_argument("--threads", type=int, default=20)
    sp.set_defaults(func=cmd_subdomains)

    sp = sub.add_parser("username", parents=[base], help="multi-site existence check")
    sp.add_argument("-u", "--username", required=True)
    sp.add_argument("--threads", type=int, default=8)
    sp.set_defaults(func=cmd_username)

    sp = sub.add_parser("metadata", parents=[base], help="image/PDF/Office hidden metadata")
    sp.add_argument("-f", "--file", required=True)
    sp.set_defaults(func=cmd_metadata)

    sp = sub.add_parser("geo", parents=[base], help="exif / ip / coords")
    sp.add_argument("--action", required=True, choices=["exif", "ip", "coords"])
    sp.add_argument("-f", "--file", help="image file, for --action exif")
    sp.add_argument("-t", "--target", help="IP address, for --action ip")
    sp.add_argument("--lat", type=float)
    sp.add_argument("--lon", type=float)
    sp.add_argument("--dms", help="'40 44 54.36 N, 73 59 8.36 W' style string")
    sp.set_defaults(func=cmd_geo)

    sp = sub.add_parser("wayback", parents=[base], help="archive.org snapshot listing/fetch")
    sp.add_argument("-t", "--target", required=True, help="URL")
    sp.add_argument("--fetch", help="'latest' or an exact YYYYMMDDhhmmss timestamp")
    sp.add_argument("--max-body", dest="max_body", type=int, default=3000)
    sp.set_defaults(func=cmd_wayback)

    sp = sub.add_parser("dork", parents=[base], help="build a dork query + search URLs")
    sp.add_argument("--site")
    sp.add_argument("--filetype")
    sp.add_argument("--intitle")
    sp.add_argument("--inurl")
    sp.add_argument("--exclude", action="append", help="term to exclude (repeatable, no leading -)")
    sp.add_argument("terms", nargs="*", help="freeform extra terms")
    sp.set_defaults(func=cmd_dork)

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
    except socket.timeout:
        log.error("timed out (raise --timeout)")
    except socket.gaierror as e:
        log.error("DNS resolution failed: %s", e)
    except ConnectionRefusedError:
        log.error("connection refused")
    except FileNotFoundError as e:
        log.error("file not found: %s", e.filename)
    except (ValueError, binascii.Error) as e:
        log.error("bad input: %s", e)
    except Exception as e:  # last-resort net so the script never dies silently
        log.error("unexpected %s: %s", type(e).__name__, e)
        if a.verbose:
            raise


if __name__ == "__main__":
    main()
