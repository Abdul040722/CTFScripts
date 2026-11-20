# CTF CLI Toolkit (CyberSci Skeletons)

A set of four standalone, modular Python CLI scripts designed for Capture The Flag (CTF) competitions—covering **OSINT**, **Web Security**, **Networking**, **Forensics**, and **Cryptography**.

Each script is structured around fast tactical iteration during a competition: optional dependencies degrade gracefully with helpful install hints, most commands automatically hunt for flags across raw and decoded outputs (base64, base32, base64url, hex, ROT13, URL-encoding, reversed strings, and single-byte XOR), and clear `EDIT HERE` / `TODO` hooks are placed where challenge-specific logic or custom payload/oracle wiring belongs.

---

## Scripts Overview

| Script | Domain | Subcommands | Core Optional Dependencies |
| :--- | :--- | :--- | :--- |
| `ctf_osint.py` | Open-Source Intelligence | `domain`, `subdomains`, `username`, `metadata`, `geo`, `wayback`, `dork`, `decode` | `requests`, `dnspython`, `pypdf`, `Pillow` |
| `ctf_web.py` | Web Exploitation | `recon`, `fuzz`, `inject`, `jwt`, `idor`, `login`, `decode` | `requests` |
| `ctf_net.py` | Networking & Sockets | `scan`, `tcp`, `udp`, `pwn`, `http`, `pcap`, `decode` | `requests`, `pwntools`, `scapy` |
| `ctf_forensics.py` | Digital Forensics | `identify`, `carve`, `disk`, `strings`, `image`, `zip`, `pcap`, `decode` | `Pillow`, `scapy` |
| `ctf_crypto.py` | Cryptography & Math | `classical`, `modmath`, `rsa`, `aes`, `hash`, `decode` | `cryptography` |

---

## Installation

All scripts run on Python 3 with standard library modules for core operations. Install only what you need (or install everything upfront):

```bash
pip install requests dnspython pypdf Pillow pwntools scapy cryptography
```

If a subcommand requires a missing library, the script exits cleanly with a one-line `pip install <package>` message.

---

## Common Mechanics & Flag Hunting

### Automatic Flag Hunting (`hunt`)
Most subcommands run `hunt()` against command outputs, responses, payloads, or extracted artifacts using `--flag-regex` (defaulting to `DEFAULT_FLAG_RE` in each script).

Before or during a competition, update `DEFAULT_FLAG_RE` in the scripts—or pass `--flag-regex` on the command line—to match the event's exact flag format:

```bash
python3 ctf_web.py recon -t http://10.0.0.5/ --flag-regex 'flag\{[^}]+\}'
```

`hunt()` checks:
1. Raw bytes
2. Common decodings: `base64`, `base64url`, `base32`, `hex`, `rot13`, `urldecode`, `reverse`
3. Single-byte XOR (`0x01`–`0xff`) on qualifying blobs and single-step decoded outputs

> **Memory guardrails:** `MAX_DECODE_SIZE` (2 MiB) and `MAX_XOR_SIZE` (64 KiB) prevent excessive memory expansion on large files/captures while still allowing raw regex scans.

### `FUZZ` Placeholder (`ctf_web.py` and `ctf_net.py`)
Commands supporting wordlists or payload injection look for the literal token `FUZZ` in supported fields (such as `-t`/`--target`, `-d`/`--data`, `-c`/`--cookie`, or `-H`/`--header`).

### Scope & Safety Reminders
- **`ctf_osint.py`** is designed strictly for publicly served data (DNS, WHOIS, Certificate Transparency logs, public profiles, and files already in your possession)—not login bypasses, private data aggregation, or data-broker scraping.
- Only target systems and endpoints you are authorized to test within the rules of the CTF or lab environment.

---

## Subcommand Reference

### 1. `ctf_osint.py`

- **`domain`**: Queries WHOIS along the IANA referral chain (raw TCP port 43) and resolves DNS records (`A`/`AAAA` via stdlib; `MX`/`TXT`/`NS`/`SOA`/`CNAME` with `dnspython`). Supports `--no-whois` and `--no-dns`.
- **`subdomains`**: Queries `crt.sh` JSON output for `*.<domain>` and optionally brute-forces a `--wordlist` with `--threads` and automatic wildcard DNS detection/suppression.
- **`username`**: Concurrently checks a curated `SITES` table (`GitHub`, `GitLab`, `Docker Hub`, `Reddit`, `Keybase`, `Steam`, `Hacker News`) for `-u/--username`.
- **`metadata`**: Auto-detects Office ZIP archives (`docProps/core.xml`, `docProps/app.xml`), PDFs (classic metadata + XMP tags), and images (EXIF fields and GPS coordinates with a Google Maps link).
- **`geo`**:
  - `--action exif -f <image>`: Extracts EXIF/GPS info.
  - `--action ip -t <ip>`: Looks up IP geolocation across `IP_GEO_PROVIDERS` (`ipapi.co` HTTPS first, falling back to `ip-api.com` HTTP).
  - `--action coords`: Converts between decimal degrees and DMS (`--lat`/`--lon` or `--dms`) and prints Google Maps and OpenStreetMap links.
- **`wayback`**: Lists daily-collapsed snapshots from the Wayback CDX API for `-t <url>` and optionally fetches a snapshot via `--fetch latest` or a `YYYYMMDDhhmmss` timestamp.
- **`dork`**: Constructs search queries from `--site`, `--filetype`, `--intitle`, `--inurl`, `--exclude`, and freeform `terms`, printing Google, Bing, and DuckDuckGo search URLs without scraping results.
- **`decode`**: Tries common decodings and runs flag hunting on `-d`, `-f`, or `stdin`.

### 2. `ctf_web.py`

- **`recon`**: Fetches a target URL (`-t`), prints response headers, cookies (with basic framework/tech hints), HTML forms, comments, and links, and probes common paths (`robots.txt`, `sitemap.xml`, `.git/HEAD`, `server-status`, `.env`, `admin/`).
- **`fuzz`**: Performs wordlist-driven brute forcing using `FUZZ` across URLs, bodies, cookies, or headers, with baseline response auto-filtering (`--filter-code`, `--filter-size`, `--show-baseline-matches`, `--threads`).
- **`inject`**: Sends payloads for `--type` (`sqli`, `xss`, `lfi`, `ssti`, `cmdi`, plus optional `--custom-payloads`) at a `FUZZ` injection point, flagging timing anomalies (`--sleep-threshold`), response size/status changes (`--diff-bytes`), signatures, reflection, or template evaluation hints.
- **`jwt`**: Decodes JWT headers and payloads (`-d` or `-f`), forges `alg:none` variants (`--none`), brute-forces HMAC secrets against a wordlist (`--crack --wordlist`), or modifies claims and re-signs (`--set key=val` with optional `--secret`).
- **`idor`**: Iterates IDs/ranges (`--ids 1-50` or `--ids 3,7,19`) at a `FUZZ` location, optionally comparing responses against a `--baseline` ID and pacing with `--delay`.
- **`login`**: Runs credential stuffing (`--combo user:pass`) or single-user password spraying (`--user` + `--passlist`), with optional CSRF token scraping (`--csrf-url`, `--csrf-field`, `--csrf-regex`), extra form fields (`--extra`), and `--success-str` / `--fail-str` heuristics.
- **`decode`**: Auto-detects and prints JWT headers/payloads, tries common decodings, and hunts for flags.

### 3. `ctf_net.py`

- **`scan`**: Threaded TCP connect scanner (`-t`, `-p` ranges/lists, `--threads`) with lightweight banner grabbing.
- **`tcp`**: Opens a raw TCP connection (`-t`, `-p`) and runs `session_logic()` using payloads from `--hex`, `-f/--file`, or `-d/--data` (supporting escape sequences like `\n`, `\r\n`, `\x41`).
- **`udp`**: Sends a single UDP datagram (`-t`, `-p`) and prints the response.
- **`pwn`**: Connects using `pwntools.remote` and runs `pwn_logic()` (with hooks for scripted I/O and `io.interactive()`).
- **`http`**: Sends single or `FUZZ`-wordlist HTTP requests (`-X`, `-d`, `-H`, `-c`, `--proxy`, `--redirects`, `--max-body`) with automatic flag hunting on bodies and headers.
- **`pcap`**: Streams a packet capture (`-f`) via `scapy.PcapReader`, aggregates payload flows, optionally prints printable strings (`--strings`) or dumps flow payloads (`--dump DIR`), and hunts for flags.
- **`decode`**: Runs common decodings and flag hunting on `-d`, `-f`, or `stdin`.

### 4. `ctf_forensics.py`

- **`identify`**: Identifies file magic signatures (including archives, executables, images, PCAP/PCAPNG, SQLite, and memory dump headers such as `PAGEDUMP`, `PAGEDU64`, `MDMP`, `EMiL`, and `AVML`), computes MD5/SHA1/SHA256 hashes, checks for MBR/GPT partition tables or embedded signatures, and hunts for flags.
- **`carve`**: Scans for known file signatures and trailers (`SIGNATURES` / `carve_end`), reporting offsets/sizes and optionally carving files to `--outdir` with `--extract`.
- **`disk`**: Parses MBR and GPT partition tables (`--sector-size`), identifies filesystem magic at partition offsets (`NTFS`, `exFAT`, `FAT32`, `FAT16/12`, `ext2/3/4`, `HFS+/HFSX`), and optionally extracts partitions to `.img` files (`--extract --outdir`).
- **`strings`**: Extracts ASCII and optional UTF-16 (LE/BE) strings (`--min-len`, `--grep`, `--utf16` / `--no-utf16`) and optionally reports 256-byte chunks above a Shannon entropy threshold (`--entropy 7.5`).
- **`image`**:
  - `--action exif`: Dumps EXIF tags and hunts for flags.
  - `--action lsb`: Extracts least-significant bits across `--channel` (`r`, `g`, `b`, `a`, `all`) and `--bits`.
  - `--action bitplane`: Renders a single bit-plane (`--bit`, `--channel gray` or RGB) to an image file (`--out`).
- **`zip`**: Supports `--action list`, `extract` (`--password`, `--outdir`), `crack` (`--wordlist` for legacy ZipCrypto), and `comment`.
- **`pcap`**: Scans reassembled TCP payload flows with `CRED_RE` for credentials/tokens, carves embedded file signatures (`--extract --outdir`), and hunts for flags.
- **`decode`**: Runs common decodings and flag hunting on `-d`, `-f`, or `stdin`.

### 5. `ctf_crypto.py`

- **`classical`**: Supports `--mode caesar`, `vigenere`, `xor`, and `auto` over `--input-format` (`text`, `hex`, `base64`), ranking candidates via English letter-frequency chi-squared scoring or decrypting with a known `--key`.
- **`modmath`**: Runs modular and number-theoretic operations via `--op`: `gcd` (extended Euclidean algorithm), `modinv`, `crt` (general Chinese Remainder Theorem), `factor` (trial division, Fermat, and Pollard's rho with `--timeout`), `dlog` (baby-step giant-step), and `isprime` (Miller-Rabin).
- **`rsa`**: Supports `--action` modes `info`, `decrypt` (from `p,q`, `--priv-d`, or `--pem`), `factor`, `wiener` (low private exponent attack), `common-modulus`, `batch-gcd` (`--batch-file`), and `hastad` (`--pair n:c` + CRT/integer root).
- **`aes`**: Supports `ecb-detect` (duplicate block check), `encrypt` and `decrypt` (`ecb` or `cbc` with PKCS#7 padding or `--no-pad`), `bitflip` (CBC block manipulation), and `ecb-oracle` (byte-at-a-time ECB recovery once `ecb_oracle_stub()` is wired up).
- **`hash`**: Identifies hash algorithms by hex length (`identify`), cracks salted/unsalted hashes against a `--wordlist` (`crack`), or performs MD5/SHA-1 Merkle–Damgård `length-extension` attacks (`--known-hash`, `--known-len` or `--secret-len-range`, `--append`).
- **`decode`**: Runs common decodings and flag hunting on `-d`, `-f`, or `stdin`.

---

## Example Workflows

```bash
# OSINT: enumerate certificate-transparency subdomains and check a handle
python3 ctf_osint.py subdomains -t example.org
python3 ctf_osint.py username -u target_handle

# Web: inspect a target, fuzz paths, and inspect a JWT
python3 ctf_web.py recon -t http://10.10.10.5/
python3 ctf_web.py fuzz -t 'http://10.10.10.5/FUZZ' --wordlist /usr/share/wordlists/dirb/common.txt --filter-code 404
python3 ctf_web.py jwt -d '<jwt_token>'

# Networking: scan ports, talk to a TCP service, and inspect a capture
python3 ctf_net.py scan -t 10.10.10.5 -p 1-1024 --threads 150
python3 ctf_net.py tcp -t 10.10.10.5 -p 9000 -d 'FLAG\n'
python3 ctf_net.py pcap -f traffic.pcapng --strings --dump flows_out

# Forensics: inspect an artifact, carve embedded files, and check image LSBs
python3 ctf_forensics.py identify -f challenge.bin
python3 ctf_forensics.py carve -f challenge.bin --extract --outdir carved
python3 ctf_forensics.py image --action lsb -f stego.png --channel rgb --bits 1

# Crypto: crack classical ciphers, factor small RSA moduli, or test AES ECB
python3 ctf_crypto.py classical --mode caesar -d 'Synt{pvn_fuvsg}'
python3 ctf_crypto.py rsa --action factor -n 3233 -e 17 -c 2790
python3 ctf_crypto.py aes --action ecb-detect -d '<hex_ciphertext>' --input-format hex
```
