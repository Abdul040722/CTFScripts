#!/usr/bin/env python3
"""
CTF FORENSICS SKELETON  (CyberSci)
=====================================
CHEAT SHEET
-----------
Install   : pip install Pillow scapy    (Pillow needed for `image`, scapy for `pcap`;
            everything else -- file carving, strings, zip, hashing -- is pure stdlib)
Help      : python3 ctf_forensics.py <cmd> -h
Flag hunt : most commands auto-search their output for --flag-regex, including
            base64/hex/rot13/xor/url/reverse decodings of it. Confirm the real flag
            format first, then change DEFAULT_FLAG_RE below.

Subcommands
-----------
identify -f evidence.bin                         magic-byte type ID, hashes, quick strings scan;
                                                    also flags MBR/GPT and raw memory-dump headers
disk     -f disk.img                               MBR/GPT partition table + filesystem-magic ID
disk     -f disk.img --extract --outdir parts/     also dumps each partition to its own .img --
                                                    then run identify/carve/strings on those
carve    -f evidence.bin --extract --outdir out/  binwalk-lite: find + pull out embedded files
strings  -f evidence.bin --min-len 6 --grep flag   ascii+utf16 strings, entropy-flagged regions
image    --action exif      -f photo.jpg           EXIF metadata dump
image    --action lsb       -f photo.png --channel r --bits 1
                                                    least-significant-bit steganography extraction
image    --action bitplane  -f photo.png --bit 0 --out plane0.png
                                                    save one bit-plane as a viewable image
zip      --action list      -f archive.zip         entries, encryption flags, comments
zip      --action extract   -f archive.zip --password hunter2 --outdir out/
zip      --action crack     -f archive.zip --wordlist rockyou.txt
                                                    legacy ZipCrypto only -- AES zips need pyzipper
pcap     -f capture.pcap --extract --outdir out/   per-flow credential regex scan + file carving
decode   -d 'ZmxhZ3t0ZXN0fQ=='                      try common decodings (or -f file, or stdin)

NOTE on memory dumps (.raw/.dmp/.vmem/.lime): `identify` recognizes common dump headers
(Windows PAGEDUMP/PAGEDU64/MDMP, Linux LiME/AVML) but this script does NOT walk kernel
structures (_EPROCESS etc.) -- those are undocumented and change layout across every OS
build, which is exactly the problem Volatility's profile/symbol system exists to solve.
For real process/handle/registry analysis once a file is confirmed to be a memory dump,
use `pip install volatility3` rather than trusting a hand-rolled struct scan here. This
script's `strings`/`carve` still do real work on a raw dump as-is (plaintext/base64
flags, embedded PE/PNG/ZIP files sitting in memory) -- try those first.

Fallbacks when this script is too slow to adapt:
  binwalk -e evidence.bin        exiftool photo.jpg         zsteg image.png (Ruby, PNG/BMP LSB)
  foremost -i evidence.bin -o out/      file evidence.bin   strings -n 6 evidence.bin | grep -i flag
  mmls/fls/icat disk.img (Sleuth Kit)   pip install pytsk3   vol3 -f dump.raw windows.pslist
"""

import argparse
import base64
import binascii
import codecs
import hashlib
import io
import logging
import math
import os
import re
import struct
import sys
import urllib.parse
import uuid
import zipfile
import zlib
from collections import Counter

try:
    from PIL import Image, ExifTags
except ImportError:
    Image = ExifTags = None
try:
    from scapy.all import PcapReader, IP, TCP, Raw
except ImportError:
    PcapReader = None

log = logging.getLogger("ctfforensics")

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


def read_file_or_stdin(path):
    if path:
        with open(path, "rb") as f:
            return f.read()
    return sys.stdin.buffer.read()


def try_decodings(blob):
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


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# =========================================================================== #
# File-type signatures (shared by identify / carve / pcap)
# =========================================================================== #
# TODO: EDIT HERE - add more magic bytes as the challenge needs (TIFF, WEBP, DOCX/XLSX
# as ZIP-with-content-types, ISO, etc). (name, magic bytes, end-of-file marker-or-None)
SIGNATURES = [
    ("PNG", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    ("JPEG", b"\xff\xd8\xff", b"\xff\xd9"),
    ("GIF", b"GIF87a", b"\x3b"),
    ("GIF", b"GIF89a", b"\x3b"),
    ("PDF", b"%PDF-", b"%%EOF"),
    ("ZIP", b"PK\x03\x04", b"PK\x05\x06"),
    ("GZIP", b"\x1f\x8b\x08", None),
    ("BMP", b"BM", None),
    ("ELF", b"\x7fELF", None),
    ("PE", b"MZ", None),
    ("RAR", b"Rar!\x1a\x07", None),
    ("7Z", b"7z\xbc\xaf\x27\x1c", None),
    ("RIFF", b"RIFF", None),  # WAV/AVI -- both start with RIFF....WAVE/AVI
    ("OGG", b"OggS", None),
    ("PCAP", b"\xd4\xc3\xb2\xa1", None),
    ("PCAPNG", b"\x0a\x0d\x0d\x0a", None),
    ("SQLITE", b"SQLite format 3\x00", None),
    # Memory-dump headers -- identification only, see the module docstring: this script
    # does not walk kernel structures (_EPROCESS etc.), use volatility3 for that.
    ("WIN_CRASHDUMP32", b"PAGEDUMP", None),
    ("WIN_CRASHDUMP64", b"PAGEDU64", None),
    ("WIN_MINIDUMP", b"MDMP", None),
    ("LIME", b"EMiL", None),  # LiME header magic 0x4C694D45, little-endian on disk
    ("AVML", b"AVML", None),
]


def find_all(data, pattern, start=0):
    idx = data.find(pattern, start)
    while idx != -1:
        yield idx
        idx = data.find(pattern, idx + 1)


def scan_signatures(data):
    """Binwalk-lite: every (offset, name, magic, trailer) match anywhere in the data."""
    hits = []
    for name, magic, trailer in SIGNATURES:
        for off in find_all(data, magic):
            hits.append((off, name, magic, trailer))
    hits.sort()
    return hits


def carve_end(data, off, name, magic, trailer, other_offsets):
    """Best-effort end offset for a carved file. Exact for PNG/ZIP/JPEG/GIF/PDF (known
    trailer format); for everything else, falls back to 'next signature found, or EOF'
    -- which is an approximation, not a real parse of that format."""
    if name == "ZIP":
        idx = data.find(b"PK\x05\x06", off)
        if idx == -1 or idx + 22 > len(data):
            return None
        comment_len = struct.unpack("<H", data[idx + 20 : idx + 22])[0]
        return idx + 22 + comment_len
    if name == "PDF" and trailer:
        idx = data.rfind(trailer)
        return idx + len(trailer) if idx != -1 and idx >= off else None
    if name == "GIF" and trailer:
        idx = data.find(trailer, off + 6)
        return idx + len(trailer) if idx != -1 else None
    if trailer:
        idx = data.find(trailer, off)
        return idx + len(trailer) if idx != -1 else None
    nxt = next((o for o in other_offsets if o > off), None)
    return nxt if nxt else len(data)


def identify_file(data: bytes):
    for name, magic, _ in SIGNATURES:
        if data.startswith(magic):
            return name
    return None


# =========================================================================== #
# identify
# =========================================================================== #
def cmd_identify(a):
    data = read_file_or_stdin(a.file)
    kind = identify_file(data) or "unknown"
    print(f"type   : {kind}")
    print(f"size   : {len(data)} bytes")
    print(f"md5    : {hashlib.md5(data).hexdigest()}")
    print(f"sha1   : {hashlib.sha1(data).hexdigest()}")
    print(f"sha256 : {hashlib.sha256(data).hexdigest()}")

    if Image and kind in ("PNG", "JPEG", "GIF", "BMP", "RIFF"):
        try:
            img = Image.open(io.BytesIO(data))
            print(f"image  : {img.format} {img.size} mode={img.mode}")
        except Exception:
            pass
    if kind == "ZIP":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                print(f"zip    : {len(z.infolist())} entries" + (f", comment={z.comment!r}" if z.comment else ""))
        except Exception:
            pass
    if kind.startswith("WIN_CRASHDUMP") or kind in ("WIN_MINIDUMP", "LIME", "AVML"):
        print("[!] looks like a memory dump -- `strings`/`carve` work on it as-is; for real "
              "process/handle analysis use volatility3, not this script (see docstring)")

    # MBR/GPT signatures live at fixed-but-nonzero offsets, so they don't fit the generic
    # magic-at-offset-0-or-anywhere SIGNATURES table -- checked directly instead.
    has_mbr = len(data) >= 512 and data[510:512] == b"\x55\xaa"
    has_gpt = len(data) >= 520 and data[512:520] == b"EFI PART"
    if has_mbr or has_gpt:
        print(f"[!] {'GPT' if has_gpt else 'MBR'} partition table signature found -- try the `disk` subcommand")

    embedded = scan_signatures(data)
    if len(embedded) > 1 or (embedded and embedded[0][0] != 0):
        print(f"[!] {len(embedded)} signature match(es) found -- possible embedded file(s), try `carve`")

    for s in re.findall(rb"[\x20-\x7e]{6,}", data)[:5000]:
        hunt(s, a.flag_re, "identify-strings")
    hunt(data, a.flag_re, "identify-raw")


# =========================================================================== #
# carve
# =========================================================================== #
def cmd_carve(a):
    data = read_file_or_stdin(a.file)
    hits = scan_signatures(data)
    if not hits:
        print("[-] no known file signatures found")
        return
    offsets = [h[0] for h in hits]
    print(f"[*] {len(hits)} candidate embedded file(s):")
    for off, name, magic, trailer in hits:
        end = carve_end(data, off, name, magic, trailer, offsets)
        size = f"{end - off}B" if end else "? (no end found)"
        print(f"  0x{off:08x}  {name:8s} {size}")

    if a.extract:
        os.makedirs(a.outdir, exist_ok=True)
        for i, (off, name, magic, trailer) in enumerate(hits):
            end = carve_end(data, off, name, magic, trailer, offsets) or len(data)
            chunk = data[off:end]
            path = os.path.join(a.outdir, f"carved_{i}_{name}_{off:08x}.bin")
            with open(path, "wb") as f:
                f.write(chunk)
            print(f"  -> wrote {path} ({len(chunk)}B)")
            hunt(chunk, a.flag_re, path)


# =========================================================================== #
# disk  (MBR/GPT partition table + filesystem-magic identification)
# =========================================================================== #
# TODO: EDIT HERE - add more partition types as the challenge needs.
MBR_TYPES = {
    0x00: "Empty", 0x01: "FAT12", 0x04: "FAT16 <32M", 0x05: "Extended (CHS)",
    0x06: "FAT16", 0x07: "NTFS/exFAT", 0x0B: "FAT32 (CHS)", 0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)", 0x0F: "Extended (LBA)", 0x82: "Linux swap", 0x83: "Linux",
    0x85: "Linux extended", 0x8E: "Linux LVM", 0xA5: "FreeBSD", 0xA8: "Mac OS X",
    0xAB: "Mac OS X Boot", 0xAF: "Mac OS X HFS+", 0xEE: "GPT protective", 0xEF: "EFI System",
}
GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft Basic Data (NTFS/FAT)",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows Recovery",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "Linux RAID",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
}


def identify_filesystem(data, offset):
    """Cheap filesystem-magic check at a partition's start -- identification only, this
    does NOT parse directory structures (MFT/inode tables); extract the partition with
    --extract and point pytsk3/Sleuth Kit or a loopback mount at it for that."""
    w = data[offset : offset + 4096]
    if len(w) < 90:
        return None
    if w[3:11] == b"NTFS    ":
        return "NTFS"
    if w[3:11] == b"EXFAT   ":
        return "exFAT"
    if w[82:90] == b"FAT32   ":
        return "FAT32"
    if w[54:62] in (b"FAT16   ", b"FAT12   "):
        return "FAT16/12"
    if len(w) >= 1082 and struct.unpack("<H", w[1080:1082])[0] == 0xEF53:
        return "ext2/3/4"
    if len(w) >= 1026 and w[1024:1026] in (b"H+", b"HX"):
        return "HFS+/HFSX"
    return None


def cmd_disk(a):
    data = read_file_or_stdin(a.file)
    sector = a.sector_size
    partitions = []  # (offset, size, label)

    has_mbr = len(data) >= 512 and data[510:512] == b"\x55\xaa"
    print(f"MBR boot signature (0x55AA): {'present' if has_mbr else 'absent'}")
    if has_mbr:
        print("-- MBR partition table --")
        for i in range(4):
            entry = data[446 + i * 16 : 446 + (i + 1) * 16]
            if len(entry) < 16 or entry[4] == 0:
                continue
            ptype = entry[4]
            lba_start = struct.unpack("<I", entry[8:12])[0]
            nsectors = struct.unpack("<I", entry[12:16])[0]
            if nsectors == 0:
                continue
            off, size = lba_start * sector, nsectors * sector
            bootable = " [bootable]" if entry[0] == 0x80 else ""
            tname = MBR_TYPES.get(ptype, f"unknown (0x{ptype:02x})")
            print(f"  entry {i}: type={tname}{bootable}  offset=0x{off:x} ({off})  "
                  f"size={size}B ({nsectors} sectors)")
            if ptype == 0xEE:
                print("    -> protective MBR; this disk likely uses GPT, see below")
            else:
                partitions.append((off, size, f"mbr{i}_{tname}"))

    gpt_off = sector
    has_gpt = len(data) >= gpt_off + 8 and data[gpt_off : gpt_off + 8] == b"EFI PART"
    print(f"GPT header ('EFI PART' at LBA 1): {'present' if has_gpt else 'absent'}")
    if has_gpt:
        print("-- GPT partition table --")
        hdr = data[gpt_off : gpt_off + 92]
        num_entries = struct.unpack("<I", hdr[80:84])[0]
        entry_size = struct.unpack("<I", hdr[84:88])[0]
        entries_off = struct.unpack("<Q", hdr[72:80])[0] * sector
        for i in range(num_entries):
            e = data[entries_off + i * entry_size : entries_off + (i + 1) * entry_size]
            if len(e) < 128 or e[0:16] == b"\x00" * 16:
                continue
            type_guid = str(uuid.UUID(bytes_le=e[0:16])).lower()
            first_lba, last_lba = struct.unpack("<QQ", e[32:48])
            name = e[56:128].decode("utf-16-le", errors="ignore").rstrip("\x00")
            off, size = first_lba * sector, (last_lba - first_lba + 1) * sector
            tname = GPT_TYPES.get(type_guid, type_guid)
            print(f"  entry {i}: type={tname}  name={name!r}  offset=0x{off:x} ({off})  size={size}B")
            partitions.append((off, size, f"gpt{i}_{name or tname}"))
            if name:
                hunt(name, a.flag_re, f"gpt-partition-name-{i}")

    if not has_mbr and not has_gpt:
        print("[-] no MBR or GPT signature found -- might be a single unpartitioned "
              "filesystem image; try `identify`/`carve`/`strings` directly on this file")
        return

    print("-- filesystem magic at each partition start --")
    for off, size, label in partitions:
        print(f"  {label}: {identify_filesystem(data, off) or 'unknown/unrecognized'}")

    if a.extract:
        os.makedirs(a.outdir, exist_ok=True)
        print("-- extracting partitions --")
        for off, size, label in partitions:
            chunk = data[off : min(off + size, len(data))]
            path = os.path.join(a.outdir, re.sub(r"[^\w.-]", "_", label) + ".img")
            with open(path, "wb") as f:
                f.write(chunk)
            print(f"  -> wrote {path} ({len(chunk)}B) -- run identify/carve/strings on it next")


# =========================================================================== #
# strings
# =========================================================================== #
def extract_ascii_strings(data, minlen=4):
    return re.findall((rb"[\x20-\x7e]{%d,}" % minlen), data)


# NOTE: LE and BE utf16 strings can spuriously overlap-match each other (a LE string's
# repeating char+\x00 bytes can also satisfy a shifted BE pattern) -- same tradeoff the
# standard `strings -e l/-e b` tools have. Garbage matches are usually obvious by eye.
def extract_utf16_strings(data, minlen=4):
    le = re.findall((rb"(?:[\x20-\x7e]\x00){%d,}" % minlen), data)
    be = re.findall((rb"\x00(?:[\x20-\x7e]\x00){%d,}" % (minlen - 1)), data)
    out = [s.decode("utf-16-le") for s in le]
    out += [s[1:].decode("utf-16-be", errors="ignore") for s in be]
    return out


def cmd_strings(a):
    data = read_file_or_stdin(a.file)
    grep = re.compile(a.grep.encode(), re.I) if a.grep else None

    found = extract_ascii_strings(data, a.min_len)
    if a.utf16:
        found += [s.encode() for s in extract_utf16_strings(data, a.min_len)]

    for s in found:
        if grep and not grep.search(s):
            continue
        print(s.decode(errors="replace"))
        hunt(s, a.flag_re, "strings")

    if a.entropy:
        print(f"-- chunks with entropy > {a.entropy} (likely compressed/encrypted/packed) --")
        chunk_size = 256
        for off in range(0, len(data), chunk_size):
            chunk = data[off : off + chunk_size]
            e = shannon_entropy(chunk)
            if e > a.entropy:
                print(f"  0x{off:08x}  entropy={e:.2f}")


# =========================================================================== #
# image  (exif / lsb steganography / bit-plane extraction)
# =========================================================================== #
def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def cmd_image(a):
    need(Image, "Pillow")
    img = Image.open(a.file)

    if a.action == "exif":
        exif = img.getexif()
        if not exif:
            print("[-] no EXIF data found")
        else:
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                print(f"  {tag}: {value}")
                hunt(str(value), a.flag_re, f"exif:{tag}")
        print(f"format={img.format} size={img.size} mode={img.mode}")

    elif a.action == "lsb":
        mode = img.mode if img.mode in ("RGB", "RGBA", "L") else "RGB"
        img = img.convert(mode)
        chan_map = {"r": 0, "g": 1, "b": 2, "a": 3}
        chan_idxs = (list(range(len(mode))) if mode != "L" else [0]) if a.channel == "all" \
            else [chan_map[c] for c in a.channel.lower() if c in chan_map]
        bit_idx = list(range(a.bits))  # EDIT HERE: use e.g. [1] to read the 2nd-LSB instead
        raw, nchan = img.tobytes(), len(mode)
        bits = []
        for off in range(0, len(raw), nchan):
            for ch in chan_idxs:
                if ch < nchan:
                    v = raw[off + ch]
                    for b in bit_idx:
                        bits.append((v >> b) & 1)
        out = bits_to_bytes(bits)
        print(f"[+] extracted {len(out)} bytes from LSBs (channels={a.channel}, bits={a.bits})")
        print(out[:300])
        hunt(out, a.flag_re, "lsb")

    elif a.action == "bitplane":
        mode = "L" if a.channel == "gray" else "RGB"
        img = img.convert(mode)
        plane = Image.eval(img, lambda px, bit=a.bit: 255 if (px >> bit) & 1 else 0)
        out_path = a.out or f"bitplane_{a.bit}.png"
        plane.save(out_path)
        print(f"[+] wrote {out_path} -- open it and look for a hidden pattern/text")


# =========================================================================== #
# zip
# =========================================================================== #
def cmd_zip(a):
    if a.action == "list":
        with zipfile.ZipFile(a.file) as z:
            for info in z.infolist():
                enc = " [ENCRYPTED]" if info.flag_bits & 0x1 else ""
                print(f"  {info.filename:40s} {info.file_size:10d}B{enc}")
                if info.comment:
                    print(f"    entry comment: {info.comment!r}")
                    hunt(info.comment, a.flag_re, f"zip-entry-comment:{info.filename}")
            if z.comment:
                print(f"[archive comment] {z.comment!r}")
                hunt(z.comment, a.flag_re, "zip-comment")

    elif a.action == "extract":
        with zipfile.ZipFile(a.file) as z:
            pwd = a.password.encode() if a.password else None
            outdir = a.outdir or "."
            z.extractall(outdir, pwd=pwd)
            print(f"[+] extracted to {outdir}")
            for name in z.namelist():
                try:
                    content = z.read(name, pwd=pwd)
                    hunt(content, a.flag_re, name)
                except Exception as e:
                    log.debug("couldn't read %s: %s", name, e)

    elif a.action == "crack":
        # NOTE: zipfile only understands legacy ZipCrypto. An AES-encrypted zip (WinZip/
        # 7-Zip AES-256) will raise NotImplementedError here -- that needs `pyzipper` instead
        # (pip install pyzipper; drop-in-compatible API, swap zipfile.ZipFile for pyzipper.AESZipFile).
        if not a.wordlist:
            raise SystemExit("[!] --wordlist is required")
        with zipfile.ZipFile(a.file) as z:
            test_name = z.namelist()[0]
            with open(a.wordlist, errors="ignore") as f:
                for line in f:
                    pw = line.rstrip("\n").encode()
                    try:
                        z.read(test_name, pwd=pw)
                        print(f"[CRACKED] password = {pw!r}")
                        return
                    except RuntimeError:
                        continue  # wrong password
                    except (zipfile.BadZipFile, zlib.error):
                        continue  # wrong password (CRC/decompress failure)
        print("[-] not found in wordlist")

    elif a.action == "comment":
        with zipfile.ZipFile(a.file) as z:
            print(f"archive comment: {z.comment!r}")
            for info in z.infolist():
                if info.comment:
                    print(f"  {info.filename}: {info.comment!r}")


# =========================================================================== #
# pcap  (credential regex scan + file carving across reassembled TCP flows)
# =========================================================================== #
CRED_RE = re.compile(rb"(?i)\b(pass(?:word|wd)?|user(?:name)?|login|authorization|token|api[_-]?key)"
                      rb"\s*[:=]\s*[^&\s\"'<>]{1,80}")


def cmd_pcap(a):
    need(PcapReader, "scapy")
    flows = {}
    with PcapReader(a.file) as rd:
        for p in rd:
            if IP in p and Raw in p and TCP in p:
                l4 = p[TCP]
                key = tuple(sorted([(p[IP].src, l4.sport), (p[IP].dst, l4.dport)]))
                flows.setdefault(key, bytearray()).extend(bytes(p[Raw].load))
    print(f"[*] {len(flows)} TCP flow(s) with payload (arrival order, not seq-sorted)")

    if a.extract:
        os.makedirs(a.outdir, exist_ok=True)

    for i, (key, buf) in enumerate(flows.items()):
        buf = bytes(buf)
        print(f"  flow {i}: {key[0]} <-> {key[1]}  ({len(buf)}B)")
        for m in CRED_RE.finditer(buf):
            print(f"    [cred?] {m.group(0)[:100]!r}")
        hits = scan_signatures(buf)
        offsets = [h[0] for h in hits]
        for off, name, magic, trailer in hits:
            end = carve_end(buf, off, name, magic, trailer, offsets) or len(buf)
            print(f"    [embedded] {name} at 0x{off:x}  ({end - off}B)")
            if a.extract:
                path = os.path.join(a.outdir, f"flow{i}_{name}_{off:x}.bin")
                with open(path, "wb") as f:
                    f.write(buf[off:end])
                hunt(buf[off:end], a.flag_re, path)
        hunt(buf, a.flag_re, f"flow{i}")


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

    ap = argparse.ArgumentParser(description="CTF forensics skeleton (see file docstring)",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("identify", parents=[base], help="magic-byte type ID + hashes + quick scan")
    sp.add_argument("-f", "--file", required=True)
    sp.set_defaults(func=cmd_identify)

    sp = sub.add_parser("carve", parents=[base], help="binwalk-lite embedded-file finder/extractor")
    sp.add_argument("-f", "--file", required=True)
    sp.add_argument("--extract", action="store_true")
    sp.add_argument("--outdir", default="carved_out")
    sp.set_defaults(func=cmd_carve)

    sp = sub.add_parser("disk", parents=[base], help="MBR/GPT partition table + filesystem-magic ID")
    sp.add_argument("-f", "--file", required=True)
    sp.add_argument("--sector-size", dest="sector_size", type=int, default=512,
                    help="bytes per sector (512 default; some images use 4096)")
    sp.add_argument("--extract", action="store_true")
    sp.add_argument("--outdir", default="disk_out")
    sp.set_defaults(func=cmd_disk)

    sp = sub.add_parser("strings", parents=[base], help="ascii+utf16 strings, entropy-flagged regions")
    sp.add_argument("-f", "--file", required=True)
    sp.add_argument("--min-len", dest="min_len", type=int, default=4)
    sp.add_argument("--grep", help="only show strings matching this regex (case-insensitive)")
    sp.add_argument("--utf16", action="store_true", default=True)
    sp.add_argument("--no-utf16", dest="utf16", action="store_false")
    sp.add_argument("--entropy", type=float, default=None, metavar="THRESHOLD",
                    help="also flag 256B chunks with entropy above this (try 7.5)")
    sp.set_defaults(func=cmd_strings)

    sp = sub.add_parser("image", parents=[base], help="exif / lsb steganography / bit-plane")
    sp.add_argument("--action", required=True, choices=["exif", "lsb", "bitplane"])
    sp.add_argument("-f", "--file", required=True)
    sp.add_argument("--channel", default="all", help="r/g/b/a/all (lsb), or 'gray' (bitplane)")
    sp.add_argument("--bits", type=int, default=1, help="how many LSBs per channel to read")
    sp.add_argument("--bit", type=int, default=0, help="which bit-plane to extract (0=LSB)")
    sp.add_argument("--out", help="output path for bitplane")
    sp.set_defaults(func=cmd_image)

    sp = sub.add_parser("zip", parents=[base], help="list/extract/crack/comment")
    sp.add_argument("--action", required=True, choices=["list", "extract", "crack", "comment"])
    sp.add_argument("-f", "--file", required=True)
    sp.add_argument("--password")
    sp.add_argument("--outdir")
    sp.add_argument("--wordlist")
    sp.set_defaults(func=cmd_zip)

    sp = sub.add_parser("pcap", parents=[base], help="credential scan + file carving across TCP flows")
    sp.add_argument("-f", "--file", required=True)
    sp.add_argument("--extract", action="store_true")
    sp.add_argument("--outdir", default="pcap_out")
    sp.set_defaults(func=cmd_pcap)

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
        log.error("bad input (hex/number/format?): %s", e)
    except zipfile.BadZipFile as e:
        log.error("not a valid zip: %s", e)
    except Exception as e:  # last-resort net so the script never dies silently
        log.error("unexpected %s: %s", type(e).__name__, e)
        if a.verbose:
            raise


if __name__ == "__main__":
    main()
