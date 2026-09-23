import base64
import binascii
import html
import re
from typing import Iterable

SCHEMES = [
    "vless", "vmess", "trojan", "ssr", "ss",
    "hysteria2", "hysteria", "hy2", "tuic", "wireguard",
    "anytls", "socks5", "socks4", "socks", "naive+",
]

_SCHEME_PATTERNS = [
    r"vless", r"vmess", r"trojan", r"ssr", r"ss",
    r"hysteria2", r"hysteria", r"hy2", r"tuic", r"wireguard",
    r"anytls", r"socks5", r"socks4", r"socks", r"naive\+https?",
]
_SCHEME_ALT = "|".join(_SCHEME_PATTERNS)

TOKEN_RE = re.compile(r"(?i)(?:" + _SCHEME_ALT + r")://[^\s]+")
SPLIT_RE = re.compile(r"(?i),(?=(?:" + _SCHEME_ALT + r")://)")
ENCODED_NL_RE = re.compile(
    r"(?i)(?:%250A|%0A|%250D|%0D)(?=(?:" + _SCHEME_ALT + r")://)"
)

_TRUNCATION_MARKERS = "…»`"
_TRAILING = "…»`%"


def clean_config(cfg: str) -> str:
    cfg = cfg.replace("%250A", "").replace("%0A", "").replace("%0D", "")
    cfg = cfg.replace("\ufffd", "")
    cfg = cfg.strip()
    cfg = cfg.strip(_TRAILING)
    return cfg.strip()


def _valid(cfg: str) -> bool:
    if len(cfg) <= 13:
        return False
    rest = cfg.split("://", 1)[1].split("#", 1)[0]
    if not rest:
        return False
    host = rest.rsplit("@", 1)[1] if "@" in rest else rest
    host = re.split(r"[:/?#]", host, maxsplit=1)[0]
    return bool(host)


def _looks_truncated(cfg: str) -> bool:
    return cfg.endswith(tuple(_TRUNCATION_MARKERS)) or cfg.endswith("%")


def _authority_complete(cfg: str) -> bool:
    rest = cfg.split("://", 1)[1].split("#", 1)[0]
    if "@" not in rest:
        return False
    hostpart = rest.rsplit("@", 1)[1]
    host = re.split(r"[:/?#]", hostpart, maxsplit=1)[0]
    if not host or host.endswith("."):
        return False
    if "." in host:
        return True
    return ":" in hostpart


def extract_configs(text: str) -> list[str]:
    text = html.unescape(text)
    text = ENCODED_NL_RE.sub("\n", text)
    out: list[str] = []
    for line in text.splitlines():
        for piece in SPLIT_RE.split(line):
            for match in TOKEN_RE.finditer(piece):
                raw = match.group(0)
                if _looks_truncated(raw):
                    cfg = clean_config(raw)
                    if _valid(cfg) and _authority_complete(cfg):
                        out.append(cfg)
                    continue
                cfg = clean_config(raw)
                if _valid(cfg):
                    out.append(cfg)
    return out


def decode_base64(text: str) -> str | None:
    compact = re.sub(r"\s+", "", text)
    pad = len(compact) % 4
    if pad:
        compact += "=" * (4 - pad)
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def dedupe_sorted(configs: Iterable[str]) -> list[str]:
    return sorted(set(configs))
