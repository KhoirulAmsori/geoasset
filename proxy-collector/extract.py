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

_SCHEME_ALT = "|".join(re.escape(s) for s in SCHEMES)
TOKEN_RE = re.compile(r"(?i)(?:" + _SCHEME_ALT + r")://[^\s]+")
SPLIT_RE = re.compile(r"(?i),(?=(?:" + _SCHEME_ALT + r")://)")

_TRAILING = "…»`%,;"


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


def extract_configs(text: str) -> list[str]:
    text = html.unescape(text)
    out: list[str] = []
    for line in text.splitlines():
        for piece in SPLIT_RE.split(line):
            for match in TOKEN_RE.finditer(piece):
                cfg = clean_config(match.group(0))
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
