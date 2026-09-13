#!/usr/bin/env python3
import json
import base64
import socket
import geoip2.database
import ipaddress
import os
from typing import Dict, Optional, Tuple, List, Set
from urllib.parse import urlparse, parse_qs
from functools import lru_cache

# Konstanta & Konfigurasi Global
STOPWORDS: Set[str] = {
    "SAS", "INC", "LTD", "LLC", "CORP", "CO", "SA", "SRO", "ASN", "LIMITED", "COMPANY",
    "ASIA", "CLOUD", "INTERNATIONAL", "PROVIDER", "ISLAND", "PRIVATE", "ONLINE",
    "OF", "AS", "BV", "HK", "MSN", "BMC", "PTE"
}
PROTO_ALIAS: Dict[str, str] = {"ss": "shadowsocks"}
COUNTRY_MMDB_PATH = "GeoLite2-Country.mmdb"
ASN_MMDB_PATH = "GeoLite2-ASN.mmdb"
LIST_PATH = "list.txt"
OUTPUT_FILE = "raven.json"

def _prepare_filters() -> Tuple[Set[str], Set[str]]:
    country_filter_env = os.environ.get("IncludedCountry", "")
    protocol_filter_env = os.environ.get("IncludedProtocols", "")
    country_filter = {c.strip().lower() for c in country_filter_env.split(",") if c.strip()}
    protocols = {PROTO_ALIAS.get(p.strip().lower(), p.strip().lower()) for p in protocol_filter_env.split(",") if p.strip()}
    return country_filter, protocols

COUNTRY_FILTERS, PROTOCOL_FILTERS = _prepare_filters()

class GeoIPResolver:
    def __init__(self, country_mmdb_path: str, asn_mmdb_path: str):
        try:
            self.country_reader = geoip2.database.Reader(country_mmdb_path)
            self.asn_reader = geoip2.database.Reader(asn_mmdb_path)
        except Exception as e:
            raise FileNotFoundError(f"Error loading GeoIP databases: {e}")

    @staticmethod
    @lru_cache(maxsize=128)
    def _resolve_hostname(hostname: str) -> str:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return hostname

    def get_country_and_isp(self, host_or_ip: str) -> Tuple[str, str]:
        ip = host_or_ip
        try:
            ipaddress.ip_address(host_or_ip)
        except ValueError:
            ip = self._resolve_hostname(host_or_ip)

        country_code, isp = "", ""
        try:
            country_response = self.country_reader.country(ip)
            country_code = (country_response.country.iso_code or "").lower()
        except Exception:
            pass
        try:
            asn_response = self.asn_reader.asn(ip)
            isp = asn_response.autonomous_system_organization or ""
        except Exception:
            pass
        return country_code, isp

class ConfigToSingbox:
    def __init__(self, resolver: GeoIPResolver, list_path: str, output_file: str):
        self.list_path = list_path
        self.output_file = output_file
        self.resolver = resolver

    @staticmethod
    def safe_b64decode(data: str) -> bytes:
        return base64.b64decode(data + "==="[: (4 - len(data) % 4) % 4])

    @staticmethod
    def _parse_url(config: str, schemes: List[str]) -> Optional[Tuple]:
        url = urlparse(config)
        if url.scheme.lower() not in schemes or not url.hostname:
            return None
        return url, parse_qs(url.query)

    @staticmethod
    def _build_transport(net: str, params: Dict) -> Dict:
        transport = {"type": net}
        if "path" in params and params["path"]:
            path = params["path"][0] if isinstance(params["path"], list) else params["path"]
            transport["path"] = path
        if "host" in params and params["host"]:
            host = params["host"][0] if isinstance(params["host"], list) else params["host"]
            transport["headers"] = {"Host": host}
        return transport

    @staticmethod
    def clean_isp_name(isp: str) -> str:
        if not isp:
            return "Unknown"
        isp_raw = isp.replace(".", "").replace(",", "").strip()
        parts = [w for w in isp_raw.replace("-", " ").split() if w and w.upper() not in STOPWORDS]
        if not parts:
            return "Unknown"
        return " ".join(parts[:2])

    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '')
            decoded = self.safe_b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
        except (ValueError, json.JSONDecodeError):
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        parsed = self._parse_url(config, ["vless"])
        if not parsed:
            return None
        url, q = parsed
        return {
            'proto': 'vless',
            'address': url.hostname,
            'port': url.port or 443,
            'uuid': url.username,
            'flow': q.get('flow', [''])[0],
            'sni': q.get('sni', [url.hostname])[0],
            'network': q.get('type', ['tcp'])[0],
            'transport': self._build_transport(q.get('type', ['tcp'])[0], q),
        }

    def parse_trojan(self, config: str) -> Optional[Dict]:
        parsed = self._parse_url(config, ["trojan"])
        if not parsed:
            return None
        url, q = parsed
        return {
            'proto': 'trojan',
            'address': url.hostname,
            'port': url.port or 443,
            'password': url.username,
            'sni': q.get('sni', [url.hostname])[0],
            'alpn': q.get('alpn', [''])[0],
            'network': q.get('type', ['tcp'])[0],
            'transport': self._build_transport(q.get('type', ['tcp'])[0], q),
        }

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        parsed = self._parse_url(config, ["hysteria2", "hy2"])
        if not parsed:
            return None
        url, q = parsed
        return {
            'proto': 'hysteria2',
            'address': url.hostname,
            'port': url.port,
            'password': url.username or q.get('password', [''])[0],
            'sni': q.get('sni', [url.hostname])[0],
        }

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            raw = config.replace('ss://', '', 1)
            if '@' in raw:
                encoded, server_parts = raw.split('@')
                method, password = self.safe_b64decode(encoded).decode('utf-8').split(':', 1)
                host, port = server_parts.split('#')[0].split(':')
            else:
                decoded = self.safe_b64decode(raw).decode('utf-8')
                creds, server_parts = decoded.split('@')
                method, password = creds.split(':', 1)
                host, port = server_parts.split(':')
            return {
                'proto': 'shadowsocks',
                'address': host,
                'port': int(port),
                'method': method,
                'password': password
            }
        except Exception:
            return None

    def parse_any(self, raw: str) -> Optional[Dict]:
        raw = raw.strip()
        if not raw:
            return None
        lower = raw.lower()
        if lower.startswith('vmess://'):
            vm = self.decode_vmess(raw)
            if not vm:
                return None
            return {
                'proto': 'vmess',
                'address': vm.get('add'),
                'port': int(vm.get('port', 0)),
                'id': vm.get('id'),
                'net': vm.get('net', 'tcp'),
                'path': vm.get('path', ''),
                'host': vm.get('host', ''),
                'tls': vm.get('tls', '')
            }
        elif lower.startswith('vless://'):
            return self.parse_vless(raw)
        elif lower.startswith('trojan://'):
            return self.parse_trojan(raw)
        elif lower.startswith('hysteria2://') or lower.startswith('hy2://'):
            return self.parse_hysteria2(raw)
        elif lower.startswith('ss://'):
            return self.parse_shadowsocks(raw)
        return None

    def make_outbound_from_parsed(self, parsed: Dict, tag: str) -> Optional[Dict]:
        proto = parsed.get('proto')
        address = parsed.get('address')
        if not proto or not address:
            return None
        
        outbound = {
            "type": proto,
            "tag": tag,
            "server": address,
            "server_port": int(parsed.get('port', 0)),
        }
        
        if proto == 'vmess':
            outbound.update({
                "uuid": parsed.get('id'),
                "security": "auto",
                "tls": {
                    "enabled": parsed.get('tls') == 'tls',
                    "insecure": True,
                    "server_name": parsed.get('host') or address
                },
                "transport": {}
            })
            if parsed.get('net') in ('ws', 'h2'):
                outbound['transport']['type'] = parsed['net']
                if parsed.get('path'): outbound['transport']['path'] = parsed['path']
                if parsed.get('host'): outbound['transport']['headers'] = {'Host': parsed['host']}
        
        elif proto == 'vless':
            outbound.update({
                "uuid": parsed.get('uuid'),
                "flow": parsed.get('flow'),
                "tls": {
                    "enabled": True,
                    "server_name": parsed.get('sni') or address,
                    "insecure": True
                },
                "transport": {}
            })
            if parsed.get('type') == 'ws':
                outbound['transport']['type'] = 'ws'
                if parsed.get('path'): outbound['transport']['path'] = parsed['path']
                if parsed.get('host'): outbound['transport']['headers'] = {'Host': parsed['host']}
        
        elif proto == 'trojan':
            outbound.update({
                "password": parsed.get('password'),
                "tls": {
                    "enabled": True,
                    "server_name": parsed.get('sni') or address,
                    "alpn": parsed.get('alpn').split(',') if parsed.get('alpn') else [],
                    "insecure": True
                },
                "transport": {}
            })
            if parsed.get('type') != 'tcp' and parsed.get('path'):
                outbound['transport']['type'] = parsed.get('type')
                outbound['transport']['path'] = parsed['path']
        
        elif proto == 'hysteria2':
            outbound.update({
                "password": parsed.get('password'),
                "tls": {
                    "enabled": True,
                    "insecure": True,
                    "server_name": parsed.get('sni') or address
                }
            })
        
        elif proto == 'shadowsocks':
            outbound.update({
                "method": parsed.get('method'),
                "password": parsed.get('password')
            })
        
        return outbound

    # --- Alur Utama ---
    def process_configs(self):
        try:
            with open(self.list_path, 'r') as f:
                raw_lines = f.readlines()
            proxies: List[Dict] = []
            for line in raw_lines:
                parsed = self.parse_any(line)
                if not parsed:
                    continue
                proto = parsed.get('proto', '')
                if PROTOCOL_FILTERS and proto.lower() not in PROTOCOL_FILTERS:
                    continue  # filter protokol lebih awal
                proxies.append(parsed)
            
            if not proxies:
                print("No valid configs found or none matched protocol filter.")
                return

            tag_counts: Dict[str, int] = {}
            outbounds: List[Dict] = []
            valid_tags: List[str] = []

            for p in proxies:
                proto = p.get('proto', '')
                address = p.get('address', '')
                
                cc, isp = self.resolver.get_country_and_isp(address)
                
                # Filter negara
                if COUNTRY_FILTERS and cc not in COUNTRY_FILTERS:
                    continue
                
                cc_upper = cc.upper() if cc else "UNK"
                isp_clean = self.clean_isp_name(isp)
                tag_counts[cc_upper] = tag_counts.get(cc_upper, 0) + 1
                tag = f"{cc_upper} {tag_counts[cc_upper]} - {isp_clean}"
                
                out = self.make_outbound_from_parsed(p, tag)
                if out:
                    outbounds.append(out)
                    valid_tags.append(tag)
            
            if not outbounds:
                print("No outbounds matched country filters.")
                return

            # Menggabungkan konfigurasi dasar dengan f-string yang lebih rapi
            base_config = {
                "log": {"disabled": False, "level": "fatal", "timestamp": True},
                "ntp": {"enabled": True, "server": "time.google.com", "server_port": 123, "interval": "30m"},
                "dns": {
                    "servers": [
                        {"type": "hosts", "tag": "hosts"},
                        {"type": "udp", "tag": "quad9-udp", "server": "9.9.9.9"},
                        {"type": "https", "tag": "quad9-doh", "server": "dns.quad9.net", "domain_resolver": {"server": "quad9-udp", "strategy": "ipv4_only"}}
                    ],
                    "rules": [
                        {"ip_accept_any": True, "server": "hosts"}
                    ],
                    "strategy": "ipv4_only", "disable_cache": False, "disable_expire": False,
                    "independent_cache": False, "reverse_mapping": True, "final": "quad9-doh"
                },
                "inbounds": [
                    {"type": "direct", "tag": "dns-in", "listen": "192.168.10.1", "listen_port": 1053},
                    {"type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": 7893}
                ],
                "outbounds": [
                    {"type": "block", "tag": "REJECT"},
                    {"type": "direct", "tag": "DIRECT"},
                    {"type": "selector", "tag": "ROUTE-ID", "outbounds": ["REJECT", "DIRECT", "MIXED"], "default": "DIRECT"},
                    {"type": "selector", "tag": "ROUTE-SG", "outbounds": ["REJECT", "DIRECT", "MIXED"], "default": "DIRECT"},
                    {"type": "selector", "tag": "MIXED", "outbounds": valid_tags},
                    {"type": "selector", "tag": "ROUTE-ADS", "outbounds": ["REJECT", "DIRECT", "MIXED"], "default": "REJECT"}
                ] + outbounds,
                "route": {
                    "rules": [
                        {"action": "sniff", "sniffer": []},
                        {"protocol": "dns", "action": "hijack-dns"},
                        {"protocol": "bittorrent", "action": "direct"},
                        {"domain": ["dns.google", "one.one.one.one"], "outbound": "DIRECT"},
                        {"rule_set": ["raven_reject", "raven_nsfw", "oisd-nsfw-small", "tiktok", "AS142160"], "action": "reject"},
                        {"network": "udp", "port": 443, "action": "reject"},
                        {"network": "udp", "outbound": "DIRECT"},
                        {"ip_is_private": True, "action": "direct"},
                        {"rule_set": ["raven_lokal"], "action": "direct"},
                        {"rule_set": ["oisd-small", "raven_ads"], "outbound": "ROUTE-ADS"},
                        {"rule_set": ["raven_direct"], "outbound": "ROUTE-ID"},
                        {"rule_set": ["raven_route-sg"], "outbound": "ROUTE-SG"},
                        {"rule_set": ["OpenIXP-IIX", "raven_route-id", "telegram"], "outbound": "ROUTE-ID"},
                    ],
                    "rule_set": [
                        {"type": "local", "tag": "raven_reject", "format": "source", "path": "raven_reject.json"},
                        {"type": "remote", "tag": "AS142160", "format": "binary", "url": "https://raw.githubusercontent.com/KhoirulAmsori/geoasset/sing-box/asn/AS142160.srs", "download_detour": "DIRECT"},
                        {"type": "remote", "tag": "tiktok", "format": "binary", "url": "https://raw.githubusercontent.com/KhoirulAmsori/geoasset/sing-box/geo/geosite/tiktok.srs", "download_detour": "DIRECT"},
                        {"type": "remote", "tag": "raven_nsfw", "format": "binary", "url": "https://raw.githubusercontent.com/KhoirulAmsori/geoasset/sing-box/geo/geosite/raven_nsfw.srs", "download_detour": "DIRECT"},
                        {"type": "remote", "tag": "oisd-nsfw-small", "format": "binary", "url": "https://raw.githubusercontent.com/KhoirulAmsori/geoasset/sing-box/geo/geosite/oisd-nsfw-small.srs", "download_detour": "DIRECT"},
                        {"type": "local", "tag": "raven_lokal", "format": "binary", "path": "lokal.srs"},
                        {"type": "local", "tag": "raven_ads", "format": "source", "path": "raven_ads.json"},
                        {"type": "remote", "tag": "oisd-small", "format": "binary", "url": "https://raw.githubusercontent.com/KhoirulAmsori/geoasset/sing-box/geo/geosite/oisd-small.srs", "download_detour": "DIRECT"},
                        {"type": "local", "tag": "raven_direct", "format": "source", "path": "raven_direct.json"},
                        {"type": "remote", "tag": "raven_route-sg", "format": "binary", "url": "https://raw.githubusercontent.com/KhoirulAmsori/geoasset/sing-box/geo/geosite/youtube.srs", "download_detour": "DIRECT"},
                        {"type": "remote", "tag": "OpenIXP-IIX", "format": "binary", "url": "https://raw.githubusercontent.com/KhoirulAmsori/geoasset/sing-box/geo/geosite/nice.srs", "download_detour": "DIRECT"},
                        {"type": "local", "tag": "raven_route-id", "format": "source", "path": "raven_route-id.json"},
                        {"type": "remote", "tag": "telegram", "format": "binary", "url": "https://raw.githubusercontent.com/KhoirulAmsori/geoasset/sing-box/geo/geoip/telegram.srs", "download_detour": "DIRECT"}
                    ],
                    "default_domain_resolver": {"server": "quad9-udp", "strategy": "ipv4_only"},
                    "default_mark": 7894,
                    "auto_detect_interface": True,
                    "final": "ROUTE-SG"
                },
                "experimental": {
                    "cache_file": {"enabled": True},
                    "clash_api": {
                        "external_controller": "0.0.0.0:9090",
                        "external_ui": "yacd",
                        "secret": "raven",
                        "external_ui_download_url": "https://github.com/KhoirulAmsori/My-openWRT-Backup/raw/main/openCLASH-YaCD/yacd.zip",
                        "external_ui_download_detour": "DIRECT"
                    }
                }
            }

            with open(self.output_file, 'w') as f:
                json.dump(base_config, f, indent=4, ensure_ascii=False)
            
            print(f"Wrote {len(outbounds)} outbounds to {self.output_file}")
            
        except FileNotFoundError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Gunakan path yang lebih aman dan eksplisit
    list_path = os.path.join(base_dir, "..", LIST_PATH)
    output_file = os.path.join(os.path.dirname(list_path), OUTPUT_FILE)
    country_mmdb_path = os.path.join(base_dir, COUNTRY_MMDB_PATH)
    asn_mmdb_path = os.path.join(base_dir, ASN_MMDB_PATH)
    
    try:
        resolver = GeoIPResolver(country_mmdb_path, asn_mmdb_path)
        converter = ConfigToSingbox(resolver, list_path, output_file)
        converter.process_configs()
    except FileNotFoundError as e:
        print(f"Initialization failed: {e}")
    except Exception as e:
        print(f"An error occurred during script execution: {e}")

if __name__ == '__main__':
    main()
