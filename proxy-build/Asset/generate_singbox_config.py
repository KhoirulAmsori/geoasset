#!/usr/bin/env python3
import json
import base64
import socket
import geoip2.database
import ipaddress
import os
import re
from typing import Dict, Optional, Tuple, List
from urllib.parse import urlparse, parse_qs

STOPWORDS = {
    "SAS", "INC", "LTD", "LLC", "CORP", "CO", "SA", "SRO", "ASN", "LIMITED", "COMPANY",
    "ASIA", "CLOUD", "INTERNATIONAL", "PROVIDER", "ISLAND", "PRIVATE", "ONLINE",
    "OF", "AS", "BV", "HK", "MSN", "BMC", "PTE"
}

country_filter_env = os.environ.get("IncludedCountry")
protocol_filter_env = os.environ.get("IncludedProtocols")

country_pattern = re.compile(
    "(" + "|".join(c.strip() for c in country_filter_env.split(",") if c.strip()) + ")",
    re.IGNORECASE
)

protocol_pattern = re.compile(
    "(" + "|".join(p.strip() for p in protocol_filter_env.split(",") if p.strip()) + ")",
    re.IGNORECASE
)


class GeoIPResolver:
    def __init__(self, country_mmdb_path: str, asn_mmdb_path: str):
        self.country_reader = geoip2.database.Reader(country_mmdb_path)
        self.asn_reader = geoip2.database.Reader(asn_mmdb_path)
        # cache: key = ip_or_host, value = (country_code, isp)
        self._cache: Dict[str, Tuple[str, str]] = {}

    def get_country_and_isp(self, host_or_ip: str) -> Tuple[str, str]:
        """
        Resolve host_or_ip to an IP (if hostname) and lookup country_code + isp from mmdb.
        Returns (country_code, isp) where country_code is lowercase ('' if unknown).
        Caches results per input string.
        """
        if host_or_ip in self._cache:
            return self._cache[host_or_ip]

        ip = host_or_ip
        try:
            # cek apakah host_or_ip adalah IP valid
            ipaddress.ip_address(host_or_ip)
        except ValueError:
            # bukan IP, berarti hostname → coba resolve
            try:
                ip = socket.gethostbyname(host_or_ip)
            except Exception:
                ip = host_or_ip  # fallback: tetap pakai input (mungkin error di geoip2)

        country_code, isp = "", ""
        try:
            country_response = self.country_reader.country(ip)
            country_code = (country_response.country.iso_code or "").lower()
        except Exception:
            country_code = ""

        try:
            asn_response = self.asn_reader.asn(ip)
            isp = asn_response.autonomous_system_organization or ""
        except Exception:
            isp = ""

        result = (country_code, isp)
        self._cache[host_or_ip] = result
        return result


class ConfigToSingbox:
    def __init__(self,
                country_mmdb_path: str,
                asn_mmdb_path: str,
                list_path: str,
                output_file: str):
        self.list_path = list_path
        self.output_file = output_file
        self.resolver = GeoIPResolver(country_mmdb_path, asn_mmdb_path)

    @staticmethod
    def clean_isp_name(isp: str) -> str:
        isp_raw = isp if isp else "Unknown"
        isp_raw = isp_raw.replace(".", "").replace(",", "").strip()

        parts = [w for w in isp_raw.replace("-", " ").split() if w and w.upper() not in STOPWORDS]

        if len(parts) >= 2:
            isp_name = f"{parts[0]} {parts[1]}"
        elif len(parts) == 1:
            isp_name = parts[0]
        else:
            isp_name = "Unknown"

        return isp_name

    # ---------- Parsers (kembalikan dict canonical) ----------
    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '')
            decoded = base64.b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
        except Exception:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'vless' or not url.hostname:
                return None
            netloc = url.netloc.split('@')[-1]
            address, port = netloc.split(':') if ':' in netloc else (netloc, '443')
            params = parse_qs(url.query)
            return {
                'proto': 'vless',
                'address': address,
                'port': int(port),
                'uuid': url.username,
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [address])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0]
            }
        except Exception:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'trojan' or not url.hostname:
                return None
            port = url.port or 443
            params = parse_qs(url.query)
            return {
                'proto': 'trojan',
                'address': url.hostname,
                'port': port,
                'password': url.username,
                'sni': params.get('sni', [url.hostname])[0],
                'alpn': params.get('alpn', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0]
            }
        except Exception:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() not in ['hysteria2', 'hy2'] or not url.hostname or not url.port:
                return None
            query = dict(pair.split('=') for pair in url.query.split('&')) if url.query else {}
            return {
                'proto': 'hysteria2',
                'address': url.hostname,
                'port': url.port,
                'password': url.username or query.get('password', ''),
                'sni': query.get('sni', url.hostname)
            }
        except Exception:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('ss://', '').split('@')
            if len(parts) != 2:
                return None
            method_pass = base64.b64decode(parts[0]).decode('utf-8')
            method, password = method_pass.split(':', 1)
            server_parts = parts[1].split('#')[0]
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
        """
        Parse raw config line to a canonical dict describing the outbound.
        """
        raw = raw.strip()
        if not raw:
            return None
        lower = raw.lower()
        if lower.startswith('vmess://'):
            vm = self.decode_vmess(raw)
            if not vm:
                return None
            # canonicalize vmess fields we need
            return {
                'proto': 'vmess',
                'address': vm.get('add'),
                'port': int(vm.get('port', 0)) if vm.get('port') else 0,
                'id': vm.get('id'),
                'net': vm.get('net', 'tcp'),
                'path': vm.get('path', ''),
                'host': vm.get('host', ''),
                'tls': vm.get('tls', '')  # 'tls' if TLS
            }
        if lower.startswith('vless://'):
            return self.parse_vless(raw)
        if lower.startswith('trojan://'):
            return self.parse_trojan(raw)
        if lower.startswith('hysteria2://') or lower.startswith('hy2://'):
            return self.parse_hysteria2(raw)
        if lower.startswith('ss://'):
            return self.parse_shadowsocks(raw)
        return None

    # ---------- Tagging utilities ----------
    def build_tags_for_addresses(self, addresses: List[str]) -> Dict[str, str]:
        """
        addresses: list of addresses in appearance order (may contain duplicates)
        returns mapping address -> tag (e.g. "US 1 - ISP")
        """
        tag_map: Dict[str, str] = {}
        counters: Dict[str, int] = {}

        # Use unique-preserving order
        seen = set()
        unique_addresses = []
        for a in addresses:
            if a not in seen:
                seen.add(a)
                unique_addresses.append(a)

        for addr in unique_addresses:
            country_code, isp = self.resolver.get_country_and_isp(addr)
            cc = country_code.upper() if country_code else "UNK"
            counters[cc] = counters.get(cc, 0) + 1
            index = counters[cc]
            isp_clean = self.clean_isp_name(isp)
            tag_map[addr] = f"{cc} {index} - {isp_clean}"

        return tag_map

    # ---------- Convert canonical parsed dict to singbox outbound ----------
    def make_outbound_from_parsed(self, parsed: Dict, tag_map: Dict[str, str]) -> Optional[Dict]:
        proto = parsed.get('proto')
        address = parsed.get('address')
        if not proto or not address:
            return None

        tag = tag_map.get(address, f"UNK 1 - ()")
        # build outbound base and add proto-specific fields
        if proto == 'vmess':
            transport = {}
            net = parsed.get('net', 'tcp')
            if net in ('ws', 'h2'):
                if parsed.get('path'):
                    transport['path'] = parsed['path']
                if parsed.get('host'):
                    transport['headers'] = {'Host': parsed['host']}
                transport['type'] = net
            return {
                "type": "vmess", "tag": tag, "server": address, "server_port": int(parsed.get('port', 0)), "uuid": parsed.get('id'), "security": "auto", "transport": transport, "tls": {
                    "enabled": parsed.get('tls') == 'tls',
                    "insecure": True,
                    "server_name": parsed.get('host') or address
                }
            }
        if proto == 'vless':
            transport = {}
            if parsed.get('type') == 'ws':
                if parsed.get('path'):
                    transport['path'] = parsed['path']
                if parsed.get('host'):
                    transport['headers'] = {'Host': parsed['host']}
                transport['type'] = 'ws'
            return {
                "type": "vless", "tag": tag, "server": address, "server_port": int(parsed.get('port', 0)), "uuid": parsed.get('uuid'), "flow": parsed.get('flow'), "tls": {
                    "enabled": True,
                    "server_name": parsed.get('sni') or address,
                    "insecure": True
                }, "transport": transport
            }
        if proto == 'trojan':
            transport = {}
            if parsed.get('type') != 'tcp' and parsed.get('path'):
                transport['path'] = parsed['path']
                transport['type'] = parsed.get('type')
            return {
                "type": "trojan", "tag": tag, "server": address, "server_port": int(parsed.get('port', 0)), "password": parsed.get('password'), "tls": {
                    "enabled": True,
                    "server_name": parsed.get('sni') or address,
                    "alpn": parsed.get('alpn').split(',') if parsed.get('alpn') else [],
                    "insecure": True
                }, "transport": transport
            }
        if proto == 'hysteria2':
            return {
                "type": "hysteria2", "tag": tag, "server": address, "server_port": int(parsed.get('port', 0)), "password": parsed.get('password'), "tls": {
                    "enabled": True,
                    "insecure": True,
                    "server_name": parsed.get('sni') or address
                }
            }
        if proto == 'shadowsocks':
            return {
                "type": "shadowsocks", "tag": tag, "server": address, "server_port": int(parsed.get('port', 0)), "method": parsed.get('method'), "password": parsed.get('password')
            }
        return None

    # ---------- Main processing ----------
    def process_configs(self):
        try:
            with open(self.list_path, 'r') as f:
                raw_lines = [l.strip() for l in f.readlines()]

            parsed_list: List[Dict] = []
            address_order: List[str] = []

            # parse all and collect addresses in appearance order
            for raw in raw_lines:
                if not raw or raw.startswith('//'):
                    continue
                parsed = self.parse_any(raw)
                if not parsed:
                    continue
                parsed_list.append(parsed)
                addr = parsed.get('address')
                if addr:
                    address_order.append(addr)

            if not parsed_list:
                print("No valid configs found.")
                return

            # Resolve addresses once and build per-country-indexed tags
            tag_map = self.build_tags_for_addresses(address_order)

            # Build outbounds
            outbounds: List[Dict] = []
            valid_tags: List[str] = []
            for p in parsed_list:
                proto = p.get('proto', '')
                addr = p.get('address', '')
                tag = tag_map.get(addr, '').split(' ')[0]

                # apply include-type
                if not protocol_pattern.search(proto):
                    continue

                # apply filter by tag (country code prefix)
                if not country_pattern.search(tag):
                    continue

                out = self.make_outbound_from_parsed(p, tag_map)
                if out:
                    outbounds.append(out)
                    valid_tags.append(out['tag'])

            if not outbounds:
                print("No outbounds matched filter/exclude rules.")
                return

            # assemble final config
            log_config = {
                "log": {"disabled": False, "level": "fatal", "timestamp": True}
            }
            
            ntp_config = {
                "ntp": {"enabled": True, "server": "time.google.com", "server_port": 123, "interval": "30m"}
            }
            
            dns_config = {
                "dns": {
                    "servers": [
                        {"type": "hosts", "tag": "hosts"},
                        {"type": "udp", "tag": "google-udp", "server": "8.8.8.8"},
                        {"type": "h3", "tag": "google-doh3", "server": "dns.google", "domain_resolver": {"server": "google-udp", "strategy": "ipv4_only"}, "tls": {"enabled": True, "insecure": False, "server_name": "dns.google", "alpn": "h3"}}
                    ],
                    "rules": [
                        {"ip_accept_any": True, "server": "hosts"}
                    ],
                    "strategy": "ipv4_only", "disable_cache": False,
                    "disable_expire": False,
                    "independent_cache": False,
                    "reverse_mapping": True,
                    "final": "google-udp"
                }
            }
            
            inbounds_config = [
                {"type": "direct", "tag": "dns-in", "listen": "192.168.10.1", "listen_port": 1053},
                {"type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": 7893}
            ]

            outbounds_config = [
                {"type": "block", "tag": "REJECT"},
                {"type": "direct", "tag": "DIRECT"},
                {"type": "selector", "tag": "ROUTE-ID", "outbounds": ["REJECT", "DIRECT", "MIXED"], "default": "DIRECT"},
                {"type": "selector", "tag": "ROUTE-SG", "outbounds": ["REJECT", "DIRECT", "MIXED"], "default": "DIRECT"},
                {"type": "selector", "tag": "MIXED", "outbounds": valid_tags},
                {"type": "selector", "tag": "ROUTE-ADS", "outbounds": ["REJECT", "DIRECT", "MIXED"], "default": "REJECT"}
            ] + outbounds

            route_config = {
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
                "default_domain_resolver": {"server": "google-udp", "strategy": "ipv4_only"},
                "default_mark": 7894,
                "auto_detect_interface": True,
                "final": "ROUTE-SG"
            }
            
            experimental_config = {
                "experimental": {
                    "cache_file": {"enabled": True},
                    "clash_api": {"external_controller": "0.0.0.0:9090", "external_ui": "yacd", "secret": "raven", "external_ui_download_url": "https://github.com/KhoirulAmsori/My-openWRT-Backup/raw/main/openCLASH-YaCD/yacd.zip", "external_ui_download_detour": "DIRECT"
                    }
                }
            }

            singbox_config = {
                **log_config,
                **ntp_config,
                **dns_config,
                "inbounds": inbounds_config,
                "outbounds": outbounds_config,
                "route": route_config,
                **experimental_config
            }

            with open(self.output_file, 'w') as f:
                json.dump(singbox_config, f, indent=4, ensure_ascii=False)

            print(f"Wrote {len(outbounds)} outbounds to {self.output_file}")

        except Exception as e:
            print(f"Error processing configs: {e}")


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    list_path = os.path.join(base_dir, "..", "list.txt")           # proxy-build/list.txt
    output_file = os.path.join(os.path.dirname(list_path), "raven.json")  # proxy-build/raven.json

    converter = ConfigToSingbox(
        country_mmdb_path="GeoLite2-Country.mmdb",
        asn_mmdb_path="GeoLite2-ASN.mmdb",
        list_path=os.path.abspath(list_path),
        output_file=os.path.abspath(output_file)
    )
    converter.process_configs()



if __name__ == '__main__':
    main()
