#!/usr/bin/python
# -*- coding: utf-8 -*-
import yaml
import json
import urllib.request
import logging
import geoip2.database
import socket
import re
import base64
import ipaddress

DEBUG_MODE = False  # set True untuk debug (IPv6 juga diproses)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

country_counters = {}  # hitungan per country


def format_proxy_name(country: str) -> str:
    """Buat nama proxy dengan format Country-XX (2 digit)."""
    count = country_counters.get(country, 0) + 1
    country_counters[country] = count
    return f"{country}-{count:02d}"


def is_ipv4_or_domain(address: str) -> bool:
    if DEBUG_MODE:
        return True
    try:
        ip = ipaddress.ip_address(address)
        return isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return True


def process_urls(urls_file, method):
    try:
        with open(urls_file, 'r') as f:
            urls = f.read().splitlines()

        for index, url in enumerate(urls):
            try:
                response = urllib.request.urlopen(url)
                data = response.read().decode('utf-8')
                method(data, index)
            except Exception as e:
                logging.error(f"Galat saat memproses {url}: {e}")
    except Exception as e:
        logging.error(f"Galat saat membaca {urls_file}: {e}")
        return


def process_clash_meta(data, index):
    index += 1
    try:
        content = yaml.safe_load(data)
        try:
            proxies = content['proxies']
        except:
            proxies = []

        for i, proxy in enumerate(proxies[:2]):
            server = proxy['server']
            if not is_ipv4_or_domain(server):
                logging.info(f"Skip Clash Meta {index}: IPv6 terdeteksi ({server})")
                continue

            if ("network" in proxy and f"{proxy['network']}" == "ws"):
                key = f"{proxy['server']}:{proxy['port']}-{proxy['ws-opts']['headers']['Host']}-ws"
                if key not in servers_list:
                    location = get_physical_location(proxy['server'])
                    proxy['name'] = format_proxy_name(location)
                    servers_list.append(key)
                else:
                    continue
            elif (f"{proxy['server']}:{proxy['port']}-{proxy['type']}" not in servers_list):
                location = get_physical_location(proxy['server'])
                proxy['name'] = format_proxy_name(location)
                servers_list.append(f"{proxy['server']}:{proxy['port']}-{proxy['type']}")
            else:
                continue
            extracted_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Galat konfigurasi Clash Meta {index}: {e}")
        return


def process_hysteria(data, index):
    index =+ 1
    try:
        content = json.loads(data)
        server_ports_slt = content['server'].split(":")
        server = server_ports_slt[0]
        if not is_ipv4_or_domain(server):
            logging.info(f"Skip Hysteria {index}: IPv6 terdeteksi ({server})")
            return

        ports = server_ports_slt[1]
        ports_slt = ports.split(',')
        server_port = int(ports_slt[0])
        if (len(ports_slt) > 1):
            mport = ports_slt[1]
        else:
            mport = server_port

        auth = content['auth_str']
        fast_open = content.get('fast_open', True)
        insecure = content['insecure']
        sni = content['server_name']
        alpn = content['alpn']
        protocol = content['protocol']
        location = get_physical_location(server)
        name = format_proxy_name(location)

        proxy = {
            "name": name,
            "type": "hysteria",
            "server": server,
            "port": server_port,
            "ports": mport,
            "auth-str": auth,
            "up": 80,
            "down": 100,
            "fast-open": fast_open,
            "protocol": protocol,
            "sni": sni,
            "skip-cert-verify": insecure,
            "alpn": [alpn]
        }
        if (f"{proxy['server']}:{proxy['port']}-hysteria" not in servers_list):
            extracted_proxies.append(proxy)
            servers_list.append(f"{proxy['server']}:{proxy['port']}-hysteria")
    except Exception as e:
        logging.error(f"Galat konfigurasi Hysteria {index}: {e}")
        return


def process_hysteria2(data, index):
    index += 1
    try:
        content = json.loads(data)
        server_ports_slt = content['server'].split(":")
        server = server_ports_slt[0]
        if not is_ipv4_or_domain(server):
            logging.info(f"Skip Hysteria2 {index}: IPv6 terdeteksi ({server})")
            return

        ports = server_ports_slt[1]
        ports_slt = ports.split(',')
        server_port = int(ports_slt[0])

        auth = content['auth']
        insecure = content['tls']['insecure']
        sni = content['tls']['sni']
        location = get_physical_location(server)
        name = format_proxy_name(location)

        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": server_port,
            "password": auth,
            "sni": sni,
            "skip-cert-verify": insecure
        }
        if (f"{proxy['server']}:{proxy['port']}-hysteria2" not in servers_list):
            extracted_proxies.append(proxy)
            servers_list.append(f"{proxy['server']}:{proxy['port']}-hysteria2")
    except Exception as e:
        logging.error(f"Galat konfigurasi Hysteria2 {index}: {e}")
        return


def process_xray(data, index):
    index += 1
    try:
        content = json.loads(data)
        outbounds = content['outbounds']
        pending_proxy = outbounds[0]
        type = pending_proxy['protocol']

        if type in ["vmess", "vless"]:
            server = pending_proxy['settings']['vnext'][0]['address']
            if not is_ipv4_or_domain(server):
                logging.info(f"Skip Xray {index}: IPv6 terdeteksi ({server})")
                return

        if (type == "vmess"):
            server = pending_proxy['settings']['vnext'][0]['address']
            port = pending_proxy['settings']['vnext'][0]['port']
            uuid = pending_proxy['settings']['vnext'][0]['users'][0]['id']
            alterId = pending_proxy['settings']['vnext'][0]['users'][0]['alterId']
            cipher = pending_proxy['settings']['vnext'][0]['users'][0]['security']
            network = pending_proxy['streamSettings']['network']
            security = pending_proxy['streamSettings'].get('security', "none")
            location = get_physical_location(server)
            name = format_proxy_name(location)
            tls = security != "none"
            sni = pending_proxy['streamSettings'].get('tlsSettings', {}).get('serverName', "")
            allowInsecure = pending_proxy['streamSettings'].get('tlsSettings', {}).get('allowInsecure', False)

            if (network in ['tcp', 'ws', 'grpc', 'h2']):
                ws_path = pending_proxy['streamSettings'].get('wsSettings', {}).get('path', "")
                ws_headers = pending_proxy['streamSettings'].get('wsSettings', {}).get('headers', {})
                grpc_serviceName = pending_proxy['streamSettings'].get('grpcSettings', {}).get('serviceName', "/")
                h2_path = pending_proxy['streamSettings'].get('httpSettings', {}).get('path', "/")
                h2_host = pending_proxy['streamSettings'].get('httpSettings', {}).get('host', [])

                proxy = {
                    "name": name,
                    "type": "vmess",
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "alterId": alterId,
                    "cipher": cipher,
                    "tls": tls,
                    "servername": sni,
                    "skip-cert-verify": allowInsecure,
                    "network": network,
                    "ws-opts": {
                        "path": ws_path,
                        "headers": ws_headers
                    },
                    "grpc-opts": {
                        "serviceName": grpc_serviceName
                    },
                    "h2-opts": {
                        "path": h2_path,
                        "host": h2_host
                    }
                }
            else:
                return
        elif (type == "vless"):
            server = pending_proxy['settings']['vnext'][0]['address']
            port = pending_proxy['settings']['vnext'][0]['port']
            uuid = pending_proxy['settings']['vnext'][0]['users'][0]['id']
            flow = pending_proxy['settings']['vnext'][0]['users'][0].get('flow', "")
            security = pending_proxy['streamSettings'].get('security', "none")
            network = pending_proxy['streamSettings']['network']
            location = get_physical_location(server)
            name = format_proxy_name(location)
            tls = security != "none"

            if (security == "reality"):
                realitySettings = pending_proxy['streamSettings'].get('realitySettings', {})
                sni = realitySettings.get('serverName', "")
                short_id = realitySettings.get('shortId', "")
                publicKey = realitySettings['publicKey']
                fingerprint = realitySettings['fingerprint']
                grpc_serviceName = pending_proxy['streamSettings'].get('grpcSettings', {}).get('serviceName', "/")

                proxy = {
                    "name": name,
                    "type": "vless",
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "flow": flow,
                    "tls": tls,
                    "servername": sni,
                    "network": network,
                    "client-fingerprint": fingerprint,
                    "grpc-opts": {
                        "grpc-service-name": grpc_serviceName
                    },
                    "reality-opts": {
                        "public-key": publicKey,
                        "short-id": short_id,
                    }
                }
            else:
                if (network in ['tcp', 'ws', 'grpc']):
                    sni = pending_proxy['streamSettings'].get('tlsSettings', {}).get('serverName', "")
                    allowInsecure = pending_proxy['streamSettings'].get('tlsSettings', {}).get('allowInsecure', False)
                    ws_path = pending_proxy['streamSettings'].get('wsSettings', {}).get('path', "")
                    ws_headers = pending_proxy['streamSettings'].get('wsSettings', {}).get('headers', {})
                    grpc_serviceName = pending_proxy['streamSettings'].get('grpcSettings', {}).get('serviceName', "/")

                    proxy = {
                        "name": name,
                        "type": "vless",
                        "server": server,
                        "port": port,
                        "uuid": uuid,
                        "tls": tls,
                        "servername": sni,
                        "skip-cert-verify": allowInsecure,
                        "network": network,
                        "ws-opts": {
                            "path": ws_path,
                            "headers": ws_headers
                        },
                        "grpc-opts": {
                            "serviceName": grpc_serviceName
                        }
                    }
                else:
                    return
        else:
            return

        if (f"{proxy['server']}:{proxy['port']}-{proxy['type']}" not in servers_list):
            extracted_proxies.append(proxy)
            servers_list.append(f"{proxy['server']}:{proxy['port']}-{proxy['type']}")
    except Exception as e:
        logging.error(f"Galat konfigurasi Xray {index}: {e}")


def get_physical_location(address):
    address = re.sub(":.*", "", address)
    try:
        ip_address = socket.gethostbyname(address)
    except socket.gaierror:
        ip_address = address

    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = reader.city(ip_address)
        country = response.country.iso_code
        return f"{country}"
    except Exception:
        return "Unknown"

def write_proxy_urls_file(output_file, proxies):
    proxy_urls = []
    for proxy in proxies:
        try:
            if (proxy['type'] == "vless"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                uuid = proxy['uuid']
                tls = int(proxy.get('tls', 0))
                network = proxy['network']
                flow = proxy.get('flow', "")
                grpc_serviceName = proxy.get('grpc-opts', {}).get('grpc-service-name', "")
                ws_path = proxy.get('ws-opts', {}).get('path', "")
                try:
                    ws_headers_host = proxy.get('ws-opts', {}).get('headers', {}).get('host', "")
                except:
                    ws_headers_host = proxy.get('ws-opts', {}).get('headers', {}).get('Host', "")

                if (tls == 0):
                    proxy_url = f"vless://{uuid}@{server}:{port}?encryption=none&flow={flow}&security=none&type={network}&serviceName={grpc_serviceName}&host={ws_headers_host}&path={ws_path}#{name}"
                else:
                    sni = proxy.get('servername', "")
                    publicKey = proxy.get('reality-opts', {}).get('public-key', "")
                    short_id = proxy.get('reality-opts', {}).get('short-id', "")
                    fingerprint = proxy.get('client-fingerprint', "")
                    if (not publicKey == ""):
                        proxy_url = f"vless://{uuid}@{server}:{port}?encryption=none&flow={flow}&security=reality&sni={sni}&fp={fingerprint}&pbk={publicKey}&sid={short_id}&type={network}&serviceName={grpc_serviceName}&host={ws_headers_host}&path={ws_path}#{name}"
                    else:
                        insecure = int(proxy.get('skip-cert-verify', 0))
                        proxy_url = f"vless://{uuid}@{server}:{port}?encryption=none&flow={flow}&security=tls&sni={sni}&fp={fingerprint}&insecure={insecure}&type={network}&serviceName={grpc_serviceName}&host={ws_headers_host}&path={ws_path}#{name}"

            elif (proxy['type'] == "vmess"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                uuid = proxy['uuid']
                alterId = proxy['alterId']
                if (int(proxy.get('tls', 0)) == 1):
                    tls = "tls"
                else:
                    tls = ""
                sni = proxy.get('servername', "")
                network = proxy['network']
                if (network == "tcp"):
                    type = "none"
                    path = ""
                    host = ""
                elif (network == "ws"):
                    type = "none"
                    path = proxy.get('ws-opts', {}).get('path', "")
                    try:
                        host = proxy.get('ws-opts', {}).get('headers', {}).get('host', "")
                    except:
                        host = proxy.get('ws-opts', {}).get('headers', {}).get('Host', "")
                elif (network == "grpc"):
                    type = "gun"
                    path = proxy.get('grpc-opts', {}).get('grpc-service-name', "")
                    host = ""
                elif (network == "h2"):
                    type = "none"
                    path = proxy.get('h2-opts', {}).get('path', "")
                    # Dapatkan host dan ubah daftar host menjadi string yang dibatasi koma
                    host = proxy.get('h2-opts', {}).get('host', [])
                    host = ','.join(host)
                else:
                    continue
                vmess_meta = {
                    "v": "2",
                    "ps": name,
                    "add": server,
                    "port": port,
                    "id": uuid,
                    "aid": alterId,
                    "net": network,
                    "type": type,
                    "host": host,
                    "path": path,
                    "tls": tls,
                    "sni": sni,
                    "alpn": ""
                }
                # Konversi vmess_meta ke string format JSON dan enkode dalam Base64
                vmess_meta = base64.b64encode(json.dumps(vmess_meta).encode('utf-8')).decode('utf-8')
                proxy_url = "vmess://" + vmess_meta

            elif (proxy['type'] == "ss"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                password = proxy['password']
                cipher = proxy['cipher']
                ss_meta = base64.b64encode(f"{cipher}:{password}").decode('utf-8')
                ss_meta = f"{ss_meta}@{server}:{port}#{name}"
                proxy_url = "ss://" + ss_meta


            elif (proxy['type'] == "hysteria"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                protocol = proxy.get('protocol', "udp")
                insecure = int(proxy.get('skip-cert-verify', 0))
                peer = proxy.get('sni', "")
                try:
                    auth = proxy['auth-str']
                except:
                    auth = proxy['auth_str']
                upmbps = proxy.get('up', "11")
                downmbps = proxy.get('down', "55")
                alpn = proxy['alpn']
                alpn = ','.join(alpn)  # Ubah daftar alpn menjadi string yang dibatasi koma
                obfs = proxy.get('obfs', "")
                proxy_url = f"hysteria://{server}:{port}/?protocol={protocol}&insecure={insecure}&peer={peer}&auth={auth}&upmbps={upmbps}&downmbps={downmbps}&alpn={alpn}&obfs={obfs}#{name}"

            elif (proxy['type'] == "hysteria2"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                auth = proxy['password']
                sni = proxy.get('sni', "")
                insecure = int(proxy.get('skip-cert-verify', 0))
                if ("obfs" in proxy and proxy['obfs'] != ""):
                    obfs = proxy['obfs']
                    obfs_password = proxy['obfs-password']
                    proxy_url = f"hysteria2://{auth}@{server}:{port}/?sni={sni}&insecure={insecure}&obfs={obfs}&obfs-password={obfs_password}#{name}"
                else:
                    proxy_url = f"hysteria2://{auth}@{server}:{port}/?sni={sni}&insecure={insecure}#{name}"

            elif (proxy['type'] == "tuic"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                uuid = proxy['uuid']
                password = proxy.get('password', "")
                congestion_controller = proxy.get('congestion-controller', "bbr")
                udp_relay_mode = proxy.get('udp-relay-mode', "naive")
                sni = proxy.get('sni', "")
                alpn = proxy.get('alpn', [])
                alpn = ','.join(alpn)
                allowInsecure = int(proxy.get('skip-cert-verify', 1))
                disable_sni = int(proxy.get('disable-sni', 0))
                proxy_url = f"tuic://{uuid}:{password}@{server}:{port}/?congestion_controller={congestion_controller}&udp_relay_mode={udp_relay_mode}&sni={sni}&alpn={alpn}&allow_insecure={allowInsecure}&disable_sni={disable_sni}#{name}"

            else:
                logging.error(f"Masalah dalam memproses {proxy['name']}: Protokol tidak didukung: {proxy['type']}")
                continue

            # print(proxy_url)
            proxy_urls.append(proxy_url)
        except Exception as e:
            logging.error(f"Masalah dalam memproses {proxy['name']}: {e}")
            continue
    # Tulis proxy_urls ke output_file
    with open(output_file, 'w', encoding='utf-8') as f:
        for proxy_url in proxy_urls:
            f.write(proxy_url + "\n")


def expand_range(pattern: str):
    """Ekspansi pola {N-M} -> list string"""
    match = re.search(r"\{(\d+)-(\d+)\}", pattern)
    if not match:
        return [pattern]

    start, end = int(match.group(1)), int(match.group(2))
    expanded = []
    for i in range(start, end + 1):
        expanded.append(pattern[:match.start()] + str(i) + pattern[match.end():])
    return expanded


def process_proxy(urls_file):
    try:
        with open(urls_file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        current_type = None
        base_url = "https://github.com/Alvin9999/PAC/raw/refs/heads/master/backup/img/1/2/ipp/"
        suffix_map = {
            "clash_meta": "/config.yaml",
            "hysteria": "/config.json",
            "hysteria2": "/config.json",
            "xray": "/config.json",
        }
        handlers = {
            "clash_meta": process_clash_meta,
            "hysteria": process_hysteria,
            "hysteria2": process_hysteria2,
            "xray": process_xray,
        }

        for line in lines:
            if line.startswith("[") and line.endswith("]"):
                current_type = line[1:-1].strip().lower()
                continue

            if current_type not in handlers:
                logging.error(f"Tipe {current_type} tidak dikenali untuk entri {line}")
                continue

            urls = expand_range(line)
            for url_part in urls:
                full_url = f"{base_url}{url_part}{suffix_map[current_type]}"
                try:
                    response = urllib.request.urlopen(full_url)
                    data = response.read().decode("utf-8")
                    handlers[current_type](data, 0)
                except Exception as e:
                    logging.error(f"Galat saat memproses {full_url}: {e}")

    except Exception as e:
        logging.error(f"Galat saat membaca {urls_file}: {e}")


if __name__ == "__main__":
    extracted_proxies = []
    servers_list = []

    process_proxy("./server_list.txt")

    write_proxy_urls_file("./Output/proxy_urls.txt", extracted_proxies)
