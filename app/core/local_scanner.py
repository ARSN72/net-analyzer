import json
import nmap
import ipaddress
import socket
import subprocess
import re
import sys
import time
import os
import requests
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.core.internal_analyzer import InternalRiskAnalyzer
from app.utils.oui import OUILookup
import asyncio


class LocalNetworkScanner:
    """
    LAN discovery + enrichment + internal risk analysis.
    This module is isolated from external intel.
    """

    def __init__(self):
        self.nm = nmap.PortScanner()
        self.analyzer = InternalRiskAnalyzer()
        self._live_hosts: set[str] = set()
        self._ttl_map: dict[str, int] = {}
        self._network_context: dict[str, str] = {}
        self.oui = OUILookup(os.path.join(os.path.dirname(__file__), "..", "..", "data", "oui", "oui.csv"))

    def scan_subnet(self, cidr: str) -> List[Dict[str, Any]]:
        """Synchronous scanning routine (run in worker thread)."""
        devices: List[Dict[str, Any]] = []

        self._network_context = self._get_network_context()
        discovered_hosts = self._discover_hosts(cidr)

        print(f"Starting service scan on {len(self._live_hosts)} hosts")
        port_results: dict[str, List[Dict[str, Any]]] = {}
        hosts_to_scan = [h for h in discovered_hosts.keys() if h in self._live_hosts]
        if hosts_to_scan:
            with ThreadPoolExecutor(max_workers=16) as executor:
                futures = {executor.submit(self._scan_host_ports, host): host for host in hosts_to_scan}
                for fut in as_completed(futures):
                    host = futures[fut]
                    try:
                        port_results[host] = fut.result()
                    except Exception:
                        port_results[host] = []

        for host, arp_mac in discovered_hosts.items():
            mac = arp_mac or "Unknown"
            vendor = "Unknown"
            hostname = "Unknown"
            hostname_source = "Unknown"
            netbios_name = "Unknown"
            netbios_domain = "Unknown"

            # Phase 2: Enrichment per host (fast port scan)
            host_ports = port_results.get(host, []) if host in self._live_hosts else []

            vendor_raw = None
            hostname_raw = None
            if host in self.nm.all_hosts():
                vendor_raw = self._get_vendor(self.nm[host])
                hostname_raw = self._get_hostname(self.nm[host])
                mac = self._get_mac(self.nm[host]) or mac

            hostname, hostname_source = self._resolve_hostname(host)
            netbios = self._netbios_lookup(host)
            if netbios.get("name"):
                netbios_name = netbios["name"]
                netbios_domain = netbios.get("domain") or "Unknown"

            device = {
                "ip": host,
                "mac": mac,
                "vendor": vendor_raw or vendor,
                "hostname": hostname_raw or hostname,
                "hostname_source": hostname_source,
                "ports": host_ports,
            }
            oui_data = self.oui.lookup(mac)
            device["mac_vendor"] = oui_data["mac_vendor"]
            device["manufacturer"] = oui_data["manufacturer"]
            device["manufacturer_address"] = oui_data["manufacturer_address"]
            device["vendor_source"] = oui_data["vendor_source"]
            device["vendor_confidence"] = oui_data["vendor_confidence"]
            device["ipv6"] = self._resolve_ipv6(device.get("hostname") or host)
            os_guess, os_conf = self._os_guess(host_ports, self._ttl_map.get(host))
            device["os_guess"] = os_guess
            device["os_confidence"] = os_conf
            device["netbios_name"] = netbios_name
            device["netbios_domain"] = netbios_domain
            device["fileserver"] = "Yes" if self._is_fileserver(host_ports, netbios_name) else "Unknown"

            device["device_type"] = self._infer_device_type(vendor, host_ports)

            # Phase 3: Analysis
            risk_input = dict(device)
            risk_input["vendor"] = vendor_raw or ""
            risk = self.analyzer.assess(risk_input)
            device["risk"] = risk.model_dump()
            device["risk_reasons"] = risk.findings

            # Rogue device heuristic: unknown vendor + open ports
            device["rogue"] = bool(vendor == "Unknown" and host_ports)

            devices.append(device)

        return devices

    def get_network_context(self) -> dict:
        return self._network_context

    async def scan_subnet_async(self, cidr: str) -> List[Dict[str, Any]]:
        """Async wrapper to offload blocking scan to a worker thread."""
        return await asyncio.to_thread(self.scan_subnet, cidr)

    def _discover_hosts(self, cidr: str) -> dict[str, str]:
        """
        Parallel host discovery:
        1) Fast probe all IPs to populate ARP and detect live hosts
        2) Parse ARP table once
        3) Fallback to nmap only if nothing found
        """
        host_map: dict[str, str] = {}
        net = ipaddress.ip_network(cidr, strict=False)
        local_ip = self._get_local_ip()
        hosts = [str(ip) for ip in net.hosts() if str(ip) != local_ip]

        # Phase 1: Active probing (parallel)
        start = time.perf_counter()
        live_hosts = self._probe_hosts_parallel(hosts)
        self._live_hosts = set(live_hosts)
        print(f"Probed {len(hosts)} IPs in {time.perf_counter() - start:.2f}s")

        # Phase 2: Aggressive Nmap discovery to populate ARP and catch silent hosts
        self.nm.scan(
            hosts=cidr,
            arguments="-sn -PR -PE -PP -PS21,22,23,80,443,445,3389 -PA80,443 -n -T4"
        )
        for h in self.nm.all_hosts():
            try:
                if self.nm[h].state() == "up":
                    self._live_hosts.add(h)
            except KeyError:
                continue
        print(f"Nmap discovery found {len(self._live_hosts)} hosts")

        # Phase 3: Parse ARP table once
        arp_hosts = self._parse_arp_table(net, local_ip)
        print(f"ARP table read complete; {len(arp_hosts)} entries in subnet")

        # Combine live probe results with ARP data
        for ip in live_hosts:
            host_map[ip] = arp_hosts.get(ip, "Unknown")
        for ip, mac in arp_hosts.items():
            if ip not in host_map:
                host_map[ip] = mac
        if not self._live_hosts and host_map:
            self._live_hosts = set(host_map.keys())

        # Fallback: if still empty, try nmap ping discovery
        if not host_map:
            self.nm.scan(hosts=cidr, arguments="-sn -PR")
            for h in self.nm.all_hosts():
                try:
                    if self.nm[h].state() == "up":
                        host_map[h] = self._get_mac(self.nm[h]) or "Unknown"
                except KeyError:
                    continue
            print(f"Nmap discovery fallback found {len(host_map)} hosts")
            if not self._live_hosts:
                self._live_hosts = set(host_map.keys())

        return host_map

    def _scan_host_ports(self, host: str) -> List[Dict[str, Any]]:
        ports: List[Dict[str, Any]] = []
        scanner = nmap.PortScanner()
        scanner.scan(hosts=host, arguments="--top-ports 100 -T4 -Pn --host-timeout 15s")
        if host not in scanner.all_hosts():
            return ports
        host_data = scanner[host]
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                svc = host_data[proto][port]
                ports.append({
                    "port": port,
                    "protocol": proto,
                    "service": svc.get("name", ""),
                    "version": svc.get("version", ""),
                })
        return ports

    def _get_mac(self, host_data) -> str:
        try:
            if "addresses" in host_data and "mac" in host_data["addresses"]:
                return host_data["addresses"]["mac"]
        except Exception:
            return ""
        return ""

    def _get_vendor(self, host_data) -> str:
        try:
            vendor_data = host_data.get("vendor", {})
            if vendor_data:
                # Pick first vendor string
                return list(vendor_data.values())[0]
        except Exception:
            return ""
        return ""

    def _get_hostname(self, host_data) -> str:
        try:
            names = host_data.get("hostnames", [])
            if names:
                return names[0].get("name", "")
        except Exception:
            return ""
        return ""

    def _infer_device_type(self, vendor: str, ports: List[Dict[str, Any]]) -> str:
        v = (vendor or "").lower()
        port_set = {p.get("port") for p in ports}
        if any(k in v for k in ["router", "cisco", "tplink", "mikrotik", "netgear"]):
            return "Router/Network"
        if any(k in v for k in ["apple", "samsung", "huawei", "xiaomi"]):
            return "Mobile/Consumer"
        if any(k in v for k in ["dell", "hp", "lenovo", "asus", "acer"]):
            return "PC/Workstation"
        if 80 in port_set or 443 in port_set:
            return "Server/Web"
        if any(p in port_set for p in [554, 8554, 8000]):
            return "IoT/Camera"
        return "Unknown"

    def _probe_ip(self, ip: str) -> tuple[bool, int | None]:
        """Send a quick ping and TCP probe to populate ARP. Returns True if reachable."""
        reachable = False
        ttl_val = None
        # ICMP ping
        try:
            ping_cmd = ["ping", "-n", "1", "-w", "200", ip] if self._is_windows() else ["ping", "-c", "1", "-W", "1", ip]
            result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=0.5)
            if result.returncode == 0:
                reachable = True
                ttl_val = self._parse_ttl(result.stdout)
        except Exception:
            pass
        # TCP probe
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            if s.connect_ex((ip, 80)) == 0:
                reachable = True
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return reachable, ttl_val

    def _probe_hosts_parallel(self, hosts: List[str]) -> List[str]:
        """Probe hosts concurrently with short timeouts."""
        live: List[str] = []
        with ThreadPoolExecutor(max_workers=64) as executor:
            futures = {executor.submit(self._probe_ip, ip): ip for ip in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    reachable, ttl_val = fut.result()
                    if ttl_val is not None:
                        self._ttl_map[ip] = ttl_val
                    if reachable:
                        live.append(ip)
                except Exception:
                    continue
        return live

    def _parse_ttl(self, output: str) -> int | None:
        m = re.search(r"TTL=(\d+)", output, re.IGNORECASE)
        if m:
            return int(m.group(1))
        m = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        if m:
            return int(m.group(1))
        return None

    def _resolve_hostname(self, ip: str) -> tuple[str, str]:
        # reverse DNS
        try:
            name = socket.gethostbyaddr(ip)[0]
            if name:
                return name, "reverse_dns"
        except Exception:
            pass
        # mDNS (best-effort)
        mdns_name = self._mdns_lookup(ip)
        if mdns_name:
            return mdns_name, "mdns"
        # NetBIOS
        nb = self._netbios_lookup(ip)
        if nb.get("name"):
            return nb["name"], "netbios"
        return "Unknown", "Unknown"

    def _mdns_lookup(self, ip: str) -> str:
        # Best-effort mDNS PTR query for reverse name
        try:
            rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            query = self._build_dns_query(rev, qtype=12)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.3)
            sock.sendto(query, ("224.0.0.251", 5353))
            data, _ = sock.recvfrom(512)
            sock.close()
            return self._parse_dns_ptr(data) or ""
        except Exception:
            return ""

    def _build_dns_query(self, name: str, qtype: int) -> bytes:
        # Minimal DNS query builder
        header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
        return header + qname + qtype.to_bytes(2, "big") + b"\x00\x01"

    def _parse_dns_ptr(self, data: bytes) -> str | None:
        # Minimal PTR parser
        if len(data) < 12:
            return None
        # skip header and question
        idx = 12
        while idx < len(data) and data[idx] != 0:
            idx += data[idx] + 1
        idx += 5  # null + qtype + qclass
        # parse first answer if present
        if idx >= len(data):
            return None
        # skip name (could be pointer)
        if data[idx] & 0xC0:
            idx += 2
        else:
            while idx < len(data) and data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
        if idx + 10 > len(data):
            return None
        rtype = int.from_bytes(data[idx:idx+2], "big")
        idx += 8  # type, class, ttl
        rdlen = int.from_bytes(data[idx:idx+2], "big")
        idx += 2
        if rtype != 12 or idx + rdlen > len(data):
            return None
        # parse PTR name
        end = idx + rdlen
        labels = []
        while idx < end and data[idx] != 0:
            length = data[idx]
            idx += 1
            labels.append(data[idx:idx+length].decode(errors="ignore"))
            idx += length
        return ".".join(labels)

    def _netbios_lookup(self, ip: str) -> dict:
        result = {}
        try:
            # NBNS query for name '*'
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.3)
            query = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + self._nbns_name("*") + b"\x00\x21\x00\x01"
            sock.sendto(query, (ip, 137))
            data, _ = sock.recvfrom(512)
            sock.close()
            if data and len(data) > 56:
                # parse name from response (basic)
                name = data[57:72].decode(errors="ignore").strip()
                result["name"] = name.replace("\x00", "").strip()
        except Exception:
            return result
        return result

    def _nbns_name(self, name: str) -> bytes:
        name = name.ljust(15)[:15]
        name = name + "\x00"
        encoded = ""
        for c in name:
            b = ord(c)
            encoded += chr(((b >> 4) & 0x0F) + 0x41)
            encoded += chr((b & 0x0F) + 0x41)
        return bytes([32]) + encoded.encode() + b"\x00"

    def _os_guess(self, ports: List[Dict[str, Any]], ttl: int | None) -> tuple[str, str]:
        port_set = {p.get("port") for p in ports}
        if 445 in port_set:
            return "Windows (low confidence)", "low"
        if 22 in port_set and 445 not in port_set:
            return "Linux/Unix (low confidence)", "low"
        if ttl is not None:
            if ttl >= 128:
                return "Windows (low confidence)", "low"
            if ttl >= 64:
                return "Linux/Unix (low confidence)", "low"
        return "Unknown", "Unknown"

    def _is_fileserver(self, ports: List[Dict[str, Any]], netbios_name: str) -> bool:
        port_set = {p.get("port") for p in ports}
        return 445 in port_set and netbios_name not in ["", "Unknown"]

    def _resolve_ipv6(self, host: str) -> str:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET6)
            if infos:
                return infos[0][4][0]
        except Exception:
            return "Not Advertised"
        return "Not Advertised"

    def _get_network_context(self) -> dict:
        try:
            token = os.getenv("IPINFO_API_KEY", "").strip()
            url = "https://ipinfo.io/json"
            if token:
                url = f"https://ipinfo.io/json?token={token}"
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "public_ip": data.get("ip", "Unknown"),
                    "isp": data.get("org", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                }
        except Exception:
            pass
        return {"public_ip": "Unknown", "isp": "Unknown", "city": "Unknown", "region": "Unknown", "country": "Unknown"}

    def _parse_arp_table(self, network: ipaddress.IPv4Network, local_ip: str | None) -> dict[str, str]:
        """Parse OS arp table and collect IP->MAC in the given network."""
        hosts: dict[str, str] = {}
        try:
            output = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, text=True)
        except Exception:
            return hosts
        # Regex for IPv4 and MAC (handles ":" or "-")
        pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{17})")
        for line in output.splitlines():
            match = pattern.search(line)
            if not match:
                continue
            ip_str, mac = match.group(1), match.group(2)
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip_obj not in network:
                continue
            if local_ip and ip_str == local_ip:
                continue
            hosts[ip_str] = mac.replace("-", ":").lower()
        return hosts

    def _get_local_ip(self) -> str | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip_addr = sock.getsockname()[0]
            sock.close()
            return ip_addr
        except Exception:
            return None

    def _is_windows(self) -> bool:
        return sys.platform.startswith("win")
