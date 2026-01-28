import json
import nmap
import ipaddress
import socket
import subprocess
import re
import sys
import time
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.core.internal_analyzer import InternalRiskAnalyzer
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

    def scan_subnet(self, cidr: str) -> List[Dict[str, Any]]:
        """Synchronous scanning routine (run in worker thread)."""
        devices: List[Dict[str, Any]] = []

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

            # Phase 2: Enrichment per host (fast port scan)
            host_ports = port_results.get(host, []) if host in self._live_hosts else []

            vendor_raw = None
            hostname_raw = None
            if host in self.nm.all_hosts():
                vendor_raw = self._get_vendor(self.nm[host])
                hostname_raw = self._get_hostname(self.nm[host])
                mac = self._get_mac(self.nm[host]) or mac

            device = {
                "ip": host,
                "mac": mac,
                "vendor": vendor_raw or vendor,
                "hostname": hostname_raw or hostname,
                "ports": host_ports,
            }

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

        # Phase 2: Parse ARP table once
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

    def _probe_ip(self, ip: str) -> bool:
        """Send a quick ping and TCP probe to populate ARP. Returns True if reachable."""
        reachable = False
        # ICMP ping
        try:
            ping_cmd = ["ping", "-n", "1", "-w", "200", ip] if self._is_windows() else ["ping", "-c", "1", "-W", "1", ip]
            result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.5)
            if result.returncode == 0:
                reachable = True
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
        return reachable

    def _probe_hosts_parallel(self, hosts: List[str]) -> List[str]:
        """Probe hosts concurrently with short timeouts."""
        live: List[str] = []
        with ThreadPoolExecutor(max_workers=64) as executor:
            futures = {executor.submit(self._probe_ip, ip): ip for ip in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    if fut.result():
                        live.append(ip)
                except Exception:
                    continue
        return live

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
