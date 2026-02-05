import ipaddress
import socket
import subprocess
import re
from datetime import datetime
from typing import Dict, Any, List
import nmap


class DeviceInspector:
    def get_device_info(self, ip: str, cached: Dict[str, Any] | None = None, network_context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "ip": ip,
            "ipv4": ip,
            "ipv6": cached.get("ipv6") if cached else self._resolve_ipv6(ip),
            "public_ip": "Unknown",
            "isp": "Unknown",
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "hostname": self._reverse_dns(ip) or "Unknown",
            "target_host": ip,
            "os_detected": "Unknown",
            "os_guess": cached.get("os_guess") if cached else "Unknown",
            "os_confidence": cached.get("os_confidence") if cached else "Unknown",
            "mac_address": "Unknown",
            "mac_vendor": "Unknown",
            "device_manufacturer": "Unknown",
            "manufacturer_address": "Unknown",
            "vendor_source": "IEEE OUI",
            "vendor_confidence": 0.0,
            "netbios_name": "Unknown",
            "netbios_domain": "Unknown",
            "fileserver": "Unknown",
            "first_seen": datetime.utcnow().isoformat(),
        }
        if cached:
            info["hostname"] = cached.get("hostname") or info["hostname"]
            info["mac_address"] = cached.get("mac") or info["mac_address"]
            info["mac_vendor"] = cached.get("mac_vendor") or info["mac_vendor"]
            info["device_manufacturer"] = cached.get("manufacturer") or info["device_manufacturer"]
            info["manufacturer_address"] = cached.get("manufacturer_address") or info["manufacturer_address"]
            info["vendor_source"] = cached.get("vendor_source") or info["vendor_source"]
            info["vendor_confidence"] = cached.get("vendor_confidence", info["vendor_confidence"])
            info["netbios_name"] = cached.get("netbios_name") or info["netbios_name"]
            info["netbios_domain"] = cached.get("netbios_domain") or info["netbios_domain"]
            info["fileserver"] = cached.get("fileserver") or info["fileserver"]
            info["device_type"] = cached.get("device_type") or "Unknown"
            info["open_ports"] = [p.get("port") for p in cached.get("ports", []) if isinstance(p, dict)]
        else:
            info["device_type"] = "Unknown"
            info["open_ports"] = []
        if network_context:
            info["public_ip"] = network_context.get("public_ip", info["public_ip"])
            info["isp"] = network_context.get("isp", info["isp"])
            info["city"] = network_context.get("city", info["city"])
            info["region"] = network_context.get("region", info["region"])
            info["country"] = network_context.get("country", info["country"])
        return info

    def ping_test(self, ip: str) -> Dict[str, Any]:
        result = {"min_ms": None, "max_ms": None, "avg_ms": None, "packet_loss": None}
        try:
            cmd = ["ping", "-n", "4", "-w", "500", ip] if self._is_windows() else ["ping", "-c", "4", "-W", "1", ip]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=3)
            # Windows
            m = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output)
            if m:
                result["min_ms"] = int(m.group(1))
                result["max_ms"] = int(m.group(2))
                result["avg_ms"] = int(m.group(3))
            m = re.search(r"Lost = \d+ \((\d+)% loss\)", output)
            if m:
                result["packet_loss"] = int(m.group(1))
            # Unix
            m = re.search(r"min/avg/max/.+ = ([\d\.]+)/([\d\.]+)/([\d\.]+)/", output)
            if m:
                result["min_ms"] = float(m.group(1))
                result["avg_ms"] = float(m.group(2))
                result["max_ms"] = float(m.group(3))
            m = re.search(r"(\d+)% packet loss", output)
            if m:
                result["packet_loss"] = int(m.group(1))
        except Exception:
            return result
        return result

    def scan_ports(self, ip: str) -> List[Dict[str, Any]]:
        ports: List[Dict[str, Any]] = []
        scanner = nmap.PortScanner()
        scanner.scan(hosts=ip, arguments="--top-ports 100 -T4 -Pn --host-timeout 15s")
        if ip not in scanner.all_hosts():
            return ports
        host_data = scanner[ip]
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

    def _reverse_dns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def _resolve_ipv6(self, ip: str) -> str:
        try:
            infos = socket.getaddrinfo(ip, None, socket.AF_INET6)
            if infos:
                return infos[0][4][0]
        except Exception:
            return ""
        return ""

    def _is_windows(self) -> bool:
        return subprocess.os.name == "nt"
