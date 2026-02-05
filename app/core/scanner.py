import socket
import nmap
from app.models.schemas import ActiveScanResult, ServiceInfo


class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target: str, scan_type: str = "quick", scan_speed: str = "standard") -> ActiveScanResult:
        """
        Executes the Nmap scan and parses the result.
        """
        print(f"[*] Starting {scan_type} scan on {target}...")

        # Resolve hostname to IP early
        try:
            resolved_ip = socket.gethostbyname(target)
            print(f"[*] Resolved {target} to {resolved_ip}")
        except socket.gaierror:
            raise Exception(f"DNS Error: Could not resolve {target}")

        # Arguments
        speed = (scan_speed or "standard").lower()
        if speed == "fast":
            timing = "-T5 --max-retries 1 --host-timeout 20s"
        elif speed == "aggressive":
            timing = "-T4 --max-retries 2 --host-timeout 60s"
        else:
            timing = "-T4 --max-retries 1 --host-timeout 40s"

        if scan_type == "quick":
            args = f"{timing} -F -Pn -n"
        else:
            args = f"{timing} -sV --top-ports 200 -Pn -n"

        # Perform scan
        self.nm.scan(hosts=resolved_ip, arguments=args)

        # Fallback if empty
        if resolved_ip not in self.nm.all_hosts() or not self.nm[resolved_ip].all_protocols():
            fallback_args = "-T4 -sT --top-ports 500 -Pn -n --max-retries 1 --host-timeout 60s"
            print(f"[*] Primary scan empty, running fallback: {fallback_args}")
            self.nm.scan(hosts=resolved_ip, arguments=fallback_args)
            if resolved_ip not in self.nm.all_hosts() or not self.nm[resolved_ip].all_protocols():
                raise Exception("Host is down or unreachable.")

        host_data = self.nm[resolved_ip]
        parsed_services = []

        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()
            for port in sorted(ports):
                service = host_data[proto][port]
                s_info = ServiceInfo(
                    port=port,
                    protocol=proto,
                    service_name=service.get('name', 'unknown'),
                    state=service.get('state', 'unknown'),
                    version=service.get('version', '')
                )
                parsed_services.append(s_info)

        return ActiveScanResult(
            ip=resolved_ip,
            hostname=host_data.hostname(),
            services=parsed_services,
            open_ports_count=len(parsed_services),
            os_detected=self._get_os(host_data)
        )

    def _get_os(self, host_data):
        if 'osmatch' in host_data and host_data['osmatch']:
            return host_data['osmatch'][0].get('name', 'Unknown')
        return "Unknown"
