import nmap
from app.models.schemas import ScanResult, ServiceInfo

class NmapScanner:
    def __init__(self):
        # Initialize the Nmap PortScanner
        self.nm = nmap.PortScanner()

    def scan(self, target: str, scan_type: str = "quick") -> ScanResult:
        """
        Executes the Nmap scan and parses the result.
        """
        print(f"[*] Starting {scan_type} scan on {target}...")
        
        # Define Nmap arguments based on scan type
        if scan_type == "quick":
            # -T4: Aggressive timing (faster)
            # -F: Fast mode (scans fewer ports)
            args = "-T4 -F"
        else:
            # -sV: Service Version Detection
            # -sC: Default scripts
            args = "-T4 -sV -sC"

        try:
            # Perform the scan
            self.nm.scan(hosts=target, arguments=args)
            
            # If target not found (down or blocked)
            if target not in self.nm.all_hosts():
                raise Exception("Host is down or unreachable.")

            host_data = self.nm[target]
            parsed_services = []

            # Loop through protocols (tcp/udp)
            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in sorted(ports):
                    service = host_data[proto][port]
                    
                    # Create a clean service object
                    s_info = ServiceInfo(
                        port=port,
                        protocol=proto,
                        service_name=service.get('name', 'unknown'),
                        state=service.get('state', 'unknown'),
                        version=service.get('version', '')
                    )
                    parsed_services.append(s_info)

            # Construct the final result
            return ScanResult(
                ip=target,
                hostname=host_data.hostname(),
                services=parsed_services,
                open_ports_count=len(parsed_services),
                os_detected=self._get_os(host_data)
            )

        except Exception as e:
            print(f"[!] Error scanning {target}: {str(e)}")
            raise e

    def _get_os(self, host_data):
        """Helper to safely extract OS name if available."""
        if 'osmatch' in host_data and host_data['osmatch']:
            return host_data['osmatch'][0]['name']
        return "Unknown"