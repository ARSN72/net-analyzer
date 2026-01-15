import os
import socket
import ipaddress
import shodan
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class ShodanIntel:
    def __init__(self):
        self.api_key = os.getenv("SHODAN_API_KEY")
        if not self.api_key:
            raise ValueError("No Shodan API Key found in .env file")
        self.api = shodan.Shodan(self.api_key)

    def get_ip_data(self, target: str):
        """
        Fetches public intelligence for a given IP.
        """
        resolved_ip = self._resolve_target(target)
        if not resolved_ip:
            return {
                "status": "error",
                "message": "Unable to resolve target hostname/IP."
            }

        if not self._is_public_ip(resolved_ip):
            return {
                "status": "error",
                "message": "Target is not a public IP. Shodan only tracks public hosts.",
                "resolved_ip": resolved_ip
            }

        print(f"[*] Fetching Shodan data for {resolved_ip}...")
        try:
            # The 'host' method returns all available data
            host_data = self.api.host(resolved_ip)
            
            return {
                "status": "found",
                "resolved_ip": resolved_ip,
                "isp": host_data.get('isp', 'Unknown'),
                "org": host_data.get('org', 'Unknown'),
                "country": host_data.get('country_name', 'Unknown'),
                "open_ports": host_data.get('ports', []),
                "vulns": list(host_data.get('vulns', [])), # List of CVE IDs
                "last_update": host_data.get('last_update', '')
            }
            
        except shodan.APIError as e:
            # Handle cases where IP is private or not indexed
            print(f"[!] Shodan error: {e}")
            return {
                "status": "error",
                "message": "IP not found in public database (might be private/local)."
            }

    def _resolve_target(self, target: str) -> str:
        """Return an IP string from a raw IP or hostname."""
        try:
            # Already an IP
            ipaddress.ip_address(target)
            return target
        except ValueError:
            # Not an IP, attempt DNS resolution
            try:
                return socket.gethostbyname(target)
            except socket.gaierror:
                return None

    def _is_public_ip(self, ip_str: str) -> bool:
        """Check if IP is public (not private/reserved/loopback)."""
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
