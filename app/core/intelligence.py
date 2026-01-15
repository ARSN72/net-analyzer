import shodan
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class ShodanIntel:
    def __init__(self):
        self.api_key = os.getenv("SHODAN_API_KEY")
        if not self.api_key:
            raise ValueError("No Shodan API Key found in .env file")
        self.api = shodan.Shodan(self.api_key)

    def get_ip_data(self, ip: str):
        """
        Fetches public intelligence for a given IP.
        """
        print(f"[*] Fetching Shodan data for {ip}...")
        try:
            # The 'host' method returns all available data
            host_data = self.api.host(ip)
            
            return {
                "status": "found",
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