import socket
import ipaddress


def get_local_subnet() -> str:
    """
    Attempt to derive the local /24 subnet from the primary IP address.
    If detection fails, default to 192.168.1.0/24.
    """
    default_subnet = "192.168.1.0/24"
    try:
        # Get primary IP by connecting to a public resolver (no traffic sent)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()

        # Assume /24 boundary and compute network
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception:
        return default_subnet
