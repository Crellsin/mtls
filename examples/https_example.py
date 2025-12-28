"""
HTTPS Example for mTLS authentication.

This example demonstrates how to use the mTLS authentication library
to create an HTTPS server and client with IP whitelisting.
"""

import logging
import json
import time
import threading
from pathlib import Path

# Add the parent directory to the path so we can import mtls_auth
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from mtls_auth.core.connection_validator import ConnectionValidator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_https_server():
    """Run an HTTPS server with mTLS and IP whitelisting."""
    # Paths to certificates
    certs_dir = Path("mtls_auth/certs")
    server_cert = certs_dir / "server" / "server.pem"
    server_key = certs_dir / "server" / "server.key"
    ca_cert = certs_dir / "ca" / "root-ca.crt"
    
    # Client IP whitelist (allow only localhost for this example)
    client_ipv4_whitelist = ["127.0.0.1", "192.168.1.0/24"]
    client_ipv6_whitelist = ["::1"]
    
    # Create connection validator for server
    validator = ConnectionValidator.create_for_server(
        cert_path=server_cert,
        key_path=server_key,
        ca_cert_path=ca_cert,
        client_ipv4_whitelist=client_ipv4_whitelist,
        client_ipv6_whitelist=client_ipv6_whitelist
    )
    
    # Create and start HTTP server
    from mtls_auth.adapters.http_adapter import HTTPAdapter
    adapter = HTTPAdapter(validator)
    server = adapter.create_server(bind_address="127.0.0.1", port=8443)
    
    logger.info("Starting HTTPS server on https://127.0.0.1:8443")
    logger.info(f"Client IP whitelist: IPv4: {client_ipv4_whitelist}, IPv6: {client_ipv6_whitelist}")
    
    # Start server in a thread
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    return server, server_thread

def run_https_client():
    """Run an HTTPS client that connects to the server."""
    # Paths to certificates
    certs_dir = Path("mtls_auth/certs")
    client_cert = certs_dir / "client" / "client.pem"
    client_key = certs_dir / "client" / "client.key"
    ca_cert = certs_dir / "ca" / "root-ca.crt"
    
    # Server IP whitelist (optional - can validate server IP)
    server_ipv4_whitelist = ["127.0.0.1", "192.168.1.0/24"]
    
    # Create connection validator for client
    validator = ConnectionValidator.create_for_client(
        cert_path=client_cert,
        key_path=client_key,
        ca_cert_path=ca_cert,
        server_ipv4_whitelist=server_ipv4_whitelist
    )
    
    # Create HTTP client
    from mtls_auth.adapters.http_adapter import HTTPAdapter
    adapter = HTTPAdapter(validator)
    client = adapter.create_client()
    
    # Make requests
    url = "https://127.0.0.1:8443/api/test"
    
    logger.info(f"Making GET request to {url}")
    try:
        response = client.request("GET", url, validate_server_ip=True)
        logger.info(f"Response status: {response['status_code']} {response['status_message']}")
        logger.info(f"Response body: {response['body']}")
    except Exception as e:
        logger.error(f"GET request failed: {e}")
    
    logger.info(f"Making POST request to {url}")
    try:
        data = {"message": "Hello from mTLS client", "timestamp": time.time()}
        response = client.request("POST", url, data=data, validate_server_ip=True)
        logger.info(f"Response status: {response['status_code']} {response['status_message']}")
        logger.info(f"Response body: {response['body']}")
    except Exception as e:
        logger.error(f"POST request failed: {e}")
    
    return client

def main():
    """Main function to run the example."""
    logger.info("=== mTLS HTTPS Example ===")
    
    try:
        # Start server
        server, server_thread = run_https_server()
        
        # Give server time to start
        time.sleep(2)
        
        # Run client
        client = run_https_client()
        
        # Keep server running for a bit
        time.sleep(5)
        
        # Stop server
        server.stop()
        server_thread.join(timeout=2)
        
        logger.info("Example completed successfully")
        
    except Exception as e:
        logger.error(f"Example failed: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
