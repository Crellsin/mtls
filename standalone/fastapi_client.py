#!/usr/bin/env python3
"""
Standalone FastAPI Client with mTLS.

This client connects to the standalone FastAPI server using mTLS.
It demonstrates how to make authenticated requests with client certificates.
"""

import logging
import json
import sys
import ssl
from pathlib import Path

# Add the parent directory to the path so we can import mtls_auth
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from mtls_auth.core.connection_validator import ConnectionValidator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Certificate paths (relative to project root)
CERTS_DIR = Path("mtls_auth/certs")
CLIENT_CERT = CERTS_DIR / "client" / "client.pem"
CLIENT_KEY = CERTS_DIR / "client" / "client.key"
CA_CERT = CERTS_DIR / "ca" / "root-ca.crt"

# Server configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8443
BASE_URL = f"https://{SERVER_HOST}:{SERVER_PORT}"

# Main endpoint (the single endpoint we are testing)
MAIN_ENDPOINT = "/api/data"

def create_ssl_context() -> ssl.SSLContext:
    """Create SSL context for mTLS connection."""
    # Create SSL context
    ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=str(CA_CERT)
    )
    
    # Load client certificate and key
    ssl_context.load_cert_chain(
        certfile=str(CLIENT_CERT),
        keyfile=str(CLIENT_KEY)
    )
    
    # Require server certificate validation
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    
    # Optional: set minimum TLS version (TLS 1.2 or higher for security)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    return ssl_context

def create_connection_validator() -> ConnectionValidator:
    """Create connection validator for client-side validation."""
    # Server IP whitelist (optional - can validate server IP)
    server_ipv4_whitelist = ["127.0.0.1", "192.168.1.0/24"]
    
    # Create connection validator for client
    validator = ConnectionValidator.create_for_client(
        cert_path=CLIENT_CERT,
        key_path=CLIENT_KEY,
        ca_cert_path=CA_CERT,
        server_ipv4_whitelist=server_ipv4_whitelist
    )
    
    return validator

async def test_connection():
    """Test connection to the server and make requests."""
    # Verify certificates exist
    if not CLIENT_CERT.exists():
        logger.error(f"Client certificate not found: {CLIENT_CERT}")
        logger.error("Please generate certificates first using generate_certs.sh")
        return False
    
    if not CLIENT_KEY.exists():
        logger.error(f"Client key not found: {CLIENT_KEY}")
        return False
    
    if not CA_CERT.exists():
        logger.error(f"CA certificate not found: {CA_CERT}")
        return False
    
    # Read client certificate for header
    with open(CLIENT_CERT, 'r') as f:
        client_cert_pem = f.read()
    
    logger.info("=" * 60)
    logger.info("Standalone FastAPI Client with mTLS")
    logger.info(f"Connecting to: {BASE_URL}")
    logger.info(f"Client Certificate: {CLIENT_CERT}")
    logger.info(f"CA Certificate: {CA_CERT}")
    logger.info("=" * 60)
    
    # Create SSL context
    ssl_context = create_ssl_context()
    
    # Create async HTTP client with the SSL context
    async with httpx.AsyncClient(
        verify=ssl_context,
        timeout=30.0
    ) as client:
        
        # Prepare headers with client certificate
        import base64
        cert_b64 = base64.b64encode(client_cert_pem.encode('utf-8')).decode('utf-8')
        headers = {"X-Client-Cert": cert_b64}
        
        # Test 1: Health endpoint (should work without client cert requirement)
        try:
            logger.info(f"1. Testing health endpoint...")
            health_url = f"{BASE_URL}/health"
            response = await client.get(health_url)
            logger.info(f"   Health check: {response.status_code} {response.reason_phrase}")
            if response.status_code == 200:
                logger.info(f"   Response: {response.json()}")
            else:
                logger.error(f"   Unexpected response: {response.text}")
        except Exception as e:
            logger.error(f"   Health check failed: {e}")
            # Don't return False here, maybe health endpoint is not accessible
        
        # Test 2: Root endpoint (requires mTLS)
        try:
            logger.info(f"\n2. Testing root endpoint (requires mTLS)...")
            root_url = f"{BASE_URL}/"
            response = await client.get(root_url, headers=headers)
            logger.info(f"   Root endpoint: {response.status_code} {response.reason_phrase}")
            if response.status_code == 200:
                data = response.json()
                logger.info(f"   Server: {data.get('server')}")
                logger.info(f"   Version: {data.get('version')}")
                logger.info(f"   Status: {data.get('status')}")
            else:
                logger.error(f"   Unexpected response: {response.text}")
        except Exception as e:
            logger.error(f"   Root endpoint failed: {e}")
            return False
        
        # Test 3: Main data endpoint (GET) - the single endpoint
        try:
            logger.info(f"\n3. Testing main data endpoint (GET) {MAIN_ENDPOINT}...")
            data_url = f"{BASE_URL}{MAIN_ENDPOINT}"
            response = await client.get(data_url, headers=headers)
            logger.info(f"   Data endpoint: {response.status_code} {response.reason_phrase}")
            if response.status_code == 200:
                data = response.json()
                logger.info(f"   Message: {data.get('message')}")
                client_info = data.get('client', {})
                logger.info(f"   Client IP: {client_info.get('ip')}")
                if client_info.get('certificate'):
                    cert = client_info['certificate']
                    if isinstance(cert, dict):
                        subject = cert.get('subject', {})
                        common_name = subject.get('common_name', 'N/A')
                        logger.info(f"   Client certificate subject: {common_name}")
                    else:
                        logger.info(f"   Client certificate (type: {type(cert).__name__}): {str(cert)[:100]}")
                logger.info(f"   Full response: {json.dumps(data, indent=2)}")
            else:
                logger.error(f"   Unexpected response: {response.text}")
                return False
        except Exception as e:
            logger.error(f"   Data endpoint (GET) failed: {e}")
            return False
        
        # Test 4: Main data endpoint (POST) - submit data
        try:
            logger.info(f"\n4. Testing main data endpoint (POST) {MAIN_ENDPOINT}...")
            data_url = f"{BASE_URL}{MAIN_ENDPOINT}"
            post_data = {
                "message": "Hello from standalone client",
                "client": "fastapi_client.py",
                "action": "testing_mtls"
            }
            response = await client.post(data_url, json=post_data, headers=headers)
            logger.info(f"   POST to data endpoint: {response.status_code} {response.reason_phrase}")
            if response.status_code == 200:
                data = response.json()
                logger.info(f"   Message: {data.get('message')}")
                logger.info(f"   Client IP: {data.get('client_ip')}")
                logger.info(f"   Received data: {json.dumps(data.get('received_data', {}), indent=2)}")
            else:
                logger.error(f"   Unexpected response: {response.text}")
                return False
        except Exception as e:
            logger.error(f"   Data endpoint (POST) failed: {e}")
            return False
        
        logger.info("\n" + "=" * 60)
        logger.info("All tests completed successfully!")
        logger.info("=" * 60)
        
        return True

def main():
    """Main function to run the client."""
    import asyncio
    
    try:
        success = asyncio.run(test_connection())
        return 0 if success else 1
    except KeyboardInterrupt:
        logger.info("Client stopped by user")
        return 0
    except Exception as e:
        logger.error(f"Client error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    exit(main())
