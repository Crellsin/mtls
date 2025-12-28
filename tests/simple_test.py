"""
Simple test for mTLS authentication using raw TCP adapter.

This test avoids HTTP server issues by using raw TCP sockets.
"""

import logging
import time
import threading
import socket
import ssl
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from mtls_auth.core.connection_validator import ConnectionValidator
from mtls_auth.adapters.raw_tcp_adapter import RawTCPAdapter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_valid_connection():
    """Test valid connection with correct certificates and whitelisted IP."""
    logger.info("=== Test 1: Valid Connection ===")
    
    # Server configuration
    server_validator = ConnectionValidator.create_for_server(
        cert_path=Path("mtls_auth/certs/server/server.pem"),
        key_path=Path("mtls_auth/certs/server/server.key"),
        ca_cert_path=Path("mtls_auth/certs/ca/root-ca.crt"),
        client_ipv4_whitelist=["127.0.0.1"],
        client_ipv6_whitelist=[]
    )
    
    # Client configuration
    client_validator = ConnectionValidator.create_for_client(
        cert_path=Path("mtls_auth/certs/client/client.pem"),
        key_path=Path("mtls_auth/certs/client/client.key"),
        ca_cert_path=Path("mtls_auth/certs/ca/root-ca.crt"),
        server_ipv4_whitelist=["127.0.0.1"]
    )
    
    # Create server
    server_adapter = RawTCPAdapter(server_validator)
    server = server_adapter.create_server(bind_address="127.0.0.1", port=0)  # Use random port
    
    # Start server in background thread
    def handle_client(sock, client_ip):
        try:
            data = sock.recv(1024)
            sock.sendall(b"Hello from server")
        except:
            pass
        finally:
            sock.close()
    
    server_thread = threading.Thread(target=server.start, args=(handle_client, 1))
    server_thread.daemon = True
    server_thread.start()
    
    # Get the actual port the server is listening on
    time.sleep(0.5)
    server_port = server.listener.server_socket.getsockname()[1]
    
    # Create client and connect
    client_adapter = RawTCPAdapter(client_validator)
    try:
        client = client_adapter.create_client(
            host="127.0.0.1",
            port=server_port,
            validate_server_ip=True
        )
        
        client.send_all(b"Hello from client")
        response = client.receive(1024)
        
        if response == b"Hello from server":
            logger.info("✓ Valid connection test PASSED")
            return True
        else:
            logger.error(f"✗ Valid connection test FAILED: Unexpected response: {response}")
            return False
            
    except Exception as e:
        logger.error(f"✗ Valid connection test FAILED: {e}")
        return False
    finally:
        server.stop()
        server_thread.join(timeout=2)

def test_blocked_ip():
    """Test connection blocked due to IP not in whitelist."""
    logger.info("=== Test 2: Blocked IP ===")
    
    # Server configuration - only allow 192.168.1.100, not 127.0.0.1
    server_validator = ConnectionValidator.create_for_server(
        cert_path=Path("mtls_auth/certs/server/server.pem"),
        key_path=Path("mtls_auth/certs/server/server.key"),
        ca_cert_path=Path("mtls_auth/certs/ca/root-ca.crt"),
        client_ipv4_whitelist=["192.168.1.100"],  # Only allow this IP
        client_ipv6_whitelist=[]
    )
    
    # Client configuration
    client_validator = ConnectionValidator.create_for_client(
        cert_path=Path("mtls_auth/certs/client/client.pem"),
        key_path=Path("mtls_auth/certs/client/client.key"),
        ca_cert_path=Path("mtls_auth/certs/ca/root-ca.crt")
    )
    
    # Create server
    server_adapter = RawTCPAdapter(server_validator)
    server = server_adapter.create_server(bind_address="127.0.0.1", port=0)
    
    def handle_client(sock, client_ip):
        sock.close()
    
    server_thread = threading.Thread(target=server.start, args=(handle_client, 1))
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(0.5)
    server_port = server.listener.server_socket.getsockname()[1]
    
    # Create client and try to connect
    client_adapter = RawTCPAdapter(client_validator)
    try:
        client = client_adapter.create_client(
            host="127.0.0.1",
            port=server_port,
            validate_server_ip=False
        )
        
        # If we get here, the test failed (connection should have been blocked)
        logger.error("✗ Blocked IP test FAILED: Connection was not blocked")
        return False
        
    except (ConnectionError, socket.error, ssl.SSLError) as e:
        if "not in whitelist" in str(e) or "Connection refused" in str(e) or "EOF occurred in violation of protocol" in str(e):
            logger.info("✓ Blocked IP test PASSED: Connection correctly blocked")
            return True
        else:
            logger.error(f"✗ Blocked IP test FAILED with unexpected error: {e}")
            return False
    except Exception as e:
        logger.error(f"✗ Blocked IP test FAILED: {e}")
        return False
    finally:
        server.stop()
        server_thread.join(timeout=2)

def test_ipv6_whitelist_config():
    """Test IPv6 whitelist configuration (not connectivity)."""
    logger.info("=== Test 3: IPv6 Whitelist Configuration ===")
    
    validator = ConnectionValidator.create_for_server(
        cert_path=Path("mtls_auth/certs/server/server.pem"),
        key_path=Path("mtls_auth/certs/server/server.key"),
        ca_cert_path=Path("mtls_auth/certs/ca/root-ca.crt"),
        client_ipv6_whitelist=["2001:db8::/32", "fd00::/8", "::1"]
    )
    
    if validator.ip_validator and len(validator.ip_validator.get_ipv6_whitelist()) > 0:
        logger.info("✓ IPv6 whitelist test PASSED: Validator created with IPv6 networks")
        return True
    else:
        logger.error("✗ IPv6 whitelist test FAILED: No IPv6 networks in validator")
        return False

def main():
    """Run all tests."""
    results = []
    
    # Test 1: Valid connection
    results.append(("Valid Connection", test_valid_connection()))
    
    # Test 2: Blocked IP
    results.append(("Blocked IP", test_blocked_ip()))
    
    # Test 3: IPv6 whitelist configuration
    results.append(("IPv6 Whitelist Config", test_ipv6_whitelist_config()))
    
    # Summary
    logger.info("\n=== Test Summary ===")
    passed = 0
    total = len(results)
    
    for name, result in results:
        status = "PASS" if result else "FAIL"
        if result:
            passed += 1
        logger.info(f"{name}: {status}")
    
    logger.info(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("\n✓ All tests passed!")
        return 0
    else:
        logger.error("\n✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    exit(main())
