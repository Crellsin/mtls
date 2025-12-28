"""
Test scenarios for mTLS authentication.

Tests various scenarios including:
1. Valid connections with proper certificates and whitelisted IPs
2. Blocked connections due to IP not in whitelist
3. Blocked connections due to invalid certificates
4. Mixed IPv4/IPv6 scenarios
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
from mtls_auth.adapters.http_adapter import HTTPAdapter

# Configure logging
logging.basicConfig(level=logging.WARNING)  # Reduce noise for tests
logger = logging.getLogger(__name__)

class TestScenarios:
    """Test scenarios for mTLS authentication."""
    
    def __init__(self):
        """Initialize test scenarios."""
        self.certs_dir = Path("mtls_auth/certs")
        
    def test_valid_https_connection(self):
        """Test valid HTTPS connection with correct certificates and whitelisted IP."""
        logger.info("=== Test 1: Valid HTTPS Connection ===")
        
        # Server configuration
        server_validator = ConnectionValidator.create_for_server(
            cert_path=self.certs_dir / "server" / "server.pem",
            key_path=self.certs_dir / "server" / "server.key",
            ca_cert_path=self.certs_dir / "ca" / "root-ca.crt",
            client_ipv4_whitelist=["127.0.0.1", "192.168.1.0/24"],
            client_ipv6_whitelist=["::1"]
        )
        
        # Client configuration
        client_validator = ConnectionValidator.create_for_client(
            cert_path=self.certs_dir / "client" / "client.pem",
            key_path=self.certs_dir / "client" / "client.key",
            ca_cert_path=self.certs_dir / "ca" / "root-ca.crt",
            server_ipv4_whitelist=["127.0.0.1"]
        )
        
        # Start server in background thread
        from mtls_auth.adapters.http_adapter import HTTPServer
        server = HTTPServer(server_validator, bind_address="127.0.0.1", port=8444)
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        time.sleep(2)  # Wait for server to start
        
        try:
            # Make request
            client = HTTPAdapter(client_validator).create_client()
            response = client.request("GET", "https://127.0.0.1:8444/", validate_server_ip=True)
            
            if response['status_code'] == 200:
                logger.info("✓ Valid HTTPS connection test PASSED")
                return True
            else:
                logger.error(f"✗ Valid HTTPS connection test FAILED: Status {response['status_code']}")
                return False
                
        except Exception as e:
            logger.error(f"✗ Valid HTTPS connection test FAILED: {e}")
            return False
        finally:
            server.stop()
            server_thread.join(timeout=2)
    
    def test_blocked_ip_https(self):
        """Test HTTPS connection blocked due to IP not in whitelist."""
        logger.info("=== Test 2: Blocked IP (HTTPS) ===")
        
        # Server configuration - only allow 192.168.1.100, not 127.0.0.1
        server_validator = ConnectionValidator.create_for_server(
            cert_path=self.certs_dir / "server" / "server.pem",
            key_path=self.certs_dir / "server" / "server.key",
            ca_cert_path=self.certs_dir / "ca" / "root-ca.crt",
            client_ipv4_whitelist=["192.168.1.100"],  # Only allow this IP
            client_ipv6_whitelist=[]
        )
        
        # Client configuration
        client_validator = ConnectionValidator.create_for_client(
            cert_path=self.certs_dir / "client" / "client.pem",
            key_path=self.certs_dir / "client" / "client.key",
            ca_cert_path=self.certs_dir / "ca" / "root-ca.crt"
        )
        
        # Start server
        from mtls_auth.adapters.http_adapter import HTTPServer
        server = HTTPServer(server_validator, bind_address="127.0.0.1", port=8445)
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        time.sleep(2)
        
        try:
            # This should fail because client IP (127.0.0.1) is not in whitelist
            client = HTTPAdapter(client_validator).create_client()
            response = client.request("GET", "https://127.0.0.1:8445/", validate_server_ip=False)
            
            # If we get here, the test failed (connection should have been blocked)
            logger.error(f"✗ Blocked IP test FAILED: Connection was not blocked")
            return False
            
        except (ConnectionError, socket.error, ssl.SSLError) as e:
            if "not in whitelist" in str(e) or "Connection refused" in str(e):
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
    
    def test_invalid_certificate(self):
        """Test connection blocked due to invalid certificate."""
        logger.info("=== Test 3: Invalid Certificate ===")
        
        # Create a self-signed certificate that won't be trusted by our CA
        import tempfile
        import subprocess
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file, \
             tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
            
            cert_path = cert_file.name
            key_path = key_file.name
            
            # Generate self-signed certificate
            subprocess.run([
                'openssl', 'req', '-new', '-x509', '-days', '1',
                '-keyout', key_path, '-out', cert_path,
                '-subj', '/CN=untrusted.example.com'
            ], check=True, capture_output=True)
        
        try:
            # Server with standard certificates
            server_validator = ConnectionValidator.create_for_server(
                cert_path=self.certs_dir / "server" / "server.pem",
                key_path=self.certs_dir / "server" / "server.key",
                ca_cert_path=self.certs_dir / "ca" / "root-ca.crt",
                client_ipv4_whitelist=["127.0.0.1"]
            )
            
            # Client with untrusted certificate
            client_validator = ConnectionValidator.create_for_client(
                cert_path=cert_path,
                key_path=key_path,
                ca_cert_path=self.certs_dir / "ca" / "root-ca.crt"
            )
            
            # Start server
            from mtls_auth.adapters.http_adapter import HTTPServer
            server = HTTPServer(server_validator, bind_address="127.0.0.1", port=8446)
            server_thread = threading.Thread(target=server.start, daemon=True)
            server_thread.start()
            time.sleep(2)
            
            try:
                # This should fail due to certificate validation
                client = HTTPAdapter(client_validator).create_client()
                response = client.request("GET", "https://127.0.0.1:8446/", validate_server_ip=False)
                
                logger.error("✗ Invalid certificate test FAILED: Connection was not blocked")
                return False
                
            except (ssl.SSLError, ConnectionError) as e:
                if "certificate" in str(e).lower() or "handshake" in str(e).lower():
                    logger.info("✓ Invalid certificate test PASSED: Connection correctly blocked")
                    return True
                else:
                    logger.error(f"✗ Invalid certificate test FAILED with unexpected error: {e}")
                    return False
            except Exception as e:
                logger.error(f"✗ Invalid certificate test FAILED: {e}")
                return False
            finally:
                server.stop()
                server_thread.join(timeout=2)
                
        finally:
            # Clean up temporary files
            import os
            if os.path.exists(cert_path):
                os.unlink(cert_path)
            if os.path.exists(key_path):
                os.unlink(key_path)
    
    def test_ipv6_whitelist(self):
        """Test IPv6 whitelist functionality."""
        logger.info("=== Test 4: IPv6 Whitelist ===")
        
        # This test is more conceptual since we're testing locally
        # In a real environment, you'd need IPv6 connectivity
        
        validator = ConnectionValidator.create_for_server(
            cert_path=self.certs_dir / "server" / "server.pem",
            key_path=self.certs_dir / "server" / "server.key",
            ca_cert_path=self.certs_dir / "ca" / "root-ca.crt",
            client_ipv6_whitelist=["2001:db8::/32", "fd00::/8", "::1"]
        )
        
        # Test that validator was created with IPv6 networks
        if validator.ip_validator and len(validator.ip_validator.get_ipv6_whitelist()) > 0:
            logger.info("✓ IPv6 whitelist test PASSED: Validator created with IPv6 networks")
            return True
        else:
            logger.error("✗ IPv6 whitelist test FAILED: No IPv6 networks in validator")
            return False
    
    def run_all_tests(self):
        """Run all test scenarios."""
        results = []
        
        # Test 1: Valid connection
        results.append(("Valid HTTPS Connection", self.test_valid_https_connection()))
        
        # Test 2: Blocked IP
        results.append(("Blocked IP", self.test_blocked_ip_https()))
        
        # Test 3: Invalid certificate
        results.append(("Invalid Certificate", self.test_invalid_certificate()))
        
        # Test 4: IPv6 whitelist
        results.append(("IPv6 Whitelist", self.test_ipv6_whitelist()))
        
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
        
        return passed == total

def main():
    """Main test runner."""
    # Enable info logging for summary
    logging.getLogger().setLevel(logging.INFO)
    
    test_scenarios = TestScenarios()
    
    if test_scenarios.run_all_tests():
        logger.info("\n✓ All tests passed!")
        return 0
    else:
        logger.error("\n✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    exit(main())
