"""
gRPC Example for mTLS authentication.

This example demonstrates how to use the mTLS authentication library
to create a gRPC server and client with IP whitelisting.
Uses gRPC health checking service for demonstration.
"""

import logging
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

def run_grpc_server():
    """Run a gRPC server with mTLS and IP whitelisting."""
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
    
    # Create gRPC server
    from mtls_auth.adapters.grpc_adapter import GRPCAdapter
    adapter = GRPCAdapter(validator)
    server = adapter.create_server(bind_address="127.0.0.1", port=50051)
    
    # Try to use health service if available
    try:
        from grpc_health.v1 import health
        from grpc_health.v1 import health_pb2_grpc
        
        # Create health servicer
        health_servicer = health.HealthServicer()
        
        def add_services(grpc_server):
            health_pb2_grpc.add_HealthServicer_to_server(health_servicer, grpc_server)
            # Set serving status
            health_servicer.set("", health_pb2_grpc.HealthServicer.SERVING)
        
        logger.info("Starting gRPC server with health service on 127.0.0.1:50051")
        server.start(add_services)
        
    except ImportError:
        logger.warning("grpc_health package not installed. Using dummy service.")
        logger.info("To install: pip install grpcio-health-checking")
        
        # Create a dummy service
        import grpc
        from concurrent import futures
        
        class DummyServicer:
            pass
        
        def add_services(grpc_server):
            # Add a generic handler that will accept any method but return unimplemented
            pass
        
        server.start(add_services)
    
    return server

def run_grpc_client():
    """Run a gRPC client that connects to the server."""
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
    
    # Create gRPC client
    from mtls_auth.adapters.grpc_adapter import GRPCAdapter
    adapter = GRPCAdapter(validator)
    client = adapter.create_client(target="127.0.0.1:50051")
    
    logger.info("Creating gRPC channel to 127.0.0.1:50051")
    channel = client.create_channel()
    
    # Try to use health service if available
    try:
        from grpc_health.v1 import health_pb2
        from grpc_health.v1 import health_pb2_grpc
        
        health_stub = health_pb2_grpc.HealthStub(channel)
        request = health_pb2.HealthCheckRequest(service="")
        
        logger.info("Making health check request")
        response = health_stub.Check(request, timeout=5)
        logger.info(f"Health check response: {response.status}")
        
    except ImportError:
        logger.warning("grpc_health package not installed. Skipping health check.")
    except Exception as e:
        logger.error(f"Health check failed: {e}")
    
    client.close()
    return client

def main():
    """Main function to run the example."""
    logger.info("=== mTLS gRPC Example ===")
    
    try:
        # Start server
        server = run_grpc_server()
        
        # Give server time to start
        time.sleep(2)
        
        # Run client
        client = run_grpc_client()
        
        # Keep server running for a bit
        time.sleep(5)
        
        # Stop server
        server.stop()
        
        logger.info("Example completed successfully")
        
    except Exception as e:
        logger.error(f"Example failed: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
