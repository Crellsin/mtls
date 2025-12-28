#!/usr/bin/env python3
"""
Standalone FastAPI Server with mTLS and IP whitelisting.

This server runs independently with a single endpoint.
"""

import logging
import asyncio
import uvicorn
import sys
import ssl
from pathlib import Path

# Add the parent directory to the path so we can import mtls_auth
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Request, HTTPException
from mtls_auth.adapters.fastapi_adapter import MTLSMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Certificate paths (relative to project root)
CERTS_DIR = Path("mtls_auth/certs")
SERVER_CERT = CERTS_DIR / "server" / "server.pem"
SERVER_KEY = CERTS_DIR / "server" / "server.key"
CA_CERT = CERTS_DIR / "ca" / "root-ca.crt"

# IP whitelist (allow localhost and private networks)
CLIENT_IPV4_WHITELIST = ["127.0.0.1", "192.168.1.0/24", "10.0.0.0/8"]
CLIENT_IPV6_WHITELIST = ["::1"]

# Server configuration
HOST = "127.0.0.1"
PORT = 8443

def create_app() -> FastAPI:
    """Create and configure FastAPI application with mTLS middleware."""
    app = FastAPI(
        title="Standalone mTLS FastAPI Server",
        description="A standalone server with mTLS authentication and IP whitelisting",
        version="1.0.0"
    )

    # Add mTLS middleware
    app.add_middleware(
        MTLSMiddleware,
        cert_path=str(SERVER_CERT),
        key_path=str(SERVER_KEY),
        ca_cert_path=str(CA_CERT),
        client_ipv4_whitelist=CLIENT_IPV4_WHITELIST,
        client_ipv6_whitelist=CLIENT_IPV6_WHITELIST,
        require_client_cert=True,
        excluded_paths=["/health"]  # Health endpoint doesn't require mTLS
    )

    @app.get("/")
    async def root():
        """Root endpoint - returns server information."""
        return {
            "server": "Standalone mTLS FastAPI Server",
            "version": "1.0.0",
            "status": "running",
            "mtls_enabled": True,
            "ip_whitelist": {
                "ipv4": CLIENT_IPV4_WHITELIST,
                "ipv6": CLIENT_IPV6_WHITELIST
            }
        }

    @app.get("/api/data")
    async def get_data(request: Request):
        """
        Single data endpoint that returns client information.
        
        This endpoint demonstrates extracting client certificate and IP information
        from the request state (set by the MTLSMiddleware).
        """
        # Get client information from request state
        client_ip = getattr(request.state, 'client_ip', 'unknown')
        client_cert = getattr(request.state, 'client_cert', None)
        
        # Extract certificate info if available
        cert_info = None
        if client_cert:
            cert_info = {
                "subject": client_cert.get("subject", {}),
                "issuer": client_cert.get("issuer", {}),
                "valid_from": client_cert.get("valid_from"),
                "valid_to": client_cert.get("valid_to"),
                "serial_number": client_cert.get("serial_number"),
            }
        
        return {
            "message": "Data from mTLS-protected endpoint",
            "client": {
                "ip": client_ip,
                "certificate": cert_info
            },
            "timestamp": asyncio.get_event_loop().time(),
            "endpoint": "/api/data"
        }

    @app.get("/health")
    async def health_check():
        """Health check endpoint (excluded from mTLS for monitoring)."""
        return {"status": "healthy", "service": "mtls-fastapi-server"}

    @app.post("/api/data")
    async def post_data(request: Request):
        """Accept POST data and echo back with client info."""
        client_ip = getattr(request.state, 'client_ip', 'unknown')
        
        try:
            data = await request.json()
        except:
            data = {"error": "No valid JSON provided"}
        
        return {
            "message": "Data received via POST",
            "client_ip": client_ip,
            "received_data": data,
            "timestamp": asyncio.get_event_loop().time()
        }

    return app

def main():
    """Main function to run the server."""
    logger.info("=" * 60)
    logger.info("Starting Standalone FastAPI Server with mTLS")
    logger.info(f"Host: {HOST}")
    logger.info(f"Port: {PORT}")
    logger.info(f"Server Certificate: {SERVER_CERT}")
    logger.info(f"CA Certificate: {CA_CERT}")
    logger.info(f"IPv4 Whitelist: {CLIENT_IPV4_WHITELIST}")
    logger.info(f"IPv6 Whitelist: {CLIENT_IPV6_WHITELIST}")
    logger.info("=" * 60)
    
    # Verify certificates exist
    if not SERVER_CERT.exists():
        logger.error(f"Server certificate not found: {SERVER_CERT}")
        logger.error("Please generate certificates first using generate_certs.sh")
        return 1
    
    if not SERVER_KEY.exists():
        logger.error(f"Server key not found: {SERVER_KEY}")
        return 1
    
    if not CA_CERT.exists():
        logger.error(f"CA certificate not found: {CA_CERT}")
        return 1
    
    # Create and run the application
    app = create_app()
    
    # Run server with mTLS configuration
    config = uvicorn.Config(
        app=app,
        host=HOST,
        port=PORT,
        ssl_certfile=str(SERVER_CERT),
        ssl_keyfile=str(SERVER_KEY),
        ssl_ca_certs=str(CA_CERT),
        ssl_cert_reqs=ssl.CERT_REQUIRED,  # require client certificate
        log_level="info"
    )
    
    server = uvicorn.Server(config)
    
    try:
        logger.info(f"Server starting on https://{HOST}:{PORT}")
        logger.info("Available endpoints:")
        logger.info("  GET  /               - Server information")
        logger.info("  GET  /api/data       - Main data endpoint (requires mTLS)")
        logger.info("  POST /api/data       - Submit data (requires mTLS)")
        logger.info("  GET  /health         - Health check (no mTLS required)")
        logger.info("\nPress Ctrl+C to stop the server")
        server.run()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
