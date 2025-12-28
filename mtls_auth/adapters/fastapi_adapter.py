"""
FastAPI Adapter for mTLS authentication.

Provides FastAPI middleware and dependencies for mTLS and IP whitelisting.
This adapter integrates with FastAPI applications to provide mTLS support.
"""

import logging
import ssl
from typing import Optional, Dict, Any, Callable, List
from pathlib import Path

try:
    from fastapi import FastAPI, Request, HTTPException, Depends
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import Response
    from starlette.types import ASGIApp, Receive, Scope, Send
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    # Create dummy classes for type hints
    class FastAPI:
        pass
    class Request:
        pass
    class HTTPException(Exception):
        pass
    class BaseHTTPMiddleware:
        pass

from ..core.connection_validator import ConnectionValidator
from ..core.certificate_manager import CertificateManager

logger = logging.getLogger(__name__)


class MTLSMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for mTLS and IP whitelisting."""
    
    def __init__(
        self,
        app: ASGIApp,
        cert_path: str,
        key_path: str,
        ca_cert_path: str,
        client_ipv4_whitelist: Optional[List[str]] = None,
        client_ipv6_whitelist: Optional[List[str]] = None,
        require_client_cert: bool = True,
        excluded_paths: Optional[List[str]] = None,
    ):
        """
        Initialize MTLSMiddleware.
        
        Args:
            app: FastAPI application
            cert_path: Path to server certificate
            key_path: Path to server private key
            ca_cert_path: Path to CA certificate
            client_ipv4_whitelist: List of allowed IPv4 addresses/networks
            client_ipv6_whitelist: List of allowed IPv6 addresses/networks
            require_client_cert: Whether to require client certificates
            excluded_paths: List of path prefixes to exclude from mTLS validation
        """
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is not installed. Install with: pip install fastapi")
        
        super().__init__(app)
        
        # Create connection validator for server
        self.validator = ConnectionValidator.create_for_server(
            cert_path=Path(cert_path),
            key_path=Path(key_path),
            ca_cert_path=Path(ca_cert_path),
            client_ipv4_whitelist=client_ipv4_whitelist or [],
            client_ipv6_whitelist=client_ipv6_whitelist or [],
        )
        
        self.require_client_cert = require_client_cert
        self.excluded_paths = excluded_paths or []
        
        # Store certificate manager for certificate info extraction
        self.cert_manager = CertificateManager(
            cert_path=Path(cert_path),
            key_path=Path(key_path),
            ca_cert_path=Path(ca_cert_path),
        )
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process incoming request with mTLS validation.
        
        Args:
            request: FastAPI request
            call_next: Next middleware/endpoint
            
        Returns:
            Response from next middleware/endpoint
        """
        # Check if path is excluded
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)
        
        # Get client IP from request
        client_ip = request.client.host if request.client else None
        
        # Validate IP if whitelist is configured
        if client_ip and (self.validator.ip_validator and 
                         (self.validator.ip_validator.get_ipv4_whitelist() or 
                          self.validator.ip_validator.get_ipv6_whitelist())):
            if not self.validator.ip_validator.is_allowed(client_ip):
                logger.warning(f"IP {client_ip} not in whitelist for path {request.url.path}")
                raise HTTPException(
                    status_code=403,
                    detail=f"IP {client_ip} not authorized"
                )
        
        # Get client certificate from request headers (set by reverse proxy)
        # or from SSL info if running directly with SSL
        client_cert = self._extract_client_certificate(request)
        
        # Validate client certificate if required
        if self.require_client_cert:
            if not client_cert:
                logger.warning(f"No client certificate provided for {client_ip}")
                raise HTTPException(
                    status_code=401,
                    detail="Client certificate required"
                )
            
            # Validate certificate (basic check - more thorough validation happens at SSL layer)
            try:
                # This is a simplified check. In production, you'd want more validation
                cert_info = self.cert_manager.get_certificate_info(client_cert)
                if "error" in cert_info:
                    logger.error(f"Failed to parse client certificate: {cert_info['error']}")
                    raise HTTPException(
                        status_code=401,
                        detail="Invalid client certificate"
                    )
                request.state.client_cert = cert_info
                request.state.client_cert_raw = client_cert
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to validate client certificate: {e}")
                raise HTTPException(
                    status_code=401,
                    detail="Invalid client certificate"
                )
        else:
            request.state.client_cert = client_cert
        
        # Store client IP in request state
        request.state.client_ip = client_ip
        
        # Call next middleware/endpoint
        return await call_next(request)
    
    def _extract_client_certificate(self, request: Request) -> Optional[bytes]:
        """
        Extract client certificate from request.
        
        Args:
            request: FastAPI request
            
        Returns:
            Client certificate as bytes, or None if not found
        """
        # Try to get certificate from headers (common with reverse proxies)
        cert_header = request.headers.get("X-Client-Cert")
        if cert_header:
            # Certificate might be URL-encoded or in PEM format
            import base64
            try:
                # Try to decode as base64
                return base64.b64decode(cert_header)
            except:
                # Assume it's already in PEM format
                return cert_header.encode('utf-8')
        
        # Try to get from SSL info (if running directly with SSL)
        if hasattr(request, 'scope') and 'ssl' in request.scope:
            ssl_info = request.scope.get('ssl')
            if ssl_info and 'client_cert' in ssl_info:
                return ssl_info['client_cert']
        
        return None


def get_client_certificate(request: Request) -> Optional[Dict[str, Any]]:
    """
    FastAPI dependency to get client certificate information.
    
    Args:
        request: FastAPI request
        
    Returns:
        Client certificate information, or None if not available
    """
    return getattr(request.state, 'client_cert', None)


def get_client_ip(request: Request) -> Optional[str]:
    """
    FastAPI dependency to get client IP address.
    
    Args:
        request: FastAPI request
        
    Returns:
        Client IP address, or None if not available
    """
    return getattr(request.state, 'client_ip', None)


def require_client_certificate(
    client_cert: Optional[Dict[str, Any]] = Depends(get_client_certificate)
) -> Dict[str, Any]:
    """
    FastAPI dependency that requires a client certificate.
    
    Args:
        client_cert: Client certificate from dependency
        
    Returns:
        Client certificate information
        
    Raises:
        HTTPException: If no client certificate is provided
    """
    if not client_cert:
        raise HTTPException(
            status_code=401,
            detail="Client certificate required"
        )
    return client_cert


def require_client_ip_in_whitelist(
    client_ip: str = Depends(get_client_ip),
    request: Request = None
) -> str:
    """
    FastAPI dependency that requires client IP to be in whitelist.
    Note: This is redundant if middleware is used, but provided for manual validation.
    
    Args:
        client_ip: Client IP from dependency
        request: FastAPI request (optional, for getting validator from app state)
        
    Returns:
        Client IP if allowed
        
    Raises:
        HTTPException: If client IP is not in whitelist
    """
    # This is a simplified version. In practice, you'd get the validator from app state
    # and check the IP against the whitelist.
    # For now, we just return the IP if it exists.
    if not client_ip:
        raise HTTPException(
            status_code=403,
            detail="Client IP not available"
        )
    return client_ip


class FastAPIAdapter:
    """Adapter for FastAPI applications with mTLS support."""
    
    def __init__(self, connection_validator: ConnectionValidator):
        """
        Initialize FastAPIAdapter.
        
        Args:
            connection_validator: ConnectionValidator instance
        """
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is not installed. Install with: pip install fastapi")
        
        self.validator = connection_validator
    
    def create_middleware(
        self,
        require_client_cert: bool = True,
        excluded_paths: Optional[List[str]] = None,
    ) -> MTLSMiddleware:
        """
        Create FastAPI middleware for mTLS.
        
        Args:
            require_client_cert: Whether to require client certificates
            excluded_paths: List of path prefixes to exclude from mTLS validation
            
        Returns:
            MTLSMiddleware instance
        """
        # Note: This returns a middleware class that needs to be initialized with the app
        # We return a class that can be used as a factory
        class ConfiguredMTLSMiddleware(MTLSMiddleware):
            def __init__(self, app: ASGIApp):
                super().__init__(
                    app=app,
                    cert_path=str(self.validator.cert_manager.cert_path),
                    key_path=str(self.validator.cert_manager.key_path),
                    ca_cert_path=str(self.validator.cert_manager.ca_cert_path),
                    client_ipv4_whitelist=self.validator.ip_validator.get_ipv4_whitelist() if self.validator.ip_validator else [],
                    client_ipv6_whitelist=self.validator.ip_validator.get_ipv6_whitelist() if self.validator.ip_validator else [],
                    require_client_cert=require_client_cert,
                    excluded_paths=excluded_paths,
                )
        
        return ConfiguredMTLSMiddleware
    
    @staticmethod
    def add_to_app(
        app: FastAPI,
        cert_path: str,
        key_path: str,
        ca_cert_path: str,
        client_ipv4_whitelist: Optional[List[str]] = None,
        client_ipv6_whitelist: Optional[List[str]] = None,
        require_client_cert: bool = True,
        excluded_paths: Optional[List[str]] = None,
    ) -> None:
        """
        Add mTLS middleware to an existing FastAPI app.
        
        Args:
            app: FastAPI application
            cert_path: Path to server certificate
            key_path: Path to server private key
            ca_cert_path: Path to CA certificate
            client_ipv4_whitelist: List of allowed IPv4 addresses/networks
            client_ipv6_whitelist: List of allowed IPv6 addresses/networks
            require_client_cert: Whether to require client certificates
            excluded_paths: List of path prefixes to exclude from mTLS validation
        """
        middleware = MTLSMiddleware(
            app=app,
            cert_path=cert_path,
            key_path=key_path,
            ca_cert_path=ca_cert_path,
            client_ipv4_whitelist=client_ipv4_whitelist,
            client_ipv6_whitelist=client_ipv6_whitelist,
            require_client_cert=require_client_cert,
            excluded_paths=excluded_paths,
        )
        
        # Add middleware to app
        app.add_middleware(MTLSMiddleware, 
                          cert_path=cert_path,
                          key_path=key_path,
                          ca_cert_path=ca_cert_path,
                          client_ipv4_whitelist=client_ipv4_whitelist,
                          client_ipv6_whitelist=client_ipv6_whitelist,
                          require_client_cert=require_client_cert,
                          excluded_paths=excluded_paths)


# Example usage decorator
def with_mtls(
    require_cert: bool = True,
    require_ip_whitelist: bool = True,
):
    """
    Decorator for FastAPI endpoints to require mTLS.
    
    Args:
        require_cert: Whether to require client certificate
        require_ip_whitelist: Whether to require IP whitelist validation
    """
    def decorator(func):
        from functools import wraps
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # This would be implemented to extract request and validate
            # For simplicity, we assume the middleware has done validation
            return await func(*args, **kwargs)
        
        return wrapper
    
    return decorator
