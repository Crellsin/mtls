"""
Django Adapter for mTLS authentication.

Provides Django middleware and utilities for mTLS and IP whitelisting.
This adapter integrates with Django applications to provide mTLS support.
"""

import logging
from typing import Optional, Dict, Any, List, Callable
from pathlib import Path

try:
    from django.conf import settings
    from django.http import HttpRequest, HttpResponse, JsonResponse
    from django.core.exceptions import PermissionDenied
    from django.utils.deprecation import MiddlewareMixin
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False
    # Create dummy classes for type hints
    class HttpRequest:
        pass
    class HttpResponse:
        pass
    class MiddlewareMixin:
        pass
    class PermissionDenied(Exception):
        pass

from ..core.connection_validator import ConnectionValidator
from ..core.certificate_manager import CertificateManager

logger = logging.getLogger(__name__)


class MTLSMiddleware(MiddlewareMixin):
    """Django middleware for mTLS and IP whitelisting."""
    
    def __init__(self, get_response: Callable):
        """
        Initialize MTLSMiddleware.
        
        Args:
            get_response: Django get_response callable
        """
        if not DJANGO_AVAILABLE:
            raise ImportError("Django is not installed. Install with: pip install django")
        
        self.get_response = get_response
        
        # Load configuration from Django settings
        self.cert_path = getattr(settings, 'MTLS_CERT_PATH', '')
        self.key_path = getattr(settings, 'MTLS_KEY_PATH', '')
        self.ca_cert_path = getattr(settings, 'MTLS_CA_CERT_PATH', '')
        self.client_ipv4_whitelist = getattr(settings, 'MTLS_CLIENT_IPV4_WHITELIST', [])
        self.client_ipv6_whitelist = getattr(settings, 'MTLS_CLIENT_IPV6_WHITELIST', [])
        self.require_client_cert = getattr(settings, 'MTLS_REQUIRE_CLIENT_CERT', True)
        self.excluded_paths = getattr(settings, 'MTLS_EXCLUDED_PATHS', [])
        
        # Create connection validator if certificates are configured
        self.validator = None
        self.cert_manager = None
        
        if self.cert_path and self.key_path and self.ca_cert_path:
            self.validator = ConnectionValidator.create_for_server(
                cert_path=Path(self.cert_path),
                key_path=Path(self.key_path),
                ca_cert_path=Path(self.ca_cert_path),
                client_ipv4_whitelist=self.client_ipv4_whitelist,
                client_ipv6_whitelist=self.client_ipv6_whitelist,
            )
            
            self.cert_manager = CertificateManager(
                cert_path=Path(self.cert_path),
                key_path=Path(self.key_path),
                ca_cert_path=Path(self.ca_cert_path),
            )
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        """
        Process request with mTLS validation.
        
        Args:
            request: Django HttpRequest
            
        Returns:
            Django HttpResponse
        """
        # Check if path is excluded
        if any(request.path.startswith(path) for path in self.excluded_paths):
            return self.get_response(request)
        
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Validate IP if whitelist is configured
        if (client_ip and self.validator and self.validator.ip_validator and
            (self.validator.ip_validator.get_ipv4_whitelist() or 
             self.validator.ip_validator.get_ipv6_whitelist())):
            
            if not self.validator.ip_validator.is_allowed(client_ip):
                logger.warning(f"IP {client_ip} not in whitelist for path {request.path}")
                raise PermissionDenied(f"IP {client_ip} not authorized")
        
        # Get client certificate
        client_cert = self._extract_client_certificate(request)
        
        # Validate client certificate if required
        if self.require_client_cert:
            if not client_cert:
                logger.warning(f"No client certificate provided for {client_ip}")
                raise PermissionDenied("Client certificate required")
            
            try:
                cert_info = self.cert_manager.get_certificate_info(client_cert)
                request.mtls_client_cert = cert_info
                request.mtls_client_cert_raw = client_cert
            except Exception as e:
                logger.error(f"Failed to validate client certificate: {e}")
                raise PermissionDenied("Invalid client certificate")
        else:
            request.mtls_client_cert = client_cert
        
        # Store client IP in request
        request.mtls_client_ip = client_ip
        
        # Call next middleware/view
        return self.get_response(request)
    
    def _get_client_ip(self, request: HttpRequest) -> Optional[str]:
        """
        Extract client IP from request.
        
        Args:
            request: Django HttpRequest
            
        Returns:
            Client IP address, or None if not available
        """
        # Try common headers for proxy setups
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For can contain multiple IPs, the first one is the client
            return x_forwarded_for.split(',')[0].strip()
        
        # Fall back to REMOTE_ADDR
        return request.META.get('REMOTE_ADDR')
    
    def _extract_client_certificate(self, request: HttpRequest) -> Optional[bytes]:
        """
        Extract client certificate from request.
        
        Args:
            request: Django HttpRequest
            
        Returns:
            Client certificate as bytes, or None if not found
        """
        # Try to get certificate from headers (common with reverse proxies)
        cert_header = request.META.get('HTTP_X_CLIENT_CERT')
        if cert_header:
            import base64
            try:
                return base64.b64decode(cert_header)
            except:
                return cert_header.encode('utf-8')
        
        # Try to get from SSL info (if running directly with SSL)
        ssl_client_cert = request.META.get('SSL_CLIENT_CERT')
        if ssl_client_cert:
            return ssl_client_cert.encode('utf-8') if isinstance(
                ssl_client_cert, str) else ssl_client_cert
        
        # Try wsgi.ssl_client_cert
        wsgi_ssl_client_cert = request.META.get('wsgi.ssl_client_cert')
        if wsgi_ssl_client_cert:
            return wsgi_ssl_client_cert.encode('utf-8') if isinstance(
                wsgi_ssl_client_cert, str) else wsgi_ssl_client_cert
        
        return None


def require_client_cert(view_func: Callable) -> Callable:
    """
    Decorator for Django views that require a client certificate.
    
    Args:
        view_func: Django view function
        
    Returns:
        Decorated view function
    """
    from functools import wraps
    
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        client_cert = getattr(request, 'mtls_client_cert', None)
        if not client_cert:
            raise PermissionDenied("Client certificate required")
        return view_func(request, *args, **kwargs)
    
    return wrapper


def get_client_certificate(request: HttpRequest) -> Optional[Dict[str, Any]]:
    """
    Get client certificate information from request.
    
    Args:
        request: Django HttpRequest
        
    Returns:
        Client certificate information, or None if not available
    """
    return getattr(request, 'mtls_client_cert', None)


def get_client_ip(request: HttpRequest) -> Optional[str]:
    """
    Get client IP address from request.
    
    Args:
        request: Django HttpRequest
        
    Returns:
        Client IP address, or None if not available
    """
    return getattr(request, 'mtls_client_ip', None)


# Django settings configuration dictionary
mtls_settings = {
    'MTLS_CERT_PATH': '',
    'MTLS_KEY_PATH': '',
    'MTLS_CA_CERT_PATH': '',
    'MTLS_CLIENT_IPV4_WHITELIST': [],
    'MTLS_CLIENT_IPV6_WHITELIST': [],
    'MTLS_REQUIRE_CLIENT_CERT': True,
    'MTLS_EXCLUDED_PATHS': [],
}


class DjangoAdapter:
    """Adapter for Django applications with mTLS support."""
    
    def __init__(self, connection_validator: ConnectionValidator):
        """
        Initialize DjangoAdapter.
        
        Args:
            connection_validator: ConnectionValidator instance
        """
        if not DJANGO_AVAILABLE:
            raise ImportError("Django is not installed. Install with: pip install django")
        
        self.validator = connection_validator
    
    @staticmethod
    def configure_settings(
        cert_path: str,
        key_path: str,
        ca_cert_path: str,
        client_ipv4_whitelist: Optional[List[str]] = None,
        client_ipv6_whitelist: Optional[List[str]] = None,
        require_client_cert: bool = True,
        excluded_paths: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate Django settings dictionary for mTLS.
        
        Args:
            cert_path: Path to server certificate
            key_path: Path to server private key
            ca_cert_path: Path to CA certificate
            client_ipv4_whitelist: List of allowed IPv4 addresses/networks
            client_ipv6_whitelist: List of allowed IPv6 addresses/networks
            require_client_cert: Whether to require client certificates
            excluded_paths: List of path prefixes to exclude from mTLS validation
            
        Returns:
            Dictionary of settings to add to Django settings
        """

        return {
                    'MTLS_CERT_PATH': cert_path,
                    'MTLS_KEY_PATH': key_path,
                    'MTLS_CA_CERT_PATH': ca_cert_path,
                    'MTLS_CLIENT_IPV4_WHITELIST': client_ipv4_whitelist or [],
                    'MTLS_CLIENT_IPV6_WHITELIST': client_ipv6_whitelist or [],
                    'MTLS_REQUIRE_CLIENT_CERT': require_client_cert,
                    'MTLS_EXCLUDED_PATHS': excluded_paths or []
                }
