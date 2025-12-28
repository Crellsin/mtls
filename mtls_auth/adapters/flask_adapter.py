"""
Flask Adapter for mTLS authentication.

Provides Flask extension and decorators for mTLS and IP whitelisting.
This adapter integrates with Flask applications to provide mTLS support.
"""

import logging
from typing import Optional, Dict, Any, List, Callable
from pathlib import Path

try:
    from flask import Flask, request, jsonify, current_app, g
    from werkzeug.exceptions import Forbidden, Unauthorized
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    # Create dummy classes for type hints
    class Flask:
        pass
    class request:
        pass

from ..core.connection_validator import ConnectionValidator
from ..core.certificate_manager import CertificateManager

logger = logging.getLogger(__name__)


class MTLS:
    """Flask extension for mTLS and IP whitelisting."""
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize MTLS extension.
        
        Args:
            app: Optional Flask application instance
        """
        if not FLASK_AVAILABLE:
            raise ImportError("Flask is not installed. Install with: pip install flask")
        
        self.app = app
        self.validator = None
        self.cert_manager = None
        self.require_client_cert = True
        self.excluded_paths = []
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """
        Initialize the extension with a Flask application.
        
        Args:
            app: Flask application instance
        """
        # Load configuration from app config
        app.config.setdefault('MTLS_CERT_PATH', '')
        app.config.setdefault('MTLS_KEY_PATH', '')
        app.config.setdefault('MTLS_CA_CERT_PATH', '')
        app.config.setdefault('MTLS_CLIENT_IPV4_WHITELIST', [])
        app.config.setdefault('MTLS_CLIENT_IPV6_WHITELIST', [])
        app.config.setdefault('MTLS_REQUIRE_CLIENT_CERT', True)
        app.config.setdefault('MTLS_EXCLUDED_PATHS', [])
        
        # Create connection validator if certificates are configured
        if (app.config['MTLS_CERT_PATH'] and 
            app.config['MTLS_KEY_PATH'] and 
            app.config['MTLS_CA_CERT_PATH']):
            
            self.validator = ConnectionValidator.create_for_server(
                cert_path=Path(app.config['MTLS_CERT_PATH']),
                key_path=Path(app.config['MTLS_KEY_PATH']),
                ca_cert_path=Path(app.config['MTLS_CA_CERT_PATH']),
                client_ipv4_whitelist=app.config['MTLS_CLIENT_IPV4_WHITELIST'],
                client_ipv6_whitelist=app.config['MTLS_CLIENT_IPV6_WHITELIST'],
            )
            
            self.cert_manager = CertificateManager(
                cert_path=Path(app.config['MTLS_CERT_PATH']),
                key_path=Path(app.config['MTLS_KEY_PATH']),
                ca_cert_path=Path(app.config['MTLS_CA_CERT_PATH']),
            )
        
        self.require_client_cert = app.config['MTLS_REQUIRE_CLIENT_CERT']
        self.excluded_paths = app.config['MTLS_EXCLUDED_PATHS']
        
        # Register before_request handler
        @app.before_request
        def validate_mtls():
            self._validate_request()
        
        # Store extension on app
        app.extensions['mtls'] = self
    
    def _validate_request(self):
        """Validate mTLS for incoming request."""
        # Check if path is excluded
        if any(request.path.startswith(path) for path in self.excluded_paths):
            return
        
        # Get client IP
        client_ip = request.remote_addr
        
        # Validate IP if whitelist is configured
        if (client_ip and self.validator and self.validator.ip_validator and
            (self.validator.ip_validator.get_ipv4_whitelist() or 
             self.validator.ip_validator.get_ipv6_whitelist())):
            
            if not self.validator.ip_validator.is_allowed(client_ip):
                logger.warning(f"IP {client_ip} not in whitelist for path {request.path}")
                raise Forbidden(f"IP {client_ip} not authorized")
        
        # Get client certificate
        client_cert = self._extract_client_certificate()
        
        # Validate client certificate if required
        if self.require_client_cert:
            if not client_cert:
                logger.warning(f"No client certificate provided for {client_ip}")
                raise Unauthorized("Client certificate required")
            
            try:
                cert_info = self.cert_manager.get_certificate_info(client_cert)
                g.client_cert = cert_info
                g.client_cert_raw = client_cert
            except Exception as e:
                logger.error(f"Failed to validate client certificate: {e}")
                raise Unauthorized("Invalid client certificate")
        else:
            g.client_cert = client_cert
        
        # Store client IP in g
        g.client_ip = client_ip
    
    def _extract_client_certificate(self) -> Optional[bytes]:
        """
        Extract client certificate from request.
        
        Returns:
            Client certificate as bytes, or None if not found
        """
        # Try to get certificate from headers (common with reverse proxies)
        cert_header = request.headers.get("X-Client-Cert")
        if cert_header:
            import base64
            try:
                return base64.b64decode(cert_header)
            except:
                return cert_header.encode('utf-8')
        
        # Try to get from SSL info (if running directly with SSL)
        if request.environ.get('SSL_CLIENT_CERT'):
            return request.environ['SSL_CLIENT_CERT'].encode('utf-8') if isinstance(
                request.environ['SSL_CLIENT_CERT'], str) else request.environ['SSL_CLIENT_CERT']
        
        # Try to get from wsgi.ssl_client_cert
        if request.environ.get('wsgi.ssl_client_cert'):
            return request.environ['wsgi.ssl_client_cert'].encode('utf-8') if isinstance(
                request.environ['wsgi.ssl_client_cert'], str) else request.environ['wsgi.ssl_client_cert']
        
        return None
    
    @staticmethod
    def get_client_certificate() -> Optional[Dict[str, Any]]:
        """
        Get client certificate information from Flask's g object.
        
        Returns:
            Client certificate information, or None if not available
        """
        if not hasattr(g, 'client_cert'):
            return None
        return g.client_cert
    
    @staticmethod
    def get_client_ip() -> Optional[str]:
        """
        Get client IP address from Flask's g object.
        
        Returns:
            Client IP address, or None if not available
        """
        if not hasattr(g, 'client_ip'):
            return None
        return g.client_ip


class MTLSFlask(Flask):
    """Flask subclass with built-in mTLS support."""
    
    def __init__(self, *args, **kwargs):
        """
        Initialize MTLSFlask.
        
        Additional keyword arguments for mTLS configuration:
            mtls_cert_path: Path to server certificate
            mtls_key_path: Path to server private key
            mtls_ca_cert_path: Path to CA certificate
            mtls_client_ipv4_whitelist: List of allowed IPv4 addresses/networks
            mtls_client_ipv6_whitelist: List of allowed IPv6 addresses/networks
            mtls_require_client_cert: Whether to require client certificates (default: True)
            mtls_excluded_paths: List of path prefixes to exclude from mTLS validation
        """
        # Extract mTLS configuration from kwargs
        mtls_config = {
            'MTLS_CERT_PATH': kwargs.pop('mtls_cert_path', ''),
            'MTLS_KEY_PATH': kwargs.pop('mtls_key_path', ''),
            'MTLS_CA_CERT_PATH': kwargs.pop('mtls_ca_cert_path', ''),
            'MTLS_CLIENT_IPV4_WHITELIST': kwargs.pop('mtls_client_ipv4_whitelist', []),
            'MTLS_CLIENT_IPV6_WHITELIST': kwargs.pop('mtls_client_ipv6_whitelist', []),
            'MTLS_REQUIRE_CLIENT_CERT': kwargs.pop('mtls_require_client_cert', True),
            'MTLS_EXCLUDED_PATHS': kwargs.pop('mtls_excluded_paths', []),
        }
        
        super().__init__(*args, **kwargs)
        
        # Update app config with mTLS settings
        for key, value in mtls_config.items():
            self.config[key] = value
        
        # Initialize MTLS extension
        self.mtls = MTLS(self)


def require_client_cert(f: Callable) -> Callable:
    """
    Decorator for Flask routes that require a client certificate.
    
    Args:
        f: Flask route function
        
    Returns:
        Decorated function
    """
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_cert = MTLS.get_client_certificate()
        if not client_cert:
            raise Unauthorized("Client certificate required")
        return f(*args, **kwargs)
    
    return decorated_function


def get_flask_client_certificate() -> Optional[Dict[str, Any]]:
    """Alias for MTLS.get_client_certificate."""
    return MTLS.get_client_certificate()


def get_flask_client_ip() -> Optional[str]:
    """Alias for MTLS.get_client_ip."""
    return MTLS.get_client_ip()


class FlaskAdapter:
    """Adapter for Flask applications with mTLS support."""
    
    def __init__(self, connection_validator: ConnectionValidator):
        """
        Initialize FlaskAdapter.
        
        Args:
            connection_validator: ConnectionValidator instance
        """
        if not FLASK_AVAILABLE:
            raise ImportError("Flask is not installed. Install with: pip install flask")
        
        self.validator = connection_validator
    
    def create_app(self, 
                   import_name: str,
                   cert_path: str,
                   key_path: str,
                   ca_cert_path: str,
                   client_ipv4_whitelist: Optional[List[str]] = None,
                   client_ipv6_whitelist: Optional[List[str]] = None,
                   require_client_cert: bool = True,
                   excluded_paths: Optional[List[str]] = None,
                   **kwargs) -> MTLSFlask:
        """
        Create a Flask application with mTLS support.
        
        Args:
            import_name: The name of the application package
            cert_path: Path to server certificate
            key_path: Path to server private key
            ca_cert_path: Path to CA certificate
            client_ipv4_whitelist: List of allowed IPv4 addresses/networks
            client_ipv6_whitelist: List of allowed IPv6 addresses/networks
            require_client_cert: Whether to require client certificates
            excluded_paths: List of path prefixes to exclude from mTLS validation
            **kwargs: Additional keyword arguments for Flask
            
        Returns:
            MTLSFlask application instance
        """
        return MTLSFlask(
            import_name,
            mtls_cert_path=cert_path,
            mtls_key_path=key_path,
            mtls_ca_cert_path=ca_cert_path,
            mtls_client_ipv4_whitelist=client_ipv4_whitelist or [],
            mtls_client_ipv6_whitelist=client_ipv6_whitelist or [],
            mtls_require_client_cert=require_client_cert,
            mtls_excluded_paths=excluded_paths or [],
            **kwargs
        )
    
    @staticmethod
    def add_to_app(app: Flask,
                   cert_path: str,
                   key_path: str,
                   ca_cert_path: str,
                   client_ipv4_whitelist: Optional[List[str]] = None,
                   client_ipv6_whitelist: Optional[List[str]] = None,
                   require_client_cert: bool = True,
                   excluded_paths: Optional[List[str]] = None) -> None:
        """
        Add mTLS support to an existing Flask app.
        
        Args:
            app: Flask application
            cert_path: Path to server certificate
            key_path: Path to server private key
            ca_cert_path: Path to CA certificate
            client_ipv4_whitelist: List of allowed IPv4 addresses/networks
            client_ipv6_whitelist: List of allowed IPv6 addresses/networks
            require_client_cert: Whether to require client certificates
            excluded_paths: List of path prefixes to exclude from mTLS validation
        """
        # Update app config
        app.config['MTLS_CERT_PATH'] = cert_path
        app.config['MTLS_KEY_PATH'] = key_path
        app.config['MTLS_CA_CERT_PATH'] = ca_cert_path
        app.config['MTLS_CLIENT_IPV4_WHITELIST'] = client_ipv4_whitelist or []
        app.config['MTLS_CLIENT_IPV6_WHITELIST'] = client_ipv6_whitelist or []
        app.config['MTLS_REQUIRE_CLIENT_CERT'] = require_client_cert
        app.config['MTLS_EXCLUDED_PATHS'] = excluded_paths or []
        
        # Initialize MTLS extension
        MTLS(app)
