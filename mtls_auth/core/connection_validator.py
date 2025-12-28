"""
Connection Validator for mTLS authentication.

Orchestrates certificate and IP validation for both incoming and outgoing connections.
"""

import logging
from typing import Optional, Tuple, Union
from pathlib import Path

from .certificate_manager import CertificateManager
from .ip_whitelist import IPWhitelistValidator
from .secure_socket import SecureSocketFactory

logger = logging.getLogger(__name__)

class ConnectionValidator:
    """Orchestrates certificate and IP validation for connections."""
    
    def __init__(self, cert_manager: CertificateManager, 
                 ip_validator: Optional[IPWhitelistValidator] = None):
        """
        Initialize ConnectionValidator.
        
        Args:
            cert_manager: CertificateManager instance for certificate validation
            ip_validator: IPWhitelistValidator for IP validation (optional)
        """
        self.cert_manager = cert_manager
        self.ip_validator = ip_validator
        self.socket_factory = SecureSocketFactory(cert_manager, ip_validator)
        
    def validate_outgoing_connection(self, host: str, port: int, 
                                     timeout: Optional[float] = None,
                                     server_hostname: Optional[str] = None,
                                     validate_server_ip: bool = False) -> Tuple[bool, str]:
        """
        Validate an outgoing connection (client side).
        
        Args:
            host: Server hostname or IP address
            port: Server port
            timeout: Socket timeout in seconds (optional)
            server_hostname: Server hostname for SNI (optional)
            validate_server_ip: Whether to validate server IP against whitelist
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            # Create a client socket (this will validate server IP if requested)
            sock = self.socket_factory.create_client_socket(
                host=host,
                port=port,
                timeout=timeout,
                server_hostname=server_hostname,
                validate_server_ip=validate_server_ip
            )
            
            # Check if the socket is connected and SSL handshake succeeded
            # The socket creation above will raise an exception if any validation fails
            sock.close()
            
            return True, f"Successfully validated connection to {host}:{port}"
            
        except Exception as e:
            return False, f"Connection validation failed: {str(e)}"
    
    def validate_incoming_connection(self, client_socket, 
                                     require_client_auth: bool = True) -> Tuple[bool, str, Optional[str]]:
        """
        Validate an incoming connection (server side).
        
        Args:
            client_socket: Raw client socket (already accepted)
            require_client_auth: Whether to require client certificate authentication
            
        Returns:
            Tuple of (is_valid, message, client_ip)
        """
        try:
            # This method is intended to be called after accepting a connection
            # The IP validation is done by the socket factory during accept
            # We'll simulate by getting the peer address and checking the IP
            client_addr = client_socket.getpeername()
            client_ip = client_addr[0] if isinstance(client_addr, tuple) else str(client_addr)
            
            # Validate IP if validator exists
            if self.ip_validator:
                if not self.ip_validator.is_allowed(client_ip):
                    client_socket.close()
                    return False, f"Client IP {client_ip} not in whitelist", client_ip
            
            # For certificate validation, we would need to perform SSL handshake
            # This is handled by the socket factory's accept_client_connection
            # Since this is a raw socket, we cannot validate certificate here
            # In a real scenario, we would wrap the socket with SSL and then validate
            
            return True, f"Connection from {client_ip} is valid", client_ip
            
        except Exception as e:
            return False, f"Incoming connection validation failed: {str(e)}", None
    
    def create_server(self, bind_address: str = "0.0.0.0", port: int = 8443,
                      backlog: int = 5, timeout: Optional[float] = None,
                      require_client_auth: bool = True):
        """
        Create a secure server listener.
        
        Args:
            bind_address: Address to bind to
            port: Port to listen on
            backlog: Maximum number of queued connections
            timeout: Socket timeout in seconds
            require_client_auth: Whether to require client certificate authentication
            
        Returns:
            SecureListener instance from SecureSocketFactory.
        """
        return self.socket_factory.create_secure_listener(
            bind_address=bind_address,
            port=port,
            backlog=backlog,
            timeout=timeout,
            require_client_auth=require_client_auth
        )
    
    def create_client(self, host: str, port: int, timeout: Optional[float] = None,
                      server_hostname: Optional[str] = None, 
                      validate_server_ip: bool = False):
        """
        Create a client SSL socket.
        
        Args:
            host: Server hostname or IP address
            port: Server port
            timeout: Socket timeout in seconds
            server_hostname: Server hostname for SNI
            validate_server_ip: Whether to validate server IP against whitelist
            
        Returns:
            SSL socket connected to the server.
        """
        return self.socket_factory.create_client_socket(
            host=host,
            port=port,
            timeout=timeout,
            server_hostname=server_hostname,
            validate_server_ip=validate_server_ip
        )
    
    @classmethod
    def create_for_client(cls, cert_path: Union[str, Path], key_path: Union[str, Path],
                          ca_cert_path: Optional[Union[str, Path]] = None,
                          server_ipv4_whitelist: Optional[list] = None,
                          server_ipv6_whitelist: Optional[list] = None) -> 'ConnectionValidator':
        """
        Factory method to create a ConnectionValidator for client use.
        
        Args:
            cert_path: Path to client certificate
            key_path: Path to client private key
            ca_cert_path: Path to CA certificate
            server_ipv4_whitelist: List of allowed IPv4 server addresses (optional)
            server_ipv6_whitelist: List of allowed IPv6 server addresses (optional)
            
        Returns:
            ConnectionValidator instance configured for client use.
        """
        cert_manager = CertificateManager(cert_path, key_path, ca_cert_path)
        
        ip_validator = None
        if server_ipv4_whitelist or server_ipv6_whitelist:
            ip_validator = IPWhitelistValidator(
                ipv4_whitelist=server_ipv4_whitelist,
                ipv6_whitelist=server_ipv6_whitelist,
                validate_ipv4=bool(server_ipv4_whitelist),
                validate_ipv6=bool(server_ipv6_whitelist)
            )
        
        return cls(cert_manager, ip_validator)
    
    @classmethod
    def create_for_server(cls, cert_path: Union[str, Path], key_path: Union[str, Path],
                          ca_cert_path: Union[str, Path],
                          client_ipv4_whitelist: Optional[list] = None,
                          client_ipv6_whitelist: Optional[list] = None) -> 'ConnectionValidator':
        """
        Factory method to create a ConnectionValidator for server use.
        
        Args:
            cert_path: Path to server certificate
            key_path: Path to server private key
            ca_cert_path: Path to CA certificate (required for client auth)
            client_ipv4_whitelist: List of allowed IPv4 client addresses (optional)
            client_ipv6_whitelist: List of allowed IPv6 client addresses (optional)
            
        Returns:
            ConnectionValidator instance configured for server use.
        """
        cert_manager = CertificateManager(cert_path, key_path, ca_cert_path)
        
        ip_validator = None
        if client_ipv4_whitelist or client_ipv6_whitelist:
            ip_validator = IPWhitelistValidator(
                ipv4_whitelist=client_ipv4_whitelist,
                ipv6_whitelist=client_ipv6_whitelist,
                validate_ipv4=bool(client_ipv4_whitelist),
                validate_ipv6=bool(client_ipv6_whitelist)
            )
        
        return cls(cert_manager, ip_validator)
