"""
Secure Socket Factory for mTLS authentication.

Creates SSL sockets with pre-connection IP validation for both client and server modes.
"""

import socket
import ssl
import logging
from typing import Optional, Tuple, Union
from pathlib import Path

from .certificate_manager import CertificateManager
from .ip_whitelist import IPWhitelistValidator

logger = logging.getLogger(__name__)

class SecureSocketFactory:
    """Factory for creating secure sockets with mTLS and IP whitelisting."""
    
    def __init__(self, cert_manager: CertificateManager, 
                 ip_validator: Optional[IPWhitelistValidator] = None):
        """
        Initialize SecureSocketFactory.
        
        Args:
            cert_manager: CertificateManager instance for SSL context
            ip_validator: IPWhitelistValidator for IP validation (optional)
        """
        self.cert_manager = cert_manager
        self.ip_validator = ip_validator
        
    def create_client_socket(self, host: str, port: int, 
                            timeout: Optional[float] = None,
                            server_hostname: Optional[str] = None,
                            validate_server_ip: bool = False) -> ssl.SSLSocket:
        """
        Create a client SSL socket with optional server IP validation.
        
        Args:
            host: Server hostname or IP address
            port: Server port
            timeout: Socket timeout in seconds (optional)
            server_hostname: Server hostname for SNI (optional, defaults to host)
            validate_server_ip: Whether to validate server IP against whitelist (if ip_validator provided)
            
        Returns:
            Connected SSL socket.
            
        Raises:
            ConnectionError: If connection fails or IP validation fails.
        """
        try:
            # Create raw socket
            raw_sock = socket.create_connection((host, port), timeout=timeout)
            
            # Validate server IP if requested and validator provided
            if validate_server_ip and self.ip_validator:
                if not self.ip_validator.is_allowed(host):
                    raw_sock.close()
                    raise ConnectionError(f"Server IP {host} not in whitelist")
            
            # Get SSL context for client
            ssl_context = self.cert_manager.get_client_ssl_context()
            
            # Create SSL socket
            server_hostname = server_hostname or host
            ssl_sock = ssl_context.wrap_socket(
                raw_sock,
                server_side=False,
                server_hostname=server_hostname
            )
            
            logger.info(f"Client SSL socket created for {host}:{port}")
            return ssl_sock
            
        except socket.error as e:
            logger.error(f"Failed to create client socket to {host}:{port}: {e}")
            raise ConnectionError(f"Connection to {host}:{port} failed: {e}")
    
    def create_server_socket(self, bind_address: str = "0.0.0.0", 
                            port: int = 8443,
                            backlog: int = 5,
                            timeout: Optional[float] = None,
                            require_client_auth: bool = True) -> socket.socket:
        """
        Create a server socket with SSL and IP validation support.
        
        Args:
            bind_address: Address to bind to (default: all interfaces)
            port: Port to listen on (default: 8443)
            backlog: Maximum number of queued connections
            timeout: Socket timeout in seconds (optional)
            require_client_auth: Whether to require client certificate authentication
            
        Returns:
            Listening server socket (not yet wrapped with SSL).
        """
        try:
            # Create server socket
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if timeout:
                server_sock.settimeout(timeout)
                
            server_sock.bind((bind_address, port))
            server_sock.listen(backlog)
            
            logger.info(f"Server socket listening on {bind_address}:{port}")
            return server_sock
            
        except socket.error as e:
            logger.error(f"Failed to create server socket on {bind_address}:{port}: {e}")
            raise
    
    def accept_client_connection(self, server_sock: socket.socket, 
                                require_client_auth: bool = True) -> Tuple[ssl.SSLSocket, Tuple[str, int]]:
        """
        Accept a client connection with IP validation and SSL wrapping.
        
        Args:
            server_sock: Listening server socket
            require_client_auth: Whether to require client certificate authentication
            
        Returns:
            Tuple of (SSL socket, (client_ip, client_port))
            
        Raises:
            ConnectionError: If IP validation fails or SSL handshake fails.
        """
        try:
            # Accept raw connection
            raw_sock, client_addr = server_sock.accept()
            client_ip, client_port = client_addr
            
            logger.debug(f"Connection from {client_ip}:{client_port}")
            
            # Validate client IP if validator provided
            if self.ip_validator:
                if not self.ip_validator.is_allowed(client_ip):
                    raw_sock.close()
                    raise ConnectionError(f"Client IP {client_ip} not in whitelist")
            
            # Get SSL context for server
            ssl_context = self.cert_manager.get_server_ssl_context(
                require_client_auth=require_client_auth
            )
            
            # Wrap with SSL
            try:
                ssl_sock = ssl_context.wrap_socket(
                    raw_sock,
                    server_side=True
                )
                
                # Verify client certificate if required
                if require_client_auth:
                    cert = ssl_sock.getpeercert()
                    if not cert:
                        ssl_sock.close()
                        raise ConnectionError("Client certificate not provided")
                    
                    logger.info(f"Client authenticated with certificate from {client_ip}")
                
                logger.info(f"SSL connection established with {client_ip}:{client_port}")
                return ssl_sock, (client_ip, client_port)
                
            except ssl.SSLError as e:
                raw_sock.close()
                logger.error(f"SSL handshake failed with {client_ip}:{client_port}: {e}")
                raise ConnectionError(f"SSL handshake failed: {e}")
                
        except socket.error as e:
            logger.error(f"Failed to accept connection: {e}")
            raise ConnectionError(f"Accept failed: {e}")
    
    def create_secure_listener(self, bind_address: str = "0.0.0.0", 
                              port: int = 8443,
                              backlog: int = 5,
                              timeout: Optional[float] = None,
                              require_client_auth: bool = True) -> 'SecureListener':
        """
        Create a secure listener that handles SSL and IP validation.
        
        Args:
            bind_address: Address to bind to
            port: Port to listen on
            backlog: Maximum number of queued connections
            timeout: Socket timeout in seconds
            require_client_auth: Whether to require client certificate authentication
            
        Returns:
            SecureListener instance.
        """
        server_sock = self.create_server_socket(
            bind_address=bind_address,
            port=port,
            backlog=backlog,
            timeout=timeout,
            require_client_auth=require_client_auth
        )
        
        return SecureListener(
            server_socket=server_sock,
            socket_factory=self,
            require_client_auth=require_client_auth
        )


class SecureListener:
    """Helper class for managing secure listening sockets."""
    
    def __init__(self, server_socket: socket.socket, 
                 socket_factory: SecureSocketFactory,
                 require_client_auth: bool = True):
        """
        Initialize SecureListener.
        
        Args:
            server_socket: Listening server socket
            socket_factory: SecureSocketFactory instance
            require_client_auth: Whether to require client certificate authentication
        """
        self.server_socket = server_socket
        self.socket_factory = socket_factory
        self.require_client_auth = require_client_auth
        self.is_running = False
        
    def accept(self) -> Tuple[ssl.SSLSocket, Tuple[str, int]]:
        """
        Accept a client connection.
        
        Returns:
            Tuple of (SSL socket, (client_ip, client_port))
        """
        return self.socket_factory.accept_client_connection(
            self.server_socket,
            require_client_auth=self.require_client_auth
        )
    
    def close(self) -> None:
        """Close the listening socket."""
        try:
            self.server_socket.close()
            logger.info("Server socket closed")
        except socket.error as e:
            logger.error(f"Error closing server socket: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.is_running = True
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        self.is_running = False
    
    def __repr__(self) -> str:
        """String representation."""
        addr = self.server_socket.getsockname()
        return f"SecureListener(listening_on={addr}, require_client_auth={self.require_client_auth})"
