"""
Raw TCP Adapter for mTLS authentication.

Provides a simple TCP server and client that use the mTLS authentication library.
"""

import socket
import logging
import threading
from typing import Optional, Callable, Any
from pathlib import Path

from ..core.connection_validator import ConnectionValidator

logger = logging.getLogger(__name__)

class RawTCPAdapter:
    """Adapter for raw TCP communication with mTLS and IP whitelisting."""
    
    def __init__(self, connection_validator: ConnectionValidator):
        """
        Initialize RawTCPAdapter.
        
        Args:
            connection_validator: ConnectionValidator instance
        """
        self.connection_validator = connection_validator
        
    def create_server(self, bind_address: str = "0.0.0.0", port: int = 8443,
                      backlog: int = 5, timeout: Optional[float] = None,
                      require_client_auth: bool = True):
        """
        Create a TCP server with mTLS and IP whitelisting.
        
        Args:
            bind_address: Address to bind to
            port: Port to listen on
            backlog: Maximum number of queued connections
            timeout: Socket timeout in seconds
            require_client_auth: Whether to require client certificate authentication
            
        Returns:
            RawTCPServer instance.
        """
        server = self.connection_validator.create_server(
            bind_address=bind_address,
            port=port,
            backlog=backlog,
            timeout=timeout,
            require_client_auth=require_client_auth
        )
        return RawTCPServer(server)
    
    def create_client(self, host: str, port: int, timeout: Optional[float] = None,
                      server_hostname: Optional[str] = None, 
                      validate_server_ip: bool = False):
        """
        Create a TCP client with mTLS and optional server IP validation.
        
        Args:
            host: Server hostname or IP address
            port: Server port
            timeout: Socket timeout in seconds
            server_hostname: Server hostname for SNI
            validate_server_ip: Whether to validate server IP against whitelist
            
        Returns:
            RawTCPClient instance.
        """
        sock = self.connection_validator.create_client(
            host=host,
            port=port,
            timeout=timeout,
            server_hostname=server_hostname,
            validate_server_ip=validate_server_ip
        )
        return RawTCPClient(sock)


class RawTCPServer:
    """TCP server with mTLS support."""
    
    def __init__(self, secure_listener):
        """
        Initialize RawTCPServer.
        
        Args:
            secure_listener: SecureListener from ConnectionValidator
        """
        self.listener = secure_listener
        self.is_running = False
        self.handler_threads = []
        
    def start(self, handler: Callable[[socket.socket, str], Any], 
              max_connections: Optional[int] = None):
        """
        Start the server with a connection handler.
        
        Args:
            handler: Function that handles a client connection, takes (socket, client_ip)
            max_connections: Maximum number of connections to handle (None for unlimited)
        """
        self.is_running = True
        logger.info(f"Raw TCP server started on {self.listener.server_socket.getsockname()}")
        
        connection_count = 0
        
        try:
            while self.is_running and (max_connections is None or connection_count < max_connections):
                try:
                    # Accept a client connection
                    ssl_sock, (client_ip, client_port) = self.listener.accept()
                    
                    # Create a thread to handle the connection
                    thread = threading.Thread(
                        target=self._handle_connection,
                        args=(ssl_sock, client_ip, client_port, handler),
                        daemon=True
                    )
                    thread.start()
                    self.handler_threads.append(thread)
                    
                    connection_count += 1
                    logger.debug(f"Accepted connection {connection_count} from {client_ip}:{client_port}")
                    
                except (socket.error, ConnectionError) as e:
                    if self.is_running:
                        logger.error(f"Error accepting connection: {e}")
                        break
                    
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        finally:
            self.stop()
    
    def _handle_connection(self, sock: socket.socket, client_ip: str, 
                          client_port: int, handler: Callable):
        """Handle a single client connection."""
        try:
            # Call the user-provided handler
            handler(sock, client_ip)
        except Exception as e:
            logger.error(f"Error handling connection from {client_ip}:{client_port}: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
    
    def stop(self):
        """Stop the server."""
        self.is_running = False
        self.listener.close()
        
        # Wait for handler threads to finish
        for thread in self.handler_threads:
            thread.join(timeout=2.0)
        
        logger.info("Raw TCP server stopped")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


class RawTCPClient:
    """TCP client with mTLS support."""
    
    def __init__(self, sock: socket.socket):
        """
        Initialize RawTCPClient.
        
        Args:
            sock: SSL socket connected to server
        """
        self.sock = sock
        
    def send(self, data: bytes) -> int:
        """
        Send data to the server.
        
        Args:
            data: Bytes to send
            
        Returns:
            Number of bytes sent.
        """
        return self.sock.send(data)
    
    def receive(self, buffer_size: int = 4096) -> bytes:
        """
        Receive data from the server.
        
        Args:
            buffer_size: Maximum number of bytes to receive
            
        Returns:
            Received bytes.
        """
        return self.sock.recv(buffer_size)
    
    def send_all(self, data: bytes) -> None:
        """
        Send all data to the server.
        
        Args:
            data: Bytes to send
        """
        self.sock.sendall(data)
    
    def close(self) -> None:
        """Close the connection."""
        try:
            self.sock.close()
            logger.debug("Client connection closed")
        except:
            pass
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
