"""
gRPC Adapter for mTLS authentication.

Provides gRPC server and client that use the mTLS authentication library.
This is a simplified adapter that shows how to integrate with gRPC.
"""

import logging
from typing import Optional, Any, Callable
import grpc

from ..core.connection_validator import ConnectionValidator

logger = logging.getLogger(__name__)

class GRPCServer:
    """gRPC server with mTLS and IP whitelisting support."""
    
    def __init__(self, connection_validator: ConnectionValidator,
                 bind_address: str = "0.0.0.0", port: int = 50051):
        """
        Initialize GRPCServer.
        
        Args:
            connection_validator: ConnectionValidator instance
            bind_address: Address to bind to
            port: Port to listen on
        """
        self.connection_validator = connection_validator
        self.bind_address = bind_address
        self.port = port
        self.server = None
        
    def start(self, add_servers_func: Callable[[grpc.Server], None]):
        """
        Start the gRPC server.
        
        Args:
            add_servers_func: Function that adds services to the gRPC server
        """
        # Get server SSL context from certificate manager
        ssl_context = self.connection_validator.cert_manager.get_server_ssl_context(
            require_client_auth=True
        )
        
        # Create server credentials
        server_credentials = grpc.ssl_server_credentials(
            [(self.connection_validator.cert_manager.key_path.read_bytes(),
              self.connection_validator.cert_manager.cert_path.read_bytes())],
            root_certificates=self.connection_validator.cert_manager.ca_cert_path.read_bytes(),
            require_client_auth=True
        )
        
        # Create gRPC server
        self.server = grpc.server(
            thread_pool=None,
            interceptors=[GRPCAuthInterceptor(self.connection_validator.ip_validator)]
        )
        
        # Add services
        add_servers_func(self.server)
        
        # Add secure port
        self.server.add_secure_port(f'{self.bind_address}:{self.port}', server_credentials)
        
        # Start server
        self.server.start()
        logger.info(f"gRPC server started on {self.bind_address}:{self.port}")
        
    def stop(self):
        """Stop the gRPC server."""
        if self.server:
            self.server.stop(grace=5)
            logger.info("gRPC server stopped")
    
    def wait_for_termination(self):
        """Wait for server termination."""
        if self.server:
            self.server.wait_for_termination()


class GRPCClient:
    """gRPC client with mTLS support."""
    
    def __init__(self, connection_validator: ConnectionValidator,
                 target: str, options: Optional[list] = None):
        """
        Initialize GRPCClient.
        
        Args:
            connection_validator: ConnectionValidator instance
            target: Server address (host:port)
            options: Additional gRPC channel options
        """
        self.connection_validator = connection_validator
        self.target = target
        self.options = options or []
        self.channel = None
        
    def create_channel(self) -> grpc.Channel:
        """Create a secure gRPC channel."""
        # Get client SSL context
        ssl_context = self.connection_validator.cert_manager.get_client_ssl_context()
        
        # Create channel credentials
        with open(self.connection_validator.cert_manager.cert_path, 'rb') as f:
            cert_data = f.read()
        with open(self.connection_validator.cert_manager.key_path, 'rb') as f:
            key_data = f.read()
        with open(self.connection_validator.cert_manager.ca_cert_path, 'rb') as f:
            ca_data = f.read()
            
        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca_data,
            private_key=key_data,
            certificate_chain=cert_data
        )
        
        # Create channel with interceptors
        self.channel = grpc.secure_channel(
            self.target,
            credentials,
            options=self.options
        )
        
        return self.channel
    
    def close(self):
        """Close the gRPC channel."""
        if self.channel:
            self.channel.close()


class GRPCAuthInterceptor(grpc.ServerInterceptor):
    """gRPC interceptor for IP whitelist validation."""
    
    def __init__(self, ip_validator):
        """
        Initialize GRPCAuthInterceptor.
        
        Args:
            ip_validator: IPWhitelistValidator instance
        """
        self.ip_validator = ip_validator
        
    def intercept_service(self, continuation, handler_call_details):
        """Intercept incoming gRPC calls to validate IP."""
        # Extract client IP from call details
        # Note: This is a simplified example. In production, you'd need to 
        # extract the IP from the handler_call_details.peer() which returns a string like "ipv4:127.0.0.1:12345"
        peer = handler_call_details.peer()
        # Parse peer string to get IP
        # Example peer string: "ipv4:127.0.0.1:12345"
        if peer:
            try:
                # Extract IP from peer string
                # This is a naive extraction, adjust as needed
                ip_part = peer.split(':')[1] if ':' in peer else peer
                if self.ip_validator and not self.ip_validator.is_allowed(ip_part):
                    # Return a "permission denied" error
                    from grpc import StatusCode
                    from grpc import _server
                    return _server._unknown_method_handler(
                        lambda request, context: context.abort(
                            StatusCode.PERMISSION_DENIED, 
                            f"IP {ip_part} not allowed"
                        )
                    )
            except Exception as e:
                logger.warning(f"Failed to validate IP from peer {peer}: {e}")
        
        # Continue with the original handler
        return continuation(handler_call_details)


class GRPCAdapter:
    """Adapter for gRPC communication with mTLS."""
    
    def __init__(self, connection_validator: ConnectionValidator):
        """
        Initialize GRPCAdapter.
        
        Args:
            connection_validator: ConnectionValidator instance
        """
        self.connection_validator = connection_validator
    
    def create_server(self, bind_address: str = "0.0.0.0", 
                      port: int = 50051) -> GRPCServer:
        """
        Create a gRPC server.
        
        Args:
            bind_address: Address to bind to
            port: Port to listen on
            
        Returns:
            GRPCServer instance.
        """
        return GRPCServer(
            connection_validator=self.connection_validator,
            bind_address=bind_address,
            port=port
        )
    
    def create_client(self, target: str, 
                      options: Optional[list] = None) -> GRPCClient:
        """
        Create a gRPC client.
        
        Args:
            target: Server address (host:port)
            options: Additional gRPC channel options
            
        Returns:
            GRPCClient instance.
        """
        return GRPCClient(
            connection_validator=self.connection_validator,
            target=target,
            options=options
        )
