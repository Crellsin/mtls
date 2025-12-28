"""
HTTP Adapter for mTLS authentication.

Provides HTTP server and client that use the mTLS authentication library.
Built on top of the raw TCP adapter with HTTP protocol handling.
"""

import http.server
import socketserver
import ssl
import logging
import json
from typing import Optional, Dict, Any, Callable
from pathlib import Path

from ..core.connection_validator import ConnectionValidator

logger = logging.getLogger(__name__)

class HTTPServer:
    """HTTP server with mTLS and IP whitelisting support."""
    
    def __init__(self, connection_validator: ConnectionValidator, 
                 bind_address: str = "0.0.0.0", port: int = 8443,
                 request_handler=None):
        """
        Initialize HTTPServer.
        
        Args:
            connection_validator: ConnectionValidator instance
            bind_address: Address to bind to
            port: Port to listen on
            request_handler: Custom request handler class (defaults to SimpleHTTPRequestHandler)
        """
        self.connection_validator = connection_validator
        self.bind_address = bind_address
        self.port = port
        self.request_handler = request_handler or SimpleHTTPRequestHandler
        self.httpd = None
        
    def start(self):
        """Start the HTTP server."""
        # Create secure listener
        secure_listener = self.connection_validator.create_server(
            bind_address=self.bind_address,
            port=self.port,
            require_client_auth=True
        )
        
        # We need to adapt the secure listener to work with http.server
        # This is a simplified approach - in production you'd want more robust handling
        self.httpd = http.server.HTTPServer((self.bind_address, self.port), self.request_handler)
        
        # Replace the socket with our secure listener's socket
        self.httpd.socket.close()  # Close the original socket
        self.httpd.socket = secure_listener.server_socket
        
        # Store the secure listener for later cleanup
        self.secure_listener = secure_listener
        
        logger.info(f"HTTPS server started on https://{self.bind_address}:{self.port}")
        
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the HTTP server."""
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("HTTPS server stopped")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


class HTTPClient:
    """HTTP client with mTLS support."""
    
    def __init__(self, connection_validator: ConnectionValidator):
        """
        Initialize HTTPClient.
        
        Args:
            connection_validator: ConnectionValidator instance
        """
        self.connection_validator = connection_validator
        
    def request(self, method: str, url: str, headers: Optional[Dict] = None,
                data: Optional[Any] = None, timeout: Optional[float] = None,
                validate_server_ip: bool = False) -> Dict[str, Any]:
        """
        Make an HTTP request with mTLS.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL (e.g., https://example.com:8443/path)
            headers: HTTP headers (optional)
            data: Request body (optional)
            timeout: Request timeout in seconds
            validate_server_ip: Whether to validate server IP against whitelist
            
        Returns:
            Dictionary with response information.
        """
        # Parse URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        if parsed.scheme != 'https':
            raise ValueError("Only HTTPS URLs are supported")
        
        host = parsed.hostname
        port = parsed.port or 443
        path = parsed.path or '/'
        
        # Create client socket
        client = self.connection_validator.create_client(
            host=host,
            port=port,
            timeout=timeout,
            validate_server_ip=validate_server_ip
        )
        
        try:
            # Build HTTP request
            request_lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {host}:{port}",
                "Connection: close",
            ]
            
            if headers:
                for key, value in headers.items():
                    request_lines.append(f"{key}: {value}")
            
            if data:
                if isinstance(data, (dict, list)):
                    data = json.dumps(data)
                    request_lines.append("Content-Type: application/json")
                    request_lines.append(f"Content-Length: {len(data)}")
                elif isinstance(data, str):
                    request_lines.append("Content-Type: text/plain")
                    request_lines.append(f"Content-Length: {len(data)}")
                else:
                    data = str(data)
                    request_lines.append("Content-Type: text/plain")
                    request_lines.append(f"Content-Length: {len(data)}")
            
            request_lines.append("")  # Empty line before body
            request = "\r\n".join(request_lines)
            
            if data:
                request += "\r\n" + data
            
            # Send request
            client.sock.sendall(request.encode('utf-8'))
            
            # Receive response
            response_data = b""
            while True:
                chunk = client.sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            
            # Parse response
            response_str = response_data.decode('utf-8', errors='ignore')
            headers_end = response_str.find('\r\n\r\n')
            if headers_end == -1:
                raise ValueError("Invalid HTTP response")
            
            headers_part = response_str[:headers_end]
            body = response_str[headers_end + 4:]
            
            # Parse status line
            lines = headers_part.split('\r\n')
            status_line = lines[0]
            status_parts = status_line.split(' ', 2)
            
            # Parse headers
            response_headers = {}
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    response_headers[key] = value
            
            return {
                'status_code': int(status_parts[1]),
                'status_message': status_parts[2],
                'headers': response_headers,
                'body': body,
                'raw_response': response_data
            }
            
        finally:
            client.sock.close()


class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Simple HTTP request handler with mTLS awareness."""
    
    def do_GET(self):
        """Handle GET request."""
        client_cert = self.connection.getpeercert()
        client_ip = self.client_address[0]
        
        response = {
            'message': 'Hello from mTLS server!',
            'client_ip': client_ip,
            'client_cert_verified': bool(client_cert),
            'path': self.path,
            'method': 'GET'
        }
        
        if client_cert:
            response['client_cert_subject'] = dict(x[0] for x in client_cert.get('subject', []))
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))
    
    def do_POST(self):
        """Handle POST request."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        client_cert = self.connection.getpeercert()
        client_ip = self.client_address[0]
        
        response = {
            'message': 'POST received',
            'client_ip': client_ip,
            'client_cert_verified': bool(client_cert),
            'path': self.path,
            'method': 'POST',
            'received_body': body
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))
    
    def log_message(self, format, *args):
        """Log message with client IP and certificate info."""
        client_cert = self.connection.getpeercert()
        cert_info = " (cert verified)" if client_cert else " (no cert)"
        logger.info(f"{self.client_address[0]} - {format % args}{cert_info}")


class HTTPAdapter:
    """Adapter for HTTP communication with mTLS."""
    
    def __init__(self, connection_validator: ConnectionValidator):
        """
        Initialize HTTPAdapter.
        
        Args:
            connection_validator: ConnectionValidator instance
        """
        self.connection_validator = connection_validator
    
    def create_server(self, bind_address: str = "0.0.0.0", port: int = 8443,
                      request_handler=None) -> HTTPServer:
        """
        Create an HTTP server.
        
        Args:
            bind_address: Address to bind to
            port: Port to listen on
            request_handler: Custom request handler
            
        Returns:
            HTTPServer instance.
        """
        return HTTPServer(
            connection_validator=self.connection_validator,
            bind_address=bind_address,
            port=port,
            request_handler=request_handler
        )
    
    def create_client(self) -> HTTPClient:
        """
        Create an HTTP client.
        
        Returns:
            HTTPClient instance.
        """
        return HTTPClient(self.connection_validator)
