"""
Certificate Manager for mTLS authentication.

Handles loading, validation, and management of X.509 certificates for both client and server.
"""

import ssl
import os
from pathlib import Path
from typing import Optional, Tuple, List, Union
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class CertificateManager:
    """Manages certificates for mTLS authentication."""
    
    def __init__(self, cert_path: Union[str, Path], key_path: Union[str, Path], 
                 ca_cert_path: Optional[Union[str, Path]] = None):
        """
        Initialize CertificateManager.
        
        Args:
            cert_path: Path to the certificate file (PEM format)
            key_path: Path to the private key file (PEM format)
            ca_cert_path: Path to the CA certificate file for validation (optional)
        """
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)
        self.ca_cert_path = Path(ca_cert_path) if ca_cert_path else None
        
        # Validate paths exist
        if not self.cert_path.exists():
            raise FileNotFoundError(f"Certificate file not found: {self.cert_path}")
        if not self.key_path.exists():
            raise FileNotFoundError(f"Key file not found: {self.key_path}")
        if self.ca_cert_path and not self.ca_cert_path.exists():
            raise FileNotFoundError(f"CA certificate file not found: {self.ca_cert_path}")
        
        # Load certificates
        self._cert_data = self.cert_path.read_text()
        self._key_data = self.key_path.read_text()
        self._ca_cert_data = self.ca_cert_path.read_text() if self.ca_cert_path else None
        
        # SSL contexts (lazy loaded)
        self._client_context: Optional[ssl.SSLContext] = None
        self._server_context: Optional[ssl.SSLContext] = None
        
    def get_client_ssl_context(self, verify_server: bool = True) -> ssl.SSLContext:
        """
        Create and return an SSL context configured for client-side mTLS.
        
        Args:
            verify_server: Whether to verify the server certificate (default: True)
            
        Returns:
            Configured SSLContext for client use.
        """
        if self._client_context is None:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
            
            if verify_server and self.ca_cert_path:
                context.load_verify_locations(cafile=str(self.ca_cert_path))
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
            # Set secure protocol and ciphers
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._client_context = context
            
        return self._client_context
    
    def get_server_ssl_context(self, require_client_auth: bool = True) -> ssl.SSLContext:
        """
        Create and return an SSL context configured for server-side mTLS.
        
        Args:
            require_client_auth: Whether to require client certificate authentication (default: True)
            
        Returns:
            Configured SSLContext for server use.
        """
        if self._server_context is None:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
            
            if require_client_auth:
                if self.ca_cert_path:
                    context.load_verify_locations(cafile=str(self.ca_cert_path))
                    context.verify_mode = ssl.CERT_REQUIRED
                else:
                    raise ValueError("CA certificate path is required for client authentication")
            else:
                context.verify_mode = ssl.CERT_NONE
                
            # Set secure protocol and ciphers
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._server_context = context
            
        return self._server_context
    
    def validate_certificate(self, cert_pem: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate a certificate (self or provided) against the CA.
        
        Args:
            cert_pem: PEM-encoded certificate string (if None, validates own certificate)
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not self.ca_cert_path:
            return False, "No CA certificate provided for validation"
            
        try:
            # This is a basic validation - in production, you might want to use
            # cryptography library for more comprehensive validation
            import tempfile
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                if cert_pem:
                    f.write(cert_pem)
                else:
                    f.write(self._cert_data)
                cert_file = f.name
                
            try:
                # Use openssl to verify (simplified approach)
                import subprocess
                result = subprocess.run(
                    ['openssl', 'verify', '-CAfile', str(self.ca_cert_path), cert_file],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    return True, "Certificate is valid"
                else:
                    return False, f"Certificate validation failed: {result.stderr}"
            finally:
                os.unlink(cert_file)
                
        except Exception as e:
            return False, f"Certificate validation error: {str(e)}"
    
    def get_certificate_info(self, cert_data: Optional[Union[str, bytes]] = None) -> dict:
        """
        Extract basic information from the certificate.
        
        Args:
            cert_data: Optional certificate data as string (PEM) or bytes (DER or PEM).
                       If None, uses the certificate file specified at initialization.
        
        Returns:
            Dictionary with certificate information.
        """
        try:
            import subprocess
            import tempfile
            
            # Determine the input source for openssl
            if cert_data is None:
                # Use the certificate file path
                cert_input = str(self.cert_path)
                openssl_args = ['openssl', 'x509', '-in', cert_input, '-noout', '-text']
            else:
                # Write certificate data to a temporary file
                with tempfile.NamedTemporaryFile(mode='wb', suffix='.crt', delete=False) as f:
                    if isinstance(cert_data, str):
                        f.write(cert_data.encode('utf-8'))
                    else:
                        f.write(cert_data)
                    cert_file = f.name
                
                try:
                    # First try PEM format
                    result = subprocess.run(
                        ['openssl', 'x509', '-in', cert_file, '-noout', '-text'],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode != 0:
                        # Try DER format
                        result = subprocess.run(
                            ['openssl', 'x509', '-in', cert_file, '-inform', 'DER', '-noout', '-text'],
                            capture_output=True,
                            text=True
                        )
                finally:
                    os.unlink(cert_file)
                    
                if result.returncode != 0:
                    return {"error": "Failed to parse certificate"}
            
            # If we used the file path, run openssl now
            if cert_data is None:
                result = subprocess.run(
                    ['openssl', 'x509', '-in', cert_input, '-noout', '-text'],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    return {"error": "Failed to parse certificate"}
            
            info = {
                "subject": "",
                "issuer": "",
                "valid_from": "",
                "valid_to": "",
                "serial_number": "",
                "signature_algorithm": "",
            }
            
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if 'Subject:' in line:
                    info['subject'] = line.split('Subject:', 1)[1].strip()
                elif 'Issuer:' in line:
                    info['issuer'] = line.split('Issuer:', 1)[1].strip()
                elif 'Not Before' in line:
                    info['valid_from'] = line.split(':', 1)[1].strip()
                elif 'Not After' in line:
                    info['valid_to'] = line.split(':', 1)[1].strip()
                elif 'Serial Number:' in line:
                    info['serial_number'] = line.split(':', 1)[1].strip()
                elif 'Signature Algorithm:' in line:
                    info['signature_algorithm'] = line.split(':', 1)[1].strip()
            
            return info
            
        except Exception as e:
            logger.warning(f"Could not extract certificate info: {e}")
            return {"error": str(e)}
    
    @staticmethod
    def create_self_signed_cert(cert_path: Union[str, Path], key_path: Union[str, Path],
                                common_name: str = "localhost", days: int = 365):
        """
        Create a self-signed certificate (for testing only).
        
        Args:
            cert_path: Path to save the certificate
            key_path: Path to save the private key
            common_name: Common name for the certificate
            days: Number of days the certificate is valid
        """
        import subprocess
        
        cert_path = Path(cert_path)
        key_path = Path(key_path)
        
        # Generate private key
        subprocess.run([
            'openssl', 'genrsa', '-out', str(key_path), '2048'
        ], check=True)
        
        # Generate self-signed certificate
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-days', str(days),
            '-key', str(key_path), '-out', str(cert_path),
            '-subj', f'/CN={common_name}'
        ], check=True)
        
        logger.info(f"Created self-signed certificate: {cert_path}")
