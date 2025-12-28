"""
mTLS Authentication Library

A Python library for mutual TLS authentication with IP whitelisting support.
Provides both client and server side functionality for secure communication.
"""

__version__ = "0.1.0"
__author__ = "MTLS Auth Team"

from .core.certificate_manager import CertificateManager
from .core.ip_whitelist import IPWhitelistValidator
from .core.secure_socket import SecureSocketFactory
from .core.connection_validator import ConnectionValidator

__all__ = [
    "CertificateManager",
    "IPWhitelistValidator",
    "SecureSocketFactory",
    "ConnectionValidator",
]
