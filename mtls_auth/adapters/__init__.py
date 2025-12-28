"""
Protocol adapters for mTLS authentication.

Provides adapters for different protocols (HTTP, gRPC, raw TCP, FastAPI, Flask, Django) 
to use the mTLS authentication library.
"""

from .raw_tcp_adapter import RawTCPAdapter
from .http_adapter import HTTPAdapter, HTTPServer, HTTPClient

# Optional gRPC adapter - only import if grpc is available
try:
    import grpc
    from .grpc_adapter import GRPCAdapter, GRPCServer, GRPCClient
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False
    # Create dummy classes to avoid import errors
    class GRPCAdapter:
        def __init__(self, *args, **kwargs):
            raise ImportError("gRPC is not installed. Install with: pip install grpcio")
    
    class GRPCServer:
        def __init__(self, *args, **kwargs):
            raise ImportError("gRPC is not installed. Install with: pip install grpcio")
    
    class GRPCClient:
        def __init__(self, *args, **kwargs):
            raise ImportError("gRPC is not installed. Install with: pip install grpcio")

# Optional FastAPI adapter
try:
    from .fastapi_adapter import (
        MTLSMiddleware, 
        get_client_certificate, 
        get_client_ip,
        require_client_certificate,
        require_client_ip_in_whitelist,
        FastAPIAdapter,
        with_mtls
    )
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    # Create dummy classes
    class MTLSMiddleware:
        def __init__(self, *args, **kwargs):
            raise ImportError("FastAPI is not installed. Install with: pip install fastapi")
    
    def get_client_certificate(*args, **kwargs):
        raise ImportError("FastAPI is not installed. Install with: pip install fastapi")
    
    def get_client_ip(*args, **kwargs):
        raise ImportError("FastAPI is not installed. Install with: pip install fastapi")
    
    def require_client_certificate(*args, **kwargs):
        raise ImportError("FastAPI is not installed. Install with: pip install fastapi")
    
    def require_client_ip_in_whitelist(*args, **kwargs):
        raise ImportError("FastAPI is not installed. Install with: pip install fastapi")
    
    class FastAPIAdapter:
        def __init__(self, *args, **kwargs):
            raise ImportError("FastAPI is not installed. Install with: pip install fastapi")
    
    def with_mtls(*args, **kwargs):
        raise ImportError("FastAPI is not installed. Install with: pip install fastapi")

# Optional Flask adapter
try:
    from .flask_adapter import (
        MTLSFlask,
        MTLS,
        require_client_cert,
        get_client_certificate as get_flask_client_certificate,
        get_client_ip as get_flask_client_ip
    )
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    # Create dummy classes
    class MTLSFlask:
        def __init__(self, *args, **kwargs):
            raise ImportError("Flask is not installed. Install with: pip install flask")
    
    class MTLS:
        def __init__(self, *args, **kwargs):
            raise ImportError("Flask is not installed. Install with: pip install flask")
    
    def require_client_cert(*args, **kwargs):
        raise ImportError("Flask is not installed. Install with: pip install flask")
    
    def get_flask_client_certificate(*args, **kwargs):
        raise ImportError("Flask is not installed. Install with: pip install flask")
    
    def get_flask_client_ip(*args, **kwargs):
        raise ImportError("Flask is not installed. Install with: pip install flask")

# Optional Django adapter
try:
    from .django_adapter import (
        MTLSMiddleware as DjangoMTLSMiddleware,
        require_client_cert as django_require_client_cert,
        mtls_settings
    )
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False
    # Create dummy classes
    class DjangoMTLSMiddleware:
        def __init__(self, *args, **kwargs):
            raise ImportError("Django is not installed. Install with: pip install django")
    
    def django_require_client_cert(*args, **kwargs):
        raise ImportError("Django is not installed. Install with: pip install django")
    
    mtls_settings = {}

__all__ = [
    "RawTCPAdapter",
    "HTTPAdapter", "HTTPServer", "HTTPClient",
    "GRPCAdapter", "GRPCServer", "GRPCClient",
    "MTLSMiddleware", "get_client_certificate", "get_client_ip",
    "require_client_certificate", "require_client_ip_in_whitelist",
    "FastAPIAdapter", "with_mtls",
    "MTLSFlask", "MTLS", "require_client_cert",
    "get_flask_client_certificate", "get_flask_client_ip",
    "DjangoMTLSMiddleware", "django_require_client_cert", "mtls_settings",
    "GRPC_AVAILABLE", "FASTAPI_AVAILABLE", "FLASK_AVAILABLE", "DJANGO_AVAILABLE"
]
