# mTLS Authentication System with IP Whitelisting

A robust mutual TLS (mTLS) authentication library for Python with built-in IP whitelisting for both IPv4 and IPv6 networks.

## Features

### Core Security

- **Mutual TLS Authentication**: Two-way certificate validation between client and server
- **IP Whitelisting**: Network-layer validation for IPv4 and IPv6 with CIDR support
- **Defense in Depth**: Multiple security layers (certificate + IP validation)
- **TLS 1.2+**: Enforces modern TLS protocols with strong cipher suites

### Framework Support

- **FastAPI**: Middleware with dependency injection for certificate info
- **Flask**: Extension pattern with decorators and Flask subclass
- **Django**: Middleware with settings configuration and view decorators
- **HTTP/HTTPS**: Built-in HTTP server and client adapters
- **gRPC**: Interceptor-based authentication for gRPC services
- **Raw TCP**: Low-level socket communication with mTLS

### Certificate Management

- **Certificate Authority**: Root CA generation and management
- **Client/Server Certs**: Automatic certificate generation with proper extensions
- **Key Usage**: Enforces proper key usage (serverAuth, clientAuth)
- **Certificate Chain**: Full chain validation against trusted CA

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd mtls

# Install dependencies (if any additional beyond standard library)
pip install -r requirements.txt
```

### Generate Certificates

```bash
# Generate CA and test certificates
chmod +x generate_certs.sh
./generate_certs.sh
```

### Basic Usage

```python
from mtls_auth.core.connection_validator import ConnectionValidator

# Server-side setup
server_validator = ConnectionValidator.create_for_server(
    cert_path="mtls_auth/certs/server/server.pem",
    key_path="mtls_auth/certs/server/server.key",
    ca_cert_path="mtls_auth/certs/ca/root-ca.crt",
    client_ipv4_whitelist=["10.0.0.0/8", "192.168.1.0/24"],
    client_ipv6_whitelist=["2001:db8::/32"]
)

# Client-side setup  
client_validator = ConnectionValidator.create_for_client(
    cert_path="mtls_auth/certs/client/client.pem",
    key_path="mtls_auth/certs/client/client.key",
    ca_cert_path="mtls_auth/certs/ca/root-ca.crt",
    server_ipv4_whitelist=["192.168.1.100"],
    server_ipv6_whitelist=["2001:db8::1"]
)
```

## 📖 Framework Integration

### FastAPI Example

```python
import time

def make_request_with_retry(client, url, max_retries=3):
    for attempt in range(max_retries):
        try:
            return client.request("GET", url)
        except (ConnectionError, TimeoutError) as e:
            if attempt == max_retries - 1:
                raise
            wait_time = 2 ** attempt  # Exponential backoff
            time.sleep(wait_time)
```

### Certificate Management on Client

**Dynamic Certificate Loading:**
```python
class DynamicCertificateManager:
    def __init__(self, cert_dir):
        self.cert_dir = Path(cert_dir)
        self.watcher = threading.Thread(target=self.watch_certificates)
        self.watcher.daemon = True
        self.watcher.start()
    
    def watch_certificates(self):
        while True:
            time.sleep(60)  # Check every minute
            if self.certificates_changed():
                self.reload_certificates()
    
    def reload_certificates(self):
        # Reload certificates without restarting client
        new_cert = self.cert_dir / "client.pem"
        new_key = self.cert_dir / "client.key"
        # Update SSL context with new certificates
```

## Security Considerations

### Defense in Depth Strategy

**Layer 1: Network Security**

- IP whitelisting at network layer
- Firewall rules limiting access
- Network segmentation

**Layer 2: Transport Security**

- Mutual TLS authentication
- Strong cipher suites (TLS 1.3 preferred)
- Perfect forward secrecy

**Layer 3: Application Security**

- Certificate validation (not just presence)
- Certificate revocation checking
- Rate limiting per client certificate

**Layer 4: Operational Security**

- Regular certificate rotation
- Key management best practices
- Audit logging of all connections

### Secure Configuration Guidelines

**TLS Configuration:**

```python
# Recommended TLS configuration
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
context.options |= ssl.OP_NO_COMPRESSION
context.options |= ssl.OP_SINGLE_DH_USE
context.options |= ssl.OP_SINGLE_ECDH_USE
```

**Certificate Validation:**

```python
def validate_certificate_chain(cert_chain, ca_cert):
    # 1. Verify signature chain
    # 2. Check expiration dates
    # 3. Validate key usage extensions
    # 4. Check revocation status
    # 5. Verify subject alternative names
    # 6. Validate certificate policies
    pass
```

### Private Key Protection

**File System Protection:**

```bash
# Set proper permissions
chmod 600 private.key
chown root:root private.key

# Use encrypted filesystems for sensitive data
mount -t ecryptfs /secure/certs /secure/certs
```

**Memory Protection:**

```python
import mmap
import os

class SecureKeyStorage:
    def __init__(self, key_path):
        # Map key into memory with restricted access
        fd = os.open(key_path, os.O_RDONLY)
        self.mapped_key = mmap.mmap(fd, 0, mmap.MAP_PRIVATE, mmap.PROT_READ)
        os.close(fd)
    
    def __del__(self):
        # Securely wipe memory
        if hasattr(self, 'mapped_key'):
            self.mapped_key[:] = b'\x00' * len(self.mapped_key)
            self.mapped_key.close()
```

## Framework Adapters

### FastAPI Adapter

**Basic Integration:**

```python
from fastapi import FastAPI, Depends
from mtls_auth.adapters.fastapi_adapter import MTLSMiddleware, get_client_certificate, get_client_ip, require_client_certificate

app = FastAPI()

# Add mTLS middleware
app.add_middleware(MTLSMiddleware,
                   cert_path="certs/server.pem",
                   key_path="certs/server.key",
                   ca_cert_path="certs/ca.crt",
                   client_ipv4_whitelist=["192.168.1.0/24"],
                   require_client_cert=True,
                   excluded_paths=["/health", "/docs"])
                   client_ipv4_whitelist=["192.168.1.0/24"],
                   require_client_cert=True,
                   excluded_paths=["/health", "/docs"])

@app.get("/secure-data")
async def get_secure_data(
    client_cert: dict = Depends(require_client_certificate),
    client_ip: str = Depends(get_client_ip)
):
    return {
        "message": "Access granted with valid certificate",
        "client_id": client_cert.get("subject", {}).get("CN"),
        "client_ip": client_ip
    }
```

**Important Notes:**

1. **Parameter Names**: Use `client_ipv4_whitelist` and `client_ipv6_whitelist` (not `ipv4_whitelist`)
2. **Optional Parameters**: The middleware supports `require_client_cert` (default: True) and `excluded_paths` (list of path prefixes to exclude from mTLS validation)
3. **Dependencies**: Use `require_client_certificate()` dependency to require a client certificate, or `get_client_certificate()` to get certificate info if available (returns None if not present)
4. **IP Validation**: The middleware automatically validates client IP against whitelist if configured

**Advanced Features:**

- Async certificate validation
- WebSocket support with mTLS
- Dependency injection for certificate info
- OpenAPI/Swagger integration

### Flask Adapter

**Basic Integration:**

```python
from flask import Flask, request, jsonify
from mtls_auth.adapters.flask_adapter import MTLSFlask, require_client_cert, get_flask_client_certificate, get_flask_client_ip

# Create Flask app with mTLS configuration
app = MTLSFlask(__name__,
                mtls_cert_path="certs/server.pem",
                mtls_key_path="certs/server.key",
                mtls_ca_cert_path="certs/ca.crt",
                mtls_client_ipv4_whitelist=["192.168.1.0/24"],
                mtls_require_client_cert=True,
                mtls_excluded_paths=["/health"])

@app.route('/api/data', methods=['GET'])
@require_client_cert
def get_data():
    client_cert = get_flask_client_certificate()
    client_ip = get_flask_client_ip()
    
    return jsonify({
        'status': 'authenticated',
        'client_id': client_cert.get("subject", {}).get("CN"),
        'client_ip': client_ip
    })
```

**Important Notes:**

1. **Configuration Parameters**: Use `mtls_client_ipv4_whitelist` and `mtls_client_ipv6_whitelist` when creating `MTLSFlask` (not `MTLS_IPV4_WHITELIST` in app.config).
2. **Optional Parameters**: The `MTLSFlask` constructor supports `mtls_require_client_cert` (default: True) and `mtls_excluded_paths` (list of path prefixes to exclude from mTLS validation).
3. **Decorator**: Use `@require_client_cert` decorator to require a client certificate for a route.
4. **Helper Functions**: Use `get_flask_client_certificate()` and `get_flask_client_ip()` to access client certificate and IP information in route handlers.

**Extension Pattern:**

```python
from flask import Flask
from mtls_auth.adapters.flask_adapter import MTLS

app = Flask(__name__)

# Configure mTLS in app config
app.config['MTLS_CERT_PATH'] = 'certs/server.pem'
app.config['MTLS_KEY_PATH'] = 'certs/server.key'
app.config['MTLS_CA_CERT_PATH'] = 'certs/ca.crt'
app.config['MTLS_CLIENT_IPV4_WHITELIST'] = ['192.168.1.0/24']
app.config['MTLS_CLIENT_IPV6_WHITELIST'] = []
app.config['MTLS_REQUIRE_CLIENT_CERT'] = True
app.config['MTLS_EXCLUDED_PATHS'] = ['/health']

# Initialize MTLS extension
mtls = MTLS(app)

# Or use factory pattern
mtls = MTLS()
mtls.init_app(app)
```

### Django Example

```python
# settings.py
MIDDLEWARE = [
    'mtls_auth.adapters.django_adapter.MTLSMiddleware',
    # ...
]

# mTLS configuration
MTLS_CERT_PATH = 'certs/server.pem'
MTLS_KEY_PATH = 'certs/server.key'
MTLS_CA_CERT_PATH = 'certs/ca.crt'
MTLS_CLIENT_IPV4_WHITELIST = ['192.168.1.0/24']
MTLS_CLIENT_IPV6_WHITELIST = []
MTLS_REQUIRE_CLIENT_CERT = True
MTLS_EXCLUDED_PATHS = ['/admin/', '/static/']
```

**Important Notes:**

1. **Configuration Keys**: Use the exact setting names as above (e.g., `MTLS_CLIENT_IPV4_WHITELIST` not `IPV4_WHITELIST`).
2. **IP Whitelists**: Both `MTLS_CLIENT_IPV4_WHITELIST` and `MTLS_CLIENT_IPV6_WHITELIST` are supported.
3. **Optional Settings**: `MTLS_REQUIRE_CLIENT_CERT` (default: True) and `MTLS_EXCLUDED_PATHS` (list of path prefixes to exclude from mTLS validation).

**View Integration:**

```python
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from mtls_auth.adapters.django_adapter import require_client_cert, get_client_certificate, get_client_ip

@require_http_methods(["GET"])
@require_client_cert
def secure_api_view(request):
    # Use the provided helper functions to get client certificate and IP
    client_cert = get_client_certificate(request)
    client_ip = get_client_ip(request)
    
    return JsonResponse({
        'authenticated': True,
        'client_id': client_cert.get("subject", {}).get("CN"),
        'client_ip': client_ip
    })
```

**Management Commands:**

```bash
python3 tests/simple_test.py
```

Test results include:

- Valid connection with certificate and whitelisted IP
- Blocked connection for IP not in whitelist  
- IPv6 whitelist configuration validation

## Documentation

### Detailed Guides

- **[IMPLEMENTATION_GUIDE.md](./IMPLEMENTATION_GUIDE.md)**: Complete implementation guide covering architecture, certificate management, and framework integration

### Directory Structure

```bash
mtls/
├── mtls_auth/                 # Core library
│   ├── core/                 # Core components (CertificateManager, IPWhitelistValidator, etc.)
│   ├── adapters/             # Framework adapters (FastAPI, Flask, Django, HTTP, gRPC, TCP)
│   └── certs/                # Certificate storage (CA, server, client)
├── examples/                 # Example implementations
├── tests/                    # Test suite
├── config/                   # Configuration templates
└── docs/                     # Additional documentation
```

## 🔧 Configuration

### IP Whitelist Configuration (YAML)

```yaml
# config/ip_whitelist.yaml.example
ipv4:
  - 10.0.0.0/8
  - 192.168.1.0/24
  - 172.16.0.0/12

ipv6:
  - 2001:db8::/32
  - fd00::/8
```

### Certificate Requirements

- **Root CA**: Must have `keyCertSign` and `cRLSign` key usage
- **Server Cert**: Must have `serverAuth` extended key usage
- **Client Cert**: Must have `clientAuth` extended key usage
- **Private Keys**: 2048-bit RSA minimum (4096-bit recommended for CA)

##  Security Considerations

### Best Practices

1. **Regular Certificate Rotation**: Rotate certificates at least annually
2. **Key Protection**: Store private keys in secure locations with minimal access
3. **IP Whitelist Maintenance**: Regularly review and update whitelisted networks
4. **Certificate Revocation**: Implement CRL or OCSP for certificate revocation
5. **Audit Logging**: Log all connection attempts with client certificate details

### Compliance

- **TLS 1.2+**: Complies with modern security standards
- **Certificate Validation**: Full chain validation against trusted CA
- **Network Segmentation**: IP whitelisting provides network-layer security
- **Defense in Depth**: Multiple independent security controls

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is available for use under open source licenses. See LICENSE file for details.

## Support

For issues, questions, or contributions:
- Open an issue in the GitHub repository
- Check the [IMPLEMENTATION_GUIDE.md](./IMPLEMENTATION_GUIDE.md) for detailed documentation
- Review test examples in the `examples/` directory

---

## DISCLAIRMER

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
Use of this package is at your own risk. The authors are not responsible for any damage, data loss, security vulnerabilities, or other issues that may arise from using this software. Users are responsible for testing and validating this software in their own environments before deploying to production

*Last updated: December 2025*
