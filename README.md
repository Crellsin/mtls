# mTLS Authentication System with IP Whitelisting

A robust, production-ready mutual TLS (mTLS) authentication library for Python with built-in IP whitelisting for both IPv4 and IPv6 networks.

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
from fastapi import FastAPI
from mtls_auth.adapters.fastapi_adapter import MTLSMiddleware

app = FastAPI()

# Add mTLS middleware
app.add_middleware(MTLSMiddleware,
                   cert_path="certs/server.pem",
                   key_path="certs/server.key",
                   ca_cert_path="certs/ca.crt",
                   ipv4_whitelist=["192.168.1.0/24"])

@app.get("/secure")
async def secure_endpoint():
    return {"message": "Access granted with valid certificate"}
```

### Flask Example

```python
from mtls_auth.adapters.flask_adapter import MTLSFlask, require_client_cert

app = MTLSFlask(__name__,
                mtls_cert_path="certs/server.pem",
                mtls_key_path="certs/server.key",
                mtls_ca_cert_path="certs/ca.crt",
                mtls_client_ipv4_whitelist=["192.168.1.0/24"])

@app.route('/api/secure')
@require_client_cert
def secure_route():
    return {"status": "authenticated"}
```

### Django Example

```python
# settings.py
MIDDLEWARE = [
    'mtls_auth.adapters.django_adapter.MTLSMiddleware',
    # ...
]

MTLS_CONFIG = {
    'CERT_PATH': 'certs/server.pem',
    'KEY_PATH': 'certs/server.key',
    'CA_CERT_PATH': 'certs/ca.crt',
    'IPV4_WHITELIST': ['192.168.1.0/24'],
    'REQUIRE_CLIENT_CERT': True,
}
```

## 🧪 Testing

Run the comprehensive test suite:

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
- **[PROGRESS_TRACKING.md](./PROGRESS_TRACKING.md)**: Development progress and security standards documentation

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
