#!/bin/bash

set -e

CERTS_DIR="mtls_auth/certs"
CA_DIR="$CERTS_DIR/ca"
SERVER_DIR="$CERTS_DIR/server"
CLIENT_DIR="$CERTS_DIR/client"

# Create directories
mkdir -p $CA_DIR $SERVER_DIR $CLIENT_DIR

echo "Generating Root CA with extensions..."
# Generate Root CA private key
openssl genrsa -out $CA_DIR/root-ca.key 4096

# Create a config file for the CA with extensions
cat > $CA_DIR/ca.cnf << 'EOF'
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
C = US
ST = State
L = City
O = Organization
CN = Root CA

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

# Generate Root CA certificate with extensions
openssl req -new -x509 -days 3650 -key $CA_DIR/root-ca.key -out $CA_DIR/root-ca.crt -config $CA_DIR/ca.cnf

echo "Generating Server certificate..."
# Generate server private key
openssl genrsa -out $SERVER_DIR/server.key 2048

# Create server CSR config
cat > $SERVER_DIR/server.cnf << 'EOF'
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = US
ST = State
L = City
O = Organization
CN = server.example.com

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:server.example.com, DNS:localhost, IP:127.0.0.1
EOF

# Generate server CSR
openssl req -new -key $SERVER_DIR/server.key -out $SERVER_DIR/server.csr -config $SERVER_DIR/server.cnf

# Create server extension file
cat > $SERVER_DIR/server.ext << 'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:server.example.com, DNS:localhost, IP:127.0.0.1
EOF

# Sign server certificate with Root CA
openssl x509 -req -days 365 -in $SERVER_DIR/server.csr -CA $CA_DIR/root-ca.crt -CAkey $CA_DIR/root-ca.key -set_serial 01 -out $SERVER_DIR/server.crt -extfile $SERVER_DIR/server.ext

echo "Generating Client certificate..."
# Generate client private key
openssl genrsa -out $CLIENT_DIR/client.key 2048

# Create client CSR config
cat > $CLIENT_DIR/client.cnf << 'EOF'
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = US
ST = State
L = City
O = Organization
CN = client.example.com

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Generate client CSR
openssl req -new -key $CLIENT_DIR/client.key -out $CLIENT_DIR/client.csr -config $CLIENT_DIR/client.cnf

# Create client extension file
cat > $CLIENT_DIR/client.ext << 'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Sign client certificate with Root CA
openssl x509 -req -days 365 -in $CLIENT_DIR/client.csr -CA $CA_DIR/root-ca.crt -CAkey $CA_DIR/root-ca.key -set_serial 02 -out $CLIENT_DIR/client.crt -extfile $CLIENT_DIR/client.ext

echo "Creating combined PEM files for server and client..."
# Combine server cert and key into pem (for some servers)
cat $SERVER_DIR/server.crt $SERVER_DIR/server.key > $SERVER_DIR/server.pem
# Combine client cert and key into pem (for clients)
cat $CLIENT_DIR/client.crt $CLIENT_DIR/client.key > $CLIENT_DIR/client.pem

echo "Copying CA cert to server and client for trust..."
cp $CA_DIR/root-ca.crt $SERVER_DIR/
cp $CA_DIR/root-ca.crt $CLIENT_DIR/

echo "Setting proper permissions..."
chmod 600 $CA_DIR/root-ca.key
chmod 600 $SERVER_DIR/server.key
chmod 600 $CLIENT_DIR/client.key

echo "Cleaning up temporary files..."
rm -f $CA_DIR/ca.cnf $SERVER_DIR/server.cnf $SERVER_DIR/server.ext $SERVER_DIR/server.csr $CLIENT_DIR/client.cnf $CLIENT_DIR/client.ext $CLIENT_DIR/client.csr

echo "Certificate generation completed."
echo "CA certificate: $CA_DIR/root-ca.crt"
echo "Server certificate: $SERVER_DIR/server.crt, key: $SERVER_DIR/server.key"
echo "Client certificate: $CLIENT_DIR/client.crt, key: $CLIENT_DIR/client.key"
