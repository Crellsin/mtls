#!/bin/bash

set -e

CERTS_DIR="mtls_auth/certs"
CA_DIR="$CERTS_DIR/ca"
SERVER_DIR="$CERTS_DIR/server"
CLIENT_DIR="$CERTS_DIR/client"

# Create directories
mkdir -p $CA_DIR $SERVER_DIR $CLIENT_DIR

echo "Generating Root CA..."
# Generate Root CA private key
openssl genrsa -out $CA_DIR/root-ca.key 4096
# Generate Root CA certificate
openssl req -new -x509 -days 3650 -key $CA_DIR/root-ca.key -out $CA_DIR/root-ca.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=Root CA"

echo "Generating Server certificate..."
# Generate server private key
openssl genrsa -out $SERVER_DIR/server.key 2048
# Generate server CSR
openssl req -new -key $SERVER_DIR/server.key -out $SERVER_DIR/server.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=server.example.com"
# Sign server certificate with Root CA
openssl x509 -req -days 365 -in $SERVER_DIR/server.csr -CA $CA_DIR/root-ca.crt -CAkey $CA_DIR/root-ca.key -set_serial 01 -out $SERVER_DIR/server.crt

echo "Generating Client certificate..."
# Generate client private key
openssl genrsa -out $CLIENT_DIR/client.key 2048
# Generate client CSR
openssl req -new -key $CLIENT_DIR/client.key -out $CLIENT_DIR/client.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=client.example.com"
# Sign client certificate with Root CA
openssl x509 -req -days 365 -in $CLIENT_DIR/client.csr -CA $CA_DIR/root-ca.crt -CAkey $CA_DIR/root-ca.key -set_serial 02 -out $CLIENT_DIR/client.crt

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

echo "Certificate generation completed."
echo "CA certificate: $CA_DIR/root-ca.crt"
echo "Server certificate: $SERVER_DIR/server.crt, key: $SERVER_DIR/server.key"
echo "Client certificate: $CLIENT_DIR/client.crt, key: $CLIENT_DIR/client.key"
