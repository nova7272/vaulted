#!/bin/bash
# =============================================================================
# XRPL Vault — Root CA & Server Certificate Generator
# =============================================================================
# Creates a private Root CA and signs a server certificate for Oracle.
# The Root CA cert is embedded in the desktop client.
# Server cert can be rotated without updating the client.
# =============================================================================

set -e

CA_DIR="./certs/ca"
SERVER_DIR="./certs/server"
CLIENT_DIR="./certs/client"
CA_VALIDITY_DAYS=3650   # 10 years
SERVER_VALIDITY_DAYS=365 # 1 year
COUNTRY="NL"
ORG="XRPL Vault"

# Parse arguments
ORACLE_DOMAIN="${1:-localhost}"
ORACLE_IP="${2:-127.0.0.1}"

echo "╔══════════════════════════════════════════════════╗"
echo "║   XRPL Vault — Certificate Authority Setup        ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Oracle domain: $ORACLE_DOMAIN"
echo "Oracle IP:     $ORACLE_IP"
echo ""

# =============================================================================
# Step 1: Create Root CA
# =============================================================================
echo "━━━ Step 1: Creating Root CA ━━━"

mkdir -p "$CA_DIR" "$SERVER_DIR" "$CLIENT_DIR"

if [ -f "$CA_DIR/ca-key.pem" ]; then
    echo "  ⚠️  Root CA already exists. Skipping creation."
    echo "  To regenerate, delete $CA_DIR/ first."
else
    # Generate CA private key (4096-bit RSA)
    openssl genrsa -out "$CA_DIR/ca-key.pem" 4096
    chmod 600 "$CA_DIR/ca-key.pem"

    # Generate CA certificate
    openssl req -new -x509 \
        -key "$CA_DIR/ca-key.pem" \
        -out "$CA_DIR/ca-cert.pem" \
        -days "$CA_VALIDITY_DAYS" \
        -subj "/C=$COUNTRY/O=$ORG/CN=XRPL Vault Root CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    echo "  ✅ Root CA created"
    echo "     Key:  $CA_DIR/ca-key.pem (KEEP SECRET!)"
    echo "     Cert: $CA_DIR/ca-cert.pem (embed in client)"
    echo "     Valid: $CA_VALIDITY_DAYS days"
fi

echo ""

# =============================================================================
# Step 2: Create Server Certificate
# =============================================================================
echo "━━━ Step 2: Creating Server Certificate ━━━"

# Create SAN (Subject Alternative Name) config
cat > "$SERVER_DIR/san.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $COUNTRY
O = $ORG
CN = $ORACLE_DOMAIN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $ORACLE_DOMAIN
DNS.2 = localhost
IP.1 = $ORACLE_IP
IP.2 = 127.0.0.1
EOF

# Generate server private key
openssl genrsa -out "$SERVER_DIR/server-key.pem" 2048
chmod 600 "$SERVER_DIR/server-key.pem"

# Generate CSR (Certificate Signing Request)
openssl req -new \
    -key "$SERVER_DIR/server-key.pem" \
    -out "$SERVER_DIR/server.csr" \
    -config "$SERVER_DIR/san.cnf"

# Sign with CA
openssl x509 -req \
    -in "$SERVER_DIR/server.csr" \
    -CA "$CA_DIR/ca-cert.pem" \
    -CAkey "$CA_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$SERVER_DIR/server-cert.pem" \
    -days "$SERVER_VALIDITY_DAYS" \
    -extensions v3_req \
    -extfile "$SERVER_DIR/san.cnf"

# Create full chain (server cert + CA cert)
cat "$SERVER_DIR/server-cert.pem" "$CA_DIR/ca-cert.pem" > "$SERVER_DIR/server-fullchain.pem"

echo "  ✅ Server certificate created"
echo "     Key:   $SERVER_DIR/server-key.pem"
echo "     Cert:  $SERVER_DIR/server-cert.pem"
echo "     Chain: $SERVER_DIR/server-fullchain.pem"
echo "     Valid: $SERVER_VALIDITY_DAYS days"
echo ""

# =============================================================================
# Step 3: Copy CA cert for client embedding
# =============================================================================
echo "━━━ Step 3: Preparing client certificate ━━━"

cp "$CA_DIR/ca-cert.pem" "$CLIENT_DIR/oracle-ca.pem"

echo "  ✅ Client CA cert: $CLIENT_DIR/oracle-ca.pem"
echo "     → Embed this in your desktop client"
echo "     → Or place next to .exe as 'oracle-ca.pem'"
echo ""

# =============================================================================
# Step 4: Verification
# =============================================================================
echo "━━━ Step 4: Verification ━━━"

# Verify chain
openssl verify -CAfile "$CA_DIR/ca-cert.pem" "$SERVER_DIR/server-cert.pem"

# Show certificate info
echo ""
echo "  CA Certificate:"
openssl x509 -in "$CA_DIR/ca-cert.pem" -noout -subject -dates | sed 's/^/    /'
echo ""
echo "  Server Certificate:"
openssl x509 -in "$SERVER_DIR/server-cert.pem" -noout -subject -dates -ext subjectAltName | sed 's/^/    /'

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║                    USAGE                          ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║                                                    ║"
echo "║  Oracle (nginx or direct):                         ║"
echo "║    ssl_certificate     server-fullchain.pem        ║"
echo "║    ssl_certificate_key server-key.pem              ║"
echo "║                                                    ║"
echo "║  Desktop Client config:                            ║"
echo "║    tls_cert_path: 'oracle-ca.pem'                  ║"
echo "║                                                    ║"
echo "║  Renew server cert (no client update needed):      ║"
echo "║    ./generate-certs.sh $ORACLE_DOMAIN $ORACLE_IP   ║"
echo "║                                                    ║"
echo "╚══════════════════════════════════════════════════╝"
