# Secure TEE Enclave Backend Service

A production-ready backend service that accepts encrypted API credentials, processes them within a Trusted Execution Environment (TEE), computes performance aggregates, and returns cryptographically signed results. The service implements zero-plaintext storage architecture to ensure complete credential security.

## Security Architecture

### Core Security Principles
- **Prohibited**: Storage of API keys or secrets in plaintext format anywhere in the system
- **Permitted**: Storage of encrypted ciphertext, public ephemeral keys, nonces, authentication tags, non-sensitive metadata, session identifiers, and signed aggregate results

### Security Implementation
- Decrypted data exists only within TEE enclave memory
- Database encryption at rest using PostgreSQL TDE or disk-level encryption
- Role-based access control (RBAC) limiting database access
- Automatic TTL-based cleanup of encrypted credentials with immediate revocation capabilities

## Quick Start Guide

### Prerequisites
- PostgreSQL database server
- Node.js version 18 or higher

### Installation
```bash
npm install
npm run build
```

### Database Configuration
```bash
export DATABASE_URL="postgresql://username:password@localhost:5432/perf_aggregator"
npm run migrate
```

### Service Startup
```bash
npm run start:enclave
```
The service will be available at `http://localhost:3000`

### Verification
```bash
curl http://localhost:3000/attestation/quote
```

Expected response format:
```json
{
  "quote": "base64-encoded-attestation",
  "enclave_pubkey": "base64-encoded-public-key", 
  "image_hash": "enclave-measurement-hash"
}
```

### Client Integration Example
```javascript
import { CryptoHelper } from './src/client/crypto-helper.js';

// 1. Verify enclave attestation
const attestation = await fetch('/attestation/quote').then(r => r.json());
const verification = await CryptoHelper.verifyAttestation(attestation, attestation.image_hash);

// 2. Encrypt credentials using X25519 ECDH + AES-GCM
const encrypted = await CryptoHelper.encryptCredentials({
  exchange: 'binance',
  apiKey: 'your-api-key',
  apiSecret: 'your-secret'
}, attestation.enclave_pubkey);

// 3. Submit encrypted credentials to enclave
const response = await fetch('/enclave/submit_key', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    ...encrypted,
    metadata: { exchange: 'binance', label: 'main', ttl: 3600 }
  })
});

const { session_id } = await response.json();

// 4. Request signed aggregates
const aggregates = await fetch('/enclave/request_aggregates', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ session_id })
}).then(r => r.json());

console.log('Signed aggregates:', aggregates.aggregates_signed);
```

## API Endpoints

### `GET /attestation/quote`
Returns enclave attestation quote and public key for verification.

**Response:**
```json
{
  "quote": "base64-encoded-attestation-quote",
  "enclave_pubkey": "base64-encoded-public-key", 
  "image_hash": "enclave-measurement-hash"
}
```

### `POST /enclave/submit_key`
Submits encrypted API credentials to the enclave for secure processing.

**Request:**
```json
{
  "ephemeral_pub": "base64-encoded-ephemeral-public-key",
  "nonce": "base64-encoded-nonce", 
  "ciphertext": "base64-encoded-encrypted-credentials",
  "tag": "base64-encoded-authentication-tag",
  "metadata": {
    "exchange": "exchange-identifier",
    "label": "credential-label", 
    "ttl": 86400
  }
}
```

**Response:**
```json
{
  "session_id": "unique-session-identifier"
}
```

### `POST /enclave/request_aggregates`
Requests signed aggregate results for a specific session.

**Request:**
```json
{
  "session_id": "session-identifier"
}
```

**Response:**
```json
{
  "aggregates_signed": {
    "signature": "base64-encoded-signature",
    "payload": {
      "pnl": 123.45,
      "sharpe": 1.23,
      "volume": 1000.00,
      "trades": 150,
      "from": "2024-01-01T00:00:00Z",
      "to": "2024-01-02T00:00:00Z"
    }
  },
  "merkle_root": "merkle-proof-root-hash",
  "logs_url": "/api/logs/session-identifier"
}
```

### `POST /enclave/revoke`
Revokes a session and permanently purges all associated data.

**Request:**
```json
{
  "session_id": "session-identifier"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Session revoked and data purged"
}
```

## Configuration

### Environment Variables
```bash
# Enclave service port (default: 3000)
ENCLAVE_PORT=3000

# Database connection string
DATABASE_URL=postgresql://localhost:5432/perf_aggregator

# Maximum TTL in seconds (default: 7 days)
MAX_TTL_SECONDS=604800

# Rate limiting configuration (default: 100 requests per 15 minutes)
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=900000

# CORS allowed origins
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

### Available Commands
```bash
npm run build          # Compile TypeScript
npm run start          # Start original aggregation service
npm run start:enclave  # Start secure enclave service
npm run migrate        # Run database migrations
npm run test           # Execute unit and integration tests
npm run test:security  # Run security-specific tests
npm run dev            # Development mode with file watching
npm run lint           # Code linting
npm run format         # Code formatting
npm run typecheck      # TypeScript type checking
```

## Database Schema

### Core Tables
- **users**: User metadata (email, status, timestamps)
- **sessions**: Enclave sessions (exchange, label, TTL, status)  
- **credentials**: Encrypted data only (ephemeral_pub, nonce, ciphertext, tag)
- **aggregates**: Signed aggregate results (operator accessible)
- **merkle_logs**: Merkle proof verification data
- **ops_logs**: Non-sensitive operational logs

### Security Controls
- `operator_readonly` role: Read-only access excluding credentials table
- `app_service` role: Limited application access with specific permissions
- Base64 format validation constraints on encrypted fields
- Automatic TTL cleanup function for expired credentials
- Encrypted storage at rest with proper key management

## Testing

### Security Test Suite
```bash
npm test
npm run test:security
```

The test suite validates:
- No plaintext secrets stored in database
- Correct encryption and decryption operations
- Session isolation and data segregation
- Complete data purging on revocation
- Input validation and sanitization
- Rate limiting functionality

### End-to-End Integration Tests
- Complete client-to-enclave workflow validation
- Verification of zero plaintext exposure
- Session revocation and data purge verification
- Database security constraint enforcement

## Production Deployment

### TEE Enclave Integration
Replace `MockEnclaveService` with production TEE implementation:
- **AWS Nitro Enclaves**: For AWS cloud deployments
- **Intel SGX**: For on-premises environments
- **Azure Confidential Computing**: For Azure cloud deployments
- **Google Confidential GKE**: For Google Cloud deployments

### Production Security Requirements
1. **Database Encryption**: Enable PostgreSQL TDE or disk-level encryption
2. **Mutual TLS**: Secure service-to-enclave communications
3. **Hardware Attestation**: Implement real TEE quote verification
4. **Monitoring**: Comprehensive access and operation monitoring
5. **Reproducible Builds**: Verifiable image hashes for attestation

### Container Deployment
```bash
# Build container image
docker build -t secure-enclave-backend .

# Production deployment
docker run -d \
  -p 3000:3000 \
  -e DATABASE_URL=$SECURE_DB_URL \
  -e ENCLAVE_PORT=3000 \
  -e MAX_TTL_SECONDS=604800 \
  secure-enclave-backend
```

## Monitoring and Observability

### Key Metrics
- Active session count
- Enclave operation latency
- Encryption/decryption error rates
- TTL cleanup frequency
- Unauthorized access attempts

### Security Logging
- All enclave operations logged (excluding sensitive data)
- Credentials table access attempts audited
- Input validation errors tracked
- Rate limiting events recorded

## Development Warnings

**Current implementation uses mock enclave for development purposes.**

### Production Migration Requirements
1. **TEE Integration**: Replace MockEnclaveService with production TEE implementation
2. **Attestation Verification**: Implement hardware-based quote verification
3. **Key Management**: Replace development keys with production-grade key material
4. **Access Control**: Implement authentication for operator endpoints
5. **Monitoring**: Deploy comprehensive security monitoring

## Support and Documentation

### Technical Resources
- Test documentation: `src/__tests__/`
- Enclave interfaces: `src/enclave/`
- Client integration examples: `src/client/crypto-helper.ts`
- Security architecture: `SECURITY.md`

### Security Guidelines
- Review security documentation before production deployment
- Implement all recommended security controls
- Conduct security audit before handling production credentials
- Follow principle of least privilege for all access controls