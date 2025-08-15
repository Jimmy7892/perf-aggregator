# Security Documentation

## 🛡️ Security Model

### Core Security Principle
**NEVER store API keys or secrets in plaintext anywhere in the system.**

### Threat Model
This system is designed to protect against:
1. **Database compromise** - Even with full DB access, attackers cannot recover plaintext API keys
2. **Log analysis attacks** - No sensitive data appears in logs
3. **Memory dumps** - Sensitive data exists only in enclave memory and is zeroed after use
4. **Insider threats** - Operators cannot access encrypted credentials
5. **Man-in-the-middle** - All communications use verified encryption
6. **Replay attacks** - Nonces and TTL prevent replay
7. **Timing attacks** - Constant-time operations where applicable

### Security Architecture

```
┌─────────────────┐    Encrypted     ┌─────────────────┐    Plaintext    ┌─────────────────┐
│   Client App    │─────────────────▶│  Backend API    │────────────────▶│  TEE Enclave    │
│                 │  X25519+AES-GCM  │                 │   Memory Only   │                 │
│ • Verify Quote  │                  │ • Store Cipher  │                 │ • Decrypt       │
│ • Encrypt Keys  │◀─────────────────│ • Never Decrypt │◀────────────────│ • Compute       │
│ • Verify Sigs   │  Signed Results  │ • Audit Logs    │  Signed Results │ • Sign & Zero   │
└─────────────────┘                  └─────────────────┘                  └─────────────────┘
         ▲                                     ▲                                     ▲
         │                                     │                                     │
    Attestation                         Database (PG)                         Hardware TEE
    Verification                     ┌─────────────────┐                    ┌─────────────────┐
                                     │ ✅ Ciphertext   │                    │ • AWS Nitro     │
                                     │ ✅ Metadata     │                    │ • Intel SGX     │
                                     │ ❌ Plaintext    │                    │ • Azure CC      │
                                     │ ❌ API Keys     │                    │ • (Mock in dev) │
                                     └─────────────────┘                    └─────────────────┘
```

## 🔐 Cryptographic Security

### Client-Side Encryption (X25519 + AES-GCM)
1. **Key Exchange**: Client generates ephemeral X25519 key pair
2. **ECDH**: Shared secret = ECDH(client_private, enclave_public)
3. **Key Derivation**: AES key = HKDF(shared_secret, salt, info)
4. **Encryption**: AES-GCM(credentials, key, nonce) → (ciphertext, tag)
5. **Transmission**: Send (ephemeral_pub, nonce, ciphertext, tag)

### Enclave Operations
1. **ECDH**: Reconstruct shared secret using enclave private key
2. **Decryption**: Recover credentials in enclave memory only
3. **Processing**: Compute aggregates from decrypted data
4. **Signing**: Sign results with enclave's Ed25519 key
5. **Memory Zeroing**: Securely zero all sensitive data

### Signature Verification
- All aggregate results are signed with Ed25519
- Clients can verify signatures using enclave's public key
- Signatures prove data integrity and authenticity

## 🗄️ Database Security

### Data Classification
| Data Type | Storage | Access | Retention |
|-----------|---------|--------|-----------|
| **API Keys** | ❌ NEVER | ❌ NEVER | ❌ NEVER |
| **Ciphertext** | ✅ Encrypted | App only | TTL auto-delete |
| **Metadata** | ✅ Plaintext | RBAC limited | Business rules |
| **Signatures** | ✅ Plaintext | Operator view | Long-term |
| **Logs** | ✅ Non-sensitive | RBAC limited | Retention policy |

### RBAC (Role-Based Access Control)
```sql
-- Operator role: Can view aggregates, cannot access credentials
GRANT SELECT ON users, sessions, aggregates, merkle_logs, ops_logs TO operator_readonly;
-- EXPLICITLY DENY access to credentials table

-- Application role: Limited access for service operations
GRANT SELECT, INSERT, UPDATE, DELETE ON all_tables TO app_service;
GRANT USAGE, SELECT ON ALL SEQUENCES TO app_service;
```

### Database Encryption
- **At Rest**: PostgreSQL TDE (Transparent Data Encryption)
- **In Transit**: SSL/TLS connections required
- **Backup**: Encrypted backups only
- **Key Management**: External key management system

## 🕐 TTL and Data Retention

### Automatic Cleanup
```sql
-- TTL cleanup runs every 5 minutes
SELECT cleanup_expired_credentials();
```

### Retention Policies
- **Encrypted Credentials**: Auto-delete after TTL (max 7 days)
- **Session Metadata**: Configurable retention
- **Signed Aggregates**: Long-term retention (business need)
- **Audit Logs**: Regulatory compliance period

## 🔍 Attestation Security

### Development (Mock)
- Uses deterministic mock quotes
- Validates basic structure
- **WARNING**: Not secure for production

### Production (Real TEE)
Must implement:
1. **Quote Verification**: Validate against vendor CA
2. **Measurement Check**: Verify enclave code hash
3. **Security Flags**: Check debug/production mode
4. **Freshness**: Ensure quote is recent
5. **Chain of Trust**: Validate complete certificate chain

Example for AWS Nitro:
```javascript
// Verify Nitro attestation document
const attestationDoc = cbor.decode(Buffer.from(quote, 'base64'));
const cose = attestationDoc.data;
// Verify signature against AWS root CA
// Check PCR measurements
// Validate timestamp
```

## 🛠️ Security Controls

### Input Validation
- All inputs validated with Zod schemas
- Base64 format validation for encrypted fields
- TTL limits enforced (5 min to 7 days max)
- Exchange and label string sanitization

### Rate Limiting
- 100 requests per 15-minute window per IP
- Configurable limits per environment
- 429 Too Many Requests on limit exceeded

### CORS and Headers
```javascript
// Security headers
helmet({
  contentSecurityPolicy: { /* strict policy */ },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  // ... other security headers
})

// CORS
cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || false,
  credentials: false
})
```

### Request Size Limits
- 1MB maximum request size
- JSON parser size limits
- Prevents DoS attacks

## 🔬 Security Testing

### Critical Test Categories
1. **No Plaintext Storage**: Verify DB never contains plaintext secrets
2. **Memory Security**: Ensure sensitive data is zeroed
3. **Encryption/Decryption**: Validate crypto operations
4. **Session Isolation**: Sessions cannot access each other's data
5. **Revocation**: Complete data purge on revocation
6. **Input Validation**: Reject malformed requests
7. **Rate Limiting**: Prevent abuse

### Security Test Examples
```typescript
// CRITICAL: Verify no plaintext in database
test('Database never contains plaintext secrets', async () => {
  // Submit encrypted credentials
  // Query database directly
  // Assert no plaintext appears anywhere
});

// CRITICAL: Memory is zeroed after use
test('Memory is securely zeroed', async () => {
  // Use sensitive data
  // Zero memory
  // Verify data is gone
});
```

## ⚠️ Security Warnings

### Development Environment
- ⚠️ **Mock Enclave**: Not secure, for development only
- ⚠️ **Mock Attestation**: No real verification
- ⚠️ **Deterministic Keys**: Replace in production
- ⚠️ **Debug Logging**: May expose more information

### Production Requirements
1. **Real TEE**: Replace MockEnclaveService
2. **Hardware Attestation**: Implement proper quote verification
3. **Key Management**: Secure key generation and storage
4. **TLS Everywhere**: Encrypt all communications
5. **Monitoring**: Comprehensive security monitoring
6. **Auditing**: Log all security events
7. **Incident Response**: Security incident procedures

## 🚨 Incident Response

### Security Event Detection
- Failed attestation verifications
- Invalid encryption attempts
- Unusual access patterns
- Database access violations
- Rate limit breaches

### Response Procedures
1. **Immediate**: Stop processing, preserve logs
2. **Assessment**: Determine scope and impact
3. **Containment**: Revoke affected sessions
4. **Recovery**: Restore from secure state
5. **Lessons Learned**: Update security measures

## 📊 Security Monitoring

### Key Metrics
- Attestation verification success rate
- Encryption/decryption error rates
- Database access attempts to restricted tables
- Rate limiting activations
- TTL cleanup frequency
- Session revocation rates

### Alerting
- Failed attestation verifications
- Database access violations
- Unusual error patterns
- Performance anomalies that might indicate attacks

## 🔄 Security Updates

### Regular Security Tasks
- [ ] Review and rotate enclave keys
- [ ] Update dependency security patches
- [ ] Review access logs for anomalies
- [ ] Test disaster recovery procedures
- [ ] Update threat model based on new threats
- [ ] Security training for operators

### Compliance
- Follow relevant standards (SOC 2, ISO 27001, etc.)
- Regular security audits
- Penetration testing
- Compliance reporting

## 📞 Security Contacts

For security issues:
1. **Critical**: Immediate escalation to security team
2. **Non-Critical**: Security review process
3. **Questions**: Security architecture team
4. **Auditing**: Compliance team

**Remember**: Security is everyone's responsibility. When in doubt, err on the side of caution.