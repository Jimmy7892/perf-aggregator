# Security Architecture Documentation

## Security Model

### Fundamental Security Principle
The system enforces zero-plaintext storage architecture: API keys and secrets are never stored in plaintext format anywhere within the system infrastructure.

### Threat Model
The system provides protection against the following attack vectors:

1. **Database Compromise**: Complete database access does not expose plaintext API credentials
2. **Log Analysis Attacks**: Sensitive data is excluded from all logging mechanisms
3. **Memory Exploitation**: Sensitive data exists exclusively in TEE enclave memory with immediate zeroing post-processing
4. **Insider Threats**: Administrative personnel cannot access encrypted credential data
5. **Network Interception**: All communications utilize cryptographically verified encryption
6. **Replay Attacks**: Cryptographic nonces and time-to-live mechanisms prevent replay exploitation
7. **Timing Analysis**: Constant-time operations implemented for cryptographic comparisons

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

## Cryptographic Implementation

### Client-Side Encryption Protocol (X25519 + AES-GCM)
1. **Key Generation**: Client generates ephemeral X25519 key pair
2. **Key Exchange**: Elliptic Curve Diffie-Hellman between client ephemeral private key and enclave public key
3. **Key Derivation**: AES-256-GCM key derived using HKDF with SHA-256
4. **Encryption**: Credentials encrypted using AES-256-GCM with random nonce
5. **Transmission**: Secure transmission of ephemeral public key, nonce, ciphertext, and authentication tag

### Enclave Processing Protocol
1. **Key Reconstruction**: Enclave reconstructs shared secret using stored private key
2. **Authenticated Decryption**: Credentials recovered exclusively in TEE memory
3. **Aggregate Computation**: Performance metrics calculated from decrypted data
4. **Digital Signing**: Results signed using enclave Ed25519 private key
5. **Memory Sanitization**: All sensitive data cryptographically zeroed

### Digital Signature Verification
- Ed25519 signatures provide cryptographic proof of data integrity
- Public key verification enables independent result validation
- Signature verification confirms enclave authenticity and data provenance

## Database Security

### Data Classification Matrix
| Data Type | Storage Policy | Access Control | Retention Policy |
|-----------|---------------|----------------|------------------|
| **API Keys** | Prohibited | No Access | Not Applicable |
| **Encrypted Credentials** | Encrypted Only | Application Service | TTL-Based Deletion |
| **Session Metadata** | Plaintext Permitted | RBAC Controlled | Business Requirements |
| **Signed Aggregates** | Plaintext Permitted | Operator Accessible | Long-Term Retention |
| **Operational Logs** | Non-Sensitive Only | RBAC Controlled | Compliance Period |

### Role-Based Access Control Implementation
```sql
-- Operator role: Read-only access excluding sensitive tables
GRANT SELECT ON users, sessions, aggregates, merkle_logs, ops_logs TO operator_readonly;
-- Explicit denial of credentials table access

-- Application service role: Minimal required permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON specified_tables TO app_service;
GRANT USAGE, SELECT ON required_sequences TO app_service;
```

### Database Encryption Standards
- **Data at Rest**: PostgreSQL Transparent Data Encryption (TDE) or filesystem-level encryption
- **Data in Transit**: Mandatory SSL/TLS with certificate validation
- **Backup Security**: Encrypted backup storage with separate key management
- **Key Management**: External Hardware Security Module (HSM) or cloud key management service

## Data Lifecycle Management

### Automated Cleanup Procedures
```sql
-- Scheduled cleanup execution every 5 minutes
SELECT cleanup_expired_credentials();
```

### Retention Policy Framework
- **Encrypted Credentials**: Automatic deletion upon TTL expiration (maximum 7 days)
- **Session Metadata**: Configurable retention based on business requirements
- **Signed Aggregates**: Long-term retention for business continuity
- **Audit Logs**: Retention period aligned with regulatory compliance requirements

## Attestation Security Framework

### Development Environment (Mock Implementation)
- Utilizes deterministic mock attestation quotes
- Implements basic structural validation
- **Critical Warning**: Not suitable for production environments

### Production Environment (Hardware TEE)
Production deployment requires implementation of:

1. **Quote Verification**: Cryptographic validation against vendor certificate authority
2. **Measurement Validation**: Verification of enclave code hash against expected values
3. **Security Configuration**: Validation of production mode flags and debug status
4. **Temporal Validation**: Freshness verification of attestation quotes
5. **Certificate Chain Validation**: Complete trust chain verification

#### AWS Nitro Enclaves Implementation Example
```javascript
// Production attestation verification
const attestationDocument = cbor.decode(Buffer.from(quote, 'base64'));
const cosePayload = attestationDocument.data;
// Verify signature against AWS Nitro root certificate authority
// Validate Platform Configuration Register (PCR) measurements
// Confirm timestamp validity and freshness
```

## Security Controls Framework

### Input Validation Protocol
- Comprehensive input validation using Zod schema validation library
- Base64 encoding format verification for all encrypted data fields
- Time-to-live (TTL) boundary enforcement (5 minutes to 7 days maximum)
- String sanitization for exchange identifiers and session labels

### Rate Limiting Implementation
- Default rate limit: 100 requests per 15-minute window per source IP
- Environment-specific configurable rate limiting parameters
- HTTP 429 "Too Many Requests" response for rate limit violations

### Security Headers and CORS Configuration
```javascript
// Comprehensive security headers implementation
helmet({
  contentSecurityPolicy: { /* Strict content security policy */ },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  // Additional security headers for comprehensive protection
})

// Cross-Origin Resource Sharing configuration
cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || false,
  credentials: false
})
```

### Request Size and DoS Protection
- Maximum request payload size: 1 MB
- JSON parser size limitations to prevent memory exhaustion
- Distributed Denial of Service (DoS) attack mitigation

## Security Testing Framework

### Critical Security Test Categories
1. **Plaintext Storage Verification**: Database inspection confirms absence of plaintext secrets
2. **Memory Security Validation**: Sensitive data cryptographic zeroing verification
3. **Cryptographic Operation Testing**: Encryption and decryption functionality validation
4. **Session Isolation Verification**: Cross-session data access prevention
5. **Revocation Completeness**: Comprehensive data purge validation
6. **Input Validation Testing**: Malformed request rejection verification
7. **Rate Limiting Validation**: Abuse prevention mechanism testing

### Security Test Implementation Examples
```typescript
// Critical security test: Plaintext storage prohibition
describe('Database Security Validation', () => {
  test('Verifies complete absence of plaintext secrets in database', async () => {
    // Submit encrypted credentials through standard flow
    // Perform direct database inspection
    // Assert no plaintext credentials exist in any table
  });
});

// Critical security test: Memory sanitization
describe('Memory Security Validation', () => {
  test('Confirms cryptographic memory zeroing', async () => {
    // Process sensitive data within enclave
    // Execute memory zeroing procedures
    // Verify complete data elimination
  });
});
```

## Security Considerations

### Development Environment Limitations
- **Mock Enclave Implementation**: Development-only implementation lacks production security guarantees
- **Simulated Attestation**: Mock attestation provides no cryptographic security assurance
- **Deterministic Key Material**: Development keys must be replaced with cryptographically secure alternatives
- **Enhanced Debug Logging**: Development logging may expose additional system information

### Production Security Requirements
1. **Hardware TEE Integration**: Replace MockEnclaveService with production TEE implementation
2. **Hardware-Based Attestation**: Implement cryptographic quote verification against vendor certificates
3. **Enterprise Key Management**: Deploy Hardware Security Module (HSM) or cloud-based key management
4. **End-to-End TLS**: Mandatory encryption for all network communications
5. **Security Information and Event Management (SIEM)**: Comprehensive security event monitoring
6. **Security Audit Logging**: Complete logging of all security-relevant operations
7. **Incident Response Framework**: Established procedures for security incident handling

## Incident Response Framework

### Security Event Detection Criteria
- Attestation verification failures
- Cryptographic operation anomalies
- Abnormal system access patterns
- Database security policy violations
- Rate limiting threshold breaches

### Incident Response Procedures
1. **Immediate Response**: Halt processing operations and preserve audit logs
2. **Impact Assessment**: Determine scope, severity, and potential data exposure
3. **Containment**: Revoke affected sessions and isolate compromised components
4. **Recovery Operations**: Restore system state from verified secure baseline
5. **Post-Incident Analysis**: Update security controls based on incident findings

## Security Monitoring and Alerting

### Critical Security Metrics
- Attestation verification success/failure ratios
- Cryptographic operation error frequencies
- Unauthorized database access attempts to restricted tables
- Rate limiting enforcement activations
- Automated TTL cleanup execution frequency
- Session revocation request patterns

### Security Alert Framework
- Real-time attestation verification failure alerts
- Database security policy violation notifications
- Anomalous error pattern detection and alerting
- Performance degradation indicators suggesting potential security incidents

## Security Maintenance Framework

### Routine Security Operations
- [ ] Cryptographic key rotation for enclave components
- [ ] Dependency vulnerability assessment and patching
- [ ] Security log analysis and anomaly review
- [ ] Disaster recovery procedure validation
- [ ] Threat model updates based on emerging threats
- [ ] Security awareness training for operational personnel

### Compliance and Governance
- Adherence to applicable security standards (SOC 2, ISO 27001, PCI DSS)
- Scheduled independent security audits
- Regular penetration testing and vulnerability assessments
- Compliance reporting and documentation maintenance

## Security Contact Framework

### Incident Escalation Procedures
1. **Critical Security Incidents**: Immediate escalation to designated security response team
2. **Non-Critical Security Issues**: Standard security review and assessment process
3. **Security Architecture Questions**: Security architecture and design team consultation
4. **Compliance and Audit**: Compliance team coordination and support

### Security Responsibility Framework
Security implementation and maintenance is a shared responsibility across all system stakeholders. When security considerations are uncertain, implementation should prioritize the most secure approach available.