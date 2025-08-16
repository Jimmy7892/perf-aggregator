/**
 * Application constants
 */

// Default configuration values
export const DEFAULT_CONFIG = {
  ENCLAVE_PORT: 3000,
  ENCLAVE_HOST: '0.0.0.0',
  MAX_TTL_SECONDS: 604800, // 7 days
  DEFAULT_TTL_SECONDS: 86400, // 1 day
  RATE_LIMIT_MAX: 100,
  RATE_LIMIT_WINDOW: 900000, // 15 minutes
  REQUEST_SIZE_LIMIT: 1024 * 1024 // 1MB
} as const;

// Crypto constants
export const CRYPTO_CONFIG = {
  CURVE: 'X25519',
  AES_ALGORITHM: 'AES-GCM',
  HKDF_ALGORITHM: 'HKDF',
  HASH_ALGORITHM: 'SHA-256',
  NONCE_SIZE: 12,
  TAG_SIZE: 16,
  SALT_SIZE: 16
} as const;

// Database constants
export const DB_CONFIG = {
  CONNECTION_TIMEOUT: 2000,
  IDLE_TIMEOUT: 30000,
  MAX_CONNECTIONS: 20
} as const;

// Validation patterns
export const VALIDATION_PATTERNS = {
  BASE64: /^[A-Za-z0-9+/]+=*$/,
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  SESSION_ID: /^[a-f0-9]{32}$/,
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
} as const;

// TTL constants
export const TTL = {
  MIN_SECONDS: 300, // 5 minutes
  MAX_SECONDS: 604800, // 7 days
  DEFAULT_SECONDS: 86400, // 1 day
  CLEANUP_INTERVAL: 5 * 60 * 1000 // 5 minutes
} as const;

// Log levels
export const LOG_LEVELS = {
  INFO: 'INFO',
  WARN: 'WARN',
  ERROR: 'ERROR'
} as const;

// Session statuses
export const SESSION_STATUS = {
  PENDING: 'pending',
  ACTIVE: 'active',
  REVOKED: 'revoked',
  DONE: 'done'
} as const;

// User statuses
export const USER_STATUS = {
  ACTIVE: 'active',
  SUSPENDED: 'suspended',
  DELETED: 'deleted'
} as const;

// Security headers
export const SECURITY_HEADERS = {
  CSP_DIRECTIVES: {
    defaultSrc: ['\'self\''],
    scriptSrc: ['\'self\''],
    styleSrc: ['\'self\'', '\'unsafe-inline\''],
    imgSrc: ['\'self\'', 'data:', 'https:'],
    connectSrc: ['\'self\''],
    fontSrc: ['\'self\''],
    objectSrc: ['\'none\''],
    mediaSrc: ['\'self\''],
    frameSrc: ['\'none\'']
  },
  HSTS: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
} as const;

// Error messages
export const ERROR_MESSAGES = {
  INVALID_BASE64: 'Invalid base64 encoding in payload',
  INVALID_CREDENTIALS: 'Invalid credentials format',
  SESSION_NOT_FOUND: 'Session not found',
  SESSION_EXPIRED: 'Session expired',
  SESSION_INVALID_STATUS: 'Session status is invalid',
  ATTESTATION_FAILED: 'Attestation verification failed',
  ENCRYPTION_FAILED: 'Encryption failed',
  DECRYPTION_FAILED: 'Decryption failed',
  VALIDATION_FAILED: 'Validation failed',
  RATE_LIMIT_EXCEEDED: 'Rate limit exceeded',
  REQUEST_TOO_LARGE: 'Request too large',
  INTERNAL_ERROR: 'Internal server error'
} as const;
