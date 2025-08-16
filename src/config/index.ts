/**
 * Centralized application configuration
 */

export interface AppConfig {
  server: {
    port: number;
    host: string;
  };
  security: {
    maxTtl: number;
    defaultTtl: number;
    rateLimitMax: number;
    rateLimitWindow: number;
    requestSizeLimit: number;
  };
  crypto: {
    curve: string;
    aesAlgorithm: string;
    hkdfAlgorithm: string;
    hashAlgorithm: string;
    nonceSize: number;
    tagSize: number;
    saltSize: number;
  };
  exchanges: {
    defaultApiInterval: number;
    maxRetries: number;
    enableRateLimit: boolean;
    defaultRateLimit: number;
  };
  cleanup: {
    sessionCleanupInterval: number;
    dataRetentionDays: number;
  };
}

export const defaultConfig: AppConfig = {
  server: {
    port: parseInt(process.env.ENCLAVE_PORT || '3000'),
    host: process.env.ENCLAVE_HOST || '0.0.0.0',
  },
  security: {
    maxTtl: 604800, // 7 days
    defaultTtl: 86400, // 1 day
    rateLimitMax: 100,
    rateLimitWindow: 900000, // 15 minutes
    requestSizeLimit: 1024 * 1024, // 1MB
  },
  crypto: {
    curve: 'X25519',
    aesAlgorithm: 'AES-GCM',
    hkdfAlgorithm: 'HKDF',
    hashAlgorithm: 'SHA-256',
    nonceSize: 12,
    tagSize: 16,
    saltSize: 16,
  },
  exchanges: {
    defaultApiInterval: 60000, // 1 minute
    maxRetries: 3,
    enableRateLimit: true,
    defaultRateLimit: 1000, // 1 second
  },
  cleanup: {
    sessionCleanupInterval: 3600000, // 1 hour
    dataRetentionDays: 30,
  },
};

export function getConfig(): AppConfig {
  return defaultConfig;
}
