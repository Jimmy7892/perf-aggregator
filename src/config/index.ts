/**
 * Centralized application configuration
 * Now uses environment-based configuration for better production support
 */

import { getEnvironment } from './environment.js';

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
  logging: {
    level: string;
    publicEnabled: boolean;
    publicPort: number;
  };
}

let cachedConfig: AppConfig | null = null;

export function getConfig(): AppConfig {
  if (cachedConfig) {
    return cachedConfig;
  }

  const env = getEnvironment();

  cachedConfig = {
    server: {
      port: env.ENCLAVE_PORT,
      host: env.ENCLAVE_HOST
    },
    security: {
      maxTtl: env.MAX_SESSION_TTL,
      defaultTtl: env.DEFAULT_SESSION_TTL,
      rateLimitMax: env.RATE_LIMIT_MAX,
      rateLimitWindow: env.RATE_LIMIT_WINDOW,
      requestSizeLimit: 1024 * 1024 // 1MB
    },
    crypto: {
      curve: 'X25519',
      aesAlgorithm: 'AES-GCM',
      hkdfAlgorithm: 'HKDF',
      hashAlgorithm: 'SHA-256',
      nonceSize: 12,
      tagSize: 16,
      saltSize: 16
    },
    exchanges: {
      defaultApiInterval: env.DEFAULT_API_INTERVAL,
      maxRetries: env.MAX_RETRIES,
      enableRateLimit: true,
      defaultRateLimit: 1000 // 1 second
    },
    cleanup: {
      sessionCleanupInterval: env.SESSION_CLEANUP_INTERVAL,
      dataRetentionDays: env.DATA_RETENTION_DAYS
    },
    logging: {
      level: env.LOG_LEVEL,
      publicEnabled: env.PUBLIC_LOGS_ENABLED,
      publicPort: env.PUBLIC_LOGS_PORT
    }
  };

  return cachedConfig;
}
