/**
 * Centralized environment variable configuration
 * Validates and provides typed access to all environment variables
 */

import { z } from 'zod';

const EnvironmentSchema = z.object({
  // Server configuration
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  ENCLAVE_PORT: z.string().transform(val => parseInt(val, 10)).default('3000'),
  ENCLAVE_HOST: z.string().default('0.0.0.0'),

  // Database configuration
  DATABASE_URL: z.string().optional(),

  // Security configuration
  JWT_SECRET: z.string().optional(),
  JWT_EXPIRES_IN: z.string().default('24h'),

  // Crypto keys (production only)
  ENCLAVE_PRIVATE_KEY_PATH: z.string().optional(),
  ENCLAVE_PUBLIC_KEY_PATH: z.string().optional(),

  // Rate limiting
  RATE_LIMIT_MAX: z.string().transform(val => parseInt(val, 10)).default('100'),
  RATE_LIMIT_WINDOW: z.string().transform(val => parseInt(val, 10)).default('900000'), // 15 minutes

  // TTL configuration
  MAX_SESSION_TTL: z.string().transform(val => parseInt(val, 10)).default('604800'), // 7 days
  DEFAULT_SESSION_TTL: z.string().transform(val => parseInt(val, 10)).default('86400'), // 1 day

  // Exchange configuration
  DEFAULT_API_INTERVAL: z.string().transform(val => parseInt(val, 10)).default('60000'), // 1 minute
  MAX_RETRIES: z.string().transform(val => parseInt(val, 10)).default('3'),

  // Cleanup intervals
  SESSION_CLEANUP_INTERVAL: z.string().transform(val => parseInt(val, 10)).default('3600000'), // 1 hour
  DATA_RETENTION_DAYS: z.string().transform(val => parseInt(val, 10)).default('30'),

  // Logging configuration
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  PUBLIC_LOGS_ENABLED: z.string().transform(val => val === 'true').default('true'),
  PUBLIC_LOGS_PORT: z.string().transform(val => parseInt(val, 10)).default('3001'),

  // External services
  BACKEND_URL: z.string().optional(),
  AGGREGATOR_BACKEND_URL: z.string().optional()
});

export type Environment = z.infer<typeof EnvironmentSchema>;

let cachedEnv: Environment | null = null;

/**
 * Get validated environment configuration
 * Caches the result for performance
 */
export function getEnvironment(): Environment {
  if (cachedEnv) {
    return cachedEnv;
  }

  try {
    cachedEnv = EnvironmentSchema.parse(process.env);
    return cachedEnv;
  } catch (error) {
    if (error instanceof z.ZodError) {
      const issues = error.issues.map(issue => `${issue.path.join('.')}: ${issue.message}`);
      throw new Error(`Environment validation failed:\n${issues.join('\n')}`);
    }
    throw error;
  }
}

/**
 * Check if running in production
 */
export function isProduction(): boolean {
  return getEnvironment().NODE_ENV === 'production';
}

/**
 * Check if running in development
 */
export function isDevelopment(): boolean {
  return getEnvironment().NODE_ENV === 'development';
}

/**
 * Check if running in test environment
 */
export function isTest(): boolean {
  return getEnvironment().NODE_ENV === 'test';
}

/**
 * Get database URL with validation
 */
export function getDatabaseUrl(): string {
  const env = getEnvironment();
  if (!env.DATABASE_URL) {
    throw new Error('DATABASE_URL is required');
  }
  return env.DATABASE_URL;
}

/**
 * Get JWT secret with validation
 */
export function getJwtSecret(): string {
  const env = getEnvironment();
  if (!env.JWT_SECRET) {
    if (isProduction()) {
      throw new Error('JWT_SECRET is required in production');
    }
    // Return development default
    return 'dev-jwt-secret-change-in-production';
  }
  return env.JWT_SECRET;
}
