/**
 * Authentication and Authorization Middleware
 *
 * Provides JWT-based authentication and role-based access control
 * for operator endpoints and administrative functions.
 */

import { FastifyRequest, FastifyReply } from 'fastify';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { Database } from '../database.js';
import { ERROR_MESSAGES } from '../constants.js';

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: UserRole;
  permissions: string[];
}

export interface JWTPayload {
  userId: string;
  email: string;
  role: UserRole;
  permissions: string[];
  iat: number;
  exp: number;
}

export type UserRole = 'operator' | 'admin' | 'viewer' | 'service';

export interface AuthConfig {
  jwtSecret: string;
  jwtExpiresIn: string;
  bcryptRounds: number;
  requireHttps: boolean;
}

// Role-based permissions
const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  admin: [
    'sessions:read',
    'sessions:write',
    'users:read',
    'users:write',
    'aggregates:read',
    'system:manage'
  ],
  operator: [
    'sessions:read',
    'users:read',
    'aggregates:read'
  ],
  viewer: [
    'aggregates:read'
  ],
  service: [
    'sessions:write',
    'aggregates:write'
  ]
};

export class AuthenticationService {
  private config: AuthConfig;
  private db: Database;

  constructor(db: Database, config?: Partial<AuthConfig>) {
    this.db = db;
    this.config = {
      jwtSecret: process.env.JWT_SECRET || 'development-secret-change-in-production',
      jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
      bcryptRounds: Number(process.env.BCRYPT_ROUNDS) || 12,
      requireHttps: process.env.NODE_ENV === 'production',
      ...config
    };

    if (process.env.NODE_ENV === 'production' && this.config.jwtSecret === 'development-secret-change-in-production') {
      throw new Error('JWT_SECRET must be set in production environment');
    }
  }

  /**
   * Hash password using bcrypt
   */
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.config.bcryptRounds);
  }

  /**
   * Verify password against hash
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  /**
   * Generate JWT token for authenticated user
   */
  generateToken(user: AuthenticatedUser): string {
    const payload: Omit<JWTPayload, 'iat' | 'exp'> = {
      userId: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions
    };

    return jwt.sign(payload, this.config.jwtSecret, {
      expiresIn: this.config.jwtExpiresIn,
      issuer: 'secure-enclave-backend',
      audience: 'enclave-operators'
    } as jwt.SignOptions);
  }

  /**
   * Verify and decode JWT token
   */
  verifyToken(token: string): JWTPayload {
    try {
      return jwt.verify(token, this.config.jwtSecret, {
        issuer: 'secure-enclave-backend',
        audience: 'enclave-operators'
      }) as JWTPayload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Token expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid token');
      }
      throw new Error('Token verification failed');
    }
  }

  /**
   * Check if user has required permission
   */
  hasPermission(user: AuthenticatedUser, requiredPermission: string): boolean {
    return user.permissions.includes(requiredPermission);
  }

  /**
   * Get permissions for role
   */
  getRolePermissions(role: UserRole): string[] {
    return ROLE_PERMISSIONS[role] || [];
  }
}

/**
 * Extract bearer token from authorization header
 */
function extractBearerToken(authHeader?: string): string | null {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7);
}

/**
 * Authentication middleware - verifies JWT token
 */
export function requireAuthentication(authService: AuthenticationService) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    try {
      // Check HTTPS requirement in production
      if (authService['config'].requireHttps && request.protocol !== 'https') {
        reply.code(400).send({
          error: 'HTTPS required',
          message: 'Authentication requires secure connection'
        });
        return;
      }

      // Extract token from Authorization header
      const token = extractBearerToken(request.headers.authorization);
      if (!token) {
        reply.code(401).send({
          error: 'Authentication required',
          message: 'Bearer token missing from Authorization header'
        });
        return;
      }

      // Verify token
      const payload = authService.verifyToken(token);

      // Attach user to request
      (request as any).user = {
        id: payload.userId,
        email: payload.email,
        role: payload.role,
        permissions: payload.permissions
      } as AuthenticatedUser;

    } catch (error) {
      reply.code(401).send({
        error: 'Authentication failed',
        message: error instanceof Error ? error.message : 'Invalid token'
      });
    }
  };
}

/**
 * Authorization middleware - checks user permissions
 */
export function requirePermission(permission: string) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const user = (request as any).user as AuthenticatedUser;

    if (!user) {
      reply.code(401).send({
        error: 'Authentication required',
        message: 'User not authenticated'
      });
      return;
    }

    if (!user.permissions.includes(permission)) {
      reply.code(403).send({
        error: 'Insufficient permissions',
        message: `Required permission: ${permission}`,
        userPermissions: user.permissions
      });
      return;
    }
  };
}

/**
 * Role-based authorization middleware
 */
export function requireRole(requiredRole: UserRole | UserRole[]) {
  const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const user = (request as any).user as AuthenticatedUser;

    if (!user) {
      reply.code(401).send({
        error: 'Authentication required',
        message: 'User not authenticated'
      });
      return;
    }

    if (!roles.includes(user.role)) {
      reply.code(403).send({
        error: 'Insufficient role',
        message: `Required role: ${roles.join(' or ')}`,
        userRole: user.role
      });
      return;
    }
  };
}

/**
 * API Key authentication middleware (for service-to-service)
 */
export function requireApiKey(validApiKeys: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const apiKey = request.headers['x-api-key'] as string;

    if (!apiKey) {
      reply.code(401).send({
        error: 'API key required',
        message: 'X-API-Key header missing'
      });
      return;
    }

    // Use constant-time comparison to prevent timing attacks
    const isValidKey = validApiKeys.some(validKey => {
      if (validKey.length !== apiKey.length) return false;

      let result = 0;
      for (let i = 0; i < validKey.length; i++) {
        result |= validKey.charCodeAt(i) ^ apiKey.charCodeAt(i);
      }
      return result === 0;
    });

    if (!isValidKey) {
      reply.code(401).send({
        error: 'Invalid API key',
        message: 'Provided API key is not valid'
      });
      return;
    }

    // Set service user context
    (request as any).user = {
      id: 'service',
      email: 'service@enclave.local',
      role: 'service' as UserRole,
      permissions: ROLE_PERMISSIONS.service
    } as AuthenticatedUser;
  };
}

/**
 * Rate limiting by user ID
 */
export function rateLimitByUser(maxRequests: number, windowMs: number) {
  const userCounts = new Map<string, { count: number; resetTime: number }>();

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const user = (request as any).user as AuthenticatedUser;
    if (!user) return; // Skip if no user (handled by auth middleware)

    const now = Date.now();
    const userId = user.id;
    const userLimit = userCounts.get(userId);

    if (!userLimit || now > userLimit.resetTime) {
      // Reset or initialize counter
      userCounts.set(userId, {
        count: 1,
        resetTime: now + windowMs
      });
      return;
    }

    if (userLimit.count >= maxRequests) {
      reply.code(429).send({
        error: 'Rate limit exceeded',
        message: `Maximum ${maxRequests} requests per ${windowMs / 1000} seconds`,
        retryAfter: Math.ceil((userLimit.resetTime - now) / 1000)
      });
      return;
    }

    userLimit.count++;
  };
}

/**
 * Audit logging middleware
 */
export function auditLog(db: Database, action: string) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const user = (request as any).user as AuthenticatedUser;
    const clientIp = request.ip;
    const userAgent = request.headers['user-agent'];

    try {
      await db.logOperation('INFO',
        `Audit: ${action} by ${user?.email || 'anonymous'} from ${clientIp}`,
        undefined
      );
    } catch (error) {
      // Don't fail request if audit logging fails
      console.error('Audit logging failed:', error);
    }
  };
}

// Type augmentation for Fastify request
declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
  }
}
