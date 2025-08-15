/**
 * Shared TypeScript type definitions
 */

// Database types
export interface User {
  id: string;
  email: string;
  created_at: Date;
  status: 'active' | 'suspended' | 'deleted';
}

export interface Session {
  id: string;
  user_id: string;
  exchange: string;
  label: string;
  created_at: Date;
  expires_at: Date;
  status: 'pending' | 'active' | 'revoked' | 'done';
}

export interface Credential {
  id: string;
  session_id: string;
  ephemeral_pub: string;
  nonce: string;
  ciphertext: Buffer;
  tag: string;
  created_at: Date;
  expires_at: Date;
}

export interface Aggregate {
  id: string;
  session_id: string;
  aggregates_signed: any;
  signed_by: string;
  created_at: Date;
}

export interface MerkleLog {
  id: string;
  session_id: string;
  merkle_root: string;
  proof_url: string | null;
  created_at: Date;
}

// API types
export interface EncryptedPayload {
  ephemeral_pub: string;
  nonce: string;
  ciphertext: string;
  tag: string;
}

export interface DecryptedCredentials {
  exchange: string;
  apiKey: string;
  apiSecret: string;
  sandbox?: boolean;
  symbols?: string[];
}

export interface AggregateResult {
  pnl: number;
  sharpe: number;
  volume: number;
  trades: number;
  from: string;
  to: string;
}

export interface SignedAggregates {
  signature: string;
  payload: AggregateResult;
}

export interface AttestationQuote {
  quote: string;
  enclave_pubkey: string;
  image_hash: string;
}

// Request/Response types
export interface SubmitKeyRequest {
  ephemeral_pub: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  metadata: {
    exchange: string;
    label: string;
    ttl?: number;
  };
}

export interface SubmitKeyResponse {
  session_id: string;
}

export interface RequestAggregatesRequest {
  session_id: string;
}

export interface RequestAggregatesResponse {
  aggregates_signed: SignedAggregates;
  merkle_root: string;
  logs_url?: string;
}

export interface RevokeRequest {
  session_id: string;
}

export interface RevokeResponse {
  success: boolean;
  message: string;
}

// Error types
export interface ErrorResponse {
  error: string;
  details?: string | any;
}

// Health check types
export interface HealthResponse {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
  database?: string;
  enclave?: string;
  error?: string;
}

// Configuration types
export interface EnclaveConfig {
  port: number;
  host: string;
  maxTtl: number;
  defaultTtl: number;
  rateLimitMax: number;
  rateLimitWindow: number;
}

// Crypto helper types
export interface Credentials {
  exchange: string;
  apiKey: string;
  apiSecret: string;
  sandbox?: boolean;
  symbols?: string[];
}

export interface AttestationVerificationResult {
  valid: boolean;
  error?: string;
}