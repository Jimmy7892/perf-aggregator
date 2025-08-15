-- Create database schema for secure TEE enclave backend
-- SECURITY: All sensitive data is encrypted; only metadata is stored in plaintext

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted'))
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    exchange TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked', 'done'))
);

-- Encrypted credentials table - CRITICAL: NO PLAINTEXT SECRETS
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    ephemeral_pub TEXT NOT NULL, -- Base64 encoded public key
    nonce TEXT NOT NULL, -- Base64 encoded nonce
    ciphertext BYTEA NOT NULL, -- Encrypted API keys/secrets
    tag TEXT NOT NULL, -- Base64 encoded authentication tag
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Aggregated results table (can be visible to operators)
CREATE TABLE aggregates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    aggregates_signed JSONB NOT NULL, -- Signed aggregated data
    signed_by TEXT NOT NULL, -- Enclave identifier
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Merkle tree logs for verification
CREATE TABLE merkle_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    merkle_root TEXT NOT NULL,
    proof_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Operations logs (non-sensitive infrastructure logs only)
CREATE TABLE ops_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    level VARCHAR(10) NOT NULL CHECK (level IN ('INFO', 'WARN', 'ERROR')),
    message TEXT NOT NULL,
    session_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_credentials_session_id ON credentials(session_id);
CREATE INDEX idx_credentials_expires_at ON credentials(expires_at);
CREATE INDEX idx_aggregates_session_id ON aggregates(session_id);
CREATE INDEX idx_merkle_logs_session_id ON merkle_logs(session_id);
CREATE INDEX idx_ops_logs_created_at ON ops_logs(created_at);

-- TTL cleanup function for expired credentials
CREATE OR REPLACE FUNCTION cleanup_expired_credentials()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Delete expired credentials
    DELETE FROM credentials WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Log cleanup activity
    INSERT INTO ops_logs (level, message) 
    VALUES ('INFO', 'Cleaned up ' || deleted_count || ' expired credentials');
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create a scheduled job to run cleanup (requires pg_cron extension)
-- SELECT cron.schedule('cleanup-expired-credentials', '*/5 * * * *', 'SELECT cleanup_expired_credentials();');

-- Role-based access control
-- Create restricted read-only role for operators
CREATE ROLE operator_readonly;
GRANT SELECT ON users, sessions, aggregates, merkle_logs, ops_logs TO operator_readonly;
-- EXPLICITLY exclude credentials table access

-- Create application role with limited access
CREATE ROLE app_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, credentials, aggregates, merkle_logs, ops_logs TO app_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_service;

-- Security constraints
ALTER TABLE credentials ADD CONSTRAINT check_ciphertext_not_empty CHECK (length(ciphertext) > 0);
ALTER TABLE credentials ADD CONSTRAINT check_ephemeral_pub_format CHECK (ephemeral_pub ~ '^[A-Za-z0-9+/]+=*$');
ALTER TABLE credentials ADD CONSTRAINT check_nonce_format CHECK (nonce ~ '^[A-Za-z0-9+/]+=*$');
ALTER TABLE credentials ADD CONSTRAINT check_tag_format CHECK (tag ~ '^[A-Za-z0-9+/]+=*$');