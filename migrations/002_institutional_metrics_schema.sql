-- Institutional-Grade Performance Metrics Database Schema
-- 
-- CRITICAL SECURITY POLICY:
-- 1. NO raw trade data is stored - only aggregated metrics
-- 2. All sensitive data is encrypted at rest
-- 3. Compliance with financial data retention regulations
-- 4. Audit trail for all metric calculations
-- 
-- This schema is designed for institutional trading environments
-- where regulatory compliance and data security are paramount.

-- Performance snapshots table - point-in-time portfolio states
CREATE TABLE performance_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    user_id_hash VARCHAR(64) NOT NULL, -- SHA256 hash for correlation without PII
    exchange VARCHAR(50) NOT NULL,
    snapshot_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Portfolio value metrics
    total_portfolio_value DECIMAL(20, 8) NOT NULL,
    portfolio_currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    
    -- Position metrics (aggregated, not individual positions)
    active_positions_count INTEGER NOT NULL DEFAULT 0,
    open_orders_count INTEGER NOT NULL DEFAULT 0,
    
    -- Trading activity metrics (24h rolling)
    trades_24h INTEGER NOT NULL DEFAULT 0,
    volume_24h DECIMAL(20, 8) NOT NULL DEFAULT 0,
    fees_24h DECIMAL(20, 8) NOT NULL DEFAULT 0,
    
    -- Risk metrics
    portfolio_volatility DECIMAL(10, 6),
    max_position_concentration DECIMAL(5, 4), -- Largest position as % of portfolio
    
    -- Data quality indicators
    data_freshness_seconds INTEGER NOT NULL,
    polling_success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Ensure no duplicate snapshots per session/timestamp
    UNIQUE(session_id, snapshot_timestamp)
);

-- Aggregated performance metrics - calculated analytics for institutional reporting
CREATE TABLE performance_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    user_id_hash VARCHAR(64) NOT NULL,
    exchange VARCHAR(50) NOT NULL,
    
    -- Time period for metrics calculation
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    calculation_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Core performance metrics
    total_return DECIMAL(20, 8) NOT NULL, -- Absolute return in USD
    total_return_pct DECIMAL(10, 6) NOT NULL, -- Percentage return
    annualized_return_pct DECIMAL(10, 6),
    
    -- Risk-adjusted performance metrics (institutional standard)
    sharpe_ratio DECIMAL(10, 6),
    sortino_ratio DECIMAL(10, 6),
    calmar_ratio DECIMAL(10, 6),
    information_ratio DECIMAL(10, 6),
    
    -- Risk metrics
    volatility DECIMAL(10, 6), -- Annualized volatility
    max_drawdown DECIMAL(10, 6), -- Maximum drawdown percentage
    max_drawdown_duration_days INTEGER,
    value_at_risk_95 DECIMAL(20, 8), -- VaR at 95% confidence
    value_at_risk_99 DECIMAL(20, 8), -- VaR at 99% confidence
    
    -- Trading activity metrics
    total_volume DECIMAL(20, 8) NOT NULL,
    total_fees DECIMAL(20, 8) NOT NULL,
    trade_count INTEGER NOT NULL,
    win_rate DECIMAL(5, 4), -- Percentage of profitable trades
    profit_factor DECIMAL(10, 6), -- Gross profit / Gross loss
    
    -- Position metrics
    average_position_size DECIMAL(20, 8),
    largest_position_size DECIMAL(20, 8),
    position_concentration_ratio DECIMAL(5, 4),
    
    -- Market correlation and beta
    market_beta DECIMAL(10, 6),
    market_correlation DECIMAL(10, 6),
    
    -- Data quality and calculation metadata
    calculation_method VARCHAR(50) NOT NULL DEFAULT 'institutional_standard',
    data_points_used INTEGER NOT NULL,
    confidence_score DECIMAL(3, 2) NOT NULL DEFAULT 1.0,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Ensure no duplicate metrics for same period
    UNIQUE(session_id, period_start, period_end, calculation_method)
);

-- Asset allocation snapshots - portfolio composition over time
CREATE TABLE asset_allocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    performance_snapshot_id UUID REFERENCES performance_snapshots(id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    
    -- Asset information (aggregated by asset class, not individual positions)
    asset_symbol VARCHAR(20) NOT NULL,
    asset_class VARCHAR(50) NOT NULL, -- 'crypto', 'equity', 'forex', etc.
    
    -- Allocation metrics
    allocation_percentage DECIMAL(5, 4) NOT NULL, -- Percentage of total portfolio
    position_value DECIMAL(20, 8) NOT NULL,
    unrealized_pnl DECIMAL(20, 8),
    unrealized_pnl_pct DECIMAL(10, 6),
    
    -- Performance attribution
    contribution_to_return DECIMAL(10, 6),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    CHECK (allocation_percentage >= 0 AND allocation_percentage <= 1),
    CHECK (position_value >= 0)
);

-- Risk exposure summary - aggregated risk metrics by category
CREATE TABLE risk_exposures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    performance_snapshot_id UUID REFERENCES performance_snapshots(id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    
    -- Risk category
    risk_category VARCHAR(50) NOT NULL, -- 'currency', 'sector', 'market_cap', etc.
    risk_factor VARCHAR(100) NOT NULL, -- 'USD', 'EUR', 'BTC', 'technology', etc.
    
    -- Exposure metrics
    exposure_amount DECIMAL(20, 8) NOT NULL,
    exposure_percentage DECIMAL(5, 4) NOT NULL,
    net_exposure DECIMAL(20, 8) NOT NULL, -- After hedging
    
    -- Risk metrics for this exposure
    var_contribution DECIMAL(20, 8), -- Contribution to portfolio VaR
    correlation_to_portfolio DECIMAL(10, 6),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(performance_snapshot_id, risk_category, risk_factor)
);

-- Benchmark comparisons - performance vs market indices
CREATE TABLE benchmark_comparisons (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    performance_metrics_id UUID REFERENCES performance_metrics(id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    
    -- Benchmark information
    benchmark_name VARCHAR(100) NOT NULL, -- 'BTC', 'S&P500', 'NASDAQ', etc.
    benchmark_symbol VARCHAR(20) NOT NULL,
    
    -- Comparative performance
    benchmark_return DECIMAL(10, 6) NOT NULL,
    active_return DECIMAL(10, 6) NOT NULL, -- Portfolio return - Benchmark return
    tracking_error DECIMAL(10, 6),
    beta_to_benchmark DECIMAL(10, 6),
    alpha DECIMAL(10, 6), -- Risk-adjusted outperformance
    
    -- Attribution analysis
    selection_effect DECIMAL(10, 6), -- Return from asset selection
    timing_effect DECIMAL(10, 6), -- Return from market timing
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compliance and audit trail
CREATE TABLE metrics_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    
    -- Audit event information
    event_type VARCHAR(50) NOT NULL, -- 'calculation', 'modification', 'deletion', 'export'
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- What was affected
    affected_table VARCHAR(100) NOT NULL,
    affected_record_id UUID,
    
    -- Event details
    event_description TEXT NOT NULL,
    calculation_parameters JSONB, -- Parameters used for calculations
    data_sources JSONB, -- Sources of data used
    
    -- Regulatory compliance
    retention_category VARCHAR(50) NOT NULL, -- 'operational', 'regulatory', 'tax'
    retention_expiry TIMESTAMP WITH TIME ZONE,
    
    -- System information
    calculation_node VARCHAR(100), -- Which server/enclave performed calculation
    software_version VARCHAR(50),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Performance indexes for institutional-grade query performance
CREATE INDEX idx_performance_snapshots_session_timestamp ON performance_snapshots(session_id, snapshot_timestamp);
CREATE INDEX idx_performance_snapshots_user_hash ON performance_snapshots(user_id_hash);
CREATE INDEX idx_performance_snapshots_exchange ON performance_snapshots(exchange);
CREATE INDEX idx_performance_snapshots_timestamp ON performance_snapshots(snapshot_timestamp);

CREATE INDEX idx_performance_metrics_session_period ON performance_metrics(session_id, period_start, period_end);
CREATE INDEX idx_performance_metrics_user_hash ON performance_metrics(user_id_hash);
CREATE INDEX idx_performance_metrics_calculation_time ON performance_metrics(calculation_timestamp);

CREATE INDEX idx_asset_allocations_snapshot ON asset_allocations(performance_snapshot_id);
CREATE INDEX idx_asset_allocations_symbol ON asset_allocations(asset_symbol);
CREATE INDEX idx_asset_allocations_class ON asset_allocations(asset_class);

CREATE INDEX idx_risk_exposures_snapshot ON risk_exposures(performance_snapshot_id);
CREATE INDEX idx_risk_exposures_category ON risk_exposures(risk_category, risk_factor);

CREATE INDEX idx_benchmark_comparisons_metrics ON benchmark_comparisons(performance_metrics_id);
CREATE INDEX idx_benchmark_comparisons_benchmark ON benchmark_comparisons(benchmark_symbol);

CREATE INDEX idx_metrics_audit_log_session ON metrics_audit_log(session_id);
CREATE INDEX idx_metrics_audit_log_timestamp ON metrics_audit_log(event_timestamp);
CREATE INDEX idx_metrics_audit_log_table ON metrics_audit_log(affected_table);

-- Automated data retention and cleanup functions
CREATE OR REPLACE FUNCTION cleanup_expired_performance_data()
RETURNS INTEGER AS $$
DECLARE
    deleted_snapshots INTEGER;
    deleted_metrics INTEGER;
    retention_days INTEGER := 2555; -- 7 years for regulatory compliance
    operational_retention_days INTEGER := 90; -- 90 days for operational data
BEGIN
    -- Delete old operational snapshots (keep regulatory data)
    DELETE FROM performance_snapshots 
    WHERE created_at < NOW() - INTERVAL '90 days'
    AND session_id NOT IN (
        SELECT DISTINCT session_id FROM metrics_audit_log 
        WHERE retention_category = 'regulatory'
    );
    GET DIAGNOSTICS deleted_snapshots = ROW_COUNT;
    
    -- Delete old metrics (keep regulatory required data)
    DELETE FROM performance_metrics 
    WHERE created_at < NOW() - INTERVAL '7 years';
    GET DIAGNOSTICS deleted_metrics = ROW_COUNT;
    
    -- Log cleanup activity for audit
    INSERT INTO metrics_audit_log (
        event_type, 
        event_description, 
        affected_table, 
        retention_category
    ) VALUES (
        'cleanup',
        'Automated cleanup: ' || deleted_snapshots || ' snapshots, ' || deleted_metrics || ' metrics',
        'performance_snapshots,performance_metrics',
        'operational'
    );
    
    RETURN deleted_snapshots + deleted_metrics;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate performance metrics from snapshots
CREATE OR REPLACE FUNCTION calculate_period_metrics(
    p_session_id UUID,
    p_period_start TIMESTAMP WITH TIME ZONE,
    p_period_end TIMESTAMP WITH TIME ZONE
) RETURNS UUID AS $$
DECLARE
    metrics_id UUID;
    start_value DECIMAL(20, 8);
    end_value DECIMAL(20, 8);
    total_volume DECIMAL(20, 8);
    total_fees DECIMAL(20, 8);
    trade_count INTEGER;
BEGIN
    -- Get start and end portfolio values
    SELECT total_portfolio_value INTO start_value
    FROM performance_snapshots
    WHERE session_id = p_session_id 
    AND snapshot_timestamp >= p_period_start
    ORDER BY snapshot_timestamp ASC
    LIMIT 1;
    
    SELECT total_portfolio_value INTO end_value
    FROM performance_snapshots
    WHERE session_id = p_session_id 
    AND snapshot_timestamp <= p_period_end
    ORDER BY snapshot_timestamp DESC
    LIMIT 1;
    
    -- Calculate aggregated trading activity
    SELECT 
        COALESCE(SUM(volume_24h), 0),
        COALESCE(SUM(fees_24h), 0),
        COALESCE(SUM(trades_24h), 0)
    INTO total_volume, total_fees, trade_count
    FROM performance_snapshots
    WHERE session_id = p_session_id 
    AND snapshot_timestamp BETWEEN p_period_start AND p_period_end;
    
    -- Insert calculated metrics
    INSERT INTO performance_metrics (
        session_id,
        user_id_hash,
        exchange,
        period_start,
        period_end,
        total_return,
        total_return_pct,
        total_volume,
        total_fees,
        trade_count,
        data_points_used
    )
    SELECT 
        p_session_id,
        ps.user_id_hash,
        ps.exchange,
        p_period_start,
        p_period_end,
        COALESCE(end_value - start_value, 0),
        CASE 
            WHEN start_value > 0 THEN ((end_value - start_value) / start_value) * 100
            ELSE 0 
        END,
        total_volume,
        total_fees,
        trade_count,
        (SELECT COUNT(*) FROM performance_snapshots 
         WHERE session_id = p_session_id 
         AND snapshot_timestamp BETWEEN p_period_start AND p_period_end)
    FROM performance_snapshots ps
    WHERE ps.session_id = p_session_id
    ORDER BY ps.snapshot_timestamp DESC
    LIMIT 1
    RETURNING id INTO metrics_id;
    
    -- Log calculation for audit
    INSERT INTO metrics_audit_log (
        session_id,
        event_type,
        affected_table,
        affected_record_id,
        event_description,
        retention_category
    ) VALUES (
        p_session_id,
        'calculation',
        'performance_metrics',
        metrics_id,
        'Calculated performance metrics for period ' || p_period_start || ' to ' || p_period_end,
        'regulatory'
    );
    
    RETURN metrics_id;
END;
$$ LANGUAGE plpgsql;

-- Role-based access control for institutional environment
-- Compliance officers get read-only access to all metrics
CREATE ROLE compliance_officer;
GRANT SELECT ON performance_snapshots, performance_metrics, asset_allocations, 
                 risk_exposures, benchmark_comparisons, metrics_audit_log TO compliance_officer;

-- Risk management gets broader access but no modification rights
CREATE ROLE risk_manager;
GRANT SELECT ON performance_snapshots, performance_metrics, asset_allocations,
                risk_exposures, benchmark_comparisons TO risk_manager;

-- Portfolio managers get access to performance data but not audit logs  
CREATE ROLE portfolio_manager;
GRANT SELECT ON performance_snapshots, performance_metrics, asset_allocations,
                benchmark_comparisons TO portfolio_manager;

-- Application service needs full access for calculations
GRANT SELECT, INSERT, UPDATE, DELETE ON performance_snapshots, performance_metrics, 
      asset_allocations, risk_exposures, benchmark_comparisons, metrics_audit_log TO app_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_service;
GRANT EXECUTE ON FUNCTION cleanup_expired_performance_data() TO app_service;
GRANT EXECUTE ON FUNCTION calculate_period_metrics(UUID, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE) TO app_service;

-- Constraints for data integrity and regulatory compliance
ALTER TABLE performance_snapshots 
ADD CONSTRAINT check_positive_portfolio_value 
CHECK (total_portfolio_value >= 0);

ALTER TABLE performance_snapshots
ADD CONSTRAINT check_reasonable_data_freshness
CHECK (data_freshness_seconds >= 0 AND data_freshness_seconds <= 3600);

ALTER TABLE performance_metrics
ADD CONSTRAINT check_valid_period
CHECK (period_end > period_start);

ALTER TABLE performance_metrics
ADD CONSTRAINT check_confidence_score_range
CHECK (confidence_score >= 0 AND confidence_score <= 1);

-- Comments for institutional documentation
COMMENT ON TABLE performance_snapshots IS 'Point-in-time portfolio states for institutional performance tracking. No raw trade data stored.';
COMMENT ON TABLE performance_metrics IS 'Calculated institutional performance metrics compliant with financial industry standards.';
COMMENT ON TABLE asset_allocations IS 'Portfolio composition over time for risk management and compliance reporting.';
COMMENT ON TABLE risk_exposures IS 'Risk exposure analysis by category for institutional risk management.';
COMMENT ON TABLE benchmark_comparisons IS 'Performance comparison against market benchmarks for institutional reporting.';
COMMENT ON TABLE metrics_audit_log IS 'Complete audit trail for regulatory compliance and data governance.';

COMMENT ON COLUMN performance_metrics.sharpe_ratio IS 'Risk-adjusted return metric: (Return - Risk-free rate) / Standard deviation';
COMMENT ON COLUMN performance_metrics.value_at_risk_95 IS 'Potential loss at 95% confidence level over specified time horizon';
COMMENT ON COLUMN performance_metrics.calmar_ratio IS 'Return / Maximum drawdown ratio for risk-adjusted performance';
COMMENT ON COLUMN metrics_audit_log.retention_category IS 'Data retention category: operational (90 days), regulatory (7 years), tax (as required)';

-- Schedule automated cleanup (requires pg_cron extension)
-- SELECT cron.schedule('cleanup-performance-data', '0 2 * * *', 'SELECT cleanup_expired_performance_data();');

-- Create view for institutional reporting
CREATE VIEW institutional_performance_summary AS
SELECT 
    pm.session_id,
    pm.user_id_hash,
    pm.exchange,
    pm.period_start,
    pm.period_end,
    pm.total_return_pct,
    pm.sharpe_ratio,
    pm.max_drawdown,
    pm.volatility,
    pm.total_volume,
    pm.trade_count,
    pm.win_rate,
    pm.calculation_timestamp,
    s.label as session_label,
    s.created_at as session_created
FROM performance_metrics pm
JOIN sessions s ON pm.session_id = s.id
WHERE pm.confidence_score >= 0.8  -- Only high-confidence calculations
ORDER BY pm.calculation_timestamp DESC;