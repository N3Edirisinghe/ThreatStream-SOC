-- ============================================================
-- SOC Platform — PostgreSQL Schema
-- Executed automatically by Docker on first start.
-- ============================================================

-- Enable pgcrypto for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- USERS & RBAC
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(128) UNIQUE NOT NULL,
    email         VARCHAR(256) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          VARCHAR(32) NOT NULL CHECK (role IN ('analyst', 'responder', 'admin')),
    is_active     BOOLEAN DEFAULT TRUE,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);

-- ============================================================
-- ASSETS (internal device / user registry)
-- ============================================================
CREATE TABLE IF NOT EXISTS assets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname      VARCHAR(256),
    ip_address    VARCHAR(45),
    asset_type    VARCHAR(64) CHECK (asset_type IN ('server','workstation','network_device','cloud_instance','unknown')),
    criticality   VARCHAR(16) DEFAULT 'low' CHECK (criticality IN ('low','medium','high','critical')),
    owner         VARCHAR(128),
    department    VARCHAR(128),
    tags          JSONB DEFAULT '{}',
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_hostname   ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_ip         ON assets(ip_address);

-- ============================================================
-- DETECTION RULES (version-controlled)
-- ============================================================
CREATE TABLE IF NOT EXISTS detection_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id       VARCHAR(64) UNIQUE NOT NULL,
    name          VARCHAR(256) NOT NULL,
    version       INTEGER DEFAULT 1,
    enabled       BOOLEAN DEFAULT TRUE,
    severity      VARCHAR(16) NOT NULL,
    rule_json     JSONB NOT NULL,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- INCIDENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    severity        VARCHAR(16) NOT NULL CHECK (severity IN ('informational','low','medium','high','critical')),
    status          VARCHAR(32) DEFAULT 'open'
                    CHECK (status IN ('open','in_progress','resolved','closed','false_positive')),
    assigned_to     UUID REFERENCES users(id) ON DELETE SET NULL,
    source_alert_id VARCHAR(64),
    mitre_tactic    VARCHAR(128),
    mitre_technique VARCHAR(32),
    sla_due_at      TIMESTAMPTZ,
    opened_at       TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    resolution_note TEXT,
    evidence_pack   JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_opened   ON incidents(opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned ON incidents(assigned_to);

-- ============================================================
-- ALERTS (lightweight relational mirror — OpenSearch is primary)
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         VARCHAR(64),
    rule_name       VARCHAR(256),
    severity        VARCHAR(16) NOT NULL,
    detection_type  VARCHAR(32) DEFAULT 'rule',
    status          VARCHAR(32) DEFAULT 'open'
                    CHECK (status IN ('open','acknowledged','escalated','false_positive','resolved')),
    host_name       VARCHAR(256),
    user_name       VARCHAR(128),
    source_ip       VARCHAR(45),
    mitre_tactic    VARCHAR(128),
    mitre_technique VARCHAR(32),
    incident_id     UUID REFERENCES incidents(id) ON DELETE SET NULL,
    raw_alert       JSONB NOT NULL,
    triggered_at    TIMESTAMPTZ NOT NULL,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_status      ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered   ON alerts(triggered_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule        ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident    ON alerts(incident_id);

-- ============================================================
-- PLAYBOOK RUNS
-- ============================================================
CREATE TABLE IF NOT EXISTS playbook_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id     VARCHAR(64) NOT NULL,
    incident_id     UUID REFERENCES incidents(id) ON DELETE SET NULL,
    alert_id        UUID REFERENCES alerts(id) ON DELETE SET NULL,
    triggered_by    VARCHAR(64),
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    status          VARCHAR(32) DEFAULT 'running'
                    CHECK (status IN ('running','completed','failed','awaiting_approval','aborted')),
    steps_log       JSONB DEFAULT '[]',
    current_step    VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_pb_runs_incident ON playbook_runs(incident_id);
CREATE INDEX IF NOT EXISTS idx_pb_runs_status   ON playbook_runs(status);

-- ============================================================
-- AUDIT LOG (append-only — never update/delete rows)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id            BIGSERIAL PRIMARY KEY,
    actor_id      UUID,
    actor_username VARCHAR(128),
    actor_role    VARCHAR(32),
    action        VARCHAR(128) NOT NULL,
    resource_type VARCHAR(128),
    resource_id   VARCHAR(256),
    detail        JSONB,
    ip_address    VARCHAR(45),
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(created_at DESC);

-- ============================================================
-- SEED: Default admin user (password = Admin@SOC123! bcrypt hash)
-- Update via: python scripts/seed_admin.py
-- ============================================================
-- Hash below is bcrypt of "Admin@SOC123!" — regenerate for production!
INSERT INTO users (username, email, password_hash, role)
VALUES (
    'admin',
    'admin@soc.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5p.ugb3rW2L5K',
    'admin'
)
ON CONFLICT (username) DO NOTHING;
