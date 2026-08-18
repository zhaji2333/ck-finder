-- =============================================================================
-- M2 迁移：指纹库 + 评分相关字段
-- =============================================================================

-- 1. 给 webapps 表增加指纹匹配所需的原始数据字段
ALTER TABLE webapps
    ADD COLUMN IF NOT EXISTS body_preview TEXT,
    ADD COLUMN IF NOT EXISTS response_header JSONB,
    ADD COLUMN IF NOT EXISTS favicon_hash BIGINT,
    ADD COLUMN IF NOT EXISTS fingerprints TEXT[] NOT NULL DEFAULT '{}';

-- 命中指纹数组索引（按指纹名查询）
CREATE INDEX IF NOT EXISTS idx_webapps_fingerprints ON webapps USING gin (fingerprints);
CREATE INDEX IF NOT EXISTS idx_webapps_favicon ON webapps (favicon_hash) WHERE favicon_hash IS NOT NULL;

-- 2. webapp_fingerprints 表：每条指纹命中证据（一对多）
CREATE TABLE IF NOT EXISTS webapp_fingerprints (
    id              BIGSERIAL PRIMARY KEY,
    webapp_id       UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    fingerprint     TEXT NOT NULL,
    branch_index    INTEGER NOT NULL DEFAULT 0,
    evidence        JSONB NOT NULL DEFAULT '[]'::jsonb,
    matched_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_webapp_fingerprints_fp ON webapp_fingerprints (fingerprint);
CREATE INDEX IF NOT EXISTS idx_webapp_fingerprints_webapp ON webapp_fingerprints (webapp_id);

-- 3. 评分快照表（M2.6 metadata 快照）
CREATE TABLE IF NOT EXISTS webapp_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    webapp_id       UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    snapshot        JSONB NOT NULL,
    schema_version  TEXT NOT NULL DEFAULT '1.0',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webapp_snapshots_webapp ON webapp_snapshots (webapp_id, created_at DESC);

-- 4. LLM 分类结果缓存表（M2.4 LLM 兜底）
CREATE TABLE IF NOT EXISTS llm_classifications (
    id              BIGSERIAL PRIMARY KEY,
    webapp_id       UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    role            TEXT NOT NULL,
    confidence      REAL NOT NULL,
    reasoning       TEXT,
    raw_response    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, provider, model)
);

CREATE INDEX IF NOT EXISTS idx_llm_classifications_webapp ON llm_classifications (webapp_id);
