-- =============================================================================
-- M3 迁移：LLM 智能增强（技术栈识别兜底 / JS 接口提取 / 源码审计缓存）
-- =============================================================================

-- 1. 技术栈识别 LLM 兜底缓存表（webapp_id + provider + model UNIQUE）
--    用途：single_site 模式 analyzeSiteHtml 正则识别不到时，LLM 兜底结果缓存
CREATE TABLE IF NOT EXISTS tech_detections (
    id              BIGSERIAL PRIMARY KEY,
    webapp_id       UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    framework       TEXT[] NOT NULL DEFAULT '{}',
    language        TEXT[] NOT NULL DEFAULT '{}',
    build_tool      TEXT[] NOT NULL DEFAULT '{}',
    architecture    TEXT,
    reasoning       TEXT,
    raw_response    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, provider, model)
);

CREATE INDEX IF NOT EXISTS idx_tech_detections_webapp ON tech_detections (webapp_id);

-- 2. 源码审计结果缓存（webapp_id + source_dir + model UNIQUE）
--    用途：source-auditor 对还原源码做 LLM 审计，同一目录不重复审计
CREATE TABLE IF NOT EXISTS source_audits (
    id              BIGSERIAL PRIMARY KEY,
    webapp_id       UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    source_dir      TEXT NOT NULL,
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    summary         JSONB NOT NULL DEFAULT '{}'::jsonb,
    finding_count   INTEGER NOT NULL DEFAULT 0,
    raw_response    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, source_dir, provider, model)
);

CREATE INDEX IF NOT EXISTS idx_source_audits_webapp ON source_audits (webapp_id);
