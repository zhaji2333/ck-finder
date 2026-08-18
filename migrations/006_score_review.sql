-- =============================================================================
-- M6 迁移：LLM 评分复核（高分资产必须经 LLM 认定）
-- =============================================================================

-- LLM 评分复核缓存：规则评分达到阈值（默认 70）的 webapp 调 LLM 复核
CREATE TABLE IF NOT EXISTS score_reviews (
    id              BIGSERIAL PRIMARY KEY,
    webapp_id       UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    role_confirmed  BOOLEAN NOT NULL DEFAULT true,
    suggested_role  TEXT,
    score_adjustment INTEGER NOT NULL DEFAULT 0,
    is_high_value   BOOLEAN NOT NULL DEFAULT false,
    reasoning       TEXT,
    raw_response    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, provider, model)
);

CREATE INDEX IF NOT EXISTS idx_score_reviews_webapp ON score_reviews (webapp_id);
