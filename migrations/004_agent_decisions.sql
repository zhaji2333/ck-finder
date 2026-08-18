-- =============================================================================
-- M4 迁移：Agent 决策缓存（混合架构：确定性主干 + LLM 决策点）
-- =============================================================================

-- 1. 侦察策略规划缓存（决策点1：LLM Planner）
--    同一种子（type+value）不重复规划
CREATE TABLE IF NOT EXISTS planner_decisions (
    id              BIGSERIAL PRIMARY KEY,
    seed_type       TEXT NOT NULL,
    seed_value      TEXT NOT NULL,
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    decision        JSONB NOT NULL DEFAULT '{}'::jsonb,
    reasoning       TEXT,
    raw_response    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (seed_type, seed_value, provider, model)
);

CREATE INDEX IF NOT EXISTS idx_planner_decisions_seed ON planner_decisions (seed_type, seed_value);

-- 2. 深挖任务选择缓存（决策点2：LLM 任务选择兜底）
--    同一 webapp 不重复询问
CREATE TABLE IF NOT EXISTS task_decisions (
    id              BIGSERIAL PRIMARY KEY,
    webapp_id       UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    decision        JSONB NOT NULL DEFAULT '{}'::jsonb,
    reasoning       TEXT,
    raw_response    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, provider, model)
);

CREATE INDEX IF NOT EXISTS idx_task_decisions_webapp ON task_decisions (webapp_id);
