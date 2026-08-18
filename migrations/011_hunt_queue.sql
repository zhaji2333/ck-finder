-- M5 迁移：持久化任务队列（hunt_tasks）
-- 支撑 7×24 挂机：任务入队/并发调度/预算/心跳/崩溃恢复。

CREATE TABLE IF NOT EXISTS hunt_tasks (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seed_id       UUID NOT NULL REFERENCES seeds(id) ON DELETE CASCADE,
  target_url    TEXT NOT NULL,                 -- 直接打的目标 URL（含路径）
  status        TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','done','failed','timeout')),
  priority      INTEGER NOT NULL DEFAULT 5,
  concurrency   INTEGER NOT NULL DEFAULT 4,    -- 全局并发数
  max_intents   INTEGER NOT NULL DEFAULT 20,   -- 每任务意图上限（预算）
  max_rounds    INTEGER NOT NULL DEFAULT 3,    -- planner 轮数上限（预算）
  credentials   JSONB,                         -- 登录凭据（cookie/账密/authorization）
  -- 心跳与墙钟（崩溃恢复 + 稳定性）
  heartbeat_at  TIMESTAMPTZ,
  started_at    TIMESTAMPTZ,
  finished_at   TIMESTAMPTZ,
  wall_timeout_ms INTEGER NOT NULL DEFAULT 30 * 60 * 1000, -- 单任务墙钟上限（30 分钟）
  result_summary TEXT,
  error         TEXT,
  retry_count   INTEGER NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_hunt_tasks_status ON hunt_tasks(status);
CREATE INDEX IF NOT EXISTS idx_hunt_tasks_seed ON hunt_tasks(seed_id);
