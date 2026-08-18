-- M2 迁移：探索图（intents / facts / activities）
-- 记录 Agent 的意图派发、事实收集与任务级事件，锚点指向收集引擎资产（asset_id）以 JOIN 评分/角色。

-- 意图：planner 派发的侦察/验证任务
CREATE TABLE IF NOT EXISTS exploration_intents (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seed_id       UUID REFERENCES seeds(id) ON DELETE CASCADE,
  intent_type   TEXT NOT NULL,                 -- recon_js / recon_asset / verify / ...
  description   TEXT NOT NULL,                 -- 意图描述（planner 自然语言）
  status        TEXT NOT NULL DEFAULT 'pending', -- pending | running | done | failed | canceled
  priority      INTEGER NOT NULL DEFAULT 5,    -- 越低越优先
  scope_anchor  TEXT NOT NULL,                 -- 授权锚点（domain/ip/url），提交时校验 in scope
  asset_id      UUID,                          -- 锚点资产（webapp 的 asset_id，可空）
  dependencies  TEXT[] NOT NULL DEFAULT '{}',  -- 依赖的意图 id（防环）
  depth         INTEGER NOT NULL DEFAULT 0,    -- 意图轮次（预算控制）
  result_summary TEXT,                         -- task_result_submit 的摘要
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_expl_intents_seed ON exploration_intents(seed_id);
CREATE INDEX IF NOT EXISTS idx_expl_intents_status ON exploration_intents(status);

-- 事实：worker 收集到的确定性信息（summary 摘要进上下文，raw_json 落盘）
CREATE TABLE IF NOT EXISTS exploration_facts (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  intent_id     UUID REFERENCES exploration_intents(id) ON DELETE CASCADE,
  seed_id       UUID REFERENCES seeds(id) ON DELETE CASCADE,
  asset_id      UUID,                          -- 锚点资产（可 JOIN webapps 评分/角色）
  fact_type     TEXT NOT NULL,                 -- tech / endpoint / js_api / param / secret / info ...
  summary       TEXT NOT NULL,                 -- 摘要（Agent 可见）
  raw_json      TEXT,                          -- 原始结构化数据
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_expl_facts_seed ON exploration_facts(seed_id);
CREATE INDEX IF NOT EXISTS idx_expl_facts_asset ON exploration_facts(asset_id);
CREATE INDEX IF NOT EXISTS idx_expl_facts_intent ON exploration_facts(intent_id);

-- 活动流水：任务级事件（意图派发/完成/预算/审计/越权拦截）
CREATE TABLE IF NOT EXISTS exploration_activities (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seed_id       UUID REFERENCES seeds(id) ON DELETE CASCADE,
  activity_type TEXT NOT NULL,                 -- intent_created / intent_done / budget / scope_denied / campaign_end
  message       TEXT NOT NULL,
  meta          JSONB NOT NULL DEFAULT '{}',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_expl_activities_seed ON exploration_activities(seed_id);
