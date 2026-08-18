-- M4 迁移：Reviewer 复审 + intel 情报 + findings 深挖字段
-- 借鉴 AutoHunter：review_reviews（AI 初审，reproduced 由系统复现设置）、intel_entries（跨任务情报复用）、
-- findings 加 deepen/escalate/superseded 状态字段。

-- 1) AI 初审记录表
CREATE TABLE IF NOT EXISTS review_reviews (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id    UUID NOT NULL REFERENCES validation_findings(id) ON DELETE CASCADE,
  verdict       TEXT NOT NULL CHECK (verdict IN ('accepted','ignored','deepen')),
  severity_final TEXT,                          -- 调级后的最终等级
  score         REAL,                           -- 置信评分（0-10）
  reasoning     TEXT NOT NULL,                  -- 判定理由
  -- reproduced：高危复现由系统实际重放确认（不信任 LLM 自填）
  reproduced    BOOLEAN NOT NULL DEFAULT false,
  reviewer_model TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_review_finding ON review_reviews(finding_id);

-- 2) intel 情报库（跨任务复用，借鉴 AutoHunter intel）
CREATE TABLE IF NOT EXISTS intel_entries (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          TEXT NOT NULL CHECK (kind IN ('cred','endpoint','fingerprint')),
  match_key     TEXT NOT NULL,                  -- cred→root域 / endpoint→指纹 / fingerprint→指纹
  payload       JSONB NOT NULL,                 -- cred{username,password} / endpoint{path,vuln_type} / fingerprint{tactic}
  confidence    TEXT NOT NULL DEFAULT 'likely' CHECK (confidence IN ('verified','likely')),
  source_finding_id UUID,                       -- 来源 finding
  hit_count     INTEGER NOT NULL DEFAULT 0,
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (kind, match_key)
);
CREATE INDEX IF NOT EXISTS idx_intel_match ON intel_entries(kind, match_key);

-- 3) validation_findings 加闭环字段
ALTER TABLE validation_findings ADD COLUMN IF NOT EXISTS review_status TEXT NOT NULL DEFAULT 'pending'
  CHECK (review_status IN ('pending','reviewed','confirmed','dismissed','escalated'));
ALTER TABLE validation_findings ADD COLUMN IF NOT EXISTS deepen_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE validation_findings ADD COLUMN IF NOT EXISTS deepen_directive TEXT;
ALTER TABLE validation_findings ADD COLUMN IF NOT EXISTS superseded_by UUID;
