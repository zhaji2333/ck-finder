-- M3 迁移：validation_findings 加 dedup_key（跨任务查重，借鉴 AutoHunter dedup.py）
-- dedup_key = sha256(host | endpoint | method | vuln_type)，不含 seed_id → 跨任务可复用查重。

ALTER TABLE validation_findings ADD COLUMN IF NOT EXISTS dedup_key TEXT;
CREATE INDEX IF NOT EXISTS idx_valfind_dedup ON validation_findings(dedup_key);
