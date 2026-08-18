-- =============================================================================
-- 013_finding_dedup_unique.sql：finding 去重改为 DB 层唯一约束（防 TOCTOU 竞态）
--
-- 原 009 只建普通索引，insertFinding 是 SELECT-then-INSERT，并发下会插重复。
-- 改为 UNIQUE 约束 + ON CONFLICT DO NOTHING 后，重复由数据库原子性兜底。
-- =============================================================================

DROP INDEX IF EXISTS idx_valfind_dedup;
CREATE UNIQUE INDEX IF NOT EXISTS idx_valfind_dedup_unique ON validation_findings(dedup_key);

INSERT INTO schema_migrations (version, description) VALUES
    ('013_finding_dedup_unique', 'finding dedup_key 唯一约束（防并发重复）')
ON CONFLICT (version) DO NOTHING;
