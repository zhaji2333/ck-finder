-- =============================================================================
-- 014_intent_asset_index.sql：exploration_intents.asset_id 加索引
--
-- 「挖洞中」标记（active_intents 子查询）按 asset_id 关联意图，
-- 原无索引会导致全表扫 exploration_intents（每列一个子查询），资产多时显著变慢。
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_expl_intents_asset ON exploration_intents(asset_id);

INSERT INTO schema_migrations (version, description) VALUES
    ('014_intent_asset_index', 'exploration_intents.asset_id 索引（挖洞中标记性能）')
ON CONFLICT (version) DO NOTHING;
