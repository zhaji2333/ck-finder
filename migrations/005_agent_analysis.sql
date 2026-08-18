-- =============================================================================
-- M5 迁移：LLM 分析驱动 Phase 1（页面语义分类）
-- =============================================================================

-- endpoints 表增加页面语义分类列（LLM 分类结果：login/admin/api_doc/upload/export/payment/debug/auth/business/static/other）
ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS page_role TEXT;

-- 分类依据/上下文（LLM reason）
ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS meta JSONB;

CREATE INDEX IF NOT EXISTS idx_endpoints_page_role ON endpoints (page_role) WHERE page_role IS NOT NULL;
