-- M3 迁移：漏洞验证结果表（validation_findings）
-- 与收集引擎的 findings（secret/sourcemap 等线索）分离：这里是「挖洞结论」，带强制证据 schema。
-- evidence 为 JSONB，必须含 5 个键：poc / raw_request / raw_response / kill_chain / self_check（DB 层双保险）。

CREATE TABLE IF NOT EXISTS validation_findings (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seed_id       UUID REFERENCES seeds(id) ON DELETE CASCADE,
  intent_id     UUID,                          -- 来源意图（可空：verify 确定性命令无意图）
  asset_id      UUID,                          -- 锚点资产（可空）
  vuln_name     TEXT NOT NULL,                 -- 漏洞名称
  vuln_type     TEXT NOT NULL,                 -- OWASP 分类：injection/xss/broken_access/file_upload/ssrf/deserialization/xxe/idor/path_traversal/info_disclosure/auth/other
  severity      TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','dismissed')),
  url           TEXT NOT NULL,                 -- 漏洞 URL
  port          INTEGER,                       -- 目标端口
  summary       TEXT NOT NULL,                 -- 漏洞摘要（Agent 可读）
  evidence      JSONB NOT NULL CHECK (
                  evidence ? 'poc' AND evidence ? 'raw_request' AND
                  evidence ? 'raw_response' AND evidence ? 'kill_chain' AND
                  evidence ? 'self_check'
                ),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_valfind_seed ON validation_findings(seed_id);
CREATE INDEX IF NOT EXISTS idx_valfind_asset ON validation_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_valfind_status ON validation_findings(status);
CREATE INDEX IF NOT EXISTS idx_valfind_severity ON validation_findings(severity);
