-- =============================================================================
-- ck-recon 初始化迁移脚本 001_init.sql
-- 对应架构文档 §5 数据模型（11 张表）+ 审计 + 缓存 + 源码转储
-- 在 PostgreSQL 16 上验证通过
-- =============================================================================

-- 扩展：UUID 主键 + 网络地址类型
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- -----------------------------------------------------------------------------
-- 1. seeds：种子（输入入口）
--    6 种 seed_type：domain / url / ip / cidr / ip_port / company_name
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS seeds (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seed_type   TEXT NOT NULL CHECK (seed_type IN ('domain', 'url', 'ip', 'cidr', 'ip_port', 'company_name')),
    value       TEXT NOT NULL,
    -- 归一化后的值（小写、去协议、去末尾斜杠等），用于去重
    value_norm  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'running', 'done', 'failed', 'partial')),
    meta        JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (seed_type, value_norm)
);

CREATE INDEX IF NOT EXISTS idx_seeds_status ON seeds (status);
CREATE INDEX IF NOT EXISTS idx_seeds_created_at ON seeds (created_at DESC);

-- -----------------------------------------------------------------------------
-- 2. assets：资产图（核心表）
--    一切发现的资产都进这张表，通过 parent_id 形成来源链（DAG）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seed_id         UUID REFERENCES seeds(id) ON DELETE CASCADE,
    parent_id       UUID REFERENCES assets(id) ON DELETE SET NULL,
    -- 资产类型：domain / subdomain / ip / url / webapp / company
    type            TEXT NOT NULL CHECK (type IN ('domain', 'subdomain', 'ip', 'url', 'webapp', 'company')),
    value           TEXT NOT NULL,
    value_norm      TEXT NOT NULL,
    -- 发现这个资产的工具（subfinder/dnsx/nmap/httpx/fofa/icp/waybackurls 等）
    discovered_by   TEXT NOT NULL,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 是否存活（最近一次探测结果）
    alive           BOOLEAN,
    meta            JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (type, value_norm)
);

CREATE INDEX IF NOT EXISTS idx_assets_seed_id ON assets (seed_id);
CREATE INDEX IF NOT EXISTS idx_assets_parent_id ON assets (parent_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets (type);
CREATE INDEX IF NOT EXISTS idx_assets_value_norm ON assets (value_norm);
CREATE INDEX IF NOT EXISTS idx_assets_discovered_by ON assets (discovered_by);
CREATE INDEX IF NOT EXISTS idx_assets_alive ON assets (alive) WHERE alive IS NOT NULL;
-- GIN 索引方便 meta 字段查询
CREATE INDEX IF NOT EXISTS idx_assets_meta ON assets USING gin (meta);

-- -----------------------------------------------------------------------------
-- 3. ips：IP 归属信息
--    一个 asset(type=ip) 对应一行
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ips (
    asset_id    UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    ip          INET NOT NULL,
    asn         BIGINT,
    org         TEXT,
    cidr        CIDR,
    isp         TEXT,
    -- 是否为 CDN IP（厂商规则判定）
    cdn_flag    BOOLEAN NOT NULL DEFAULT false,
    cdn_vendor  TEXT,
    country     TEXT,
    region      TEXT,
    city        TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ips_ip ON ips USING gist (ip inet_ops);
CREATE INDEX IF NOT EXISTS idx_ips_asn ON ips (asn) WHERE asn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ips_cdn_flag ON ips (cdn_flag) WHERE cdn_flag = true;

-- -----------------------------------------------------------------------------
-- 4. services：端口 / 服务（一个 asset(type=ip) 可对应多个端口）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS services (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ip          INET NOT NULL,
    port        INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
    protocol    TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    service     TEXT,
    version     TEXT,
    banner      TEXT,
    -- 是否为 http/https（httpx 会进一步探测为 webapp）
    is_http     BOOLEAN NOT NULL DEFAULT false,
    discovered_by TEXT NOT NULL,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ip, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_services_asset_id ON services (asset_id);
CREATE INDEX IF NOT EXISTS idx_services_ip_port ON services (ip, port);
CREATE INDEX IF NOT EXISTS idx_services_service ON services (service) WHERE service IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_services_is_http ON services (is_http) WHERE is_http = true;

-- -----------------------------------------------------------------------------
-- 5. webapps：Web 应用（httpx 探测出存活 URL 后入库）
--    一切评分、JS 挖掘、源码收集都挂在这一层
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS webapps (
    asset_id            UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    url                 TEXT NOT NULL,
    url_norm            TEXT NOT NULL UNIQUE,
    -- 最终访问 URL（跟随跳转后）
    final_url           TEXT,
    scheme              TEXT NOT NULL CHECK (scheme IN ('http', 'https')),
    host                TEXT NOT NULL,
    port                INTEGER NOT NULL,
    path                TEXT NOT NULL DEFAULT '/',
    title               TEXT,
    status_code         INTEGER,
    -- 技术栈数组（httpx -tech-detect 输出）
    tech                TEXT[] NOT NULL DEFAULT '{}',
    -- webserver（httpx 输出的 Server header，如 nginx/Apache/BWS）
    webserver           TEXT,
    -- 资产角色（评分引擎判定）
    role                TEXT CHECK (role IN (
        'admin', 'backend', 'business', 'api', 'dev', 'middleware', 'static', 'unknown'
    )),
    -- 评分（0-100，规则引擎计算）
    score               INTEGER NOT NULL DEFAULT 0,
    -- 评分明细（每条加分减分项的证据）
    score_breakdown     JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- WAF / CDN
    waf                 TEXT,
    cdn                 BOOLEAN NOT NULL DEFAULT false,
    -- 是否存在登录页
    login_page          BOOLEAN NOT NULL DEFAULT false,
    -- 是否难以攻击（CDN+WAF 双重防护等）
    hard_to_attack      BOOLEAN NOT NULL DEFAULT false,
    -- 任务门控建议：['dirscan', 'jsmining', 'history_url', 'github_search', 'source_collect']
    suggested_next      TEXT[] NOT NULL DEFAULT '{}'::text[],
    -- 探测时间
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    meta                JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_webapps_host ON webapps (host);
CREATE INDEX IF NOT EXISTS idx_webapps_score ON webapps (score DESC);
CREATE INDEX IF NOT EXISTS idx_webapps_role ON webapps (role) WHERE role IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_webapps_login_page ON webapps (login_page) WHERE login_page = true;
CREATE INDEX IF NOT EXISTS idx_webapps_tech ON webapps USING gin (tech);
CREATE INDEX IF NOT EXISTS idx_webapps_suggested_next ON webapps USING gin (suggested_next);

-- -----------------------------------------------------------------------------
-- 6. fingerprints：指纹明细（一个 webapp 可对应多条指纹）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fingerprints (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webapp_id   UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    tech        TEXT NOT NULL,
    version     TEXT,
    -- 指纹来源工具（httpx/EHole/wappalyzer/wih 等）
    source_tool TEXT NOT NULL,
    -- 证据（HTTP header / body / cookie 等）
    evidence    TEXT,
    confidence  REAL NOT NULL DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, tech, version, source_tool)
);

CREATE INDEX IF NOT EXISTS idx_fingerprints_webapp_id ON fingerprints (webapp_id);
CREATE INDEX IF NOT EXISTS idx_fingerprints_tech ON fingerprints (tech);

-- -----------------------------------------------------------------------------
-- 7. endpoints：端点（URL/接口路径）
--    来源：js / historical / dirscan
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoints (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webapp_id   UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    url         TEXT NOT NULL,
    path        TEXT NOT NULL,
    method      TEXT NOT NULL DEFAULT 'GET',
    -- 来源：js / historical / dirscan / fofa / icp
    source      TEXT NOT NULL CHECK (source IN ('js', 'historical', 'dirscan', 'fofa', 'icp', 'manual')),
    status_code INTEGER,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, path, method, source)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_webapp_id ON endpoints (webapp_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_path ON endpoints (path);
CREATE INDEX IF NOT EXISTS idx_endpoints_source ON endpoints (source);

-- -----------------------------------------------------------------------------
-- 8. js_apis：JS 内提取的接口（M3/M4 产出）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS js_apis (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webapp_id   UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    api_path    TEXT NOT NULL,
    method      TEXT NOT NULL DEFAULT 'GET',
    params      TEXT[] NOT NULL DEFAULT '{}',
    -- 在哪个 JS 文件中发现的
    source_js   TEXT,
    found_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, api_path, method)
);

CREATE INDEX IF NOT EXISTS idx_js_apis_webapp_id ON js_apis (webapp_id);
CREATE INDEX IF NOT EXISTS idx_js_apis_api_path ON js_apis (api_path);

-- -----------------------------------------------------------------------------
-- 9. params：参数（历史参数 / JS 内参数）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS params (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webapp_id   UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    param       TEXT NOT NULL,
    -- 来源：historical / js / dirscan
    source      TEXT NOT NULL CHECK (source IN ('historical', 'js', 'dirscan')),
    -- 上下文（出现在哪个 URL/JS）
    context     TEXT,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, param, source)
);

CREATE INDEX IF NOT EXISTS idx_params_webapp_id ON params (webapp_id);
CREATE INDEX IF NOT EXISTS idx_params_param ON params (param);

-- -----------------------------------------------------------------------------
-- 10. source_dumps：源码转储（M4 webpack 还原产物）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS source_dumps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webapp_id       UUID NOT NULL REFERENCES webapps(asset_id) ON DELETE CASCADE,
    source_dir      TEXT NOT NULL,
    file_count      INTEGER NOT NULL DEFAULT 0,
    size_bytes      BIGINT NOT NULL DEFAULT 0,
    -- INDEX.json 路径（相对 source_dir）
    index_path      TEXT,
    -- 是否已成功还原（source-map 解码完成）
    restored        BOOLEAN NOT NULL DEFAULT false,
    -- 是否完整（无 .map 缺失）
    complete        BOOLEAN NOT NULL DEFAULT false,
    -- 入口文件列表
    entry_points    TEXT[] NOT NULL DEFAULT '{}',
    -- 还原产物压缩包路径（tar.gz，对外下载用）
    archive_path    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (webapp_id, source_dir)
);

CREATE INDEX IF NOT EXISTS idx_source_dumps_webapp_id ON source_dumps (webapp_id);
CREATE INDEX IF NOT EXISTS idx_source_dumps_restored ON source_dumps (restored) WHERE restored = true;

-- -----------------------------------------------------------------------------
-- 11. findings：发现（敏感信息 / 源码泄露 / 已知漏洞组件 hint 等）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    webapp_id   UUID REFERENCES webapps(asset_id) ON DELETE CASCADE,
    -- 类型：sourcemap / secret / cve_hint / internal_ip / sensitive_path / github_leak
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    detail      TEXT NOT NULL,
    evidence    TEXT,
    source_tool TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    meta        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings (asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_webapp_id ON findings (webapp_id) WHERE webapp_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings (type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings (created_at DESC);

-- -----------------------------------------------------------------------------
-- 12. scan_runs：扫描记录（避免重扫的关键表）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seed_id         UUID REFERENCES seeds(id) ON DELETE SET NULL,
    -- 扫描的目标资产（可空，全 seed 扫描时为 NULL）
    asset_id        UUID REFERENCES assets(id) ON DELETE SET NULL,
    tool            TEXT NOT NULL,
    params          JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running', 'done', 'failed', 'timeout', 'canceled')),
    -- 原始输出文件路径（jsonl/txt）
    raw_output_path TEXT,
    -- 结果摘要（命中数等）
    result_summary  JSONB NOT NULL DEFAULT '{}'::jsonb,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_seed_id ON scan_runs (seed_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_asset_id ON scan_runs (asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_runs_tool ON scan_runs (tool);
CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs (status);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started_at ON scan_runs (started_at DESC);
-- 复合索引：判断某资产是否已跑过某工具（避免重扫）
CREATE INDEX IF NOT EXISTS idx_scan_runs_asset_tool ON scan_runs (asset_id, tool) WHERE asset_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 13. cache：L2 探测结果缓存（Redis 的持久化备份/复用，可选）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cache (
    key         TEXT PRIMARY KEY,
    payload     JSONB NOT NULL,
    ttl         INTEGER NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 过期时间 = created_at + ttl 秒；应用层写入时计算（避免 generated column 的 immutable 限制）
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cache_expires_at ON cache (expires_at);

-- -----------------------------------------------------------------------------
-- 14. audit_log：全量审计（安全层红线，M1 必做）
--    所有工具调用、Scope Gate 决策、LLM 调用都留痕
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- actor: system / tool:<name> / llm:<provider> / user:<id>
    actor       TEXT NOT NULL,
    -- action: tool_call / scope_decision / llm_call / data_write / source_download
    action      TEXT NOT NULL,
    -- 操作目标（资产 ID / URL / 文件路径等）
    target      TEXT,
    -- 决策：allow / deny / pass / fail
    decision    TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'pass', 'fail', 'info')),
    reason      TEXT,
    meta        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_log_decision ON audit_log (decision);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log (target) WHERE target IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 15. schema_migrations：迁移版本管理
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    description TEXT
);

INSERT INTO schema_migrations (version, description) VALUES
    ('001_init', '初始迁移：14 张核心表 + 索引')
ON CONFLICT (version) DO NOTHING;

-- =============================================================================
-- 完毕
-- =============================================================================
