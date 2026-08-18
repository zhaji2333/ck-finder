-- =============================================================================
-- 012_asset_groups.sql：资产管理分组（资产组）
--
-- 资产组 = 命名 + 授权范围（scope）的容器，把「添加资产 → 信息收集 → 挖洞」的组织单位。
-- 资产归属：按 scope 匹配（webapp.host 命中组范围即归属），无需显式成员表。
-- =============================================================================

CREATE TABLE IF NOT EXISTS asset_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 资产组名称（唯一）
    name        TEXT NOT NULL UNIQUE,
    -- 资产组范围（域名/IP/CIDR 白名单）
    scope       TEXT[] NOT NULL DEFAULT '{}',
    -- 备注描述
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asset_groups_name ON asset_groups (name);
CREATE INDEX IF NOT EXISTS idx_asset_groups_scope ON asset_groups USING gin (scope);

INSERT INTO schema_migrations (version, description) VALUES
    ('012_asset_groups', '资产管理分组（资产组：名称 + 授权范围）')
ON CONFLICT (version) DO NOTHING;
