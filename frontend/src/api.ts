// 统一 API 层：fetch 封装 + 全部端点

async function j<T = unknown>(url: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((d as { error?: string }).error || r.statusText);
  return d as T;
}

function post<T = unknown>(url: string, body?: unknown): Promise<T> {
  return j<T>(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

function put<T = unknown>(url: string, body?: unknown): Promise<T> {
  return j<T>(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

function del<T = unknown>(url: string): Promise<T> {
  return j<T>(url, { method: 'DELETE' });
}

// ---- 类型 ----
export interface WebappRow {
  assetId: string;
  url: string;
  title?: string | null;
  score: number;
  role?: string | null;
  tech?: string[];
  findingCount?: number;
  statusCode?: number | null;
  loginPage?: boolean;
  cdn?: boolean;
  waf?: string | null;
  webserver?: string | null;
  host?: string | null;
  port?: number | null;
  /** 当前挖洞中的活跃意图数（running+pending） */
  activeIntents?: number;
}

export interface SeedRow {
  id: string;
  seedType: string;
  value: string;
  status: string;
  assetCount: number;
  webappCount: number;
  createdAt: string;
  progress?: { stage?: string; stageLabel?: string; deepScan?: { done: number; total: number } } | null;
  meta?: { hunt?: boolean };
  intentCounts?: Record<string, number>;
  intentsTotal?: number;
}

export interface AssetStats {
  types: Record<string, number>;
  domain: number;
  ip: number;
  webapp: number;
  services: number;
  ips: number;
  alive: number;
  roles: Record<string, number>;
}

export interface Group {
  id: string;
  name: string;
  description?: string;
  scope: string[];
  created_at?: string;
  updated_at?: string;
  webapp_count?: number;
  domain_count?: number;
}

export interface Finding {
  id: string;
  vulnName: string;
  vulnType: string;
  severity: string;
  url: string;
  summary: string;
  status: string;
  reviewStatus: string;
  deepenCount?: number;
  deepenDirective?: string | null;
  evidence?: { poc: string; raw_request: string; raw_response: string; self_check: unknown };
}

export interface ReviewRecord {
  verdict: string;
  reproduced?: boolean;
  score?: number;
  reasoning?: string;
}

export interface Overview {
  seeds: number;
  assets: number;
  webapps: number;
  intents: Record<string, number>;
  intentsTotal: number;
  findings: Record<string, number>;
  findingsTotal: number;
  findingBySeverity: Record<string, number>;
  intel: Record<string, number>;
  highValueFindings: Array<{ reviewStatus: string; severity: string; count: number }>;
}

export interface ConfigField {
  key: string;
  label: string;
  group: string;
  type: string;
  secret?: boolean;
  placeholder?: string;
  help?: string;
  value: string;
  set: boolean;
}

// ---- 端点 ----
export const api = {
  health: () => j<{ status: string; postgres: unknown; redis: unknown; assetCount: number }>('/healthz'),

  // 看板
  overview: () => j<Overview>('/api/command/overview'),
  seeds: (limit = 100) => j<{ total: number; seeds: SeedRow[] }>(`/api/command/seeds?limit=${limit}`),

  // 挖洞
  intents: (seedId?: string) =>
    j<{
      total?: number;
      intents?: Array<Record<string, unknown>>;
      tasks?: Array<{ seedId: string; intents: Array<Record<string, unknown>> }>;
    }>(`/api/command/intents${seedId ? `?seed_id=${seedId}` : ''}`),
  run: (body: { seed: string; scope?: string[]; goal?: string; maxRounds?: number; maxIntents?: number }) =>
    post<{ seedId: string; seedType: string; goal?: string | null }>('/api/command/run', body),
  cancelStuck: () => post<{ canceled: number }>('/api/command/intents/cancel-stuck'),
  clearIntents: (seedId?: string) => post<{ intents: number; facts: number; activities: number }>('/api/command/intents/clear', { seedId }),
  hunt: (body: { urls: string[]; concurrency?: number; goal?: string }) =>
    post<{ started: number; urls: string[] }>('/api/command/hunt', body),

  // 资产管理
  assetStats: () => j<AssetStats>('/api/command/assets/stats'),
  assets: (type: string, q = '', limit = 500) =>
    j<{ type: string; total: number; assets: unknown[] }>(
      `/api/command/assets?type=${type}&q=${encodeURIComponent(q)}&limit=${limit}`,
    ),
  assetAdd: (value: string, collect: boolean) =>
    post<{ seedId: string; seedType: string; value: string; scopeEntry: string; collectStarted: boolean }>(
      '/api/command/assets/add',
      { value, collect },
    ),
  assetDelete: (id: string) => del<{ deleted: number; assetIds: string[] }>(`/api/command/assets/${id}`),
  assetMetadata: (id: string) => j<Record<string, unknown>>(`/api/v1/assets/${id}/metadata`),
  assetRow: (id: string) => j<Record<string, unknown>>(`/api/v1/assets/${id}`),
  purge: (domain: string) => post<{ deletedSeeds: number; deletedAssets: number }>('/api/command/purge', { domain }),
  deepScan: (id: string) => post<{ finalScore: number; finalLevel: string; ranTasks?: string[] }>(`/api/v1/webapps/${id}/deep-scan`),
  sourceDumps: (id: string) => j<{ sourceDumps?: unknown[]; records?: unknown[] }>(`/api/v1/sources/${id}`),
  sources: (limit = 50) => j<{ sourceDumps?: unknown[]; records?: unknown[]; total?: number }>(`/api/v1/sources?limit=${limit}`),

  // 资产组
  groups: () => j<{ total: number; groups: Group[] }>('/api/command/groups'),
  groupCreate: (body: { name: string; scope: string[]; description?: string }) =>
    post<{ group: Group }>('/api/command/groups', body),
  groupDetail: (id: string) => j<{ group: Group; webappTotal: number; webapps: unknown[] }>(`/api/command/groups/${id}`),
  groupDelete: (id: string) => del<{ deleted: number }>(`/api/command/groups/${id}`),
  groupCollect: (id: string) => post<{ groupId: string; name: string; collectStarted: number }>(`/api/command/groups/${id}/collect`),

  // 白名单
  scope: () => j<{ scope: string[] }>('/api/command/scope'),
  scopeChange: (action: 'add' | 'remove', value: string) => post<{ scope: string[] }>('/api/command/scope', { action, value }),

  // 任务管理
  seedsV1: (limit = 100) => j<{ total: number; seeds: SeedRow[] }>(`/api/v1/seeds?limit=${limit}`),
  seedSubmit: (seed: string, mode: string) =>
    post<{ seedId: string }>('/api/v1/seeds', { seed, options: { mode } }),
  seedDelete: (id: string) => del<{ deleted: number }>(`/api/command/seeds/${id}`),
  seedBatchDelete: (ids: string[]) => post<{ deleted: number }>('/api/command/seeds/batch-delete', { ids }),
  recover: () => post<{ staleRuns: number; recoveredSeeds: number }>('/api/command/recover'),
  icpSubmit: (name: string, company: string) => post<{ seedId: string; company: string; name: string; status: string }>('/api/command/icp', { name, company }),
  icpList: () => j<{ total: number; tasks: Array<{ id: string; company: string; status: string; name: string; icp_domain_count?: number; subdomain_count?: number; webapp_count?: number }> }>('/api/command/icp'),

  // 复审
  reviewFindings: (status = 'pending', limit = 50) =>
    j<{ total: number; findings: Finding[] }>(`/api/review/findings?status=${status}&limit=${limit}`),
  reviewDetail: (id: string) => j<{ finding: Finding; reviews: ReviewRecord[] }>(`/api/review/findings/${id}`),
  reviewAi: (id: string) => post<{ outcome: { verdict: string; reproduced?: boolean } }>(`/api/review/findings/${id}/review`),
  reviewPending: () => post<{ total: number; results: unknown[] }>('/api/review/review-pending'),
  reviewDecision: (id: string, action: string) => post(`/api/review/findings/${id}/decision`, { action }),
  reviewDeepen: (id: string, directive: string) => post(`/api/review/findings/${id}/deepen`, { directive }),
  intel: (kind?: string) => j<{ stats?: Record<string, number>; entries?: unknown[] }>(`/api/review/intel${kind ? `?kind=${kind}` : ''}`),

  // 设置
  config: () => j<{ fields: ConfigField[]; status: { llmConfigured: boolean; llmPoolProviders: number; scope: string[]; scopeGateEnabled: boolean; model: string; modelPro: string }; envPath: string }>('/api/config'),
  configSave: (updates: Record<string, string>) => put<{ changed: string[]; skipped: string[] }>('/api/config', { updates }),
  configTestLlm: () => post<{ ok: boolean; model?: string; reply?: string; error?: string }>('/api/config/test-llm'),

  // 采集（收集引擎）
  findingsV1: (webappId: string, limit = 20) =>
    j<{ findings: Array<{ type: string; severity: string; detail: string }> }>(`/api/v1/findings?webapp_id=${webappId}&limit=${limit}`),
};

export type Api = typeof api;
