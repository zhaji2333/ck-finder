import { describe, expect, it } from 'vitest';
import { normalizeSeed, normalizeSeedAs } from '../../src/recon/seeds/normalizer.js';
import { SeedNormalizeError } from '../../src/recon/seeds/types.js';

describe('normalizeSeed', () => {
	describe('domain', () => {
		it('正常域名', () => {
			const s = normalizeSeed('example.com');
			expect(s.seedType).toBe('domain');
			expect(s.valueNorm).toBe('example.com');
			expect(s.parsed).toEqual({ kind: 'domain', domain: 'example.com' });
		});

		it('大写转小写', () => {
			const s = normalizeSeed('EXAMPLE.COM');
			expect(s.valueNorm).toBe('example.com');
		});

		it('去 www 前缀', () => {
			const s = normalizeSeed('www.example.com');
			expect(s.valueNorm).toBe('example.com');
		});

		it('去末尾斜杠', () => {
			const s = normalizeSeed('example.com/');
			expect(s.valueNorm).toBe('example.com');
		});

		it('多级子域', () => {
			const s = normalizeSeed('api.v2.example.com');
			expect(s.valueNorm).toBe('api.v2.example.com');
		});

		it('无效域名抛错', () => {
			expect(() => normalizeSeedAs('not_a_domain', 'domain')).toThrow(SeedNormalizeError);
		});
	});

	describe('url', () => {
		it('http URL', () => {
			const s = normalizeSeed('http://example.com/path');
			expect(s.seedType).toBe('url');
			expect(s.valueNorm).toBe('http://example.com/path');
			expect(s.parsed).toEqual({
				kind: 'url',
				url: 'http://example.com/path',
				scheme: 'http',
				host: 'example.com',
				port: null,
				path: '/path',
				domain: 'example.com',
			});
		});

		it('https URL 默认端口不保留', () => {
			const s = normalizeSeed('https://example.com:443/');
			expect(s.parsed.kind).toBe('url');
			if (s.parsed.kind === 'url') {
				expect(s.parsed.port).toBe(null);
				expect(s.valueNorm).toBe('https://example.com/');
			}
		});

		it('非默认端口保留', () => {
			const s = normalizeSeed('http://example.com:8080/path');
			if (s.parsed.kind === 'url') {
				expect(s.parsed.port).toBe(8080);
				expect(s.valueNorm).toBe('http://example.com:8080/path');
			}
		});

		it('去 www 前缀', () => {
			const s = normalizeSeed('https://www.example.com/');
			if (s.parsed.kind === 'url') {
				expect(s.parsed.host).toBe('example.com');
			}
		});

		it('根路径统一', () => {
			const s = normalizeSeed('https://example.com');
			if (s.parsed.kind === 'url') {
				expect(s.parsed.path).toBe('/');
			}
		});

		it('不包含 query/fragment', () => {
			const s = normalizeSeed('https://example.com/path?foo=bar#baz');
			if (s.parsed.kind === 'url') {
				expect(s.parsed.url).toBe('https://example.com/path');
			}
		});
	});

	describe('ip', () => {
		it('正常 IP', () => {
			const s = normalizeSeed('1.2.3.4');
			expect(s.seedType).toBe('ip');
			expect(s.parsed).toEqual({ kind: 'ip', ip: '1.2.3.4' });
		});

		it('边界 IP', () => {
			expect(normalizeSeed('0.0.0.0').valueNorm).toBe('0.0.0.0');
			expect(normalizeSeed('255.255.255.255').valueNorm).toBe('255.255.255.255');
		});

		it('无效 IP 抛错', () => {
			expect(() => normalizeSeedAs('256.1.1.1', 'ip')).toThrow(SeedNormalizeError);
			expect(() => normalizeSeedAs('1.2.3', 'ip')).toThrow(SeedNormalizeError);
		});
	});

	describe('cidr', () => {
		it('正常 CIDR', () => {
			const s = normalizeSeed('10.0.0.0/24');
			expect(s.seedType).toBe('cidr');
			expect(s.valueNorm).toBe('10.0.0.0/24');
			expect(s.parsed).toEqual({ kind: 'cidr', cidr: '10.0.0.0/24', ip: '10.0.0.0', prefix: 24 });
		});

		it('非 network 地址标准化为 network', () => {
			const s = normalizeSeed('10.0.0.5/24');
			expect(s.valueNorm).toBe('10.0.0.0/24');
		});

		it('/32 单主机', () => {
			const s = normalizeSeed('1.2.3.4/32');
			expect(s.valueNorm).toBe('1.2.3.4/32');
		});

		it('/0 全网', () => {
			const s = normalizeSeed('255.255.255.255/0');
			expect(s.valueNorm).toBe('0.0.0.0/0');
		});

		it('无效前缀抛错', () => {
			expect(() => normalizeSeedAs('1.2.3.4/33', 'cidr')).toThrow(SeedNormalizeError);
		});
	});

	describe('ip_port', () => {
		it('正常 IP:Port', () => {
			const s = normalizeSeed('1.2.3.4:8080');
			expect(s.seedType).toBe('ip_port');
			expect(s.parsed).toEqual({ kind: 'ip_port', ip: '1.2.3.4', port: 8080 });
		});

		it('端口边界', () => {
			expect(normalizeSeed('1.2.3.4:1').valueNorm).toBe('1.2.3.4:1');
			expect(normalizeSeed('1.2.3.4:65535').valueNorm).toBe('1.2.3.4:65535');
		});

		it('端口超范围抛错', () => {
			expect(() => normalizeSeedAs('1.2.3.4:0', 'ip_port')).toThrow(SeedNormalizeError);
			expect(() => normalizeSeedAs('1.2.3.4:65536', 'ip_port')).toThrow(SeedNormalizeError);
		});
	});

	describe('company_name', () => {
		it('中文公司名', () => {
			const s = normalizeSeed('北京某某科技有限公司');
			expect(s.seedType).toBe('company_name');
			expect(s.valueNorm).toBe('北京某某科技有限公司');
		});

		it('合并连续空格', () => {
			const s = normalizeSeed('北京   某某   科技   有限公司');
			expect(s.valueNorm).toBe('北京 某某 科技 有限公司');
		});

		it('保留大小写（英文公司名）', () => {
			const s = normalizeSeed('Alibaba Group');
			expect(s.valueNorm).toBe('Alibaba Group');
		});
	});

	describe('自动判定优先级', () => {
		it('URL 优先于 Domain（含路径）', () => {
			const s = normalizeSeed('example.com/admin');
			expect(s.seedType).toBe('url');
		});

		it('CIDR 优先于 IP（含 / 前缀）', () => {
			const s = normalizeSeed('10.0.0.0/24');
			expect(s.seedType).toBe('cidr');
		});

		it('IP:Port 优先于 Domain', () => {
			const s = normalizeSeed('1.2.3.4:8080');
			expect(s.seedType).toBe('ip_port');
		});

		it('纯 IP 识别为 IP 而非 Domain', () => {
			const s = normalizeSeed('1.2.3.4');
			expect(s.seedType).toBe('ip');
		});

		it('带协议的 URL 识别为 URL', () => {
			const s = normalizeSeed('https://example.com');
			expect(s.seedType).toBe('url');
		});

		it('兜底识别为 Company Name', () => {
			const s = normalizeSeed('某公司');
			expect(s.seedType).toBe('company_name');
		});

		it('空字符串抛错', () => {
			expect(() => normalizeSeed('')).toThrow(SeedNormalizeError);
			expect(() => normalizeSeed('   ')).toThrow(SeedNormalizeError);
		});
	});
});
