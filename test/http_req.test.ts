/**
 * http_req 工具测试：本地 mock server 验证请求/响应/raw 记录。
 */
import { type Server, createServer } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { httpReqTool } from '../src/tools/http_req.js';

let server: Server;
let port = 0;

beforeAll(async () => {
	server = createServer((req, res) => {
		if (req.url === '/login') {
			let body = '';
			req.on('data', (c) => {
				body += c;
			});
			req.on('end', () => {
				if (body.includes('admin')) {
					res.writeHead(302, { Location: '/dashboard', 'Set-Cookie': 'PHPSESSID=abc123' });
					res.end();
				} else {
					res.writeHead(200, { 'Content-Type': 'text/html' });
					res.end('<html>wrong password</html>');
				}
			});
			return;
		}
		if (req.url === '/data') {
			res.writeHead(200, { 'Content-Type': 'application/json' });
			res.end(JSON.stringify({ userId: 1, secret: 'x'.repeat(200) }));
			return;
		}
		res.writeHead(404);
		res.end('not found');
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
	port = (server.address() as { port: number }).port;
});

afterAll(() => {
	server.close();
});

const base = () => `http://127.0.0.1:${port}`;

describe('http_req', () => {
	it('GET 返回状态/头/正文 + raw 记录', async () => {
		const res = await httpReqTool.execute('c1', { url: `${base()}/data` });
		expect(res.details.status).toBe(200);
		expect(res.details.rawRequest).toContain('GET /data HTTP/1.1');
		expect(res.details.rawResponse).toContain('HTTP/1.1 200');
		expect(res.details.rawResponse).toContain('"userId"');
	});

	it('POST 登录成功（302）记录原始请求', async () => {
		const res = await httpReqTool.execute('c2', {
			url: `${base()}/login`,
			method: 'POST',
			body: 'username=admin&password=admin',
			followRedirects: false,
		});
		expect(res.details.status).toBe(302);
		expect(res.details.rawRequest).toContain('POST /login HTTP/1.1');
		expect(res.details.rawRequest).toContain('username=admin&password=admin');
		expect(res.details.rawRequest).toContain('Content-Length:');
	});

	it('POST 登录失败（200 + 错误体）', async () => {
		const res = await httpReqTool.execute('c3', {
			url: `${base()}/login`,
			method: 'POST',
			body: 'username=bob&password=wrong',
			followRedirects: false,
		});
		expect(res.details.status).toBe(200);
		expect(res.details.rawResponse).toContain('wrong password');
	});

	it('自定义 header 与 cookie 生效', async () => {
		const res = await httpReqTool.execute('c4', {
			url: `${base()}/login`,
			method: 'POST',
			body: 'username=admin&password=admin',
			cookie: 'PHPSESSID=abc123',
			followRedirects: false,
		});
		expect(res.details.rawRequest).toContain('cookie: PHPSESSID=abc123');
	});

	it('超时抛错', async () => {
		await expect(
			httpReqTool.execute('c5', { url: 'http://10.255.255.1:9999/', timeoutMs: 1500 }),
		).rejects.toThrow();
	});
});
