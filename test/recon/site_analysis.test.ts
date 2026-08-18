import { describe, expect, it } from 'vitest';
import { analyzeSiteHtml } from '../../src/recon/pipeline/single_site.js';

describe('analyzeSiteHtml', () => {
	it('React SPA：框架 + 架构 + JS 提取', () => {
		const html = `<!DOCTYPE html><html><head>
      <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
      <script src="/static/js/main.js"></script>
      <script src="https://cdn.example.com/vendor.min.js"></script>
      </head><body>
      <noscript>You need to enable JavaScript to run this app.</noscript>
      <div id="root"></div>
      </body></html>`;
		const a = analyzeSiteHtml(html, {}, 'https://app.example.com/login');
		expect(a.framework).toContain('react');
		expect(a.architecture).toBe('spa');
		expect(a.jsUrls).toContain('https://app.example.com/static/js/main.js');
		expect(a.jsUrls).toContain('https://cdn.example.com/vendor.min.js');
	});

	it('Next.js SSR：__NEXT_DATA__ 指纹', () => {
		const html = `<html><head><script>window.__NEXT_DATA__ = {"props":{}}</script>
      <script src="/_next/static/chunks/main.js"></script></head></html>`;
		const a = analyzeSiteHtml(html, {}, 'https://next.example.com');
		expect(a.framework).toContain('next');
		expect(a.buildTool).toContain('webpack');
		expect(a.architecture).toBe('ssr');
	});

	it('Vue + webpack：指纹检测', () => {
		const html = `<html><body><div id="app" data-v-12345678></div>
      <script src="/assets/app.js"></script>
      <script>window.webpackJsonp=[];</script></body></html>`;
		const a = analyzeSiteHtml(html, {}, 'https://vue.example.com');
		expect(a.framework).toContain('vue');
		expect(a.buildTool).toContain('webpack');
		expect(a.architecture).toBe('spa');
	});

	it('PHP/WordPress：响应头 + generator 语言检测', () => {
		const html = `<html><head>
      <meta name="generator" content="WordPress 6.4">
      <link rel="stylesheet" href="/wp-content/themes/x/style.css">
      <form action="/wp-login.php" method="post"></form>
      </head></html>`;
		const a = analyzeSiteHtml(html, { 'x-powered-by': 'PHP/8.2.10' }, 'https://blog.example.com');
		expect(a.framework).toContain('wordpress');
		expect(a.language).toContain('php');
	});

	it('ASP.NET：X-AspNet-Version 语言检测', () => {
		const html = `<html><body><form action="/login.aspx"></form></body></html>`;
		const a = analyzeSiteHtml(
			html,
			{ 'x-aspnet-version': '4.0.30319' },
			'https://corp.example.com',
		);
		expect(a.language).toContain('csharp');
	});

	it('静态站：Hugo generator → static', () => {
		const html = `<html><head><meta name="generator" content="Hugo 0.120.0"></head>
      <body><a href="/about.html">About</a><a href="/blog.html">Blog</a><a href="/contact.html">Contact</a></body></html>`;
		const a = analyzeSiteHtml(html, {}, 'https://docs.example.com');
		expect(a.architecture).toBe('static');
		expect(a.framework).toEqual([]);
	});

	it('MPA：多 .html 链接', () => {
		const html = `<html><body>
      <a href="/a.html">A</a><a href="/b.html">B</a><a href="/c.html">C</a><a href="/d.html">D</a>
      <script src="/js/common.js"></script>
      </body></html>`;
		const a = analyzeSiteHtml(html, {}, 'https://portal.example.com');
		expect(a.architecture).toBe('mpa');
		expect(a.jsUrls).toHaveLength(1);
	});

	it('协议相对 URL 解析为 https', () => {
		const html = `<html><body><script src="//cdn.example.com/app.js"></script></body></html>`;
		const a = analyzeSiteHtml(html, {}, 'https://site.example.com');
		expect(a.jsUrls).toContain('https://cdn.example.com/app.js');
	});
});
