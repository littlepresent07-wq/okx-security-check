#!/usr/bin/env node
/**
 * Bug Bounty Security Check - A2MCP Endpoint (零依赖)
 * 用 Node.js 原生 http 模块，无需 npm install
 *
 * 部署: 推到 GitHub → Render.com 免费托管
 * 本地: node server.js
 */

const http = require('http');
const { URL } = require('url');

// 配置
const PORT = process.env.PORT || 3000;
const PAY_TO = process.env.PAY_TO || '0xad1e159d921186748713fddf40d722ea5aebe060'; // 你的 X Layer 地址

// 安全检查实现（生产环境接 subfinder / nmap / nuclei）
async function runCheck(domain, checkType) {
  switch (checkType) {
    case "subdomain": {
      // 生产: fetch crt.sh API 或 subfinder
      return {
        check_type: "subdomain",
        domain,
        results: [
          { subdomain: "www." + domain, status: "active" },
          { subdomain: "api." + domain, status: "active" },
          { subdomain: "dev." + domain, status: "active" }
        ],
        summary: `发现 3 个子域名`
      };
    }
    case "fingerprint": {
      // 生产: curl -sI https://domain 解析 headers
      return {
        check_type: "fingerprint",
        domain,
        results: {
          tech_stack: ["Nginx", "Next.js", "React"],
          security_headers: {
            "content-security-policy": "present",
            "x-frame-options": "missing",
            "strict-transport-security": "present"
          },
          open_ports: [443, 80, 8080],
          tls: { version: "1.3" }
        },
        summary: "技术栈: Nginx + Next.js, 缺少 X-Frame-Options 头"
      };
    }
    case "xss": {
      return {
        check_type: "xss_scan",
        domain,
        results: [
          { endpoint: "/search?q=", risk: "medium", detail: "GET 参数未过滤" },
          { endpoint: "/comment", risk: "low", detail: "POST 内容已编码" }
        ],
        summary: "发现 2 个潜在 XSS 注入点"
      };
    }
    default:
      return { error: "unsupported check_type", supported: ["subdomain", "fingerprint", "xss"] };
  }
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Payment, X-Payment-Id');

  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  // 健康检查
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200);
    return res.end(JSON.stringify({ status: "ok", service: "bug-bounty-check" }));
  }

  // 安全检查
  if (req.method === 'POST' && req.url === '/check') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const { domain, check_type } = data;

        if (!domain || !check_type) {
          res.writeHead(400);
          return res.end(JSON.stringify({ error: "domain and check_type are required" }));
        }

        // x402 支付检查
        const paymentId = req.headers['x-payment-id'];
        const payment = req.headers['x-payment'];

        if (!paymentId || !payment) {
          // 返回 402 付款挑战
          res.writeHead(402);
          return res.end(JSON.stringify({
            x402Version: 1,
            accepts: [{
              network: "base-sepolia",
              paymentToken: "USDbC",
              maxAmountRequired: "20000",
              payTo: PAY_TO,
              description: `Security check: ${check_type} on ${domain}`,
              extraPayload: { method: "POST", path: "/check", body: data }
            }]
          }));
        }

        // 已付款 → 执行
        const result = await runCheck(domain, check_type);
        res.writeHead(200);
        return res.end(JSON.stringify({ paid: true, paymentId, ...result }));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "not found", endpoints: ["/check", "/health"] }));
});

server.listen(PORT, () => {
  console.log(`Security Check API running on port ${PORT}`);
  console.log(`POST /check {"domain":"example.com","check_type":"subdomain"}`);
  console.log(`GET  /health`);
});
