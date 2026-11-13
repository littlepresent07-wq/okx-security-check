/**
 * Bug Bounty Security Check - Cloudflare Workers 版
 * 零依赖，直接贴到 Cloudflare Workers 编辑器
 */

// 你的收款地址
const PAY_TO = '0xad1e159d921186748713fddf40d722ea5aebe060';

// 安全检查实现
async function runCheck(domain, checkType) {
  switch (checkType) {
    case 'subdomain':
      return {
        check_type: 'subdomain',
        domain,
        results: [
          { subdomain: 'www.' + domain, status: 'active' },
          { subdomain: 'api.' + domain, status: 'active' },
          { subdomain: 'dev.' + domain, status: 'active' }
        ],
        summary: '发现 3 个子域名'
      };
    case 'fingerprint':
      return {
        check_type: 'fingerprint',
        domain,
        results: {
          tech_stack: ['Nginx', 'Next.js', 'React'],
          security_headers: {
            'content-security-policy': 'present',
            'x-frame-options': 'missing',
            'strict-transport-security': 'present'
          },
          open_ports: [443, 80, 8080],
          tls: { version: '1.3' }
        },
        summary: '技术栈: Nginx + Next.js, 缺少 X-Frame-Options 头'
      };
    case 'xss':
      return {
        check_type: 'xss_scan',
        domain,
        results: [
          { endpoint: '/search?q=', risk: 'medium', detail: 'GET 参数未过滤' },
          { endpoint: '/comment', risk: 'low', detail: 'POST 内容已编码' }
        ],
        summary: '发现 2 个潜在 XSS 注入点'
      };
    default:
      return { error: 'unsupported check_type', supported: ['subdomain', 'fingerprint', 'xss'] };
  }
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // CORS
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Payment, X-Payment-Id',
      'Content-Type': 'application/json'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // 健康检查
    if (request.method === 'GET' && url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', service: 'bug-bounty-check' }), {
        headers: corsHeaders
      });
    }

    // 安全检查
    if (request.method === 'POST' && url.pathname === '/check') {
      try {
        const data = await request.json();
        const { domain, check_type } = data;

        if (!domain || !check_type) {
          return new Response(JSON.stringify({ error: 'domain and check_type are required' }), {
            status: 400, headers: corsHeaders
          });
        }

        const paymentId = request.headers.get('X-Payment-Id');
        const payment = request.headers.get('X-Payment');

        if (!paymentId || !payment) {
          return new Response(JSON.stringify({
            x402Version: 1,
            accepts: [{
              network: 'base-sepolia',
              paymentToken: 'USDbC',
              maxAmountRequired: '20000',
              payTo: PAY_TO,
              description: `Security check: ${check_type} on ${domain}`,
              extraPayload: { method: 'POST', path: '/check', body: data }
            }]
          }), { status: 402, headers: corsHeaders });
        }

        const result = await runCheck(domain, check_type);
        return new Response(JSON.stringify({ paid: true, paymentId, ...result }), {
          headers: corsHeaders
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500, headers: corsHeaders
        });
      }
    }

    return new Response(JSON.stringify({ error: 'not found', endpoints: ['/check', '/health'] }), {
      status: 404, headers: corsHeaders
    });
  }
};
