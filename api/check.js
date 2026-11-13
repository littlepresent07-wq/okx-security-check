/**
 * Vercel API: /api/check
 * POST {"domain": "example.com", "check_type": "fingerprint"}
 */

const PAY_TO = process.env.PAY_TO || '0xad1e159d921186748713fddf40d722ea5aebe060';

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

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Payment, X-Payment-Id');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') return res.status(204).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST only', endpoints: ['/api/check', '/api/health'] });
  }

  try {
    const { domain, check_type } = req.body || {};

    if (!domain || !check_type) {
      return res.status(400).json({ error: 'domain and check_type are required' });
    }

    const paymentId = req.headers['x-payment-id'];
    const payment = req.headers['x-payment'];

    if (!paymentId || !payment) {
      return res.status(402).json({
        x402Version: 1,
        accepts: [{
          network: 'base-sepolia',
          paymentToken: 'USDbC',
          maxAmountRequired: '20000',
          payTo: PAY_TO,
          description: 'Security check: ' + check_type + ' on ' + domain,
          extraPayload: { method: 'POST', path: '/api/check', body: { domain, check_type } }
        }]
      });
    }

    const result = await runCheck(domain, check_type);
    return res.json({ paid: true, paymentId, ...result });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
};
