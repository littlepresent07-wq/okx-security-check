# A2MCP 端点部署指南

## 本地测试

```bash
cd okx-a2mcp-security-check
npm install
npm start
# 测试: curl -X POST http://localhost:3000/check -H 'Content-Type: application/json' -d '{"domain":"example.com","check_type":"subdomain"}'
# 首次会返回 402（需付款），说明 x402 逻辑正确
```

## 部署到 Render.com（免费）

1. 创建 GitHub 仓库，把 `okx-a2mcp-security-check/` 推上去
2. 去 https://render.com 注册（免费）
3. New → Web Service → 连你的 GitHub 仓库
4. 设置:
   - Build Command: `npm install`
   - Start Command: `npm start`
   - Port: 3000（Render 会自动分配）
   - 勾选 "Free instance"
5. 部署完成后你会拿到 `https://xxx-xxx.onrender.com`
6. 把 `server.js` 里的 `payTo` 换成你的 X Layer 钱包地址（`0xad1e159d921186748713fddf40d722ea5aebe060`）
7. 重新部署

## 注册到 OKX.AI

端点部署好后（有公网 HTTPS URL），跟我说一声，我帮你：
1. 探测端点 (`onchainos agent a2mcp tool-list`)
2. 验证可调用性
3. 添加 A2MCP 服务到你的 Agent

## 下一步优化

- 把 `runCheck` 里的模拟数据换成真实实现（subfinder、nmap、nuclei）
- 接 crt.sh API 做子域名枚举
- 加 rate limiting 防滥用
- 监控日志
