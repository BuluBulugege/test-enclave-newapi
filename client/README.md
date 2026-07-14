# 客户端验证手册 — 如何确认你连的是真正的无日志 enclave

在把任何 prompt 发给这个 AI 网关之前，你可以**自己验证**它确实运行在一个
无法读取/存储你数据、且只连官方上游的 SGX enclave 里。不需要相信运营方。

## 你在验证什么

| 检查 | 含义 |
|---|---|
| **Check 1 · 结构 & 活性** | 取回远程认证 `quote`：Intel SGX CPU 产出的、描述 enclave 内确切代码的签名声明。 |
| **Check 2 · 度量比对（MRENCLAVE）** | MRENCLAVE 是 enclave 代码+配置的硬件哈希。它必须等于你**独立**拿到的期望值（签名发布 / 你自己可复现重建）。相等 ⇒ 运行的就是那份"不存正文、强制官方 URL"的审计代码。 |
| **Check 3 · 通道绑定** | quote 内嵌 enclave TLS 公钥的 SHA-512。把服务器实际出示的证书公钥同样哈希，必须相等 ⇒ 被认证的 enclave 就是你正在通话的端点（防止运营方转发别人的 quote）。 |
| **+ DCAP 签名链** | 用 Intel DCAP 库验证 quote 确由 Intel 签名——这一步杜绝伪造 quote。由 Go 工具 `relay-verify -dcap-verify` 完成。 |

**只有 Check 1–3 + DCAP 链全部通过，才应发送 prompt。**

## 快速开始（Python，跨平台）

```bash
# Check 1/2 仅需标准库；Check 3（通道绑定）需要：
pip install cryptography

python3 verify_enclave.py \
  --addr 8.217.148.82:8443 \
  --mrenclave 98ba342adb8092d60c940e75ce8e07036c96226595b03f16bb8d35a52a1872ee
```

期望输出：

```
✓ Check 1 quote obtained (4734 bytes) and parsed
✓ Check 2 MRENCLAVE matches the pinned value
✓ Check 3 quote is bound to THIS TLS channel (report_data == SHA-512(server pubkey))
RESULT: PARTIAL PASS (structure + MRENCLAVE + channel binding)
```

若 MRENCLAVE 不符，工具会 `✗ Check 2 FAILED` 并拒绝——**不要**发送 prompt。

## 完整保证：加上 DCAP 签名链验证

纯 Python 工具做了度量与通道绑定，但没有验证 quote 的 Intel 签名。要杜绝伪造
quote，在装有 `libsgx_dcap_quoteverify` 的机器上再跑 Go 验证器：

```bash
CGO_ENABLED=1 go build -tags dcap ./cmd/relay-verify
./relay-verify -addr 8.217.148.82:8443 \
  -mrenclave 98ba342adb8092d60c940e75ce8e07036c96226595b03f16bb8d35a52a1872ee -dcap-verify
```

通过后显示 `✅ DCAP signature chain verified to Intel SGX root` + `VERIFICATION PASSED`。

## 验证后直接发 prompt（同一条已验证通道）

验证器可在三项检查通过后，立即向**同一个已认证的 enclave** 发一条真实请求，
从而闭环证明"验证 → 发送"。发送前会**重新固定通道**：读取本次连接服务器出示的
TLS 证书，要求 `SHA-512(公钥)` 等于已验证 quote 里的 `report_data`，确保 prompt
只发给那台被认证的 enclave（需要 `cryptography` 包，否则拒绝发送而非明发）。

```bash
python3 verify_enclave.py \
  --addr 8.217.148.82:8443 \
  --mrenclave 98ba342adb8092d60c940e75ce8e07036c96226595b03f16bb8d35a52a1872ee \
  --token <你的网关 API token> \
  --model databricks-claude-opus-4-8 \
  --send-prompt "Reply with exactly: VERIFIED"
```

期望结尾：

```
✓ HTTP 200 — response received over the attested, no-content channel:
    'VERIFIED'
    usage: 20+8 tokens
```

enclave 只服务 **official（官方）** 渠道/分组，且每个请求真正到达的上游主机是在
enclave 内部强制的（编译进 MRENCLAVE），运营方无法改指向 MITM 代理。当前支持的
官方上游:

| Provider | 模型示例 | enclave 端点格式 |
|---|---|---|
| OpenAI | gpt-4o-mini | `/v1/chat/completions`（固定官方 host） |
| OpenRouter | deepseek/deepseek-chat | `/v1/chat/completions`（+ 归属头） |
| Anthropic | claude-* | `/v1/messages`（原生 Messages API） |
| Gemini / AI-Studio | gemini-* | OpenAI 兼容面（enclave 内改写路径） |
| AWS Bedrock | Nova / Claude | 区域 host 内部推导 + SigV4 签名（含 STS） |
| Databricks | databricks-claude-opus-4-8 | per-workspace host（`*.azuredatabricks.net`，enclave 重校验后 Bearer） |

> Databricks / OpenAI / OpenRouter / Gemini 走 OpenAI 格式（`/v1/chat/completions`）；
> Anthropic 走原生 `/v1/messages`。Databricks 这类 suffix-host 提供商在 `/official`
> 上**只支持 OpenAI 格式**（enclave 透传不做正文转换），对 `/v1/messages` 会明确拒绝。

## 期望的 MRENCLAVE 从哪来（重要）

不要从被验证的服务器获取期望值（那会变成"自己证明自己"）。正确来源：
1. 项目的**签名发布**（`docs/RELEASE-enclave.md`）；或
2. 你**自己按源码可复现重建**得到（`cmd/relay-core/Dockerfile.reproducible`），
   两次构建字节一致、零外部依赖，得到的 MRENCLAVE 应与线上一致。

## 常见问题

- **为什么用 `curl -k` / 跳过证书校验？** 证书是自签的 RA-TLS 证书；信任来自
  **quote**，不是 CA。这是设计使然，不是降级。
- **调用返回 403 `unsupported_country_region_territory`？** 这是上游 OpenAI 对
  演示服务器所在区域的地域封锁——说明请求**已到达真官方 OpenAI**，链路正确。
