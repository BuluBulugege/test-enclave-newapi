# 可视化交互演示（FastAPI）

一个网页，两个按钮，让懂前后端的人**看懂**：
1. 怎么验证一台服务器确实是真正的无日志 SGX enclave；
2. 一次 AI 请求在每一跳到底带了什么数据——尤其看清**发给不可信 new-api 的那一跳里没有你的 prompt**。

页面所有动作都调用真实的公网 enclave 端点，不是假数据。

## 运行

```bash
pip install -r requirements.txt

# 可选：设一个默认网关 token（也可以直接在网页输入框里粘贴）
export RELAY_DEMO_TOKEN=<你的网关 token>

uvicorn app:app --port 8000
# 打开 http://127.0.0.1:8000
```

可选环境变量：
- `ENCLAVE_ADDR`（默认 `8.217.148.82:8443`）
- `EXPECTED_MRENCLAVE`（默认当前上线值）
- `RELAY_DEMO_TOKEN`（默认空；也可在 UI 粘贴）

## 页面在做什么

- **① 开始验证** → 调 `GET /api/verify`：后端实时取回 enclave 的远程认证 quote，跑三项检查
  （结构 / MRENCLAVE 指纹比对 / TLS 通道绑定），每项用大白话解释。
- **② 发送并可视化** → 调 `POST /api/chat`：后端把你的 prompt 真实地发给 enclave，
  返回真实响应 + 一份"每一跳带了什么"的 trace。网页把 4 个节点（你 / SGX Enclave /
  new-api 控制面 / OpenAI 官方）画成流程图，逐跳高亮并展示该边界上流动的真实/结构化数据。

## 后端接口

| 接口 | 作用 |
|---|---|
| `GET /` | 内嵌脚本的可视化页面 |
| `GET /api/config` | 端点 + 期望 MRENCLAVE |
| `GET /api/verify` | 实时验证（quote 结构 + MRENCLAVE + 通道绑定）|
| `POST /api/chat` | 实时经 enclave 转发一次请求，返回响应 + 逐跳 trace |

> 完整杜绝伪造 quote 还需 DCAP 签名链验证（见 `../client/`）。403 = 香港地域封锁（=请求已到达真官方 OpenAI）。
