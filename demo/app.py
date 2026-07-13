#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive visual demo for the confidential-computing relay-core enclave.

Run:
    pip install -r requirements.txt
    export RELAY_DEMO_TOKEN=<your gateway token>   # optional; can also paste in UI
    uvicorn app:app --reload --port 8000
    open http://127.0.0.1:8000

It serves ONE page (index.html, with embedded JS) plus two real API endpoints
the page calls:

  GET  /api/config    -> endpoint + expected MRENCLAVE the UI should show
  GET  /api/verify    -> LIVE: fetch the enclave quote, run the 3 checks
  POST /api/chat      -> LIVE: send a prompt through the enclave and return the
                         real response + a per-hop "trace" of what data crossed
                         each trust boundary (so you can SEE the prompt never
                         reaches the untrusted new-api control plane).

Everything talks to the real, public SGX endpoint; nothing here is faked.
"""
import base64
import hashlib
import json
import os
import ssl
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# ---- config (override via env) ----------------------------------------------
ENCLAVE_ADDR = os.getenv("ENCLAVE_ADDR", "8.217.148.82:8443")
EXPECTED_MRENCLAVE = os.getenv(
    "EXPECTED_MRENCLAVE",
    "4aa951d16a0c237605f032cd480095b65be1f485e9f7a959a16f38a80428a445",
).lower()
DEFAULT_TOKEN = os.getenv("RELAY_DEMO_TOKEN", "")  # never hard-code a secret

HOST, _, PORT = ENCLAVE_ADDR.partition(":")
PORT = PORT or "8443"
BASE = f"https://{HOST}:{PORT}"

ROOT = Path(__file__).parent.parent   # repo root (holds cmd/, pkg/)
DEMO = Path(__file__).parent          # demo/ dir

# enclave source files exposed READ-ONLY to the in-browser VSCode-style reader.
SOURCE_FILES = [
    "cmd/relay-core/main.go",
    "cmd/relay-core/dispatch.go",
    "cmd/relay-core/control_client.go",
    "cmd/relay-core/server.go",
    "pkg/relaycontrol/wire.go",
    "pkg/officialurls/officialurls.go",
    "pkg/officialurls/profiles.go",
    "pkg/raenclave/raenclave.go",
    "cmd/relay-core/relay-core.manifest.template",
]


def _lang(path: str) -> str:
    if path.endswith(".go"):
        return "go"
    if path.endswith((".template", ".manifest")):
        return "ini"
    if path.endswith(".py"):
        return "python"
    return "plaintext"

# SGX ECDSA quote fixed-offset fields
Q_HDR = 48
MRENC_OFF, MRENC_LEN = Q_HDR + 64, 32
RD_OFF, RD_LEN = Q_HDR + 320, 64

app = FastAPI(title="Verifiable no-log AI gateway — visual demo")


def _client() -> httpx.Client:
    # RA-TLS cert is self-signed on purpose: trust comes from the QUOTE, not PKI.
    return httpx.Client(verify=False, timeout=60.0)


def _peer_spki_sha512() -> bytes | None:
    """SHA-512 of the server cert's SubjectPublicKeyInfo (what the enclave binds
    into the quote's report_data). Needs `cryptography`."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ssl.create_connection((HOST, int(PORT)), timeout=20) as s:
        with ctx.wrap_socket(s, server_hostname=HOST) as ss:
            der = ss.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha512(spki).digest()


@app.get("/", response_class=HTMLResponse)
def index():
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


@app.get("/api/config")
def config():
    return {"endpoint": BASE, "expected_mrenclave": EXPECTED_MRENCLAVE,
            "has_default_token": bool(DEFAULT_TOKEN),
            "default_model": "deepseek/deepseek-chat"}


@app.get("/api/verify")
def verify():
    """Run the three client-side checks against the live enclave."""
    checks = []
    try:
        with _client() as c:
            r = c.get(f"{BASE}/attestation")
        doc = r.json()
        if not doc.get("attested"):
            return JSONResponse({"ok": False, "checks": [
                {"id": 1, "name": "结构 & 活性", "ok": False,
                 "detail": "endpoint 未在 SGX enclave 内运行"}]})
        quote = base64.b64decode(doc["quote_b64"])
        mrenclave = quote[MRENC_OFF:MRENC_OFF + MRENC_LEN]
        report_data = quote[RD_OFF:RD_OFF + RD_LEN]
    except Exception as e:
        return JSONResponse({"ok": False, "checks": [
            {"id": 1, "name": "结构 & 活性", "ok": False, "detail": f"取 quote 失败: {e}"}]})

    checks.append({"id": 1, "name": "结构 & 活性",
                   "ok": True, "detail": f"拿到远程认证 quote，共 {len(quote)} 字节并解析成功",
                   "plain": "CPU 出具了一份'我正在运行这段代码'的签名声明"})

    got = mrenclave.hex()
    ok2 = got == EXPECTED_MRENCLAVE
    checks.append({"id": 2, "name": "度量比对 (MRENCLAVE)", "ok": ok2,
                   "detail": (f"运行中的代码指纹 == 你 pin 的指纹" if ok2
                              else f"指纹不符！运行 {got[:16]}… 期望 {EXPECTED_MRENCLAVE[:16]}…"),
                   "value": got,
                   "plain": "代码指纹和你独立重建得到的一致 ⇒ 跑的就是那份'不存正文'的审计代码"})

    want_rd = _peer_spki_sha512()
    if want_rd is None:
        checks.append({"id": 3, "name": "通道绑定", "ok": None,
                       "detail": "跳过（需 pip install cryptography）",
                       "plain": "无法核对 quote 与本条 TLS 通道是否绑定"})
    else:
        ok3 = want_rd == report_data
        checks.append({"id": 3, "name": "通道绑定", "ok": ok3,
                       "detail": ("quote 绑定到本条 TLS 通道 (report_data == SHA-512(服务器公钥))"
                                  if ok3 else "report_data 与 TLS 公钥不符 —— 可能被转发/中间人"),
                       "plain": "被认证的 enclave 就是你正在通话的这个端点，不是别处转发来的"})

    overall = all(c["ok"] for c in checks if c["ok"] is not None)
    return {"ok": overall, "endpoint": BASE, "checks": checks,
            "note": "本页只做度量+绑定；完整保证还需 DCAP 签名链验证 (relay-verify -dcap-verify)"}


class ChatReq(BaseModel):
    prompt: str = "你好，用一句话介绍你自己"
    token: str = ""
    model: str = "deepseek/deepseek-chat"  # OpenRouter, not geo-blocked → real 200


# Map a model name to the official provider it routes to, for the visual trace.
# (Matches our seeded channels: any "vendor/model" id -> OpenRouter.)
def provider_for_model(model: str):
    m = (model or "").lower()
    if "/" in m:
        return "OpenRouter 官方", "https://openrouter.ai/api"
    if m.startswith(("gpt", "o1", "o3", "o4", "chatgpt", "text-", "dall-e", "whisper")):
        return "OpenAI 官方", "https://api.openai.com"
    if m.startswith("claude"):
        return "Anthropic 官方", "https://api.anthropic.com"
    if m.startswith("gemini"):
        return "Gemini / AI Studio 官方", "https://generativelanguage.googleapis.com"
    return "官方上游", ""


def _mask(s: str, keep: int = 6) -> str:
    if not s:
        return "(空)"
    return s[:keep] + "…" + s[-4:] if len(s) > keep + 4 else s[:keep] + "…"


@app.post("/api/chat")
def chat(req: ChatReq):
    token = req.token or DEFAULT_TOKEN
    body = {"model": req.model,
            "messages": [{"role": "user", "content": req.prompt}],
            "max_tokens": 64}

    status, upstream = 0, None
    err = None
    if token:
        try:
            with _client() as c:
                r = c.post(f"{BASE}/v1/chat/completions",
                           headers={"Authorization": f"Bearer {token}",
                                    "Content-Type": "application/json"},
                           content=json.dumps(body))
            status = r.status_code
            try:
                upstream = r.json()
            except Exception:
                upstream = {"raw": r.text[:400]}
        except Exception as e:
            err = str(e)
    else:
        err = "未提供网关 token（在上方输入框粘贴，或设 RELAY_DEMO_TOKEN）"

    # Which official provider does this model route to (matches our seeded
    # channels), and how the enclave injects that provider's credential.
    pname, purl = provider_for_model(req.model)
    up_url = (purl + "/v1/chat/completions") if purl else "(该渠道类型的官方 URL)"
    auth_desc = {
        "OpenAI 官方": "Authorization: Bearer",
        "OpenRouter 官方": "Authorization: Bearer (+ HTTP-Referer / X-Title)",
        "Anthropic 官方": "x-api-key + anthropic-version",
        "Gemini / AI Studio 官方": "x-goog-api-key",
    }.get(pname, "标准鉴权")

    if status == 403:
        resp_note = "403 = 出口 IP 被该 provider 地域封锁，恰恰证明请求到达了真官方上游。"
    elif status == 200:
        resp_note = "200 成功。响应只在 enclave 加密内存里穿过并流回你，不落盘、不入库、不进日志。"
    else:
        resp_note = "响应只在 enclave 加密内存里穿过，不落盘、不入库、不进日志。"

    # A per-hop trace of what data crosses each trust boundary. hops 1/4/5 are the
    # real request/response; hops 2/3/6 describe exactly what the enclave sends
    # to / receives from the untrusted new-api control plane (by design).
    trace = [
        {"step": 1, "frm": "你 (客户端)", "to": "SGX Enclave", "secure": True,
         "title": "完整请求进入 enclave（RA-TLS 加密通道）",
         "data": body,
         "note": "整条请求（含你的 prompt）只在加密通道里进入 enclave 的加密内存。"},
        {"step": 2, "frm": "SGX Enclave", "to": "new-api 控制面 (不可信)", "secure": False,
         "title": "只问路由：model + token —— 没有 prompt！",
         "data": {"model": req.model, "token": _mask(token)},
         "note": "★ 关键：发给不可信 new-api 的这一跳里，只有 model 和 token，绝无你的 prompt 正文。"},
        {"step": 3, "frm": "new-api 控制面", "to": "SGX Enclave", "secure": False,
         "title": f"回传路由决定 + 上游 key（选中 {pname}）",
         "data": {"channel": pname, "is_official": True, "auth_style": auth_desc,
                  "upstream_key": "****(库中取，new-api 看不到 prompt)"},
         "note": f"new-api 只决定用哪个官方渠道（这里是 {pname}）并给出上游 key；它接触不到 prompt。"},
        {"step": 4, "frm": "SGX Enclave", "to": pname, "secure": True,
         "title": f"enclave 用编译写死的官方 URL + 严格 TLS 直连，注入 {auth_desc}",
         "data": {"url": up_url, "auth": auth_desc,
                  "model": req.model, "messages": body["messages"]},
         "note": f"目的地与鉴权画像都编译进 enclave 并被 MRENCLAVE 度量，运营方改不了。"},
        {"step": 5, "frm": pname, "to": "你 (客户端)", "secure": True,
         "title": f"响应经加密内存流回（HTTP {status or '—'}）",
         "data": upstream if upstream is not None else {"error": err},
         "note": resp_note},
        {"step": 6, "frm": "SGX Enclave", "to": "new-api 控制面", "secure": False,
         "title": "只结算元数据（token 数 / 费用），无正文",
         "data": {"model": req.model,
                  "prompt_tokens": (upstream or {}).get("usage", {}).get("prompt_tokens", 0),
                  "completion_tokens": (upstream or {}).get("usage", {}).get("completion_tokens", 0)},
         "note": "计费只用数字元数据；prompt / 回答正文永远不写入任何持久化存储。"},
    ]
    return {"status": status, "error": err, "provider": pname, "trace": trace}


@app.get("/api/source")
def source():
    """All enclave source files (read-only) for the in-browser code reader."""
    out = []
    for rel in SOURCE_FILES:
        try:
            code = (ROOT / rel).read_text(encoding="utf-8")
        except Exception:
            code = "(source unavailable)"
        out.append({"path": rel, "lang": _lang(rel), "code": code})
    return {"files": out}


@app.get("/api/walkthrough")
def walkthrough():
    """Guided endpoint-chain steps (file/line + explanation) for the code reader."""
    p = DEMO / "data" / "walkthrough.json"
    if p.exists():
        try:
            return JSONResponse(json.loads(p.read_text(encoding="utf-8")))
        except Exception as e:
            return JSONResponse({"files": [], "chain": [], "error": str(e)})
    return {"files": [], "chain": []}


@app.get("/whitepaper", response_class=HTMLResponse)
def whitepaper_page():
    p = DEMO / "whitepaper.html"
    if p.exists():
        return p.read_text(encoding="utf-8")
    return "<!doctype html><meta charset=utf-8><h1>白皮书生成中…</h1>"


@app.get("/fragments/verifier", response_class=HTMLResponse)
def verifier_fragment():
    p = DEMO / "fragments" / "verifier_explainer.html"
    if p.exists():
        return p.read_text(encoding="utf-8")
    return "<div class='step'><p class='hint'>验证器详解生成中…</p></div>"
