#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Assemble demo/wp_sections/*.html (section fragments authored by the fanout)
into a single polished demo/whitepaper.html with head/CSS/TOC/footer.

Run after the whitepaper-fanout workflow completes:
    python3 build_whitepaper.py
"""
import re
from pathlib import Path

HERE = Path(__file__).parent
SECT_DIR = HERE / "wp_sections"
OUT = HERE / "whitepaper.html"
MRENCLAVE = "4aa951d16a0c237605f032cd480095b65be1f485e9f7a959a16f38a80428a445"

CSS = """
:root{--ink:#0f1222;--ink2:#3a3f5c;--muted:#6b7188;--bg:#f5f6fb;--card:#fff;--line:#e6e7f0;
--brand:#4f46e5;--teal:#0ea5a4;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--code:#0b1020}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans SC",Roboto,Arial,sans-serif;color:var(--ink);background:var(--bg);line-height:1.7}
code,pre{font-family:"SF Mono",ui-monospace,Menlo,Consolas,monospace}
.hero{background:radial-gradient(1100px 460px at 18% -10%,#2a2f6b,#12142e 55%,#0b0d20);color:#fff;padding:56px 0 44px}
.wrap{max-width:900px;margin:0 auto;padding:0 22px}
.hero h1{font-size:clamp(26px,4.5vw,40px);margin:0 0 10px;font-weight:800;letter-spacing:-.01em}
.hero p{color:#c7cbef;margin:0 0 8px;font-size:16px;max-width:720px}
.hero .meta{margin-top:16px;font-size:12.5px;color:#aab0e0;font-family:"SF Mono",monospace;word-break:break-all}
nav.toc{position:sticky;top:0;background:rgba(255,255,255,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--line);z-index:10}
nav.toc .wrap{display:flex;gap:6px;flex-wrap:wrap;padding-top:10px;padding-bottom:10px}
nav.toc a{font-size:13px;color:var(--ink2);text-decoration:none;padding:5px 10px;border-radius:8px;white-space:nowrap}
nav.toc a:hover{background:#eef0fe;color:var(--brand)}
main{padding:26px 0 60px}
section.wp{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:26px 30px;margin:20px 0;box-shadow:0 1px 2px rgba(16,18,34,.04);scroll-margin-top:70px}
section.wp h2{font-size:clamp(20px,3vw,26px);margin:0 0 12px;font-weight:800;letter-spacing:-.01em}
section.wp h3{font-size:16px;margin:20px 0 8px}
section.wp p{margin:0 0 14px;color:var(--ink2)}
section.wp ul{margin:6px 0 14px;padding-left:22px}section.wp li{margin:6px 0;color:var(--ink2)}
section.wp b{color:var(--ink)}
figure.fig{margin:18px 0;text-align:center;background:#fff;border:1px solid var(--line);border-radius:12px;padding:18px 12px}
figure.fig svg{display:block;margin:0 auto;max-width:720px;width:100%;height:auto}
figure.fig figcaption{margin-top:10px;font-size:13px;color:var(--muted)}
table.wp-t{width:100%;border-collapse:collapse;font-size:14px;margin:10px 0}
table.wp-t th,table.wp-t td{border:1px solid var(--line);padding:9px 12px;text-align:left;vertical-align:top}
table.wp-t th{background:#f6f7fb;font-weight:700}
footer{border-top:1px solid var(--line);color:var(--muted);font-size:13px;padding:28px 0 60px}
footer .wrap{word-break:break-all}
"""


def main():
    files = sorted(SECT_DIR.glob("*.html")) if SECT_DIR.exists() else []
    if not files:
        print("no section fragments found in", SECT_DIR)
        return
    sections, toc = [], []
    for f in files:
        html = f.read_text(encoding="utf-8").strip()
        sid_m = re.search(r'id="(s-[\w-]+)"', html)
        h2_m = re.search(r"<h2[^>]*>(.*?)</h2>", html, re.S)
        sid = sid_m.group(1) if sid_m else f.stem
        title = re.sub(r"<[^>]+>", "", h2_m.group(1)).strip() if h2_m else f.stem
        toc.append((sid, title))
        sections.append(html)
    nav = "".join(f'<a href="#{sid}">{title}</a>' for sid, title in toc)
    page = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>可验证的无日志 AI 网关 · 技术白皮书</title><style>{CSS}</style></head>
<body>
<header class="hero"><div class="wrap">
<h1>可验证的无日志 AI 网关 · 技术白皮书</h1>
<p>基于 Intel SGX 机密计算 + DCAP 远程认证 + RA-TLS，构建在开源 AI 网关 new-api 之上。自顶向下讲清整条技术脉络与密码学细节。</p>
<div class="meta">上线端点 https://8.217.148.82:8443 · MRENCLAVE {MRENCLAVE} · 开源 github.com/BuluBulugege/test-enclave-newapi</div>
</div></header>
<nav class="toc"><div class="wrap">{nav}</div></nav>
<main><div class="wrap">
{chr(10).join(sections)}
</div></main>
<footer><div class="wrap">可验证的无日志 AI 网关 · 技术白皮书 · MRENCLAVE {MRENCLAVE} · 基于 QuantumNous/new-api（保留其署名与许可）</div></footer>
</body></html>"""
    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT} ({len(page)} bytes) with {len(sections)} sections; svg={page.count('<svg')}")


if __name__ == "__main__":
    main()
