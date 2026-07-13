// Package officialurls is the single source of truth for each channel type's
// official/default upstream base URL, indexed by channel type id.
//
// It is a pure leaf package: it imports ONLY the standard library, so it can be
// linked into the SGX relay-core enclave without
// dragging in model / service / logger or any other business package. The
// enclave measures this table into MRENCLAVE, which makes the set of official
// endpoints tamper-proof at runtime: a malicious host cannot repoint an
// "official" channel at a MITM proxy, because the enclave dials the compiled-in
// official host and ignores any host-supplied base URL override.
//
// The index positions MUST stay aligned with constant.ChannelType* ids. The
// constant package aliases constant.ChannelBaseURLs = officialurls.BaseURLs, and
// a golden-index test pins the well-known entries so an accidental insertion or
// reordering fails CI instead of silently shifting every provider's endpoint.
package officialurls

import (
	"net/url"
	"strings"
)

// normalizeHost extracts and lower-cases the hostname from a host or full URL,
// stripping scheme, userinfo, port, and any trailing dot. Returns "" on parse
// failure. Defensive against lookalike/tricks (uppercase, port, userinfo).
func normalizeHost(hostOrURL string) string {
	s := strings.TrimSpace(hostOrURL)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "//" + s // let url.Parse treat a bare host[:port] as authority
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

// IsOfficialHostSuffix reports whether host (a hostname or full URL) is an
// official upstream host for a per-resource/per-region channel type, using each
// provider's real host shape. The apex is always the provider's (azure.com /
// amazonaws.com / googleapis.com — all provider-controlled), so an apex-swap
// like "openai.azure.com.attacker.com" is rejected because it does not end with
// the required suffix. Boundaries match each provider's actual format:
//   - Azure  (3): "{resource}.openai.azure.com" / ".cognitiveservices.azure.com"
//     (dot label boundary — "evil-openai.azure.com" is NOT under the zone → rejected)
//   - AWS   (33): "bedrock-runtime.{region}.amazonaws.com" (prefix + suffix, so a
//     bare "s3.amazonaws.com" is rejected)
//   - Vertex(41): "aiplatform.googleapis.com" or "{region}-aiplatform.googleapis.com"
//     (regional host joins the region with a hyphen, so the hyphen form is allowed)
func IsOfficialHostSuffix(channelType int, host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	switch channelType {
	case 3:
		return strings.HasSuffix(h, ".openai.azure.com") || strings.HasSuffix(h, ".cognitiveservices.azure.com")
	case 33:
		return strings.HasPrefix(h, "bedrock-runtime.") && strings.HasSuffix(h, ".amazonaws.com")
	case 41:
		return h == "aiplatform.googleapis.com" || strings.HasSuffix(h, "-aiplatform.googleapis.com")
	default:
		return false
	}
}

// BaseURLs maps channelType -> official base URL. The index is the channel type
// id (see constant.ChannelType*). An empty string means the type has no
// official default (custom / self-hosted / SDK-only providers); such a type can
// never be classified as "official".
var BaseURLs = []string{
	"",                                          // 0  Unknown
	"https://api.openai.com",                    // 1  OpenAI
	"https://oa.api2d.net",                      // 2  Midjourney
	"",                                          // 3  Azure (no default; per-resource endpoint)
	"http://localhost:11434",                    // 4  Ollama
	"https://api.openai-sb.com",                 // 5  MidjourneyPlus
	"https://api.openaimax.com",                 // 6  OpenAIMax
	"https://api.ohmygpt.com",                   // 7  OhMyGPT
	"",                                          // 8  Custom (always user-supplied)
	"https://api.caipacity.com",                 // 9  AILS
	"https://api.aiproxy.io",                    // 10 AIProxy
	"",                                          // 11 PaLM (no default)
	"https://api.api2gpt.com",                   // 12 API2GPT
	"https://api.aigc2d.com",                    // 13 AIGC2D
	"https://api.anthropic.com",                 // 14 Anthropic
	"https://aip.baidubce.com",                  // 15 Baidu
	"https://open.bigmodel.cn",                  // 16 Zhipu
	"https://dashscope.aliyuncs.com",            // 17 Ali
	"",                                          // 18 Xunfei (no default)
	"https://api.360.cn",                        // 19 360
	"https://openrouter.ai/api",                 // 20 OpenRouter
	"https://api.aiproxy.io",                    // 21 AIProxyLibrary
	"https://fastgpt.run/api/openapi",           // 22 FastGPT
	"https://hunyuan.tencentcloudapi.com",       // 23 Tencent
	"https://generativelanguage.googleapis.com", // 24 Gemini
	"https://api.moonshot.cn",                   // 25 Moonshot
	"https://open.bigmodel.cn",                  // 26 Zhipu_v4
	"https://api.perplexity.ai",                 // 27 Perplexity
	"",                                          // 28
	"",                                          // 29
	"",                                          // 30
	"https://api.lingyiwanwu.com",               // 31 LingYiWanWu
	"",                                          // 32
	"",                                          // 33 Aws (no default; region-based)
	"https://api.cohere.ai",                     // 34 Cohere
	"https://api.minimax.chat",                  // 35 MiniMax
	"",                                          // 36 SunoAPI
	"https://api.dify.ai",                       // 37 Dify
	"https://api.jina.ai",                       // 38 Jina
	"https://api.cloudflare.com",                // 39 Cloudflare
	"https://api.siliconflow.cn",                // 40 SiliconFlow
	"",                                          // 41 VertexAi (no default)
	"https://api.mistral.ai",                    // 42 Mistral
	"https://api.deepseek.com",                  // 43 DeepSeek
	"https://api.moka.ai",                       // 44 MokaAI
	"https://ark.cn-beijing.volces.com",         // 45 VolcEngine
	"https://qianfan.baidubce.com",              // 46 BaiduV2
	"",                                          // 47 Xinference (no default)
	"https://api.x.ai",                          // 48 Xai
	"https://api.coze.cn",                       // 49 Coze
	"https://api.klingai.com",                   // 50 Kling
	"https://visual.volcengineapi.com",          // 51 Jimeng
	"https://api.vidu.cn",                       // 52 Vidu
	"https://llm.submodel.ai",                   // 53 Submodel
	"https://ark.cn-beijing.volces.com",         // 54 DoubaoVideo
	"https://api.openai.com",                    // 55 Sora
	"https://api.replicate.com",                 // 56 Replicate
	"https://chatgpt.com",                       // 57 Codex
	"",                                          // 58 AdvancedCustom (always user-supplied)
}

// For returns the official base URL for a channel type, or "" if the type id is
// out of range or the type has no official default.
func For(channelType int) string {
	if channelType < 0 || channelType >= len(BaseURLs) {
		return ""
	}
	return BaseURLs[channelType]
}

// HasOfficial reports whether the channel type has a non-empty official default.
// Types without one (Azure, Custom, PaLM, Xunfei, Aws, VertexAi, Xinference,
// SunoAPI, AdvancedCustom, ...) can never be classified as official.
func HasOfficial(channelType int) bool {
	return For(channelType) != ""
}

// IsOfficialURL reports whether resolvedBaseURL is exactly the official default
// for channelType. The comparison is a byte-for-byte string match (no
// canonicalization) so that the untrusted host and the enclave agree on the
// exact same predicate. Returns false for types with no official default.
//
// resolvedBaseURL is the value AFTER the blank->default fallback (i.e. what
// model.Channel.GetBaseURL returns): a channel left blank resolves to the
// official default and is official; any non-empty override that differs is not.
func IsOfficialURL(channelType int, resolvedBaseURL string) bool {
	official := For(channelType)
	if official == "" {
		return false
	}
	return resolvedBaseURL == official
}
