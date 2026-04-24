package main

// config.go
// 读取环境变量并装进 Config struct。
// 把所有配置的"入口"集中在这里，其它文件只读这个 struct。
// 缺必填项时直接 panic，让容器起不来，总比带病上线好。

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
)

// Config 是 Portal 运行需要的所有配置。
// 来源全是环境变量，通过 Docker Compose 的 env_file 从 .env 注入。
type Config struct {
	// --- Entra (Azure AD) OIDC ---
	TenantID     string // GUID, e.g. e72914d3-...
	ClientID     string // App Registration 的 Application (client) ID
	ClientSecret string // Client Secret Value，敏感

	// --- iKuai 自定义认证 ---
	IKuaiAppKey     string // iKuai 云面板 "生成" 出的 appkey，敏感
	IKuaiWebAuthURL string // iKuai 放行接口，默认按官方文档 https://portal.ikuai8-wifi.com/Action/webauth-up
	//                        开成 env 是因为不同固件/部署可能要换 host (走路由器 LAN IP) 或换 scheme

	// --- Portal 自身 ---
	SessionSecret []byte // HMAC 签 cookie 用的随机密钥，32 字节，敏感
	PublicURL     string // e.g. https://wifi.login.example.com
	ListenAddr    string // e.g. 127.0.0.1:28080

	// --- 品牌化 ---
	BrandName    string // 显示在登录页上的组织名，默认 "Kazuha Hub"
	BrandColor   string // CSS 主色，hex 格式如 "#2563eb"
	BrandLogoURL string // logo 图片 URL，留空则不显示

	// --- iKuai 自定义认证参数 ---
	// 不同固件版本 query string 里的字段名不一样，用 | 分隔的备选名单。
	IKuaiIPKeys  []string // 默认 user_ip|ip|ipaddr
	IKuaiMACKeys []string // 默认 user_mac|mac|usrmac|devmac
}

func loadConfig() Config {
	cfg := Config{
		TenantID:     mustEnv("TENANT_ID"),
		ClientID:     mustEnv("CLIENT_ID"),
		ClientSecret: mustEnv("CLIENT_SECRET"),
		IKuaiAppKey:  mustEnv("IKUAI_APPKEY"),
		PublicURL:    mustEnv("PUBLIC_URL"),

		IKuaiWebAuthURL: envOr("IKUAI_WEBAUTH_URL",
			"https://portal.ikuai8-wifi.com/Action/webauth-up"),

		ListenAddr:   envOr("LISTEN_ADDR", "127.0.0.1:28080"),
		BrandName:    envOr("BRAND_NAME", "Kazuha Hub"),
		BrandColor:   envOr("BRAND_COLOR", "#2563eb"),
		BrandLogoURL: envOr("BRAND_LOGO_URL", ""),

		IKuaiIPKeys:  splitCSV(envOr("IKUAI_IP_KEYS", "user_ip,ip,ipaddr")),
		IKuaiMACKeys: splitCSV(envOr("IKUAI_MAC_KEYS", "user_mac,mac,usrmac,devmac")),
	}

	// SESSION_SECRET 必须是 32 字节 hex (64 个字符)，用 `openssl rand -hex 32` 生成。
	secretHex := mustEnv("SESSION_SECRET")
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		log.Fatalf("SESSION_SECRET 必须是 hex 字符串: %v", err)
	}
	if len(secret) < 32 {
		log.Fatalf("SESSION_SECRET 至少 32 字节 (64 个 hex 字符), 当前 %d", len(secret))
	}
	cfg.SessionSecret = secret

	// PublicURL 必须是 https，iKuai 和 Entra 都不接受 http 回调。
	if !strings.HasPrefix(cfg.PublicURL, "https://") {
		log.Fatalf("PUBLIC_URL 必须以 https:// 开头, 当前: %s", cfg.PublicURL)
	}
	// 去掉末尾 / 免得拼 URL 出现 //
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")

	return cfg
}

// Issuer 返回 Entra 的 OIDC issuer URL，用于 go-oidc provider discovery。
// 格式: https://login.microsoftonline.com/{tenant-id}/v2.0
func (c Config) Issuer() string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", c.TenantID)
}

// RedirectURL 是 Entra 回跳地址，必须和 App Registration 里配的一字不差。
func (c Config) RedirectURL() string {
	return c.PublicURL + "/auth/callback"
}

// --- 小工具 ---

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("环境变量 %s 未设置", key)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
