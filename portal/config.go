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
	"strconv"
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
	IKuaiAppKey       string // iKuai 云面板 "生成" 出的 appkey，敏感
	IKuaiWebAuthURL   string // iKuai 放行接口，默认按官方文档 https://portal.ikuai8-wifi.com/Action/webauth-up
	IKuaiCustomName   string // custom_name 参数, iKuai 审计日志里用它区分对接的 portal
	IKuaiReleaseType  string // release_type 参数, 默认 "1"
	IKuaiUserIDPrefix string // user_id 前缀, 非空时 user_id = "{prefix}-{upn}"

	// --- Portal 自身 ---
	SessionSecret []byte // HMAC 签 cookie 用的随机密钥，32 字节，敏感
	PublicURL     string // e.g. https://wifi.login.example.com
	ListenAddr    string // e.g. 127.0.0.1:28080

	// --- 品牌化 ---
	BrandName    string // 显示在登录页上的组织名
	BrandColor   string // CSS 主色, hex 格式
	BrandLogoURL string // 留空则用 static/logo-title-*.png

	// --- iKuai 字段名兼容 ---
	IKuaiIPKeys  []string // 默认 user_ip,ip,ipaddr
	IKuaiMACKeys []string // 默认 user_mac,mac,usrmac,devmac

	// --- Duo 免密推送 (可选, 全空则禁用) ---
	DuoIKey             string   // Duo Auth API Integration Key
	DuoSKey             string   // Duo Auth API Secret Key, 敏感
	DuoAPIHost          string   // api-XXXXXXXX.duosecurity.com
	DuoPushTimeoutSec   int      // push 等待超时秒数, 默认 60
	AllowedEmailDomains []string // 允许走免密流程的邮箱域名, 逗号分隔. 空 = 免密流程禁用
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
		IKuaiCustomName:   envOr("IKUAI_CUSTOM_NAME", "kazuha-hub"),
		IKuaiReleaseType:  envOr("IKUAI_RELEASE_TYPE", "1"),
		IKuaiUserIDPrefix: envOr("IKUAI_USER_ID_PREFIX", ""),

		ListenAddr:   envOr("LISTEN_ADDR", "127.0.0.1:28080"),
		BrandName:    envOr("BRAND_NAME", "Kazuha Hub"),
		BrandColor:   envOr("BRAND_COLOR", "#2563eb"),
		BrandLogoURL: envOr("BRAND_LOGO_URL", ""),

		IKuaiIPKeys:  splitCSV(envOr("IKUAI_IP_KEYS", "user_ip,ip,ipaddr")),
		IKuaiMACKeys: splitCSV(envOr("IKUAI_MAC_KEYS", "user_mac,mac,usrmac,devmac")),

		DuoIKey:             envOr("DUO_IKEY", ""),
		DuoSKey:             envOr("DUO_SKEY", ""),
		DuoAPIHost:          envOr("DUO_API_HOST", ""),
		DuoPushTimeoutSec:   envOrInt("DUO_PUSH_TIMEOUT", 60),
		AllowedEmailDomains: splitCSV(envOr("ALLOWED_EMAIL_DOMAINS", "")),
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
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")

	// Duo 三个值要么全给要么全空, 给一半就报错
	if (cfg.DuoIKey != "" || cfg.DuoSKey != "" || cfg.DuoAPIHost != "") &&
		!(cfg.DuoIKey != "" && cfg.DuoSKey != "" && cfg.DuoAPIHost != "") {
		log.Fatalf("DUO_IKEY / DUO_SKEY / DUO_API_HOST 必须全部设置或全部留空, 当前: ikey=%v skey=%v host=%v",
			cfg.DuoIKey != "", cfg.DuoSKey != "", cfg.DuoAPIHost != "")
	}

	// Duo 启用时必须配域名白名单, 否则任何陌生邮箱都能触发推送
	if cfg.IsDuoEnabled() && len(cfg.AllowedEmailDomains) == 0 {
		log.Fatalf("启用 Duo 免密流程必须同时设置 ALLOWED_EMAIL_DOMAINS (至少一个域名), 防止推送滥发")
	}

	return cfg
}

// IsDuoEnabled 三个必须项都填了才算启用.
func (c Config) IsDuoEnabled() bool {
	return c.DuoIKey != "" && c.DuoSKey != "" && c.DuoAPIHost != ""
}

// Issuer 返回 Entra 的 OIDC issuer URL, 用于 go-oidc provider discovery.
// 格式: https://login.microsoftonline.com/{tenant-id}/v2.0
func (c Config) Issuer() string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", c.TenantID)
}

// RedirectURL 是 Entra 回跳地址, 必须和 App Registration 里配的一字不差.
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

func envOrInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("环境变量 %s 必须是整数, 当前: %q", key, v)
	}
	return n
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
