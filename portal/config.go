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
type Config struct {
	// --- Entra (Azure AD) OIDC ---
	TenantID     string
	ClientID     string
	ClientSecret string // 敏感

	// --- iKuai 自定义认证 ---
	IKuaiAppKey       string // 敏感
	IKuaiWebAuthURL   string
	IKuaiCustomName   string
	IKuaiReleaseType  string
	IKuaiUserIDPrefix string

	// --- Portal 自身 ---
	SessionSecret []byte // 敏感
	PublicURL     string
	ListenAddr    string

	// --- 品牌化 ---
	BrandName    string
	BrandColor   string
	BrandLogoURL string

	// --- iKuai 字段名兼容 ---
	IKuaiIPKeys  []string
	IKuaiMACKeys []string

	// --- Duo 免密推送 (可选, 全空则禁用) ---
	DuoIKey             string
	DuoSKey             string // 敏感
	DuoAPIHost          string
	DuoPushTimeoutSec   int
	AllowedEmailDomains []string

	// --- 访客码管理 Admin (可选, 空则禁用整个访客码流程) ---
	// 启用 = ADMIN_EMAILS 至少有一个邮箱. 这些邮箱的人 Entra 登录 /admin 后可以管理访客码.
	AdminEmails []string
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

		AdminEmails: splitCSV(envOr("ADMIN_EMAILS", "")),
	}

	secretHex := mustEnv("SESSION_SECRET")
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		log.Fatalf("SESSION_SECRET 必须是 hex 字符串: %v", err)
	}
	if len(secret) < 32 {
		log.Fatalf("SESSION_SECRET 至少 32 字节 (64 个 hex 字符), 当前 %d", len(secret))
	}
	cfg.SessionSecret = secret

	if !strings.HasPrefix(cfg.PublicURL, "https://") {
		log.Fatalf("PUBLIC_URL 必须以 https:// 开头, 当前: %s", cfg.PublicURL)
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")

	if (cfg.DuoIKey != "" || cfg.DuoSKey != "" || cfg.DuoAPIHost != "") &&
		!(cfg.DuoIKey != "" && cfg.DuoSKey != "" && cfg.DuoAPIHost != "") {
		log.Fatalf("DUO_IKEY / DUO_SKEY / DUO_API_HOST 必须全部设置或全部留空")
	}
	if cfg.IsDuoEnabled() && len(cfg.AllowedEmailDomains) == 0 {
		log.Fatalf("启用 Duo 免密流程必须同时设置 ALLOWED_EMAIL_DOMAINS")
	}

	return cfg
}

func (c Config) IsDuoEnabled() bool {
	return c.DuoIKey != "" && c.DuoSKey != "" && c.DuoAPIHost != ""
}

// IsAdminEnabled 是否开放 admin 后台 + 访客码流程.
func (c Config) IsAdminEnabled() bool {
	return len(c.AdminEmails) > 0
}

// IsAdminEmail 判断某个 UPN 是否 admin.
func (c Config) IsAdminEmail(upn string) bool {
	u := strings.ToLower(strings.TrimSpace(upn))
	for _, a := range c.AdminEmails {
		if strings.ToLower(strings.TrimSpace(a)) == u {
			return true
		}
	}
	return false
}

func (c Config) Issuer() string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", c.TenantID)
}

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
