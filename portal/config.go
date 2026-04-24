package main

// config.go
// 读取环境变量并装进 Config struct.

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// Config 是 Portal 运行需要的所有配置.
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

	// --- Duo 集成 (可选) ---
	// 需要 Duo Admin Panel 里两种 application:
	//   1. "Auth API"     → DUO_IKEY + DUO_SKEY     (仅用于 preauth 探测用户是否在 Duo)
	//   2. "Web SDK"      → DUO_CLIENT_ID + DUO_CLIENT_SECRET (Universal Prompt 的 OIDC 流程)
	// DUO_API_HOST 两种 application 共享 (同一个 Duo 租户).
	// 任一组密钥缺失就视为 Duo 未启用.
	DuoIKey             string
	DuoSKey             string // 敏感
	DuoClientID         string
	DuoClientSecret     string // 敏感
	DuoAPIHost          string
	AllowedEmailDomains []string // 做邮箱域名白名单, 防外人触发 Duo 推送

	// --- 访客码管理 Admin (可选) ---
	AdminEmails []string
	// 访客码持久化文件路径. 空 = 纯内存 (重启数据丢).
	// 非空则启动加载 + 每次变更原子写盘, 配合 docker volume 挂出来即可.
	GuestCodesPath string
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
		DuoClientID:         envOr("DUO_CLIENT_ID", ""),
		DuoClientSecret:     envOr("DUO_CLIENT_SECRET", ""),
		DuoAPIHost:          envOr("DUO_API_HOST", ""),
		AllowedEmailDomains: splitCSV(envOr("ALLOWED_EMAIL_DOMAINS", "")),

		AdminEmails:    splitCSV(envOr("ADMIN_EMAILS", "")),
		GuestCodesPath: strings.TrimSpace(envOr("GUEST_CODES_PATH", "")),
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

	// Duo: 5 个字段要么全填 要么全空, 给一半就报错
	duoFields := map[string]string{
		"DUO_IKEY":          cfg.DuoIKey,
		"DUO_SKEY":          cfg.DuoSKey,
		"DUO_CLIENT_ID":     cfg.DuoClientID,
		"DUO_CLIENT_SECRET": cfg.DuoClientSecret,
		"DUO_API_HOST":      cfg.DuoAPIHost,
	}
	filled, empty := 0, 0
	for _, v := range duoFields {
		if v == "" {
			empty++
		} else {
			filled++
		}
	}
	if filled > 0 && empty > 0 {
		log.Fatalf("Duo 配置不完整: 以下 5 个字段必须同时设置或同时留空 — %v", duoFields)
	}
	if cfg.IsDuoEnabled() && len(cfg.AllowedEmailDomains) == 0 {
		log.Fatalf("启用 Duo 必须同时设置 ALLOWED_EMAIL_DOMAINS")
	}

	return cfg
}

// IsDuoEnabled: 5 个 Duo 字段都填了才算启用.
func (c Config) IsDuoEnabled() bool {
	return c.DuoIKey != "" && c.DuoSKey != "" &&
		c.DuoClientID != "" && c.DuoClientSecret != "" &&
		c.DuoAPIHost != ""
}

// IsAdminEnabled 是否开放 admin 后台 + 访客码流程.
func (c Config) IsAdminEnabled() bool {
	return len(c.AdminEmails) > 0
}

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
