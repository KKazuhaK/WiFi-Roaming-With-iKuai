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
	"time"
)

// Config 是 Portal 运行需要的所有配置.
type Config struct {
	// --- Entra (Azure AD) OIDC ---
	TenantID     string
	ClientID     string
	ClientSecret string // 敏感

	// --- iKuai 自定义认证 ---
	IKuaiAppKey         string // 敏感
	IKuaiWebAuthURL     string
	IKuaiReleaseType    string
	IKuaiPolicyDefaults map[IKuaiAuthProfile]IKuaiPolicy

	// --- Portal 自身 ---
	SessionSecret []byte // 敏感
	PublicURL     string
	ListenAddr    string
	// TrustProxy: 是否信任 X-Real-IP / X-Forwarded-For. 默认 true (兼容现有反代部署).
	// 当 Portal 直接暴露公网时务必置 false, 否则攻击者可伪造 IP 绕过限流.
	// 启动时若 LISTEN_ADDR 不是 loopback 且 TRUST_PROXY 显式为 false, 仅按 remote addr 计.
	TrustProxy bool
	// DataDir: 持久化文件根目录. 默认 /data 兼容容器场景 (docker-compose bind-mount
	// /data → ./data). 裸二进制 + systemd 部署时通常设 /var/lib/wifi-portal.
	DataDir string

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
	// /admin 准入两种方式, 任一成立即通过, 可单独用也可共用:
	//   AdminEmails    UPN 白名单 (历史方式, 小团队直接列人)
	//   AdminGroupIDs  Entra Security Group 的 Object ID (GUID) 列表,
	//                  组员即有 admin 权限, 无需改 env
	// 两个都为空 = admin 后台完全禁用.
	AdminEmails   []string
	AdminGroupIDs []string

	// --- 限流配置 ---
	// 规则 1: /auth/start 按邮箱失败计数, 双窗口. 成功回调清零.
	AuthEmailFailsShort  int           // 短窗口上限 (default 5)
	AuthEmailWindowShort time.Duration // 短窗口长度 (default 3m)
	AuthEmailFailsLong   int           // 长窗口上限 (default 20)
	AuthEmailWindowLong  time.Duration // 长窗口长度 (default 1h)
	// 规则 5: /auth/guest-code 按 MAC 失败计数, 成功清零.
	GuestCodeMacFails  int           // 默认 6
	GuestCodeMacWindow time.Duration // 默认 30m
	// 规则 6: 单 IP 跨端点累计失败, 超限后短时冷却. 默认不升级永久,
	// 因为内网 DHCP IP 不适合作为长期身份.
	IPFailsLimit    int           // 默认 20
	IPFailsWindow   time.Duration // 默认 5m
	IPBanDuration   time.Duration // 冷却时长, 默认 2m
	IPBanEscalateAt int           // 第 N 次触发永久封禁, 默认 999999 (近似关闭)
	// 账号枚举防护: /auth/start 返回 opaque token, 浏览器访问 /auth/proceed 再内跳.
	AuthProceedTTL time.Duration // token 存活 (default 5m)

	// --- 事件日志 (admin observability) ---
	EventLogRetention time.Duration // 超过此时长的事件会被 gc 掉, 默认 7 天
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
		IKuaiReleaseType:    envOr("IKUAI_RELEASE_TYPE", "1"),
		IKuaiPolicyDefaults: defaultIKuaiPoliciesFromEnv(),

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

		AdminEmails:   splitCSV(envOr("ADMIN_EMAILS", "")),
		AdminGroupIDs: splitCSV(envOr("ADMIN_GROUP_IDS", "")),

		AuthEmailFailsShort:  envOrInt("AUTH_EMAIL_FAILS_SHORT", 5),
		AuthEmailWindowShort: envOrDuration("AUTH_EMAIL_WINDOW_SHORT", 3*time.Minute),
		AuthEmailFailsLong:   envOrInt("AUTH_EMAIL_FAILS_LONG", 20),
		AuthEmailWindowLong:  envOrDuration("AUTH_EMAIL_WINDOW_LONG", time.Hour),
		GuestCodeMacFails:    envOrInt("GUEST_CODE_MAC_FAILS", 6),
		GuestCodeMacWindow:   envOrDuration("GUEST_CODE_MAC_WINDOW", 30*time.Minute),
		IPFailsLimit:         envOrInt("IP_FAILS_LIMIT", 20),
		IPFailsWindow:        envOrDuration("IP_FAILS_WINDOW", 5*time.Minute),
		IPBanDuration:        envOrDuration("IP_BAN_DURATION", 2*time.Minute),
		IPBanEscalateAt:      envOrInt("IP_BAN_ESCALATE_AT", 999999),
		AuthProceedTTL:       envOrDuration("AUTH_PROCEED_TTL", 5*time.Minute),

		EventLogRetention: time.Duration(envOrInt("EVENT_LOG_RETENTION_DAYS", 7)) * 24 * time.Hour,

		TrustProxy: envOrBool("TRUST_PROXY", true),
		DataDir:    envOr("DATA_DIR", "/data"),
	}

	secretHex := mustEnv("SESSION_SECRET")
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		log.Fatalf("SESSION_SECRET must be a hex string: %v", err)
	}
	if len(secret) < 32 {
		log.Fatalf("SESSION_SECRET must be at least 32 bytes (64 hex chars), got %d", len(secret))
	}
	cfg.SessionSecret = secret

	if !strings.HasPrefix(cfg.PublicURL, "https://") {
		log.Fatalf("PUBLIC_URL must start with https://, got: %s", cfg.PublicURL)
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
		log.Fatalf("Duo config incomplete: the following 5 fields must all be set or all be empty: %v", duoFields)
	}
	if cfg.IsDuoEnabled() && len(cfg.AllowedEmailDomains) == 0 {
		log.Fatalf("Duo requires ALLOWED_EMAIL_DOMAINS to be set")
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
// UPN 白名单和组准入任一配置即视为启用.
func (c Config) IsAdminEnabled() bool {
	return len(c.AdminEmails) > 0 || len(c.AdminGroupIDs) > 0
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
		log.Fatalf("env %s is not set", key)
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
		log.Fatalf("env %s must be an integer, got: %q", key, v)
	}
	return n
}

func envOrNonNegativeInt(key string, fallback int) int {
	n := envOrInt(key, fallback)
	if n < 0 {
		log.Fatalf("env %s must be a non-negative integer, got: %d", key, n)
	}
	return n
}

// envOrDuration: 解析 time.Duration (如 "5m", "1h30m"). 空值走 fallback.
// envOrBool: 解析 "true/false/1/0/yes/no/on/off". 空值走 fallback.
// 不接受其它字符串 — 错配是致命的限流问题, 直接 fatal 暴露问题.
func envOrBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	log.Fatalf("env %s must be a boolean (true/false), got: %q", key, v)
	return fallback
}

func envOrDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("env %s must be a duration (e.g. 5m, 1h), got: %q", key, v)
	}
	return d
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
