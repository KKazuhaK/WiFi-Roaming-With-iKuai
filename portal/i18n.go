package main

// i18n.go
// 三语字符串表 + 语言判定.

import (
	"net/http"
	"strings"
)

type Lang string

const (
	LangZHCN Lang = "zh-cn"
	LangZHTW Lang = "zh-tw"
	LangEN   Lang = "en"
)

// Strings 字段中带 %s 的会被 BrandName 替换.
type Strings struct {
	// 登录主页
	Title        string
	Subtitle     string
	SignInButton string // "使用 %s SSO 登录"
	GuestButton  string // "访客码登录"

	// 邮箱输入步骤
	EmailHint      string // "输入你的组织邮箱以继续登录"
	EmailLabel     string
	ContinueButton string // "继续"

	// 访客码步骤
	GuestCodeHint    string
	GuestCodeLabel   string
	GuestCodeVerify  string
	GuestCodeInvalid string

	// 错误 / 通用
	InvalidEmail     string
	InvalidDomain    string
	AccountDenied    string // Duo / admin 拒绝账号
	RateLimited      string // 通用限流 (没有具体倒计时信息时显示)
	RateLimitedRetry string // 有倒计时: "请在 %s 后再试" — %s 会被前端替换成具体时间
	RateLimitedPermanent string // 永久封禁: 联系管理员
	NotAuthorizedMsg string
	GuestBlockedMsg  string
	SessionLostMsg   string
	ExpiredMsg       string
	ErrorTitle       string
	ErrorGenericMsg  string
	Footer           string

	// 按钮通用
	Back   string
	Cancel string
	Retry  string
	Or     string

	// 时间单位 (给前端 fmtRetryAfter 拼 "N 分钟"/"N minutes" 用)
	UnitSeconds string // "秒" / "seconds"
	UnitMinutes string // "分钟" / "minutes"
	UnitHours   string // "小时" / "hours"

	// 语言切换
	LangZHCNLabel string
	LangZHTWLabel string
	LangENLabel   string

	// 杂项 (暂未在模板里用, 保留)
	ConnectingInfo string
	SuccessTitle   string
	SuccessMsg     string
	LabelDevice    string
	LabelAccount   string
}

var stringsZHCN = Strings{
	Title:        "连接至 %s Roaming 网络",
	Subtitle:     "登录 %s 账号即可接入网络",
	SignInButton: "使用 %s SSO 登录",
	GuestButton:  "访客码登录",

	EmailHint:      "输入你的组织邮箱以继续登录",
	EmailLabel:     "组织邮箱",
	ContinueButton: "继续",

	GuestCodeHint:    "请输入管理员发给你的访客码",
	GuestCodeLabel:   "访客码",
	GuestCodeVerify:  "验证",
	GuestCodeInvalid: "访客码无效, 请核对后重试",

	InvalidEmail:     "邮箱格式不正确",
	InvalidDomain:    "邮箱域名不在允许列表, 请使用组织邮箱",
	AccountDenied:    "此账号被管理员标记为拒绝, 请联系管理员",
	RateLimited:      "操作过于频繁, 请稍后再试",
	RateLimitedRetry: "操作过于频繁, 请在 %s 后再试",
	RateLimitedPermanent: "由于多次触发安全限制, 此 IP 已被永久封禁. 请联系管理员解除.",
	NotAuthorizedMsg: "此账号不在允许范围内。请联系管理员。",
	GuestBlockedMsg:  "抱歉，外部访客账号暂不允许连接 WiFi。",
	SessionLostMsg:   "会话已丢失，请重新从 WiFi 界面打开登录页。",
	ExpiredMsg:       "登录超时，请重新尝试。",
	ErrorTitle:       "连接失败",
	ErrorGenericMsg:  "暂时无法完成认证，请稍后重试。如问题持续请联系管理员。",
	Footer:           "© %s · WiFi",

	Back:   "返回",
	Cancel: "取消",
	Retry:  "重试",
	Or:     "或",

	UnitSeconds: "秒",
	UnitMinutes: "分钟",
	UnitHours:   "小时",

	LangZHCNLabel: "简体",
	LangZHTWLabel: "繁體",
	LangENLabel:   "English",

	ConnectingInfo: "正在跳转到登录...",
	SuccessTitle:   "已连接",
	SuccessMsg:     "你已成功接入 %s。本次会话有效期 8 小时。",
	LabelDevice:    "设备",
	LabelAccount:   "账号",
}

var stringsZHTW = Strings{
	Title:        "連接至 %s Roaming 網路",
	Subtitle:     "登入 %s 帳號即可接入網路",
	SignInButton: "使用 %s SSO 登入",
	GuestButton:  "訪客碼登入",

	EmailHint:      "輸入你的組織郵箱以繼續登入",
	EmailLabel:     "組織郵箱",
	ContinueButton: "繼續",

	GuestCodeHint:    "請輸入管理員發給你的訪客碼",
	GuestCodeLabel:   "訪客碼",
	GuestCodeVerify:  "驗證",
	GuestCodeInvalid: "訪客碼無效, 請核對後重試",

	InvalidEmail:     "郵箱格式不正確",
	InvalidDomain:    "郵箱域名不在允許列表, 請使用組織郵箱",
	AccountDenied:    "此帳號被管理員標記為拒絕, 請聯絡管理員",
	RateLimited:      "操作過於頻繁, 請稍後再試",
	RateLimitedRetry: "操作過於頻繁, 請在 %s 後再試",
	RateLimitedPermanent: "由於多次觸發安全限制, 此 IP 已被永久封禁. 請聯絡管理員解除.",
	NotAuthorizedMsg: "此帳號不在允許範圍內。請聯絡管理員。",
	GuestBlockedMsg:  "抱歉，外部訪客帳號暫不允許連接 WiFi。",
	SessionLostMsg:   "工作階段已遺失，請重新從 WiFi 介面開啟登入頁。",
	ExpiredMsg:       "登入逾時，請重新嘗試。",
	ErrorTitle:       "連線失敗",
	ErrorGenericMsg:  "暫時無法完成驗證，請稍後重試。如問題持續請聯絡管理員。",
	Footer:           "© %s · WiFi",

	Back:   "返回",
	Cancel: "取消",
	Retry:  "重試",
	Or:     "或",

	UnitSeconds: "秒",
	UnitMinutes: "分鐘",
	UnitHours:   "小時",

	LangZHCNLabel: "简体",
	LangZHTWLabel: "繁體",
	LangENLabel:   "English",

	ConnectingInfo: "正在跳轉到登入...",
	SuccessTitle:   "已連線",
	SuccessMsg:     "你已成功接入 %s。本次工作階段有效期 8 小時。",
	LabelDevice:    "裝置",
	LabelAccount:   "帳號",
}

var stringsEN = Strings{
	Title:        "Connect to %s Roaming",
	Subtitle:     "Sign in with your %s account to connect",
	SignInButton: "Sign in with %s SSO",
	GuestButton:  "Guest code sign-in",

	EmailHint:      "Enter your organization email to continue",
	EmailLabel:     "Organization email",
	ContinueButton: "Continue",

	GuestCodeHint:    "Enter the guest code provided by your administrator",
	GuestCodeLabel:   "Guest code",
	GuestCodeVerify:  "Verify",
	GuestCodeInvalid: "Invalid guest code. Please double-check and retry.",

	InvalidEmail:     "Invalid email format",
	InvalidDomain:    "Email domain not allowed. Use your organization email.",
	AccountDenied:    "This account is denied by admin. Please contact your administrator.",
	RateLimited:      "Too many attempts. Please wait a bit and try again.",
	RateLimitedRetry: "Too many attempts. Please try again in %s.",
	RateLimitedPermanent: "This IP has been permanently blocked after repeated security violations. Please contact your administrator.",
	NotAuthorizedMsg: "This account is not authorized. Please contact your admin.",
	GuestBlockedMsg:  "Sorry, external guest accounts are not allowed to connect to WiFi.",
	SessionLostMsg:   "Session lost. Please reopen the login page from your WiFi dialog.",
	ExpiredMsg:       "Sign-in timed out. Please try again.",
	ErrorTitle:       "Connection Failed",
	ErrorGenericMsg:  "Could not complete authentication. Please try again later or contact your admin.",
	Footer:           "© %s · WiFi",

	Back:   "Back",
	Cancel: "Cancel",
	Retry:  "Retry",
	Or:     "or",

	UnitSeconds: "seconds",
	UnitMinutes: "minutes",
	UnitHours:   "hours",

	LangZHCNLabel: "简体",
	LangZHTWLabel: "繁體",
	LangENLabel:   "English",

	ConnectingInfo: "Redirecting to sign-in...",
	SuccessTitle:   "Connected",
	SuccessMsg:     "You are now connected to %s. This session is valid for 8 hours.",
	LabelDevice:    "Device",
	LabelAccount:   "Account",
}

func pickLang(r *http.Request) Lang {
	if q := r.URL.Query().Get("lang"); q != "" {
		if l, ok := parseLang(q); ok {
			return l
		}
	}
	al := r.Header.Get("Accept-Language")
	if al != "" {
		for _, part := range strings.Split(al, ",") {
			tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
			if l, ok := parseLang(tag); ok {
				return l
			}
		}
	}
	return LangEN
}

func parseLang(raw string) (Lang, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.HasPrefix(s, "zh-tw"),
		strings.HasPrefix(s, "zh-hk"),
		strings.HasPrefix(s, "zh-mo"),
		strings.HasPrefix(s, "zh-hant"):
		return LangZHTW, true
	case strings.HasPrefix(s, "zh"):
		return LangZHCN, true
	case strings.HasPrefix(s, "en"):
		return LangEN, true
	}
	return "", false
}

func (l Lang) s() Strings {
	switch l {
	case LangZHCN:
		return stringsZHCN
	case LangZHTW:
		return stringsZHTW
	default:
		return stringsEN
	}
}
