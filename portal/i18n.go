package main

// i18n.go
// 三语字符串表 + 语言判定。
// 支持: zh-cn (简体), zh-tw (繁體), en (英文).
// 规则: 优先级 ?lang=xx 查询参数 > Accept-Language header > 默认英文 (海外/未知 fallback).

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

// Strings: 带 %s 的字段会被 BrandName 替换.
type Strings struct {
	Title            string
	Subtitle         string
	SignInButton     string // SSO 按钮
	DuoButton        string // Duo 快捷登录按钮
	GuestButton      string // 访客码登录按钮
	ConnectingInfo   string
	NotAuthorizedMsg string
	GuestBlockedMsg  string
	SessionLostMsg   string
	ExpiredMsg       string
	SuccessTitle     string
	SuccessMsg       string
	ErrorTitle       string
	ErrorGenericMsg  string
	Footer           string
	LangZHCNLabel    string
	LangZHTWLabel    string
	LangENLabel      string
	LabelDevice      string
	LabelAccount     string

	// Duo 免密流程
	DuoEmailHint     string // 输入框上方提示
	DuoEmailLabel    string // input 的 aria-label
	DuoSendPush      string // "发送推送" 按钮
	DuoPushSent      string // "已发送推送到你的手机"
	DuoApproveOnApp  string // "请在 Duo Mobile 中批准"
	DuoRemaining     string // "剩余 %ds"
	DuoApproved      string // "已批准, 正在接入..."
	DuoDenied        string // "推送被拒绝"
	DuoTimeout       string // "推送超时"
	DuoError         string // 网络/服务端错误
	DuoInvalidEmail  string // 邮箱格式不对
	DuoInvalidDomain string // 邮箱域名不允许
	DuoDeniedAccount string // Duo 管理员标记拒绝这个账号

	// 访客码流程
	GuestCodeHint    string // 访客码输入框上方提示
	GuestCodeLabel   string // 访客码 input 的 aria-label / placeholder
	GuestCodeVerify  string // "验证" 按钮
	GuestCodeInvalid string // "访客码无效"

	Back             string // "返回"
	Cancel           string // "取消"
	Retry            string // "重试"
	Or               string // "或者"
}

var stringsZHCN = Strings{
	Title:            "连接至 %s Roaming 网络",
	Subtitle:         "登录 %s 账号即可接入网络",
	SignInButton:     "使用 %s SSO 登录",
	DuoButton:        "使用 Duo 快捷登录",
	GuestButton:      "访客码登录",
	ConnectingInfo:   "正在跳转到登录...",
	NotAuthorizedMsg: "此账号不在允许范围内。请联系管理员。",
	GuestBlockedMsg:  "抱歉，外部访客账号暂不允许连接 WiFi。",
	SessionLostMsg:   "会话已丢失，请重新从 WiFi 界面打开登录页。",
	ExpiredMsg:       "登录超时，请重新尝试。",
	SuccessTitle:     "已连接",
	SuccessMsg:       "你已成功接入 %s。本次会话有效期 8 小时。",
	ErrorTitle:       "连接失败",
	ErrorGenericMsg:  "暂时无法完成认证，请稍后重试。如问题持续请联系管理员。",
	Footer:           "© %s · WiFi",
	LangZHCNLabel:    "简体",
	LangZHTWLabel:    "繁體",
	LangENLabel:      "English",
	LabelDevice:      "设备",
	LabelAccount:     "账号",

	DuoEmailHint:     "输入你的组织邮箱, 我们会向你的 Duo Mobile 发送批准推送",
	DuoEmailLabel:    "组织邮箱",
	DuoSendPush:      "发送推送",
	DuoPushSent:      "推送已发送到你的设备",
	DuoApproveOnApp:  "请在 Duo Mobile 中批准接入请求",
	DuoRemaining:     "剩余 %d 秒",
	DuoApproved:      "已批准, 正在接入...",
	DuoDenied:        "推送已被拒绝, 请重试或使用 SSO 登录",
	DuoTimeout:       "推送超时未响应, 请重试",
	DuoError:         "暂时无法联系 Duo 服务, 请稍后或改用 SSO",
	DuoInvalidEmail:  "邮箱格式不正确",
	DuoInvalidDomain: "邮箱域名不在允许列表, 请使用组织邮箱",
	DuoDeniedAccount: "此账号被管理员标记为拒绝, 请联系管理员",

	GuestCodeHint:    "请输入管理员发给你的访客码",
	GuestCodeLabel:   "访客码",
	GuestCodeVerify:  "验证",
	GuestCodeInvalid: "访客码无效, 请核对后重试",

	Back:   "返回",
	Cancel: "取消",
	Retry:  "重试",
	Or:     "或",
}

var stringsZHTW = Strings{
	Title:            "連接至 %s Roaming 網路",
	Subtitle:         "登入 %s 帳號即可接入網路",
	SignInButton:     "使用 %s SSO 登入",
	DuoButton:        "使用 Duo 快捷登入",
	GuestButton:      "訪客碼登入",
	ConnectingInfo:   "正在跳轉到登入...",
	NotAuthorizedMsg: "此帳號不在允許範圍內。請聯絡管理員。",
	GuestBlockedMsg:  "抱歉，外部訪客帳號暫不允許連接 WiFi。",
	SessionLostMsg:   "工作階段已遺失，請重新從 WiFi 介面開啟登入頁。",
	ExpiredMsg:       "登入逾時，請重新嘗試。",
	SuccessTitle:     "已連線",
	SuccessMsg:       "你已成功接入 %s。本次工作階段有效期 8 小時。",
	ErrorTitle:       "連線失敗",
	ErrorGenericMsg:  "暫時無法完成驗證，請稍後重試。如問題持續請聯絡管理員。",
	Footer:           "© %s · WiFi",
	LangZHCNLabel:    "简体",
	LangZHTWLabel:    "繁體",
	LangENLabel:      "English",
	LabelDevice:      "裝置",
	LabelAccount:     "帳號",

	DuoEmailHint:     "輸入你的組織郵箱, 我們會向你的 Duo Mobile 發送批准推送",
	DuoEmailLabel:    "組織郵箱",
	DuoSendPush:      "發送推送",
	DuoPushSent:      "推送已發送到你的裝置",
	DuoApproveOnApp:  "請在 Duo Mobile 中批准接入請求",
	DuoRemaining:     "剩餘 %d 秒",
	DuoApproved:      "已批准, 正在接入...",
	DuoDenied:        "推送已被拒絕, 請重試或使用 SSO 登入",
	DuoTimeout:       "推送逾時未回應, 請重試",
	DuoError:         "暫時無法聯絡 Duo 服務, 請稍後或改用 SSO",
	DuoInvalidEmail:  "郵箱格式不正確",
	DuoInvalidDomain: "郵箱域名不在允許列表, 請使用組織郵箱",
	DuoDeniedAccount: "此帳號被管理員標記為拒絕, 請聯絡管理員",

	GuestCodeHint:    "請輸入管理員發給你的訪客碼",
	GuestCodeLabel:   "訪客碼",
	GuestCodeVerify:  "驗證",
	GuestCodeInvalid: "訪客碼無效, 請核對後重試",

	Back:   "返回",
	Cancel: "取消",
	Retry:  "重試",
	Or:     "或",
}

var stringsEN = Strings{
	Title:            "Connect to %s Roaming",
	Subtitle:         "Sign in with your %s account to connect",
	SignInButton:     "Sign in with %s SSO",
	DuoButton:        "Quick sign-in with Duo",
	GuestButton:      "Guest code sign-in",
	ConnectingInfo:   "Redirecting to sign-in...",
	NotAuthorizedMsg: "This account is not authorized. Please contact your admin.",
	GuestBlockedMsg:  "Sorry, external guest accounts are not allowed to connect to WiFi.",
	SessionLostMsg:   "Session lost. Please reopen the login page from your WiFi dialog.",
	ExpiredMsg:       "Sign-in timed out. Please try again.",
	SuccessTitle:     "Connected",
	SuccessMsg:       "You are now connected to %s. This session is valid for 8 hours.",
	ErrorTitle:       "Connection Failed",
	ErrorGenericMsg:  "Could not complete authentication. Please try again later or contact your admin.",
	Footer:           "© %s · WiFi",
	LangZHCNLabel:    "简体",
	LangZHTWLabel:    "繁體",
	LangENLabel:      "English",
	LabelDevice:      "Device",
	LabelAccount:     "Account",

	DuoEmailHint:     "Enter your organization email. We'll send a Duo Mobile push for approval.",
	DuoEmailLabel:    "Organization email",
	DuoSendPush:      "Send push",
	DuoPushSent:      "Push sent to your device",
	DuoApproveOnApp:  "Approve the login request in Duo Mobile",
	DuoRemaining:     "%d seconds remaining",
	DuoApproved:      "Approved, connecting...",
	DuoDenied:        "Push was denied. Please retry or sign in with SSO.",
	DuoTimeout:       "Push timed out. Please retry.",
	DuoError:         "Duo service unavailable. Please retry or use SSO.",
	DuoInvalidEmail:  "Invalid email format",
	DuoInvalidDomain: "Email domain not allowed. Use your organization email.",
	DuoDeniedAccount: "This account is denied by admin. Please contact your administrator.",

	GuestCodeHint:    "Enter the guest code provided by your administrator",
	GuestCodeLabel:   "Guest code",
	GuestCodeVerify:  "Verify",
	GuestCodeInvalid: "Invalid guest code. Please double-check and retry.",

	Back:   "Back",
	Cancel: "Cancel",
	Retry:  "Retry",
	Or:     "or",
}

// pickLang 按优先级决定用哪种语言。
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
