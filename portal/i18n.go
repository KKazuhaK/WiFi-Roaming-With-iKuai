package main

// i18n.go
// 双语字符串表 + 语言判定。
// 规则: 优先级 ?lang=xx 查询参数 > Accept-Language header > 默认 zh
// 支持: zh (中文), en (英文)

import (
	"net/http"
	"strings"
)

type Lang string

const (
	LangZH Lang = "zh"
	LangEN Lang = "en"
)

// Strings 是页面上所有能出现的文案。
// 加新文案时在两个 map 里都要加。
type Strings struct {
	Title             string
	Subtitle          string
	SignInButton      string
	ConnectingInfo    string
	NotAuthorizedMsg  string
	GuestBlockedMsg   string
	SessionLostMsg    string
	ExpiredMsg        string
	SuccessTitle      string
	SuccessMsg        string
	ErrorTitle        string
	ErrorGenericMsg   string
	Footer            string
	LangSwitchToZH    string
	LangSwitchToEN    string
	// 调试信息显示 (可选)
	LabelDevice  string
	LabelAccount string
}

var stringsZH = Strings{
	Title:            "连接到 %s WiFi",
	Subtitle:         "用你的组织账号登录以连接网络",
	SignInButton:     "使用 Microsoft 账号登录",
	ConnectingInfo:   "正在跳转到 Microsoft 登录...",
	NotAuthorizedMsg: "此账号不在允许范围内。请联系管理员。",
	GuestBlockedMsg:  "抱歉，外部访客账号暂不允许连接 WiFi。",
	SessionLostMsg:   "会话已丢失，请重新从 WiFi 界面打开登录页。",
	ExpiredMsg:       "登录超时，请重新尝试。",
	SuccessTitle:     "已连接",
	SuccessMsg:       "你已成功接入 %s。本次会话有效期 8 小时。",
	ErrorTitle:       "连接失败",
	ErrorGenericMsg:  "暂时无法完成认证，请稍后重试。如问题持续请联系管理员。",
	Footer:           "© %s · 由 Entra ID 保护",
	LangSwitchToZH:   "中文",
	LangSwitchToEN:   "English",
	LabelDevice:      "设备",
	LabelAccount:     "账号",
}

var stringsEN = Strings{
	Title:            "Connect to %s WiFi",
	Subtitle:         "Sign in with your organization account to connect",
	SignInButton:     "Sign in with Microsoft",
	ConnectingInfo:   "Redirecting to Microsoft sign-in...",
	NotAuthorizedMsg: "This account is not authorized. Please contact your admin.",
	GuestBlockedMsg:  "Sorry, external guest accounts are not allowed to connect to WiFi.",
	SessionLostMsg:   "Session lost. Please reopen the login page from your WiFi dialog.",
	ExpiredMsg:       "Sign-in timed out. Please try again.",
	SuccessTitle:     "Connected",
	SuccessMsg:       "You are now connected to %s. This session is valid for 8 hours.",
	ErrorTitle:       "Connection Failed",
	ErrorGenericMsg:  "Could not complete authentication. Please try again later or contact your admin.",
	Footer:           "© %s · Secured by Entra ID",
	LangSwitchToZH:   "中文",
	LangSwitchToEN:   "English",
	LabelDevice:      "Device",
	LabelAccount:     "Account",
}

// pickLang 按优先级决定用哪种语言。
func pickLang(r *http.Request) Lang {
	// 1. 显式 ?lang= 参数
	if q := r.URL.Query().Get("lang"); q != "" {
		switch strings.ToLower(q) {
		case "zh", "zh-cn", "zh-hans":
			return LangZH
		case "en", "en-us":
			return LangEN
		}
	}
	// 2. Accept-Language header
	al := r.Header.Get("Accept-Language")
	if al != "" {
		// 很简单的判断: 包含 zh 就是中文，否则英文。
		// 不处理 q-value 优先级——对我们的用户群体过度。
		if strings.Contains(strings.ToLower(al), "zh") {
			return LangZH
		}
	}
	// 3. 默认中文 (用户群体主要在国内)
	return LangZH
}

// s 返回对应语言的文案表。
func (l Lang) s() Strings {
	if l == LangEN {
		return stringsEN
	}
	return stringsZH
}
