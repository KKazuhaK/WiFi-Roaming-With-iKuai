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

// Strings 是页面上所有能出现的文案。
// 加新文案时三个 map 都要加。
// Title / Subtitle / SignInButton / Footer / SuccessMsg 里的 %s 会被替换成 BrandName.
type Strings struct {
	Title            string
	Subtitle         string
	SignInButton     string
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
}

var stringsZHCN = Strings{
	Title:            "连接至 %s Roaming 网络",
	Subtitle:         "登录 %s 账号即可接入网络",
	SignInButton:     "使用 %s SSO 登录",
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
}

var stringsZHTW = Strings{
	Title:            "連接至 %s Roaming 網路",
	Subtitle:         "登入 %s 帳號即可接入網路",
	SignInButton:     "使用 %s SSO 登入",
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
}

var stringsEN = Strings{
	Title:            "Connect to %s Roaming",
	Subtitle:         "Sign in with your %s account to connect",
	SignInButton:     "Sign in with %s SSO",
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
}

// pickLang 按优先级决定用哪种语言。
func pickLang(r *http.Request) Lang {
	// 1. 显式 ?lang= 参数
	if q := r.URL.Query().Get("lang"); q != "" {
		if l, ok := parseLang(q); ok {
			return l
		}
	}
	// 2. Accept-Language header
	// 遍历所有候选项 (按用户偏好顺序), 取第一个我们支持的
	al := r.Header.Get("Accept-Language")
	if al != "" {
		for _, part := range strings.Split(al, ",") {
			// 去掉 q-value (例: "zh-CN;q=0.9" → "zh-CN")
			tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
			if l, ok := parseLang(tag); ok {
				return l
			}
		}
	}
	// 3. 默认英文
	return LangEN
}

// parseLang 把一个语言 tag (比如 "zh-CN", "zh-TW", "zh-Hant-HK", "en-US") 映射到我们的三档。
// 不认识的返回 ok=false 让调用方继续试下一个或回落默认。
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

// s 返回对应语言的文案表。
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
