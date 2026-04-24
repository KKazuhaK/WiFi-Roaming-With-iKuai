package main

// duo.go
// Duo Auth API v2 客户端. 仅实现我们需要的三个端点:
//   POST /auth/v2/preauth      探测用户状态: auth / allow / enroll / deny
//   POST /auth/v2/auth         触发推送 (factor=push, async=1) -> 返回 txid
//   GET  /auth/v2/auth_status  轮询 txid 的结果 (waiting / allow / deny)
//
// 签名算法 (Duo 规定):
//   canon = date + "\n" + METHOD + "\n" + lowercase(host) + "\n" + path + "\n" + canonicalParams
//   sig   = HMAC-SHA1(skey, canon).hex
//   Authorization: Basic base64(ikey + ":" + sig)
//   Date: RFC 2822 格式
//
// 注意:
//   - canonicalParams 的 URL 编码用 RFC 3986 (空格用 %20 不用 +)
//     Go 的 url.QueryEscape 对空格用 +, 需要手动替换
//   - SKEY 是敏感秘钥, 只从 env 读, 不写日志

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DuoClient 封装签名 + 发请求.
type DuoClient struct {
	ikey    string
	skey    string
	apiHost string // 小写, 不带 scheme
	http    *http.Client
}

func newDuoClient(cfg Config) *DuoClient {
	return &DuoClient{
		ikey:    cfg.DuoIKey,
		skey:    cfg.DuoSKey,
		apiHost: strings.ToLower(cfg.DuoAPIHost),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// duoEnvelope 是 Duo 所有 API 响应的外壳.
type duoEnvelope struct {
	Stat     string          `json:"stat"`
	Code     int             `json:"code,omitempty"`
	Message  string          `json:"message,omitempty"`
	Response json.RawMessage `json:"response"`
}

// --- preauth ---

// PreauthResult: "result" 有 4 种取值: auth / allow / enroll / deny.
type PreauthResult struct {
	Result    string          `json:"result"`
	StatusMsg string          `json:"status_msg"`
	Devices   []PreauthDevice `json:"devices,omitempty"`
}

type PreauthDevice struct {
	Device       string   `json:"device"`
	Type         string   `json:"type"`
	Capabilities []string `json:"capabilities"`
}

// HasPushCapable 是否至少一个设备支持 push.
func (p *PreauthResult) HasPushCapable() bool {
	for _, d := range p.Devices {
		for _, c := range d.Capabilities {
			if c == "push" {
				return true
			}
		}
	}
	return false
}

// Preauth 查询用户在 Duo 里的状态和可用因素.
func (c *DuoClient) Preauth(username string) (*PreauthResult, error) {
	params := url.Values{}
	params.Set("username", username)

	var res PreauthResult
	if err := c.call("POST", "/auth/v2/preauth", params, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// --- auth ---

type authTxResult struct {
	TxID string `json:"txid"`
}

// AuthPushAsync 发起异步 push 认证. device=auto 让 Duo 挑默认设备.
// pushInfo 是 URL 编码的 key=value&key=value, 会显示在手机批准页上.
func (c *DuoClient) AuthPushAsync(username, pushInfo string) (string, error) {
	params := url.Values{}
	params.Set("username", username)
	params.Set("factor", "push")
	params.Set("device", "auto")
	params.Set("async", "1")
	if pushInfo != "" {
		params.Set("pushinfo", pushInfo)
	}

	var res authTxResult
	if err := c.call("POST", "/auth/v2/auth", params, &res); err != nil {
		return "", err
	}
	return res.TxID, nil
}

// --- auth_status ---

// AuthStatusResult: result = allow / deny / waiting.
// deny 时 Status 可能是 user_cancelled / timeout / fraud 等.
type AuthStatusResult struct {
	Result    string `json:"result"`
	Status    string `json:"status"`
	StatusMsg string `json:"status_msg"`
}

func (c *DuoClient) AuthStatus(txid string) (*AuthStatusResult, error) {
	params := url.Values{}
	params.Set("txid", txid)

	var res AuthStatusResult
	if err := c.call("GET", "/auth/v2/auth_status", params, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// --- 内部: 签名 + 发 HTTP ---

func (c *DuoClient) call(method, path string, params url.Values, out any) error {
	date := time.Now().UTC().Format(time.RFC1123Z)
	canonParams := canonicalParams(params)
	canon := date + "\n" + method + "\n" + c.apiHost + "\n" + path + "\n" + canonParams

	mac := hmac.New(sha1.New, []byte(c.skey))
	mac.Write([]byte(canon))
	sig := hex.EncodeToString(mac.Sum(nil))
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.ikey+":"+sig))

	fullURL := "https://" + c.apiHost + path
	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest(method, fullURL, strings.NewReader(canonParams))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else { // GET
		if canonParams != "" {
			fullURL = fullURL + "?" + canonParams
		}
		req, err = http.NewRequest(method, fullURL, nil)
		if err != nil {
			return err
		}
	}
	req.Header.Set("Date", date)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("User-Agent", "KazuhaHub-Portal/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("duo http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("duo read body: %w", err)
	}

	var env duoEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("duo unmarshal: %w (http=%d body=%q)", err, resp.StatusCode, truncate(string(body), 200))
	}
	if env.Stat != "OK" {
		return fmt.Errorf("duo api error: %s (code=%d stat=%s)", env.Message, env.Code, env.Stat)
	}
	if out != nil && len(env.Response) > 0 {
		if err := json.Unmarshal(env.Response, out); err != nil {
			return fmt.Errorf("duo unmarshal response: %w", err)
		}
	}
	return nil
}

// canonicalParams: key 升序, 每个 key 下 values 保持顺序,
// key=value&key=value, 空格用 %20.
func canonicalParams(params url.Values) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0)
	for _, k := range keys {
		for _, v := range params[k] {
			parts = append(parts, rfc3986Escape(k)+"="+rfc3986Escape(v))
		}
	}
	return strings.Join(parts, "&")
}

// rfc3986Escape: Go 的 url.QueryEscape 把空格编码成 +, Duo 要求 %20 (RFC 3986).
func rfc3986Escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
