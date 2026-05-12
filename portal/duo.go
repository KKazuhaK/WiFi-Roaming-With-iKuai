package main

// duo.go
// Duo Auth API v2 is kept only for preauth, which checks whether a user exists in Duo.
// Actual 2FA is handled by Duo Universal Prompt (duo_universal.go), not direct pushes from this API.
//
// Signing algorithm:
//   canon = date + "\n" + METHOD + "\n" + lowercase(host) + "\n" + path + "\n" + canonicalParams
//   sig   = HMAC-SHA1(skey, canon).hex
//   Authorization: Basic base64(ikey:sig)
//   Date: RFC 2822

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type DuoClient struct {
	ikey    string
	skey    string
	apiHost string
	http    *http.Client
}

func newDuoClient(cfg Config) *DuoClient {
	return &DuoClient{
		ikey:    cfg.DuoIKey,
		skey:    cfg.DuoSKey,
		apiHost: strings.ToLower(cfg.DuoAPIHost),
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

type duoEnvelope struct {
	Stat     string          `json:"stat"`
	Code     int             `json:"code,omitempty"`
	Message  string          `json:"message,omitempty"`
	Response json.RawMessage `json:"response"`
}

// PreauthResult.Result can be auth / allow / enroll / deny.
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

func (p *PreauthResult) HasUniversalPromptCapable() bool {
	// Universal Prompt can use almost any factor (push, passcode, phone, WebAuthn).
	// Any registered device is enough; a non-empty devices array means the user is enrolled.
	return len(p.Devices) > 0
}

func (c *DuoClient) Preauth(username string) (*PreauthResult, error) {
	params := url.Values{}
	params.Set("username", username)
	var res PreauthResult
	if err := c.call("POST", "/auth/v2/preauth", params, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// --- Internals ---

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
	} else {
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
	// Bound the body size to avoid OOM from Duo failures or oversized MITM responses (audit #13).
	body, err := readBoundedBody(resp.Body, duoMaxResponseBytes)
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

func rfc3986Escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
