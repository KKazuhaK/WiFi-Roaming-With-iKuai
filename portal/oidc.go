package main

// oidc.go
// Entra ID (Azure AD) OIDC 授权码流程的封装.
// AuthURL 支持 loginHint (=用户已输入的邮箱) 让 Entra 登录页预填邮箱, 省用户再敲一次.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCClient struct {
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

type UserInfo struct {
	Subject  string
	UPN      string
	Name     string
	Email    string
	TenantID string
	Groups   []string // Entra Security Group 的 Object ID 列表, 用于 admin 准入
}

func (u UserInfo) IsGuest() bool {
	return strings.Contains(u.UPN, "#EXT#")
}

// IsAdmin 判定是否有 /admin 后台权限. 两种路径任一成立即通过:
//   1. UPN 在 ADMIN_EMAILS 列表里
//   2. 任意一个用户所属组 ID 出现在 ADMIN_GROUP_IDS 里
// 只在登录回调时调用 — 之后 /admin 请求靠 cookie 信任.
// 注意: Entra 对超过 ~200 个组的用户会改发 _claim_names overage 指示,
// id_token 里不再直接列出 groups. 小团队不会碰到.
func (u UserInfo) IsAdmin(cfg Config) bool {
	if cfg.IsAdminEmail(u.UPN) {
		return true
	}
	if len(cfg.AdminGroupIDs) == 0 || len(u.Groups) == 0 {
		return false
	}
	allow := make(map[string]struct{}, len(cfg.AdminGroupIDs))
	for _, g := range cfg.AdminGroupIDs {
		allow[strings.ToLower(strings.TrimSpace(g))] = struct{}{}
	}
	for _, g := range u.Groups {
		if _, ok := allow[strings.ToLower(strings.TrimSpace(g))]; ok {
			return true
		}
	}
	return false
}

func newOIDCClient(ctx context.Context, cfg Config) (*OIDCClient, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer())
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed (check TENANT_ID / network): %w", err)
	}
	oauth := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL(),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})
	return &OIDCClient{provider: provider, oauth: oauth, verifier: verifier}, nil
}

// AuthURL: 构造去 Entra 的授权 URL.
// loginHint 非空时作为 login_hint 传过去, Entra 登录页会预填这个邮箱.
func (c *OIDCClient) AuthURL(state, nonce, loginHint string) string {
	opts := []oauth2.AuthCodeOption{
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	}
	if loginHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", loginHint))
	}
	return c.oauth.AuthCodeURL(state, opts...)
}

func (c *OIDCClient) Exchange(ctx context.Context, cfg Config, code, expectedNonce string) (*UserInfo, error) {
	token, err := c.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code-to-token exchange failed: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("response missing id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}
	if idToken.Nonce != expectedNonce {
		return nil, errors.New("nonce mismatch (possible replay)")
	}
	var claims struct {
		Sub               string   `json:"sub"`
		UPN               string   `json:"upn"`
		Name              string   `json:"name"`
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		TID               string   `json:"tid"`
		Groups            []string `json:"groups"`
		// 如果用户所属组太多超出 id_token 限制, Entra 只发 _claim_names + _claim_sources,
		// 用户需要去 Graph API 拉. 我们不处理这种情况, 有需要再加 Graph 调用.
		ClaimNames map[string]string `json:"_claim_names"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("claims parse failed: %w", err)
	}
	if claims.TID != cfg.TenantID {
		return nil, fmt.Errorf("tenant mismatch: expected %s, got %s", cfg.TenantID, claims.TID)
	}
	if _, overage := claims.ClaimNames["groups"]; overage && len(claims.Groups) == 0 {
		// 用户组太多触发 overage, Entra 只发 _claim_names 指向 Graph API,
		// 没把真实的组 ID 放 id_token 里. 我们不调 Graph, 所以这种用户靠组
		// 准入 admin 会失败; 靠 UPN 白名单的 admin 不受影响.
		// 打一行日志, 排查 "明明在 admin 组里为什么拒我" 时有迹可循.
		log.Printf("OIDC: user %q has groups overage; admin-via-group unavailable, use ADMIN_EMAILS or wire Graph API", claims.UPN)
	}
	upn := claims.UPN
	if upn == "" {
		upn = claims.PreferredUsername
	}
	email := claims.Email
	if email == "" {
		email = claims.PreferredUsername
	}
	return &UserInfo{
		Subject:  claims.Sub,
		UPN:      upn,
		Name:     claims.Name,
		Email:    email,
		TenantID: claims.TID,
		Groups:   claims.Groups,
	}, nil
}
