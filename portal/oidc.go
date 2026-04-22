package main

// oidc.go
// Entra ID (Azure AD) OIDC 授权码流程的封装。
// 只暴露两个操作给 main:
//   (a) AuthURL(state, nonce) → 浏览器要跳的 Entra 授权 URL
//   (b) Exchange(ctx, code, nonce) → 用 code 换 token, 校验 id_token, 返回用户信息
//
// 用 github.com/coreos/go-oidc/v3/oidc 做签名校验 + JWKS 自动刷新。

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCClient 聚合了 OIDC provider + OAuth2 config + ID token verifier。
type OIDCClient struct {
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// UserInfo 是我们从 id_token 里能提取的、对授权决策有用的字段。
type UserInfo struct {
	Subject  string // sub: 用户唯一 ID, 跨 tenant 稳定
	UPN      string // upn: user@kazuha.org (Member) 或 xxx#EXT#@... (Guest)
	Name     string // name: 显示名
	Email    string // email 或 preferred_username
	TenantID string // tid: 必须等于我们的 TenantID
}

// IsGuest 判断是不是 B2B 访客账号。
// Microsoft 约定: Guest 的 UPN 里会包含 #EXT# 字样，Member 的不会。
func (u UserInfo) IsGuest() bool {
	return strings.Contains(u.UPN, "#EXT#")
}

// newOIDCClient 连 Entra 拉 discovery 文档，缓存公钥，构造 verifier。
// 容器启动时调用一次，失败直接 fatal。
func newOIDCClient(ctx context.Context, cfg Config) (*OIDCClient, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer())
	if err != nil {
		return nil, fmt.Errorf("oidc discovery 失败 (检查 TENANT_ID / 网络): %w", err)
	}

	oauth := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL(),
		Endpoint:     provider.Endpoint(),
		// openid/profile/email 是标准 claims, 不需要 admin consent
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &OIDCClient{
		provider: provider,
		oauth:    oauth,
		verifier: verifier,
	}, nil
}

// AuthURL 构造去 Entra 的授权 URL。
// prompt=select_account 强制每次都显示账号选择，避免上一个用户在手机上残留 cookie 导致错误账号静默登录。
func (c *OIDCClient) AuthURL(state, nonce string) string {
	return c.oauth.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	)
}

// Exchange 执行完整的 code → token → verify → claims 提取。
// 返回的 UserInfo 保证:
//   - id_token 签名有效
//   - iss / aud / exp / nonce 校验通过
//   - tid 字段和配置里的 TenantID 一致
// 但 Guest 检查不在这里做——让 handler 决定怎么处理（因为要返回友好的错误页）。
func (c *OIDCClient) Exchange(ctx context.Context, cfg Config, code, expectedNonce string) (*UserInfo, error) {
	// 1. code → tokens
	token, err := c.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code 换 token 失败: %w", err)
	}

	// 2. 从 token response 里拿 id_token 字段
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("响应里没有 id_token")
	}

	// 3. 验签 + 基础 claims (iss/aud/exp)
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token 验证失败: %w", err)
	}

	// 4. 验 nonce (go-oidc 不会替我们验)
	if idToken.Nonce != expectedNonce {
		return nil, errors.New("nonce 不匹配 (可能被重放)")
	}

	// 5. 解 claims
	var claims struct {
		Sub               string `json:"sub"`
		UPN               string `json:"upn"`
		Name              string `json:"name"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		TID               string `json:"tid"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("claims 解析失败: %w", err)
	}

	// 6. Tenant 检查 (防跨租户攻击)
	if claims.TID != cfg.TenantID {
		return nil, fmt.Errorf("tenant 不匹配: 期待 %s, 实际 %s", cfg.TenantID, claims.TID)
	}

	// 7. 组装 UserInfo
	// UPN 有时没有 (比如某些个人账户)，兜底用 preferred_username
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
	}, nil
}
