package main

// oidc.go
// Entra ID (Azure AD) OIDC 授权码流程的封装.
// AuthURL 支持 loginHint (=用户已输入的邮箱) 让 Entra 登录页预填邮箱, 省用户再敲一次.

import (
	"context"
	"errors"
	"fmt"
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
}

func (u UserInfo) IsGuest() bool {
	return strings.Contains(u.UPN, "#EXT#")
}

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
		return nil, fmt.Errorf("code 换 token 失败: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("响应里没有 id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token 验证失败: %w", err)
	}
	if idToken.Nonce != expectedNonce {
		return nil, errors.New("nonce 不匹配 (可能被重放)")
	}
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
	if claims.TID != cfg.TenantID {
		return nil, fmt.Errorf("tenant 不匹配: 期待 %s, 实际 %s", cfg.TenantID, claims.TID)
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
	}, nil
}
