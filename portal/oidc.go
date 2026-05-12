package main

// oidc.go
// Wrapper for the Entra ID (Azure AD) OIDC authorization-code flow.
// AuthURL supports loginHint, using the email already typed by the user to prefill Entra login.

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
	Groups   []string // Entra Security Group Object IDs for admin access.
}

func (u UserInfo) IsGuest() bool {
	// Case-insensitive: Microsoft currently uses uppercase "#EXT#", but security should not rely
	// on a vendor never changing this casing.
	return strings.Contains(strings.ToUpper(u.UPN), "#EXT#")
}

// IsAdmin reports whether the user can access /admin. Either path is sufficient:
//   1. UPN is in ADMIN_EMAILS.
//   2. Any user group ID is in ADMIN_GROUP_IDS.
// It only runs during login callback; later /admin requests trust the cookie.
// Note: Entra uses _claim_names overage indicators for users in more than ~200 groups and stops
// listing groups directly in id_token. Small teams usually do not hit this.
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

// AuthURL builds the authorization URL for Entra.
// A non-empty loginHint is sent as login_hint so Entra can prefill the email field.
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
		// If the user belongs to too many groups for id_token, Entra sends only _claim_names and
		// _claim_sources; resolving that requires Graph API and is intentionally not handled here.
		ClaimNames map[string]string `json:"_claim_names"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("claims parse failed: %w", err)
	}
	if claims.TID != cfg.TenantID {
		return nil, fmt.Errorf("tenant mismatch: expected %s, got %s", cfg.TenantID, claims.TID)
	}
	if _, overage := claims.ClaimNames["groups"]; overage && len(claims.Groups) == 0 {
		// Group overage: Entra sent _claim_names pointing to Graph API instead of real group IDs.
		// Because this portal does not call Graph, group-based admin access will fail for this user;
		// UPN allowlist access still works. Log this for troubleshooting.
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
