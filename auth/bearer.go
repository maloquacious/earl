// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mdhender/earl"
)

// Bearer describes an API that authenticates with a token in a header.
type Bearer struct {
	// LoginPath is the endpoint that exchanges credentials for a token.
	// Required.
	LoginPath string

	// LogoutPath revokes a token. When empty, logout is local-only: earl
	// forgets the credential and tells the server nothing.
	LogoutPath string

	// RenewPath exchanges a renewal credential for a fresh token. When empty,
	// the Auth does not implement earl.Refresher and a 401 is reported as
	// itself.
	RenewPath string

	// RenewField is the request key carrying the renewal credential. Defaults
	// to "refreshToken".
	RenewField string

	// Header and Prefix say how the token is attached, defaulting together to
	// "Authorization" and "Bearer ". Naming a Header of your own leaves Prefix
	// alone, so an API-key header can carry the bare value.
	Header string
	Prefix string

	Fields Fields

	// Skip names further paths that authenticate from the request body rather
	// than from the attached credential, so that earl does not answer their
	// 401s by renewing. ecv4 needed this as a prefix test on /auth/.
	Skip func(path string) bool
}

// NewBearer returns an earl.Auth for b.
//
// The result implements earl.Refresher when b.RenewPath is set and not
// otherwise, so that SPEC §9.3's second condition is decided by configuration
// rather than by a method that would have to fail at run time.
func NewBearer(b Bearer) earl.Auth {
	// The "Bearer " default belongs to the default header. A caller who names
	// their own header - an API-key scheme, say - is saying exactly what goes
	// in it, and an empty Prefix there is a choice rather than an omission.
	if b.Header == "" {
		b.Header = "Authorization"
		if b.Prefix == "" {
			b.Prefix = "Bearer "
		}
	}
	if b.RenewField == "" {
		b.RenewField = "refreshToken"
	}
	b.Fields = b.Fields.withDefaults()

	base := &bearer{Bearer: b}
	if b.RenewPath == "" {
		return base
	}
	return &renewingBearer{bearer: base}
}

type bearer struct{ Bearer }

var _ earl.Auth = (*bearer)(nil)

// Attach sets the credential header. A zero credential leaves req untouched, so
// the request goes out anonymously and the server decides.
func (b *bearer) Attach(req *http.Request, cred earl.Credential) {
	if cred.IsZero() {
		return
	}
	req.Header.Set(b.Header, b.Prefix+cred.Value)
}

// Login exchanges an identity and a secret for a token.
func (b *bearer) Login(ctx context.Context, tr earl.Transport, identity, secret string) (earl.Credential, error) {
	body, err := json.Marshal(map[string]string{
		b.Fields.Identity: identity,
		b.Fields.Secret:   secret,
	})
	if err != nil {
		return earl.Credential{}, fmt.Errorf("encode login request: %w", err)
	}
	resp, err := tr.Do(ctx, http.MethodPost, b.LoginPath, body, earl.Credential{})
	if err != nil {
		return earl.Credential{}, err
	}
	if !resp.OK() {
		return earl.Credential{}, statusError(http.MethodPost, b.LoginPath, resp)
	}
	return b.credentialFrom(resp.Body)
}

// Logout revokes the token. With no LogoutPath there is nothing to tell the
// server, and earl still forgets the credential locally.
func (b *bearer) Logout(ctx context.Context, tr earl.Transport, cred earl.Credential) error {
	if b.LogoutPath == "" {
		return nil
	}
	resp, err := tr.Do(ctx, http.MethodPost, b.LogoutPath, nil, cred)
	if err != nil {
		return err
	}
	if !resp.OK() {
		return statusError(http.MethodPost, b.LogoutPath, resp)
	}
	return nil
}

// SelfAuthenticating reports the paths that authenticate from the request body.
// A 401 from one of them means bad credentials, so renewing and retrying would
// be pointless and would report the wrong cause.
func (b *bearer) SelfAuthenticating(path string) bool {
	if samePath(path, b.LoginPath) || samePath(path, b.RenewPath) || samePath(path, b.LogoutPath) {
		return true
	}
	return b.Skip != nil && b.Skip(path)
}

func (b *bearer) credentialFrom(body []byte) (earl.Credential, error) {
	token := stringAt(body, b.Fields.Token)
	if token == "" {
		return earl.Credential{}, fmt.Errorf("response carried no %q", b.Fields.Token)
	}
	return earl.Credential{
		Value:     token,
		Renew:     stringAt(body, b.Fields.Renew),
		ExpiresAt: expiryFrom(body, b.Fields),
	}, nil
}

// renewingBearer is a bearer whose API can mint a fresh token from a renewal
// credential.
type renewingBearer struct{ *bearer }

var _ earl.Refresher = (*renewingBearer)(nil)

// Refresh exchanges the saved renewal credential for a fresh token.
func (r *renewingBearer) Refresh(ctx context.Context, tr earl.Transport, cred earl.Credential) (earl.Credential, error) {
	if cred.Renew == "" {
		return earl.Credential{}, earl.ErrNoRenewal
	}
	body, err := json.Marshal(map[string]string{r.RenewField: cred.Renew})
	if err != nil {
		return earl.Credential{}, fmt.Errorf("encode renewal request: %w", err)
	}
	resp, err := tr.Do(ctx, http.MethodPost, r.RenewPath, body, earl.Credential{})
	if err != nil {
		return earl.Credential{}, err
	}
	if !resp.OK() {
		return earl.Credential{}, statusError(http.MethodPost, r.RenewPath, resp)
	}
	fresh, err := r.credentialFrom(resp.Body)
	if err != nil {
		return earl.Credential{}, err
	}
	// Servers commonly reissue only the access token. Keeping the old renewal
	// credential is what lets the next expiry be renewed too, instead of the
	// second 401 being the one that makes the caller log in again.
	if fresh.Renew == "" {
		fresh.Renew = cred.Renew
	}
	return fresh, nil
}

func statusError(method, path string, resp *earl.Response) error {
	return &earl.StatusError{Method: method, Path: path, Status: resp.Status, Body: resp.Body}
}
