// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/maloquacious/earl"
)

// Cookie describes an API that authenticates with a session cookie.
//
// The credential is returned exactly once, in the Set-Cookie header of a
// successful login, and never in a response body - so capturing it at login is
// the only opportunity there will be.
type Cookie struct {
	// LoginPath is the endpoint that establishes a session. Required.
	LoginPath string

	// LogoutPath and LogoutMethod end one. They default to LoginPath and
	// DELETE, which is what a session-as-a-resource API looks like.
	LogoutPath   string
	LogoutMethod string

	// Name breaks a tie when a login response sets more than one cookie. It is
	// not normally needed: a successful login sets exactly one, so whatever
	// arrives is the session, and a configurable server setting is not
	// something the caller should have to discover and repeat.
	Name string

	Fields Fields
}

// NewCookie returns an earl.Auth for c.
func NewCookie(c Cookie) earl.Auth {
	if c.LogoutPath == "" {
		c.LogoutPath = c.LoginPath
	}
	if c.LogoutMethod == "" {
		c.LogoutMethod = http.MethodDelete
	}
	c.Fields = c.Fields.withDefaults()
	return &cookie{Cookie: c}
}

type cookie struct{ Cookie }

var _ earl.Auth = (*cookie)(nil)

// Attach sends the saved session back.
//
// The name saved at login is authoritative; the configured Name is the
// fallback. A credential file written before names were saved therefore still
// works, instead of failing in a way that looks like an expired session.
func (c *cookie) Attach(req *http.Request, cred earl.Credential) {
	if cred.IsZero() {
		return
	}
	name := cred.Name
	if name == "" {
		name = c.Name
	}
	if name == "" {
		return
	}
	req.AddCookie(&http.Cookie{Name: name, Value: cred.Value})
}

// Login authenticates and captures the session cookie.
func (c *cookie) Login(ctx context.Context, tr earl.Transport, identity, secret string) (earl.Credential, error) {
	body, err := json.Marshal(map[string]string{
		c.Fields.Identity: identity,
		c.Fields.Secret:   secret,
	})
	if err != nil {
		return earl.Credential{}, fmt.Errorf("encode login request: %w", err)
	}
	resp, err := tr.Do(ctx, http.MethodPost, c.LoginPath, body, earl.Credential{})
	if err != nil {
		return earl.Credential{}, err
	}
	if !resp.OK() {
		return earl.Credential{}, statusError(http.MethodPost, c.LoginPath, resp)
	}

	session, err := c.sessionCookie(resp)
	if err != nil {
		return earl.Credential{}, err
	}

	// The cookie's own expiry is what the server will enforce. The body's is
	// the fallback, for a server that sets a session cookie without Expires.
	expires := session.Expires
	if expires.IsZero() {
		expires = expiryFrom(resp.Body, c.Fields)
	}
	return earl.Credential{Value: session.Value, Name: session.Name, ExpiresAt: expires}, nil
}

// Logout ends the session on the server.
func (c *cookie) Logout(ctx context.Context, tr earl.Transport, cred earl.Credential) error {
	resp, err := tr.Do(ctx, c.LogoutMethod, c.LogoutPath, nil, cred)
	if err != nil {
		return err
	}
	if !resp.OK() {
		return statusError(c.LogoutMethod, c.LogoutPath, resp)
	}
	return nil
}

// SelfAuthenticating reports the login endpoint, which authenticates from the
// request body rather than from a cookie.
func (c *cookie) SelfAuthenticating(path string) bool {
	return samePath(path, c.LoginPath)
}

// sessionCookie picks the session out of a login response.
//
// When more than one cookie arrives - a load balancer adding a routing cookie -
// it refuses rather than guesses. Sending a routing cookie as a credential and
// saving the real session nowhere is worse than failing, and the caller is told
// the names so they can say which. Only names are listed; a cookie's value is
// never shown.
func (c *cookie) sessionCookie(resp *earl.Response) (*http.Cookie, error) {
	if c.Name != "" {
		for _, ck := range resp.Cookies {
			if ck.Name == c.Name {
				return ck, nil
			}
		}
		return nil, fmt.Errorf("login response set no %q cookie (it set: %s)", c.Name, cookieNames(resp.Cookies))
	}
	switch len(resp.Cookies) {
	case 0:
		return nil, errors.New("login succeeded but set no cookie")
	case 1:
		return resp.Cookies[0], nil
	default:
		return nil, fmt.Errorf("login response set %d cookies (%s); set Name to say which is the session",
			len(resp.Cookies), cookieNames(resp.Cookies))
	}
}

func cookieNames(cookies []*http.Cookie) string {
	names := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		names = append(names, ck.Name)
	}
	return strings.Join(names, ", ")
}
