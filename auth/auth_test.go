// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/maloquacious/earl"
	"github.com/maloquacious/earl/auth"
)

// stub is a Transport that answers from a script, recording what it was asked.
type stub struct {
	responses map[string]*earl.Response
	calls     []string
	bodies    map[string]string
	creds     map[string]earl.Credential
}

func newStub() *stub {
	return &stub{
		responses: map[string]*earl.Response{},
		bodies:    map[string]string{},
		creds:     map[string]earl.Credential{},
	}
}

func (s *stub) Do(_ context.Context, method, path string, body []byte, cred earl.Credential) (*earl.Response, error) {
	s.calls = append(s.calls, method+" "+path)
	s.bodies[path] = string(body)
	s.creds[path] = cred
	if resp, ok := s.responses[path]; ok {
		return resp, nil
	}
	return &earl.Response{Status: http.StatusNotFound, Body: []byte(`{"error":"no stub"}`)}, nil
}

func jsonResponse(status int, body string, cookies ...*http.Cookie) *earl.Response {
	return &earl.Response{Status: status, Body: []byte(body), Cookies: cookies, Header: http.Header{}}
}

// --- Bearer ---------------------------------------------------------------

func TestBearerAttach(t *testing.T) {
	a := auth.NewBearer(auth.Bearer{LoginPath: "/login"})

	req, _ := http.NewRequest(http.MethodGet, "http://x/y", nil)
	a.Attach(req, earl.Credential{Value: "tok"})
	if got := req.Header.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("Authorization = %q", got)
	}

	anon, _ := http.NewRequest(http.MethodGet, "http://x/y", nil)
	a.Attach(anon, earl.Credential{})
	if len(anon.Header) != 0 {
		t.Errorf("a zero credential must leave the request untouched, got %v", anon.Header)
	}
}

func TestBearerAttachHonoursHeaderAndPrefix(t *testing.T) {
	a := auth.NewBearer(auth.Bearer{LoginPath: "/login", Header: "X-Api-Key", Prefix: ""})
	req, _ := http.NewRequest(http.MethodGet, "http://x/y", nil)
	a.Attach(req, earl.Credential{Value: "tok"})
	if got := req.Header.Get("X-Api-Key"); got != "tok" {
		t.Errorf("X-Api-Key = %q", got)
	}
}

// SPEC §9.3 condition 2 is decided by configuration, not by a method that has
// to fail at run time.
func TestBearerIsARefresherOnlyWhenConfigured(t *testing.T) {
	if _, ok := auth.NewBearer(auth.Bearer{LoginPath: "/login"}).(earl.Refresher); ok {
		t.Error("a Bearer with no RenewPath must not satisfy earl.Refresher")
	}
	if _, ok := auth.NewBearer(auth.Bearer{LoginPath: "/login", RenewPath: "/renew"}).(earl.Refresher); !ok {
		t.Error("a Bearer with a RenewPath must satisfy earl.Refresher")
	}
}

// A dotted path reaches into an envelope, so ecv8's {"data":{…}} needs no code.
func TestBearerLoginReadsDottedPaths(t *testing.T) {
	s := newStub()
	s.responses["/login"] = jsonResponse(http.StatusOK,
		`{"data":{"token":"tok-1","refreshToken":"ren-1","expires_at":"2030-01-02T03:04:05Z"}}`)

	a := auth.NewBearer(auth.Bearer{
		LoginPath: "/login",
		Fields: auth.Fields{
			Identity: "email", Secret: "secret",
			Token: "data.token", Renew: "data.refreshToken", Expires: "data.expires_at",
		},
	})

	cred, err := a.Login(t.Context(), s, "a@b.test", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Value != "tok-1" || cred.Renew != "ren-1" {
		t.Errorf("got %+v", cred)
	}
	if want := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC); !cred.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", cred.ExpiresAt, want)
	}
	if got := s.bodies["/login"]; !strings.Contains(got, `"email":"a@b.test"`) || !strings.Contains(got, `"secret":"hunter2"`) {
		t.Errorf("login body = %s", got)
	}
}

// ecv4's server reported a lifetime rather than an instant.
func TestBearerLoginReadsATTL(t *testing.T) {
	s := newStub()
	s.responses["/login"] = jsonResponse(http.StatusOK, `{"accessToken":"tok","expiresInSeconds":900}`)

	a := auth.NewBearer(auth.Bearer{
		LoginPath: "/login",
		Fields:    auth.Fields{Token: "accessToken", TTL: "expiresInSeconds"},
	})
	cred, err := a.Login(t.Context(), s, "a@b.test", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(cred.ExpiresAt); d < 14*time.Minute || d > 15*time.Minute {
		t.Errorf("expiry in %v, want about 15 minutes", d)
	}
}

func TestBearerLoginFailureIsAStatusError(t *testing.T) {
	s := newStub()
	s.responses["/login"] = jsonResponse(http.StatusUnauthorized, `{"error":"bad credentials"}`)

	a := auth.NewBearer(auth.Bearer{LoginPath: "/login"})
	_, err := a.Login(t.Context(), s, "a@b.test", "wrong")
	status, ok := err.(*earl.StatusError)
	if !ok {
		t.Fatalf("err = %v (%T), want *earl.StatusError", err, err)
	}
	if status.Status != http.StatusUnauthorized {
		t.Errorf("status = %d", status.Status)
	}
	if earl.ExitCode(err) != 3 {
		t.Errorf("ExitCode = %d, want 3", earl.ExitCode(err))
	}
}

func TestBearerLoginWithoutAToken(t *testing.T) {
	s := newStub()
	s.responses["/login"] = jsonResponse(http.StatusOK, `{"nothing":"useful"}`)
	a := auth.NewBearer(auth.Bearer{LoginPath: "/login"})
	if _, err := a.Login(t.Context(), s, "a@b.test", "hunter2"); err == nil {
		t.Fatal("want an error when the response carries no token")
	}
}

func TestBearerRefreshKeepsTheRenewalCredential(t *testing.T) {
	s := newStub()
	s.responses["/renew"] = jsonResponse(http.StatusOK, `{"token":"tok-2"}`)

	a := auth.NewBearer(auth.Bearer{LoginPath: "/login", RenewPath: "/renew"}).(earl.Refresher)
	fresh, err := a.Refresh(t.Context(), s, earl.Credential{Value: "tok-1", Renew: "ren-1"})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Value != "tok-2" {
		t.Errorf("Value = %q", fresh.Value)
	}
	// Dropping it would make the next expiry the one that forces a login.
	if fresh.Renew != "ren-1" {
		t.Errorf("Renew = %q, want the old renewal credential carried forward", fresh.Renew)
	}
	if got := s.bodies["/renew"]; !strings.Contains(got, `"refreshToken":"ren-1"`) {
		t.Errorf("renew body = %s", got)
	}
}

func TestBearerRefreshWithoutARenewalCredential(t *testing.T) {
	a := auth.NewBearer(auth.Bearer{LoginPath: "/login", RenewPath: "/renew"}).(earl.Refresher)
	_, err := a.Refresh(t.Context(), newStub(), earl.Credential{Value: "tok"})
	if err != earl.ErrNoRenewal {
		t.Errorf("err = %v, want ErrNoRenewal so the 401 stands on its own", err)
	}
}

func TestBearerSelfAuthenticating(t *testing.T) {
	a := auth.NewBearer(auth.Bearer{
		LoginPath:  "/auth/login",
		RenewPath:  "/auth/refresh",
		LogoutPath: "/auth/logout",
		Skip:       func(p string) bool { return strings.HasPrefix(p, "/auth/") },
	}).(earl.SelfAuthenticator)

	for _, p := range []string{"/auth/login", "auth/login", "/auth/refresh", "/auth/logout", "/auth/anything"} {
		if !a.SelfAuthenticating(p) {
			t.Errorf("%s should be self-authenticating", p)
		}
	}
	if a.SelfAuthenticating("/me") {
		t.Error("/me should not be self-authenticating")
	}
}

func TestBearerLogoutIsLocalOnlyWithoutAPath(t *testing.T) {
	s := newStub()
	a := auth.NewBearer(auth.Bearer{LoginPath: "/login"})
	if err := a.Logout(t.Context(), s, earl.Credential{Value: "tok"}); err != nil {
		t.Fatal(err)
	}
	if len(s.calls) != 0 {
		t.Errorf("calls = %v, want none", s.calls)
	}
}

// --- Cookie ---------------------------------------------------------------

// SPEC §13.7. A successful login sets exactly one cookie, so whatever arrives
// is the session and the caller never has to know its name.
func TestCookieLoginCapturesTheOnlyCookie(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	s := newStub()
	s.responses["/session"] = jsonResponse(http.StatusOK, `{"data":{}}`,
		&http.Cookie{Name: "ec_session", Value: "sess-1", Expires: expires})

	a := auth.NewCookie(auth.Cookie{LoginPath: "/session"})
	cred, err := a.Login(t.Context(), s, "a@b.test", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Value != "sess-1" || cred.Name != "ec_session" {
		t.Errorf("got %+v, want the cookie and its name", cred)
	}
	if !cred.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want the cookie's own expiry", cred.ExpiresAt)
	}
}

func TestCookieLoginFallsBackToTheBodyExpiry(t *testing.T) {
	s := newStub()
	s.responses["/session"] = jsonResponse(http.StatusOK, `{"data":{"expires_at":"2030-01-02T03:04:05Z"}}`,
		&http.Cookie{Name: "ec_session", Value: "sess-1"}) // no Expires

	a := auth.NewCookie(auth.Cookie{LoginPath: "/session", Fields: auth.Fields{Expires: "data.expires_at"}})
	cred, err := a.Login(t.Context(), s, "a@b.test", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC); !cred.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", cred.ExpiresAt, want)
	}
}

// Guessing risks sending a routing cookie as a credential and saving the real
// session nowhere, which is worse than failing.
func TestCookieLoginRefusesToGuess(t *testing.T) {
	s := newStub()
	s.responses["/session"] = jsonResponse(http.StatusOK, `{}`,
		&http.Cookie{Name: "AWSALB", Value: "routing-value"},
		&http.Cookie{Name: "ec_session", Value: "the-real-session"})

	a := auth.NewCookie(auth.Cookie{LoginPath: "/session"})
	_, err := a.Login(t.Context(), s, "a@b.test", "hunter2")
	if err == nil {
		t.Fatal("want a refusal when two cookies arrive")
	}
	msg := err.Error()
	if !strings.Contains(msg, "AWSALB") || !strings.Contains(msg, "ec_session") {
		t.Errorf("err = %q, want the candidate names", msg)
	}
	for _, value := range []string{"routing-value", "the-real-session"} {
		if strings.Contains(msg, value) {
			t.Errorf("err = %q leaked a cookie value", msg)
		}
	}
}

func TestCookieNameBreaksTheTie(t *testing.T) {
	s := newStub()
	s.responses["/session"] = jsonResponse(http.StatusOK, `{}`,
		&http.Cookie{Name: "AWSALB", Value: "routing"},
		&http.Cookie{Name: "ec_session", Value: "sess-1"})

	a := auth.NewCookie(auth.Cookie{LoginPath: "/session", Name: "ec_session"})
	cred, err := a.Login(t.Context(), s, "a@b.test", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Value != "sess-1" {
		t.Errorf("got %q, want the named cookie", cred.Value)
	}
}

func TestCookieLoginWithNoCookieAtAll(t *testing.T) {
	s := newStub()
	s.responses["/session"] = jsonResponse(http.StatusOK, `{}`)
	a := auth.NewCookie(auth.Cookie{LoginPath: "/session"})
	if _, err := a.Login(t.Context(), s, "a@b.test", "hunter2"); err == nil {
		t.Fatal("want an error when the login sets no cookie")
	}
}

// The name saved at login wins, so a file written before names were saved still
// works instead of failing in a way that looks like an expired session.
func TestCookieAttachPrefersTheSavedName(t *testing.T) {
	a := auth.NewCookie(auth.Cookie{LoginPath: "/session", Name: "configured"})

	req, _ := http.NewRequest(http.MethodGet, "http://x/y", nil)
	a.Attach(req, earl.Credential{Value: "sess", Name: "saved"})
	if ck, err := req.Cookie("saved"); err != nil || ck.Value != "sess" {
		t.Errorf("cookies = %q, want the saved name", req.Header.Get("Cookie"))
	}

	fallback, _ := http.NewRequest(http.MethodGet, "http://x/y", nil)
	a.Attach(fallback, earl.Credential{Value: "sess"})
	if ck, err := fallback.Cookie("configured"); err != nil || ck.Value != "sess" {
		t.Errorf("cookies = %q, want the configured name as the fallback", fallback.Header.Get("Cookie"))
	}

	anon, _ := http.NewRequest(http.MethodGet, "http://x/y", nil)
	a.Attach(anon, earl.Credential{})
	if len(anon.Header) != 0 {
		t.Errorf("a zero credential must leave the request untouched, got %v", anon.Header)
	}
}

func TestCookieLogoutDefaultsToDeleteOnTheLoginPath(t *testing.T) {
	s := newStub()
	s.responses["/session"] = jsonResponse(http.StatusNoContent, "")
	a := auth.NewCookie(auth.Cookie{LoginPath: "/session"})
	if err := a.Logout(t.Context(), s, earl.Credential{Value: "sess", Name: "ec_session"}); err != nil {
		t.Fatal(err)
	}
	if len(s.calls) != 1 || s.calls[0] != "DELETE /session" {
		t.Errorf("calls = %v, want a DELETE on the login path", s.calls)
	}
	if s.creds["/session"].Value != "sess" {
		t.Error("logout must carry the credential it is revoking")
	}
}

func TestCookieRequestBodyUsesConfiguredFieldNames(t *testing.T) {
	s := newStub()
	s.responses["/session"] = jsonResponse(http.StatusOK, `{}`, &http.Cookie{Name: "s", Value: "v"})
	a := auth.NewCookie(auth.Cookie{LoginPath: "/session", Fields: auth.Fields{Identity: "username", Secret: "pass"}})
	if _, err := a.Login(t.Context(), s, "someone", "hunter2"); err != nil {
		t.Fatal(err)
	}
	var sent map[string]string
	json.Unmarshal([]byte(s.bodies["/session"]), &sent)
	if sent["username"] != "someone" || sent["pass"] != "hunter2" {
		t.Errorf("body = %v", sent)
	}
}
