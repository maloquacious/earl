// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl_test

// SPEC Appendix A.1 claims that ecv4, ecv6, and ecv8 are each a Config value
// and that nothing in them needs a code path this module does not have. These
// tests are that claim, executed: each configuration is driven end to end
// against a server shaped like the one it was written for.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mdhender/earl"
	"github.com/mdhender/earl/auth"
)

func run(t *testing.T, cfg earl.Config, args ...string) (string, string, error) {
	t.Helper()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	cfg.Stdout, cfg.Stderr = out, errOut
	cfg.Stdin = strings.NewReader("")
	err := earl.Run(t.Context(), cfg, args)
	return out.String(), errOut.String(), err
}

func credentialsIn(t *testing.T, prefix string) {
	t.Helper()
	t.Setenv(prefix+"_CREDENTIALS", filepath.Join(t.TempDir(), "credentials.json"))
}

// --- ecv4: bearer tokens, refresh on 401, /auth/* excluded ----------------

func TestAppendixECV4(t *testing.T) {
	var access, refreshes int
	token := func() string { return fmt.Sprintf("a%d", access) }

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/login":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			if in["username"] != "admin@example.com" || in["password"] != "secret" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"bad credentials"}`)
				return
			}
			access++
			fmt.Fprintf(w, `{"accessToken":%q,"refreshToken":"r1","expiresInSeconds":900,"tokenType":"Bearer"}`, token())
		case "/auth/refresh":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			if in["refreshToken"] != "r1" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"bad refresh token"}`)
				return
			}
			refreshes++
			access++
			fmt.Fprintf(w, `{"accessToken":%q,"expiresInSeconds":900}`, token())
		default:
			if r.Header.Get("Authorization") != "Bearer "+token() {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"unauthorized"}`)
				return
			}
			fmt.Fprint(w, `{"user":{"id":1,"username":"admin@example.com"}}`)
		}
	}))
	defer srv.Close()

	credentialsIn(t, "EARL")
	cfg := earl.Config{
		Program: "earl", EnvPrefix: "EARL", Env: "development",
		BaseURL: srv.URL, IdentityName: "authn-email", WhoamiPath: "/me",
		ReloginOnExpiry: true,
		Auth: auth.NewBearer(auth.Bearer{
			LoginPath: "/auth/login",
			RenewPath: "/auth/refresh",
			Skip:      func(p string) bool { return strings.HasPrefix(p, "/auth/") },
			Fields: auth.Fields{
				Identity: "username", Secret: "password",
				Token: "accessToken", Renew: "refreshToken", TTL: "expiresInSeconds",
			},
		}),
	}

	if _, errOut, err := run(t, cfg, "login", "--authn-email", "admin@example.com", "--secret", "secret"); err != nil {
		t.Fatalf("login: %v\n%s", err, errOut)
	}
	if out, errOut, err := run(t, cfg, "whoami"); err != nil {
		t.Fatalf("whoami: %v\n%s", err, errOut)
	} else if !strings.Contains(out, "admin@example.com") {
		t.Errorf("whoami = %q", out)
	}

	// Rotate the token out from under earl: the saved one is now stale.
	access++
	if _, errOut, err := run(t, cfg, "get", "/me"); err != nil {
		t.Fatalf("want the refresh-and-retry to succeed: %v\n%s", err, errOut)
	}
	if refreshes != 1 {
		t.Errorf("refreshes = %d, want 1", refreshes)
	}

	// A 401 from /auth/login means bad credentials, not an expired token.
	before := refreshes
	if _, _, err := run(t, cfg, "post", "/auth/login", "-d", `{"username":"admin@example.com","password":"wrong"}`); earl.ExitCode(err) != 3 {
		t.Errorf("ExitCode = %d, want 3", earl.ExitCode(err))
	}
	if refreshes != before {
		t.Error("a self-authenticating path must not trigger a renewal")
	}
}

// --- ecv6: bearer tokens, several identities, no renewal ------------------

func TestAppendixECV6(t *testing.T) {
	tokens := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// This server is mounted under /api, which is where ecv6's base URL
		// pointed; earl joins its paths onto that.
		switch strings.TrimPrefix(r.URL.Path, "/api") {
		case "/auth/login":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			if in["secret"] != "hunter2hunter2" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"bad credentials"}`)
				return
			}
			tok := "t-" + in["email"]
			tokens[tok] = in["email"]
			fmt.Fprintf(w, `{"token":%q,"tokenType":"Bearer","expiresAt":%q}`,
				tok, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		case "/auth/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			who, ok := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"unauthorized"}`)
				return
			}
			fmt.Fprintf(w, `{"email":%q}`, who)
		}
	}))
	defer srv.Close()

	credentialsIn(t, "EARL")
	cfg := earl.Config{
		Program: "earl", EnvPrefix: "EARL", Env: "development",
		BaseURL: srv.URL + "/api", WhoamiPath: "/me",
		Auth: auth.NewBearer(auth.Bearer{
			LoginPath:  "/auth/login",
			LogoutPath: "/auth/logout",
			Fields: auth.Fields{
				Identity: "email", Secret: "secret",
				Token: "token", Expires: "expiresAt",
			},
		}),
	}

	for _, who := range []string{"admin@example.com", "player@example.com"} {
		if _, errOut, err := run(t, cfg, "login", "--email", who, "--secret", "hunter2hunter2"); err != nil {
			t.Fatalf("login %s: %v\n%s", who, err, errOut)
		}
	}

	// Two identities in one file, chosen between with --email.
	out, _, err := run(t, cfg, "--email", "player@example.com", "whoami")
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if !strings.Contains(out, "player@example.com") {
		t.Errorf("whoami = %q, want the selected identity", out)
	}

	list, errOut, err := run(t, cfg, "identities")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list, "admin@example.com") || !strings.Contains(list, "player@example.com") {
		t.Errorf("identities = %q", list)
	}
	if !strings.Contains(errOut, "several saved") {
		t.Errorf("stderr = %q, want the note about choosing", errOut)
	}

	if _, _, err := run(t, cfg, "--email", "admin@example.com", "logout"); err != nil {
		t.Fatalf("logout: %v", err)
	}
	after, _, _ := run(t, cfg, "identities")
	if strings.Contains(after, "admin@example.com") {
		t.Error("logout did not forget the credential")
	}
}

// --- ecv8: session cookie, base URL carrying its own API path -------------

func TestAppendixECV8(t *testing.T) {
	const cookieName = "ec_session"
	live := map[string]bool{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["password"] != "hunter2hunter2" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"title":"Unauthorized"}`)
			return
		}
		live["s1"] = true
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "s1", HttpOnly: true,
			Expires: time.Now().Add(time.Hour)})
		fmt.Fprintf(w, `{"data":{"email":%q}}`, in["email"])
	})
	mux.HandleFunc("GET /api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(cookieName)
		if err != nil || !live[ck.Value] {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"title":"Unauthorized"}`)
			return
		}
		fmt.Fprint(w, `{"data":{"email":"admin@example.com"}}`)
	})
	mux.HandleFunc("DELETE /api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie(cookieName); err == nil {
			delete(live, ck.Value)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	credentialsIn(t, "ECV8")
	cfg := earl.Config{
		Program: "earl", EnvPrefix: "ECV8", Env: "development",
		// No path on the base URL: APIPath fills it in.
		BaseURL: srv.URL, APIPath: "/api/v1", WhoamiPath: "/session",
		Auth: auth.NewCookie(auth.Cookie{
			LoginPath: "/session",
			Fields:    auth.Fields{Identity: "email", Secret: "password", Expires: "data.expires_at"},
		}),
	}

	if _, errOut, err := run(t, cfg, "login", "--email", "admin@example.com", "--password", "x"); err == nil {
		t.Fatalf("a wrong password must fail\n%s", errOut)
	}
	if _, errOut, err := run(t, cfg, "login", "--email", "admin@example.com", "--secret", "hunter2hunter2"); err != nil {
		t.Fatalf("login: %v\n%s", err, errOut)
	}

	out, errOut, err := run(t, cfg, "whoami")
	if err != nil {
		t.Fatalf("whoami: %v\n%s", err, errOut)
	}
	if !strings.Contains(out, "admin@example.com") {
		t.Errorf("whoami = %q", out)
	}
	// The session value is never printed, at any point.
	if strings.Contains(out+errOut, "s1") {
		t.Errorf("the session cookie reached the terminal: %q %q", out, errOut)
	}

	if _, _, err := run(t, cfg, "logout"); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if live["s1"] {
		t.Error("logout did not end the session on the server")
	}
	if _, _, err := run(t, cfg, "whoami"); earl.ExitCode(err) != 3 {
		t.Errorf("ExitCode = %d, want 3 once the session is gone", earl.ExitCode(err))
	}
}
