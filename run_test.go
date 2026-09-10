// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPrefix = "EARLTEST"

// api is a stand-in server. It is deliberately not any real API: earl is not
// allowed to know one.
type api struct {
	*httptest.Server

	mu            sync.Mutex
	token         string
	logins        int
	refreshes     int
	refuseRefresh bool
	alwaysDeny    bool
	lastAuth      string
	lastHeaders   http.Header
}

func newAPI(t *testing.T) *api {
	t.Helper()
	a := &api{}
	a.Server = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.Close)
	return a
}

func (a *api) handle(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastAuth = r.Header.Get("Authorization")
	a.lastHeaders = r.Header.Clone()

	writeJSON := func(status int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}

	switch r.URL.Path {
	case "/login":
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["identity"] == "" || in["secret"] != "hunter2" {
			writeJSON(http.StatusUnauthorized, `{"error":"bad credentials"}`)
			return
		}
		a.logins++
		a.token = fmt.Sprintf("tok-%d", a.logins)
		writeJSON(http.StatusOK, fmt.Sprintf(
			`{"data":{"token":%q,"renew":"ren-1","expires_at":%q}}`,
			a.token, time.Now().Add(time.Hour).UTC().Format(time.RFC3339)))
	case "/refresh":
		a.refreshes++
		if a.refuseRefresh {
			writeJSON(http.StatusUnauthorized, `{"error":"renewal rejected"}`)
			return
		}
		a.token = fmt.Sprintf("tok-r%d", a.refreshes)
		writeJSON(http.StatusOK, fmt.Sprintf(`{"data":{"token":%q}}`, a.token))
	case "/logout":
		w.WriteHeader(http.StatusNoContent)
	case "/public":
		writeJSON(http.StatusOK, `{"public":true}`)
	case "/empty":
		w.WriteHeader(http.StatusNoContent)
	case "/text":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "not json at all")
	case "/boom":
		writeJSON(http.StatusInternalServerError, `{"error":"boom"}`)
	case "/echo":
		body := new(bytes.Buffer)
		body.ReadFrom(r.Body)
		writeJSON(http.StatusOK, fmt.Sprintf(`{"method":%q,"body":%q}`, r.Method, body.String()))
	case "/headers":
		out, _ := json.Marshal(r.Header)
		writeJSON(http.StatusOK, string(out))
	default: // /me and everything else is protected
		if a.alwaysDeny || a.token == "" || a.lastAuth != "Bearer "+a.token {
			writeJSON(http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		writeJSON(http.StatusOK, `{"identity":"a@b.test"}`)
	}
}

func (a *api) counts() (logins, refreshes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.logins, a.refreshes
}

// basicAuth is a bearer scheme with no renewal, so it does not satisfy
// Refresher and SPEC §9.3's second condition is false.
type basicAuth struct{}

func (basicAuth) Attach(req *http.Request, cred Credential) {
	if cred.IsZero() {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cred.Value)
}

func (basicAuth) Login(ctx context.Context, tr Transport, identity, secret string) (Credential, error) {
	body, _ := json.Marshal(map[string]string{"identity": identity, "secret": secret})
	resp, err := tr.Do(ctx, http.MethodPost, "/login", body, Credential{})
	if err != nil {
		return Credential{}, err
	}
	if !resp.OK() {
		return Credential{}, &StatusError{Method: "POST", Path: "/login", Status: resp.Status, Body: resp.Body}
	}
	return credFrom(resp.Body), nil
}

func (basicAuth) Logout(ctx context.Context, tr Transport, cred Credential) error {
	resp, err := tr.Do(ctx, http.MethodPost, "/logout", nil, cred)
	if err != nil {
		return err
	}
	if !resp.OK() {
		return &StatusError{Method: "POST", Path: "/logout", Status: resp.Status, Body: resp.Body}
	}
	return nil
}

func (basicAuth) SelfAuthenticating(path string) bool {
	return strings.HasPrefix(path, "/login") || strings.HasPrefix(path, "/refresh")
}

// renewAuth adds renewal, satisfying Refresher.
type renewAuth struct{ basicAuth }

func (renewAuth) Refresh(ctx context.Context, tr Transport, cred Credential) (Credential, error) {
	if cred.Renew == "" {
		return Credential{}, ErrNoRenewal
	}
	body, _ := json.Marshal(map[string]string{"renew": cred.Renew})
	resp, err := tr.Do(ctx, http.MethodPost, "/refresh", body, Credential{})
	if err != nil {
		return Credential{}, err
	}
	if !resp.OK() {
		return Credential{}, &StatusError{Method: "POST", Path: "/refresh", Status: resp.Status, Body: resp.Body}
	}
	fresh := credFrom(resp.Body)
	if fresh.Renew == "" {
		fresh.Renew = cred.Renew
	}
	return fresh, nil
}

func credFrom(body []byte) Credential {
	var doc struct {
		Data struct {
			Token     string    `json:"token"`
			Renew     string    `json:"renew"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"data"`
	}
	json.Unmarshal(body, &doc)
	return Credential{Value: doc.Data.Token, Renew: doc.Data.Renew, ExpiresAt: doc.Data.ExpiresAt}
}

func testConfig(t *testing.T, baseURL string) Config {
	t.Helper()
	t.Setenv(testPrefix+"_CREDENTIALS", filepath.Join(t.TempDir(), "credentials.json"))
	return Config{
		Program:    "earl",
		Version:    "0.0.0-test",
		EnvPrefix:  testPrefix,
		BaseURL:    baseURL,
		Env:        "test",
		WhoamiPath: "/me",
		Auth:       renewAuth{},
		Stdin:      strings.NewReader(""),
	}
}

type result struct {
	stdout string
	stderr string
	err    error
}

func (r result) all() string { return r.stdout + r.stderr }

func runCmd(t *testing.T, cfg Config, args ...string) result {
	t.Helper()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	cfg.Stdout, cfg.Stderr = out, errOut
	err := Run(t.Context(), cfg, args)
	return result{stdout: out.String(), stderr: errOut.String(), err: err}
}

func mustLogin(t *testing.T, cfg Config) {
	t.Helper()
	r := runCmd(t, cfg, "login", "--email", "a@b.test", "--secret", "hunter2")
	if r.err != nil {
		t.Fatalf("login: %v\n%s", r.err, r.stderr)
	}
}

// --- SPEC §13.3: the output contract -------------------------------------

func TestSuccessGoesToStdout(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	r := runCmd(t, cfg, "get", "/public")
	if r.err != nil {
		t.Fatalf("err = %v", r.err)
	}
	if got := strings.TrimSpace(r.stdout); got != `{"public":true}` {
		t.Errorf("stdout = %q, want the raw body", got)
	}
}

// A non-terminal destination gets the bytes unchanged, so a pipe into jq stays
// machine-readable.
func TestNonTerminalOutputIsRaw(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	r := runCmd(t, cfg, "get", "/public")
	if strings.Contains(r.stdout, "\n  ") {
		t.Errorf("stdout = %q, want no indentation for a non-terminal writer", r.stdout)
	}
}

func TestEmptyBodyWritesNothing(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	r := runCmd(t, cfg, "get", "/empty")
	if r.err != nil {
		t.Fatalf("err = %v", r.err)
	}
	if r.stdout != "" {
		t.Errorf("stdout = %q, want nothing for a 204", r.stdout)
	}
}

func TestNonJSONPassesThrough(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	r := runCmd(t, cfg, "get", "/text")
	if got := strings.TrimSpace(r.stdout); got != "not json at all" {
		t.Errorf("stdout = %q", got)
	}
}

func TestFailureGoesToStderrAndExitsThree(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	r := runCmd(t, cfg, "get", "/boom")

	if r.stdout != "" {
		t.Errorf("stdout = %q, want nothing: a failed request must not feed a pipeline", r.stdout)
	}
	if !strings.Contains(r.stderr, "500") || !strings.Contains(r.stderr, "boom") {
		t.Errorf("stderr = %q, want the status and the server's explanation", r.stderr)
	}
	if got := ExitCode(r.err); got != 3 {
		t.Errorf("ExitCode = %d, want 3", got)
	}
}

func TestTransportFailureExitsTwo(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1") // nothing listens here
	r := runCmd(t, cfg, "get", "/me")
	if got := ExitCode(r.err); got != 2 {
		t.Errorf("ExitCode = %d, want 2 for a request that got no answer", got)
	}
}

func TestUsageErrorExitsOne(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	for _, args := range [][]string{
		{"get"},                      // no path
		{"get", "/a", "/b"},          // two paths
		{"nonesuch", "/x"},           // unknown command
		{"login", "positional"},      // login takes none
		{"get", "/p", "-d", "@nope"}, // missing body file
	} {
		r := runCmd(t, cfg, args...)
		if got := ExitCode(r.err); got != 1 {
			t.Errorf("%q: ExitCode = %d, want 1", args, got)
		}
	}
}

func TestHelpSucceeds(t *testing.T) {
	cfg := testConfig(t, "not-a-url-at-all")
	r := runCmd(t, cfg, "--help")
	if r.err != nil {
		t.Errorf("--help returned %v; help must succeed whatever else is wrong", r.err)
	}
	if !strings.Contains(r.stderr, "earl") {
		t.Errorf("stderr = %q, want usage text", r.stderr)
	}
}

// --- SPEC §13.4: credential secrecy --------------------------------------

// The one invariant that cannot be recovered once broken.
func TestCredentialNeverPrinted(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)

	var transcript strings.Builder
	record := func(r result) { transcript.WriteString(r.all()) }

	record(runCmd(t, cfg, "-v", "login", "--email", "a@b.test", "--secret", "hunter2"))
	record(runCmd(t, cfg, "-v", "identities"))
	record(runCmd(t, cfg, "-v", "whoami"))

	a.mu.Lock()
	a.alwaysDeny = true
	a.mu.Unlock()
	record(runCmd(t, cfg, "-v", "get", "/me")) // forces a renewal
	record(runCmd(t, cfg, "-v", "logout"))

	a.mu.Lock()
	tokens := []string{a.token, "tok-1", "ren-1", "hunter2"}
	a.mu.Unlock()

	for _, secret := range tokens {
		if secret == "" {
			continue
		}
		if strings.Contains(transcript.String(), secret) {
			t.Errorf("a credential (%q) reached the terminal:\n%s", secret, transcript.String())
		}
	}
}

// --- SPEC §13.6: renewal --------------------------------------------------

func TestRenewalOnUnauthorized(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	mustLogin(t, cfg)

	// Invalidate the saved token server-side without telling earl.
	a.mu.Lock()
	a.token = "rotated-away"
	a.mu.Unlock()

	r := runCmd(t, cfg, "get", "/me")
	if r.err != nil {
		t.Fatalf("want the retry to succeed, got %v\n%s", r.err, r.stderr)
	}
	if _, refreshes := a.counts(); refreshes != 1 {
		t.Errorf("refreshes = %d, want exactly 1", refreshes)
	}
	if !strings.Contains(r.stderr, "renewed") {
		t.Errorf("stderr = %q, want a diagnostic naming the renewal", r.stderr)
	}
}

func TestRenewalHappensAtMostOnce(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	mustLogin(t, cfg)

	// Nothing will satisfy this server, so a retrying client would loop.
	a.mu.Lock()
	a.alwaysDeny = true
	a.mu.Unlock()

	r := runCmd(t, cfg, "get", "/me")
	if got := ExitCode(r.err); got != 3 {
		t.Errorf("ExitCode = %d, want 3", got)
	}
	if _, refreshes := a.counts(); refreshes != 1 {
		t.Errorf("refreshes = %d, want exactly 1 per invocation", refreshes)
	}
}

func TestNoRenewalWithoutACredential(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)

	// No login, so the request is anonymous and its 401 is the endpoint
	// legitimately refusing.
	r := runCmd(t, cfg, "get", "/me")
	if got := ExitCode(r.err); got != 3 {
		t.Errorf("ExitCode = %d, want 3", got)
	}
	if _, refreshes := a.counts(); refreshes != 0 {
		t.Errorf("refreshes = %d, want 0 for an anonymous 401", refreshes)
	}
}

func TestNoRenewalWithoutARefresher(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	cfg.Auth = basicAuth{} // no Refresher
	mustLogin(t, cfg)

	a.mu.Lock()
	a.alwaysDeny = true
	a.mu.Unlock()

	r := runCmd(t, cfg, "get", "/me")
	if got := ExitCode(r.err); got != 3 {
		t.Errorf("ExitCode = %d, want 3", got)
	}
	if _, refreshes := a.counts(); refreshes != 0 {
		t.Errorf("refreshes = %d, want 0 when the Auth cannot renew", refreshes)
	}
}

func TestNoRenewalOnSelfAuthenticatingPath(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	mustLogin(t, cfg)

	// A 401 from the login endpoint means bad credentials. Renewing would be
	// pointless and would report the wrong cause.
	r := runCmd(t, cfg, "post", "/login", "-d", `{"identity":"a@b.test","secret":"wrong"}`)
	if got := ExitCode(r.err); got != 3 {
		t.Errorf("ExitCode = %d, want 3", got)
	}
	if _, refreshes := a.counts(); refreshes != 0 {
		t.Errorf("refreshes = %d, want 0 for a self-authenticating path", refreshes)
	}
}

func TestFailedRenewalReportsOriginalStatus(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	mustLogin(t, cfg)

	a.mu.Lock()
	a.alwaysDeny, a.refuseRefresh = true, true
	a.mu.Unlock()

	r := runCmd(t, cfg, "get", "/me")
	status, ok := errAs[*StatusError](r.err)
	if !ok {
		t.Fatalf("err = %v, want a StatusError", r.err)
	}
	if status.Status != http.StatusUnauthorized || status.Path != "/me" {
		t.Errorf("got %d %s, want the original 401 on /me", status.Status, status.Path)
	}
	if !strings.Contains(r.stderr, "renewal failed") {
		t.Errorf("stderr = %q, want a diagnostic explaining the failure", r.stderr)
	}
}

// --- request shape --------------------------------------------------------

func TestNoAuthSendsNoCredential(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	mustLogin(t, cfg)

	runCmd(t, cfg, "get", "/public", "--no-auth")
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastAuth != "" {
		t.Errorf("Authorization = %q, want none under --no-auth", a.lastAuth)
	}
}

func TestHeadersOverrideAndRemove(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)

	runCmd(t, cfg, "get", "/headers", "-H", "X-Trace: abc", "-H", "Accept: text/csv", "-H", "User-Agent:")
	a.mu.Lock()
	defer a.mu.Unlock()
	if got := a.lastHeaders.Get("X-Trace"); got != "abc" {
		t.Errorf("X-Trace = %q", got)
	}
	if got := a.lastHeaders.Get("Accept"); got != "text/csv" {
		t.Errorf("Accept = %q, want -H to override earl's own header", got)
	}
	if got := a.lastHeaders.Get("User-Agent"); got != "" {
		t.Errorf("User-Agent = %q, want an empty -H value to remove it", got)
	}
}

func TestBodyIsSentOnEveryVerb(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	for _, verb := range []string{"get", "post", "put", "patch", "delete"} {
		r := runCmd(t, cfg, verb, "/echo", "-d", `{"sent":true}`)
		if r.err != nil {
			t.Fatalf("%s: %v", verb, r.err)
		}
		if !strings.Contains(r.stdout, `{\"sent\":true}`) {
			t.Errorf("%s: body did not reach the server: %s", verb, r.stdout)
		}
	}
}

func TestPathIsUsedVerbatim(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	r := runCmd(t, cfg, "get", "/headers?a=b&c=d")
	if r.err != nil {
		t.Fatalf("query string was not passed through: %v", r.err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			reached = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	cfg := testConfig(t, srv.URL)
	r := runCmd(t, cfg, "get", "/start")
	if reached {
		t.Error("the redirect was followed; a 302 must be reported, not chased")
	}
	status, ok := errAs[*StatusError](r.err)
	if !ok || status.Status != http.StatusFound {
		t.Errorf("err = %v, want the 302 itself", r.err)
	}
}

// --- identity selection ---------------------------------------------------

func TestAmbiguousIdentity(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	mustLogin(t, cfg)
	r := runCmd(t, cfg, "login", "--email", "second@b.test", "--secret", "hunter2")
	if r.err != nil {
		t.Fatal(r.err)
	}

	// A verb request goes out anonymously and the server decides.
	if _, refreshes := a.counts(); refreshes != 0 {
		t.Fatalf("unexpected renewal")
	}
	verb := runCmd(t, cfg, "get", "/public")
	if verb.err != nil {
		t.Errorf("an ambiguous identity must not stop an anonymous request: %v", verb.err)
	}

	// A session command must instead say what to do about it.
	out := runCmd(t, cfg, "logout")
	if ExitCode(out.err) != 1 {
		t.Errorf("ExitCode = %d, want 1", ExitCode(out.err))
	}
	if !strings.Contains(out.stderr, "a@b.test") || !strings.Contains(out.stderr, "second@b.test") {
		t.Errorf("stderr = %q, want the choices named", out.stderr)
	}
}

func TestLogoutForgetsLocallyEvenWhenTheServerRefuses(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	mustLogin(t, cfg)

	a.mu.Lock()
	a.alwaysDeny = true
	a.mu.Unlock()

	runCmd(t, cfg, "logout")
	r := runCmd(t, cfg, "identities")
	if !strings.Contains(r.stderr, "no saved credentials") {
		t.Errorf("the credential survived a refused logout: %q %q", r.stdout, r.stderr)
	}
}

func TestWhoamiIsAPlainRequest(t *testing.T) {
	a := newAPI(t)
	cfg := testConfig(t, a.URL)
	mustLogin(t, cfg)
	r := runCmd(t, cfg, "whoami")
	if r.err != nil {
		t.Fatalf("%v\n%s", r.err, r.stderr)
	}
	if !strings.Contains(r.stdout, "a@b.test") {
		t.Errorf("stdout = %q, want the server's answer", r.stdout)
	}
}

func TestVersionCommand(t *testing.T) {
	cfg := testConfig(t, "http://example.test")
	r := runCmd(t, cfg, "version")
	if r.err != nil || strings.TrimSpace(r.stdout) != "0.0.0-test" {
		t.Errorf("stdout = %q, err = %v", r.stdout, r.err)
	}
}

func errAs[T error](err error) (T, bool) {
	var zero T
	if err == nil {
		return zero, false
	}
	for e := err; e != nil; {
		if t, ok := e.(T); ok {
			return t, true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return zero, false
}
