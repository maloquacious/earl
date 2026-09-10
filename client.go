// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxResponse bounds a response body. Eight megabytes is larger than any
// response a person reads and small enough that a misconfigured server cannot
// exhaust this process (SPEC §7.5).
const maxResponse = 8 << 20

// client is one configured client: where to talk, which identity to use, and
// where to write the result.
type client struct {
	cfg       *Config
	baseURL   string
	identity  string
	userAgent string
	http      *http.Client
	verbose   bool
	storePath string

	// renewed guards the at-most-once renewal of SPEC §9.3. It is per
	// invocation, not per request, so a retry cannot itself trigger a retry.
	renewed bool
}

var _ Transport = (*client)(nil)

// newClient validates the resolved flags and builds the client.
//
// It runs inside a command's Exec rather than while the tree is built, because
// the flag values are not parsed yet at that point - and because a --help
// request must not be refused for a --base-url it would never use.
func newClient(cfg *Config, rf *rootValues) (*client, error) {
	base, err := normalizeBaseURL(*rf.baseURL, cfg.APIPath)
	if err != nil {
		return nil, &UsageError{Err: err}
	}
	path, err := credentialsPath(cfg)
	if err != nil {
		return nil, err
	}
	if *rf.insecure {
		fmt.Fprintf(cfg.Stderr, "%s: TLS certificate verification is disabled\n", cfg.Program)
	}

	agent := cfg.Program
	if cfg.Version != "" {
		agent += "/" + cfg.Version
	}
	return &client{
		cfg:       cfg,
		baseURL:   base,
		identity:  strings.TrimSpace(*rf.identity),
		userAgent: agent,
		http:      newHTTPClient(*rf.timeout, *rf.insecure),
		verbose:   *rf.verbose,
		storePath: path,
	}, nil
}

// newHTTPClient builds the transport.
//
// Redirects are refused rather than followed: this is a tool for seeing what an
// endpoint actually returns, and silently following a 302 would hide it. It
// would also risk carrying the credential to wherever the redirect pointed.
func newHTTPClient(timeout time.Duration, insecure bool) *http.Client {
	c := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if insecure {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		c.Transport = tr
	}
	return c
}

// Do implements Transport: one request, carrying cred, with no caller headers.
// It is what an Auth uses so that login and logout reach the server exactly as
// every other command does.
func (c *client) Do(ctx context.Context, method, path string, body []byte, cred Credential) (*Response, error) {
	return c.send(ctx, method, path, body, cred, nil)
}

// send issues one request and returns the answer without interpreting it.
func (c *client) send(ctx context.Context, method, path string, body []byte, cred Credential, headers []string) (*Response, error) {
	target := joinURL(c.baseURL, path)

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, &UsageError{Err: fmt.Errorf("build request: %w", err)}
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", c.userAgent)
	if !cred.IsZero() {
		c.cfg.Auth.Attach(req, cred)
	}
	// Caller headers are applied last, so -H can override anything above it,
	// including the credential header.
	if err := applyHeaders(req, headers); err != nil {
		return nil, &UsageError{Err: err}
	}

	if c.verbose {
		fmt.Fprintf(c.cfg.Stderr, "%s: > %s %s (body %d bytes, credential %s)\n",
			c.cfg.Program, method, target, len(body), yesNo(!cred.IsZero()))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &TransportError{Method: method, Path: path, Err: err}
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, &TransportError{Method: method, Path: path, Err: fmt.Errorf("read response: %w", err)}
	}
	if c.verbose {
		fmt.Fprintf(c.cfg.Stderr, "%s: < %d (body %d bytes)\n", c.cfg.Program, resp.StatusCode, len(data))
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Cookies: resp.Cookies(), Body: data}, nil
}

// request performs one verb command: resolve the credential, send, renew and
// retry once on a 401 where SPEC §9.3 allows it, and render the answer.
func (c *client) request(ctx context.Context, method, path string, body []byte, headers []string, noAuth bool) error {
	var (
		who  string
		cred Credential
	)
	if !noAuth {
		s, err := c.load()
		if err != nil {
			return err
		}
		who, cred = s.resolve(c.baseURL, c.identity)
	}

	resp, err := c.send(ctx, method, path, body, cred, headers)
	if err != nil {
		return err
	}

	if c.shouldRenew(resp, cred, path) {
		if renewed, ok := c.renew(ctx, who, cred); ok {
			if resp, err = c.send(ctx, method, path, body, renewed, headers); err != nil {
				return err
			}
		}
	}
	return c.emit(method, path, resp)
}

// shouldRenew applies the four conditions of SPEC §9.3.
func (c *client) shouldRenew(resp *Response, cred Credential, path string) bool {
	switch {
	case resp.Status != http.StatusUnauthorized:
		return false
	case cred.IsZero():
		// A 401 on an anonymous request is the endpoint legitimately refusing.
		return false
	case c.renewed:
		return false
	}
	if _, ok := c.cfg.Auth.(Refresher); !ok && !c.canRelogin() {
		return false
	}
	if sa, ok := c.cfg.Auth.(SelfAuthenticator); ok && sa.SelfAuthenticating(path) {
		// These endpoints authenticate from the request body, so their 401
		// means bad credentials. Renewing and retrying would be pointless and
		// would report the wrong cause.
		return false
	}
	return true
}

// renew mints a fresh credential after a 401 and saves it. It reports whether
// the caller should retry.
//
// It sets the guard before trying anything, so a failure is as final as a
// success: at most one renewal per invocation, whatever the outcome.
func (c *client) renew(ctx context.Context, who string, cred Credential) (Credential, bool) {
	c.renewed = true

	if r, ok := c.cfg.Auth.(Refresher); ok {
		fresh, err := r.Refresh(ctx, c, cred)
		switch {
		case err == nil:
			if saved, ok := c.remember(who, fresh, "renewed"); ok {
				return saved, true
			}
			return Credential{}, false
		case errors.Is(err, ErrNoRenewal):
			// Nothing to try, so nothing to report: the 401 stands on its own.
		default:
			fmt.Fprintf(c.cfg.Stderr, "%s: credential rejected and renewal failed: %v\n", c.cfg.Program, err)
		}
	}

	if !c.canRelogin() {
		return Credential{}, false
	}
	identity, secret := c.reloginInputs()
	fresh, err := c.cfg.Auth.Login(ctx, c, identity, secret)
	if err != nil {
		fmt.Fprintf(c.cfg.Stderr, "%s: credential rejected and re-login failed: %v\n", c.cfg.Program, err)
		return Credential{}, false
	}
	if saved, ok := c.remember(identity, fresh, "re-authenticated"); ok {
		return saved, true
	}
	return Credential{}, false
}

// remember saves a renewed credential and announces it on stderr.
func (c *client) remember(who string, cred Credential, how string) (Credential, bool) {
	if cred.IsZero() {
		fmt.Fprintf(c.cfg.Stderr, "%s: %s but no credential came back\n", c.cfg.Program, how)
		return Credential{}, false
	}
	s, err := c.load()
	if err != nil {
		fmt.Fprintf(c.cfg.Stderr, "%s: %v\n", c.cfg.Program, err)
		return Credential{}, false
	}
	s.put(c.baseURL, who, cred)
	if err := saveStore(c.storePath, s); err != nil {
		fmt.Fprintf(c.cfg.Stderr, "%s: %v\n", c.cfg.Program, err)
		return Credential{}, false
	}
	fmt.Fprintf(c.cfg.Stderr, "%s: credential %s for %s\n", c.cfg.Program, how, who)
	return cred, true
}

// canRelogin reports whether a full re-login is both permitted and possible.
//
// It is off by default because it means a usable secret is sitting in the
// environment of every invocation, which is a choice an application makes
// deliberately.
func (c *client) canRelogin() bool {
	if !c.cfg.ReloginOnExpiry {
		return false
	}
	identity, secret := c.reloginInputs()
	return identity != "" && secret != ""
}

func (c *client) reloginInputs() (identity, secret string) {
	return c.identity, os.Getenv(c.cfg.EnvPrefix + "_SECRET")
}

// emit renders a completed response (SPEC §8.1, §8.2). A 2xx writes the body to
// stdout; anything else becomes a StatusError, so that a failed request cannot
// feed a pipeline as though it had succeeded.
func (c *client) emit(method, path string, resp *Response) error {
	if resp.OK() {
		c.writeBody(resp.Body)
		return nil
	}
	return &StatusError{Method: method, Path: path, Status: resp.Status, Body: resp.Body}
}

// writeBody writes a successful response: indented when stdout is a terminal,
// raw otherwise so a pipe into jq stays machine-readable. An empty body, as
// from a 204, writes nothing.
func (c *client) writeBody(body []byte) {
	if len(body) == 0 {
		return
	}
	out := formatJSON(body, isTerminal(c.cfg.Stdout))
	fmt.Fprintln(c.cfg.Stdout, strings.TrimRight(out, "\n"))
}

func (c *client) load() (store, error) { return loadStore(c.storePath) }

// login exchanges an identity and a secret for a credential and saves it.
func (c *client) login(ctx context.Context, secret string) error {
	identity := strings.TrimSpace(c.identity)
	if identity == "" || secret == "" {
		return usagef("login needs an identity and a secret (--%s/--secret, or %s_%s/%s_SECRET)",
			c.cfg.IdentityName, c.cfg.EnvPrefix, strings.ToUpper(c.cfg.IdentityName), c.cfg.EnvPrefix)
	}

	cred, err := c.cfg.Auth.Login(ctx, c, identity, secret)
	if err != nil {
		return err
	}
	if cred.IsZero() {
		return fmt.Errorf("login succeeded but returned no credential")
	}

	s, err := c.load()
	if err != nil {
		return err
	}
	s.put(c.baseURL, identity, cred)
	if err := saveStore(c.storePath, s); err != nil {
		return err
	}

	// The note goes to stderr so that stdout stays clean for piping.
	who := strings.ToLower(identity)
	if cred.ExpiresAt.IsZero() {
		fmt.Fprintf(c.cfg.Stderr, "%s: logged in as %s at %s\n", c.cfg.Program, who, c.baseURL)
	} else {
		fmt.Fprintf(c.cfg.Stderr, "%s: logged in as %s at %s (expires %s)\n",
			c.cfg.Program, who, c.baseURL, cred.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// logout revokes the saved credential and forgets it.
//
// The local copy is dropped whatever the server says. A credential the server
// has already forgotten, or refuses to talk about, is not one worth keeping -
// leaving it would only produce confusing 401s later.
func (c *client) logout(ctx context.Context) error {
	s, err := c.load()
	if err != nil {
		return err
	}
	who, cred := s.resolve(c.baseURL, c.identity)
	if cred.IsZero() {
		return c.noCredentialError(s)
	}

	revokeErr := c.cfg.Auth.Logout(ctx, c, cred)

	s.drop(c.baseURL, who)
	if err := saveStore(c.storePath, s); err != nil {
		return err
	}

	if status, ok := errors.AsType[*StatusError](revokeErr); ok && status.Status == http.StatusUnauthorized {
		fmt.Fprintf(c.cfg.Stderr, "%s: credential for %s was already invalid; forgotten locally\n", c.cfg.Program, who)
		return nil
	}
	if revokeErr != nil {
		return revokeErr
	}
	fmt.Fprintf(c.cfg.Stderr, "%s: logged out %s at %s\n", c.cfg.Program, who, c.baseURL)
	return nil
}

// identities lists the credentials saved for this base URL (SPEC §10.5). It
// prints identities and expiries and never a credential value: a terminal
// scrollback or a screen recording is not a place to leave a live session.
func (c *client) identities() error {
	s, err := c.load()
	if err != nil {
		return err
	}
	saved := s.identities(c.baseURL)
	if len(saved) == 0 {
		fmt.Fprintf(c.cfg.Stderr, "%s: no saved credentials for %s (%s)\n", c.cfg.Program, c.baseURL, c.storePath)
		return nil
	}

	// The path goes to stderr because it is context, not data: seeing it is how
	// it becomes obvious which file, and which environment, is in play.
	fmt.Fprintf(c.cfg.Stderr, "%s (%s)\n", c.baseURL, c.storePath)
	for _, who := range saved {
		cred := s[c.baseURL][who]
		switch {
		case cred.ExpiresAt.IsZero():
			fmt.Fprintf(c.cfg.Stdout, "%s\n", who)
		case cred.Expired():
			fmt.Fprintf(c.cfg.Stdout, "%s\texpired %s\n", who, cred.ExpiresAt.Format(time.RFC3339))
		default:
			fmt.Fprintf(c.cfg.Stdout, "%s\texpires %s\n", who, cred.ExpiresAt.Format(time.RFC3339))
		}
	}
	if len(saved) > 1 && c.identity == "" {
		fmt.Fprintf(c.cfg.Stderr, "%s: several saved; pass --%s to choose one\n", c.cfg.Program, c.cfg.IdentityName)
	}
	return nil
}

// noCredentialError reports why no credential could be used, naming the choices
// when the problem is that there are several and naming the command to run when
// the problem is that there are none. Either way the caller is told what to do
// next, which is the difference between an error they can act on and one they
// have to investigate.
func (c *client) noCredentialError(s store) error {
	saved := s.identities(c.baseURL)
	if len(saved) > 1 && c.identity == "" {
		return usagef("several saved credentials for %s; pass --%s (one of: %s)",
			c.baseURL, c.cfg.IdentityName, strings.Join(saved, ", "))
	}
	if c.identity != "" {
		return usagef("no saved credential for %s at %s; run %q first",
			strings.ToLower(c.identity), c.baseURL, c.cfg.Program+" login")
	}
	return usagef("no saved credential for %s; run %q first", c.baseURL, c.cfg.Program+" login")
}

// normalizeBaseURL validates --base-url and fills in the API path when the URL
// carries none, so that both of these address the same endpoint:
//
//	--base-url https://ec.example.com
//	--base-url https://ec.example.com/api/v1
func normalizeBaseURL(raw, apiPath string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("base URL %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("base URL %q: needs a scheme and a host, like https://host:port", raw)
	}
	if apiPath != "" && (u.Path == "" || u.Path == "/") {
		u.Path = apiPath
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// joinURL joins the base URL and a path with exactly one slash between them.
//
// The path is used verbatim, including any query string, and is neither escaped
// nor normalized: a client that rewrites a path cannot be used to find out what
// the server does with an odd one.
func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

// applyHeaders applies -H values. An empty value removes the header, which is
// the only way to unset one earl sets for itself.
func applyHeaders(req *http.Request, headers []string) error {
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return fmt.Errorf("header %q: want \"Name: value\"", h)
		}
		if value = strings.TrimSpace(value); value == "" {
			// A nil slice, not Del: net/http substitutes its own User-Agent
			// for a header that is merely absent, and only a present-but-empty
			// entry suppresses it. The same assignment removes any other
			// header, so there is one rule rather than a special case.
			req.Header[http.CanonicalHeaderKey(name)] = nil
			continue
		}
		req.Header.Set(name, value)
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
