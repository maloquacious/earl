// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"context"
	"net/http"
)

// Auth supplies the parts of authentication that differ between APIs: how a
// credential is obtained, how it is attached to a request, and how it is
// revoked. It is the only thing an application must implement or configure
// (SPEC §9.1).
type Auth interface {
	// Attach adds cred to req. A zero Credential must leave req unchanged, so
	// that an anonymous request is sent as-is and the server decides.
	Attach(req *http.Request, cred Credential)

	// Login exchanges an identity and a secret for the credential to save.
	Login(ctx context.Context, tr Transport, identity, secret string) (Credential, error)

	// Logout revokes cred on the server. An error does not prevent earl from
	// dropping the local copy: a credential the server has forgotten is not
	// one worth keeping, and leaving it produces confusing 401s later.
	Logout(ctx context.Context, tr Transport, cred Credential) error
}

// Refresher is implemented by an Auth that can renew a credential without the
// secret. earl calls Refresh at most once per invocation.
type Refresher interface {
	Refresh(ctx context.Context, tr Transport, cred Credential) (Credential, error)
}

// SelfAuthenticator is implemented by an Auth whose own endpoints authenticate
// from the request body rather than from the attached credential. earl does not
// react to a 401 from such a path by renewing and retrying: the 401 means bad
// credentials, and retrying would be both pointless and misleading.
type SelfAuthenticator interface {
	SelfAuthenticating(path string) bool
}

// Transport sends one request against the configured base URL. earl hands it to
// an Auth so that login and logout reach the server exactly as every other
// command does - same base URL, timeout, redirect policy, limit, and
// User-Agent - without an Auth building a client of its own.
type Transport interface {
	Do(ctx context.Context, method, path string, body []byte, cred Credential) (*Response, error)
}

// Response is one answered request.
type Response struct {
	Status  int
	Header  http.Header
	Cookies []*http.Cookie
	Body    []byte
}

// OK reports whether the status is 2xx.
func (r *Response) OK() bool { return r.Status/100 == 2 }
