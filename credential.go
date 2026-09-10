// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import "time"

// Credential is one saved authentication, whatever its scheme. Value is the
// live secret; everything else is metadata for attaching or renewing it.
//
// The zero Credential means "no credential": a request carrying it is sent
// anonymously and the server decides (SPEC §10.3).
type Credential struct {
	Value     string            `json:"value"`
	Name      string            `json:"name,omitempty"`  // cookie name, when the scheme has one
	Renew     string            `json:"renew,omitempty"` // refresh token, when the scheme has one
	ExpiresAt time.Time         `json:"expires_at,omitzero"`
	Extra     map[string]string `json:"extra,omitempty"` // scheme-specific, opaque to earl
}

// IsZero reports whether c holds no credential.
func (c Credential) IsZero() bool { return c.Value == "" }

// Expired reports whether c's recorded expiry has passed.
//
// It is advisory. earl never refuses to send an expired credential: clocks
// disagree, and the server is the authority on whether a credential is still
// good (SPEC §9.2). It labels identities output and nothing else.
func (c Credential) Expired() bool {
	return !c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt)
}
