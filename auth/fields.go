// Copyright (c) 2026 Michael D Henderson. All rights reserved.

// Package auth carries the credential schemes earl ships with: Bearer, for an
// API that authenticates with a token in a header, and Cookie, for one that
// authenticates with a session cookie.
//
// Both are configuration rather than code. What differs between APIs is the
// login path and the names of a handful of JSON fields, so both are described
// with a Fields value and neither needs a type per server.
//
// An API that authenticates some other way implements earl.Auth directly. That
// is the whole point of the interface; nothing here is privileged.
package auth

import (
	"encoding/json"
	"strings"
	"time"
)

// Fields names the JSON keys of a login exchange (SPEC §9.4).
//
// Request entries are plain keys. Response entries are dotted paths, so an
// enveloped body needs no code: "data.token" reaches into {"data":{"token":…}}.
type Fields struct {
	Identity string // request key for the identity:  "email", "username"
	Secret   string // request key for the secret:    "secret", "password"
	Token    string // response path to the credential: "token", "accessToken", "data.token"
	Renew    string // response path to the renewal credential: "refreshToken"
	Expires  string // response path to an RFC 3339 expiry: "expiresAt", "data.expires_at"
	TTL      string // response path to a lifetime in seconds: "expiresInSeconds"
}

func (f Fields) withDefaults() Fields {
	if f.Identity == "" {
		f.Identity = "email"
	}
	if f.Secret == "" {
		f.Secret = "password"
	}
	if f.Token == "" {
		f.Token = "token"
	}
	return f
}

// lookup walks a dotted path through a JSON document.
func lookup(body []byte, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	current := doc
	for segment := range strings.SplitSeq(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		if current, ok = object[segment]; !ok {
			return nil, false
		}
	}
	return current, true
}

// stringAt returns the string at a dotted path, or "" when it is absent or is
// not a string.
func stringAt(body []byte, path string) string {
	value, ok := lookup(body, path)
	if !ok {
		return ""
	}
	s, _ := value.(string)
	return s
}

// expiryFrom reads the credential's expiry, preferring an absolute timestamp
// over a lifetime when both are configured and present.
//
// A missing or unparseable expiry yields the zero time rather than an error: it
// is metadata, not the credential, and is not worth failing a login over.
func expiryFrom(body []byte, f Fields) time.Time {
	if f.Expires != "" {
		if s := stringAt(body, f.Expires); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t
			}
		}
	}
	if f.TTL != "" {
		if value, ok := lookup(body, f.TTL); ok {
			if seconds, ok := value.(float64); ok && seconds > 0 {
				return time.Now().Add(time.Duration(seconds) * time.Second)
			}
		}
	}
	return time.Time{}
}

// samePath compares two API paths ignoring a leading slash.
func samePath(a, b string) bool {
	if b == "" {
		return false
	}
	return strings.TrimLeft(a, "/") == strings.TrimLeft(b, "/")
}
