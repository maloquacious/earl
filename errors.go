// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// StatusError is a request that was answered with a non-2xx status.
//
// Body is carried raw rather than rendered, because whether it is indented
// depends on the stream it lands on (SPEC §8.3), which an error does not know.
type StatusError struct {
	Method string
	Path   string
	Status int
	Body   []byte
}

func (e *StatusError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s -> %d", e.Method, e.Path, e.Status)
	if text := http.StatusText(e.Status); text != "" {
		fmt.Fprintf(&b, " %s", text)
	}
	return b.String()
}

// TransportError is a request that got no answer at all.
type TransportError struct {
	Method string
	Path   string
	Err    error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Method, e.Path, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

// UsageError is a command line earl could not act on.
type UsageError struct{ Err error }

func (e *UsageError) Error() string { return e.Err.Error() }
func (e *UsageError) Unwrap() error { return e.Err }

func usagef(format string, args ...any) error {
	return &UsageError{Err: fmt.Errorf(format, args...)}
}

// ErrNoRenewal reports that an Auth cannot renew a credential. earl treats it
// as "nothing to try" rather than as a renewal failure, so a 401 is reported
// as itself instead of behind a misleading diagnostic.
var ErrNoRenewal = errors.New("no renewal mechanism configured")

// ExitCode maps an error to the process exit code required by SPEC §8.4:
//
//	0  success
//	1  usage, configuration, or local error
//	2  transport failure - the request did not get an answer
//	3  the request got an answer and it was not 2xx
func ExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case isType[*StatusError](err):
		return 3
	case isType[*TransportError](err):
		return 2
	default:
		return 1
	}
}

func isType[T error](err error) bool {
	_, ok := errors.AsType[T](err)
	return ok
}
