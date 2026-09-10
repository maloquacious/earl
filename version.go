// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"github.com/maloquacious/semver"
)

var (
	version = semver.Version{
		Major: 0,
		Minor: 1,
		Patch: 0,
		Build: semver.Commit(),
	}
)

// Version reports this module's version.
//
// Build carries the commit the binary was built from, read from the build
// information the Go toolchain embeds, so it is present in an installed binary
// and empty under `go run` or `go test`.
//
// An application wires it into its own Config, where it names the binary in the
// User-Agent and answers the version command:
//
//	earl.Main(earl.Config{Version: earl.Version().String(), ...})
func Version() semver.Version {
	return version
}
