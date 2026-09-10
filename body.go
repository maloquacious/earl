// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadValue resolves an indirect flag value into bytes (SPEC §7.4):
//
//	""       no value
//	@-       read stdin
//	@name    read the file name
//	other    the literal bytes
//
// The sigil is required. Auto-detecting a file by stat, as ecv4 did, sends a
// mistyped path to the server as a literal body and answers with a confusing
// 4xx; a missing @file is an error here instead.
//
// The indirection matters for a secret as much as for a body: @- keeps it out
// of the command line, where anyone who can list processes would see it, and
// out of the shell history.
func ReadValue(stdin io.Reader, value string) ([]byte, error) {
	switch {
	case value == "":
		return nil, nil
	case value == "@-":
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read from stdin: %w", err)
		}
		return data, nil
	case strings.HasPrefix(value, "@"):
		name := value[1:]
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		return data, nil
	default:
		return []byte(value), nil
	}
}

// readSecret is ReadValue with trailing newlines trimmed, because a secret
// typed into a file or echoed down a pipe picks up a line ending that is not
// part of it. A body is never trimmed: the bytes are the point.
func readSecret(stdin io.Reader, value string) (string, error) {
	data, err := ReadValue(stdin, value)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimRight(data, "\r\n")), nil
}
