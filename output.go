// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

// formatJSON indents body when pretty is set and the bytes are valid JSON, and
// otherwise returns them unchanged (SPEC §8.3). Anything that is not JSON
// passes through in both cases, because a client that mangles what it does not
// recognize cannot be used to find out what the server sent.
func formatJSON(body []byte, pretty bool) string {
	if !pretty || !json.Valid(body) {
		return string(body)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, body, "", "  "); err != nil {
		return string(body)
	}
	return buf.String()
}

// isTerminal reports whether w is a character device, which is what decides
// indented against raw output. Anything that is not an *os.File - a test
// buffer, a pipe into jq - is not a terminal.
func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
