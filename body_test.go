// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SPEC §13.2.
func TestReadValue(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "body.json")
	if err := os.WriteFile(file, []byte(`{"from":"file"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("empty is no body", func(t *testing.T) {
		got, err := ReadValue(strings.NewReader(""), "")
		if err != nil || got != nil {
			t.Fatalf("got %q, %v; want nil, nil", got, err)
		}
	})

	t.Run("literal", func(t *testing.T) {
		got, err := ReadValue(strings.NewReader(""), `{"k":"v"}`)
		if err != nil || string(got) != `{"k":"v"}` {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("file", func(t *testing.T) {
		got, err := ReadValue(strings.NewReader(""), "@"+file)
		if err != nil || string(got) != `{"from":"file"}` {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("stdin", func(t *testing.T) {
		got, err := ReadValue(strings.NewReader(`{"from":"stdin"}`), "@-")
		if err != nil || string(got) != `{"from":"stdin"}` {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	// The whole reason the sigil is required: ecv4 stat'd the argument, so a
	// mistyped path became a literal body and the server answered with a
	// confusing 4xx instead of earl answering with the real problem.
	t.Run("missing file is an error, not a literal body", func(t *testing.T) {
		got, err := ReadValue(strings.NewReader(""), "@"+filepath.Join(dir, "absent.json"))
		if err == nil {
			t.Fatalf("want an error, got body %q", got)
		}
	})

	// A path that exists is still a literal body without the sigil.
	t.Run("no sigil means literal even when the file exists", func(t *testing.T) {
		got, err := ReadValue(strings.NewReader(""), file)
		if err != nil || string(got) != file {
			t.Fatalf("got %q, %v; want the path itself", got, err)
		}
	})
}

func TestReadSecretTrimsLineEndings(t *testing.T) {
	got, err := readSecret(strings.NewReader("hunter2\r\n"), "@-")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

// A body is never trimmed: the bytes are the point.
func TestReadValueDoesNotTrimBody(t *testing.T) {
	got, err := ReadValue(strings.NewReader("{}\n"), "@-")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{}\n" {
		t.Errorf("got %q, want the bytes unchanged", got)
	}
}
