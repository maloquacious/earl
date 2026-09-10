// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"context"
	"slices"
	"testing"

	"github.com/peterbourgon/ff/v4"
)

// SPEC §13.1. Arity is derived from the tree, so this exercises the derivation
// against a real tree rather than guarding a hand-maintained list.
func TestDeriveArityFromTree(t *testing.T) {
	_, a, err := buildTree(t, testConfig(t, "http://example.test"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	want := map[string]bool{
		"--base-url": true, "--email": true, "--timeout": true, "--secret": true,
		"-d": true, "--data": true, "-H": true, "--header": true,
		"--insecure": false, "--verbose": false, "-v": false, "--no-auth": false,
	}
	for token, takesValue := range want {
		got, ok := a[token]
		if !ok {
			t.Errorf("arity has no entry for %s", token)
			continue
		}
		if got != takesValue {
			t.Errorf("arity[%s] = %v, want %v", token, got, takesValue)
		}
	}
}

// An extension flag is discovered through ff, not declared to earl.
func TestDeriveArityFromExtension(t *testing.T) {
	fs := ff.NewFlagSet("impersonate")
	fs.StringLong("as-account", "", "account to impersonate")
	fs.BoolLong("dry-run", "do not save the credential")

	cfg := testConfig(t, "http://example.test")
	cfg.Extra = []*ff.Command{{
		Name:  "impersonate",
		Flags: fs,
		Exec:  func(context.Context, []string) error { return nil },
	}}

	_, a, err := buildTree(t, cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !a["--as-account"] {
		t.Error("--as-account should take a value")
	}
	if a["--dry-run"] {
		t.Error("--dry-run should not take a value")
	}
}

// A flag name that means two different things in one tree is refused at
// construction rather than mis-parsed at run time.
func TestDeriveArityConflict(t *testing.T) {
	fs := ff.NewFlagSet("odd")
	fs.BoolLong("data", "not the same --data at all")

	cfg := testConfig(t, "http://example.test")
	cfg.Extra = []*ff.Command{{
		Name:  "odd",
		Flags: fs,
		Exec:  func(context.Context, []string) error { return nil },
	}}

	if _, _, err := buildTree(t, cfg); err == nil {
		t.Fatal("want an arity conflict error, got nil")
	}
}

func TestReorder(t *testing.T) {
	a := arity{
		"-d": true, "--data": true, "-H": true, "--header": true,
		"--base-url": true, "--email": true,
		"--no-auth": false, "-v": false, "--verbose": false,
	}

	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "flag after path is hoisted",
			in:   []string{"post", "/accounts", "-d", `{"k":"v"}`},
			want: []string{"post", "-d", `{"k":"v"}`, "/accounts"},
		},
		{
			name: "root flags keep their place before the subcommand",
			in:   []string{"--base-url", "http://x", "get", "/me", "--no-auth"},
			want: []string{"--base-url", "http://x", "get", "--no-auth", "/me"},
		},
		{
			name: "several flags and a path",
			in:   []string{"post", "/p", "-d", "@f", "--no-auth", "-H", "X: 1"},
			want: []string{"post", "-d", "@f", "--no-auth", "-H", "X: 1", "/p"},
		},
		{
			name: "equals form consumes nothing further",
			in:   []string{"post", "/p", `--data={"k":"v"}`},
			want: []string{"post", `--data={"k":"v"}`, "/p"},
		},
		{
			name: "a bare dash is a positional",
			in:   []string{"post", "-d", "@-", "-"},
			want: []string{"post", "-d", "@-", "-"},
		},
		{
			name: "double dash ends flag processing",
			in:   []string{"get", "--", "-weird-path", "-d"},
			want: []string{"get", "--", "-weird-path", "-d"},
		},
		{
			name: "double dash in the root section is copied verbatim",
			in:   []string{"--", "get", "/me", "-d", "x"},
			want: []string{"--", "get", "/me", "-d", "x"},
		},
		{
			name: "short cluster takes a value only on its last rune",
			in:   []string{"get", "/me", "-vd", "body"},
			want: []string{"get", "-vd", "body", "/me"},
		},
		{
			name: "already ordered is unchanged",
			in:   []string{"get", "--no-auth", "/me"},
			want: []string{"get", "--no-auth", "/me"},
		},
		{
			name: "empty",
			in:   []string{},
			want: []string{},
		},
		{
			name: "a value that looks like a path is not mistaken for one",
			in:   []string{"post", "-d", "/not/a/path", "/real/path"},
			want: []string{"post", "-d", "/not/a/path", "/real/path"},
		},
		{
			name: "a trailing value flag with no value does not run off the end",
			in:   []string{"post", "/p", "-d"},
			want: []string{"post", "-d", "/p"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := reorder(tc.in, a)
			if !slices.Equal(got, tc.want) {
				t.Errorf("reorder(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// buildTree normalizes a Config and builds its command tree. build requires a
// normalized Config; Run is what normally does that.
func buildTree(t *testing.T, cfg Config) (*ff.Command, arity, error) {
	t.Helper()
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return build(&cfg)
}
