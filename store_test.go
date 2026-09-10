// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// SPEC §13.5.
func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "credentials.json")
	want := Credential{Value: "v", Name: "n", Renew: "r", ExpiresAt: time.Now().UTC().Truncate(time.Second)}

	s := store{}
	s.put("http://a", "A@B.test", want)
	if err := saveStore(path, s); err != nil {
		t.Fatal(err)
	}

	back, err := loadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := back["http://a"]["a@b.test"]
	if got.Value != want.Value || got.Name != want.Name || got.Renew != want.Renew || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("got %+v, want %+v (identity should be lowercased)", got, want)
	}
}

func TestLoadMissingStoreIsEmpty(t *testing.T) {
	s, err := loadStore(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("a missing file must not be an error: %v", err)
	}
	if len(s) != 0 {
		t.Errorf("got %v, want an empty store", s)
	}
}

// A file that already existed keeps its old mode unless the write replaces it.
func TestSaveResetsAnOpenMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := store{}
	s.put("http://a", "a@b.test", Credential{Value: "v"})
	if err := saveStore(path, s); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600: a credential readable by every account on the machine is a published one", got)
	}
}

func TestStoreResolve(t *testing.T) {
	const base = "http://a"

	t.Run("explicit identity", func(t *testing.T) {
		s := store{}
		s.put(base, "one@b.test", Credential{Value: "1"})
		s.put(base, "two@b.test", Credential{Value: "2"})
		who, cred := s.resolve(base, "TWO@b.test")
		if who != "two@b.test" || cred.Value != "2" {
			t.Errorf("got %q/%q", who, cred.Value)
		}
	})

	t.Run("exactly one saved", func(t *testing.T) {
		s := store{}
		s.put(base, "only@b.test", Credential{Value: "1"})
		who, cred := s.resolve(base, "")
		if who != "only@b.test" || cred.Value != "1" {
			t.Errorf("got %q/%q", who, cred.Value)
		}
	})

	t.Run("ambiguous yields nothing", func(t *testing.T) {
		s := store{}
		s.put(base, "one@b.test", Credential{Value: "1"})
		s.put(base, "two@b.test", Credential{Value: "2"})
		if _, cred := s.resolve(base, ""); !cred.IsZero() {
			t.Errorf("got %q, want the zero credential", cred.Value)
		}
	})

	t.Run("none saved yields nothing", func(t *testing.T) {
		if _, cred := (store{}).resolve(base, ""); !cred.IsZero() {
			t.Error("want the zero credential")
		}
	})

	t.Run("another server is not consulted", func(t *testing.T) {
		s := store{}
		s.put("http://elsewhere", "one@b.test", Credential{Value: "1"})
		if _, cred := s.resolve(base, ""); !cred.IsZero() {
			t.Error("credentials must not leak between base URLs")
		}
	})
}

func TestStoreDropAndIdentities(t *testing.T) {
	const base = "http://a"
	s := store{}
	s.put(base, "b@x.test", Credential{Value: "2"})
	s.put(base, "a@x.test", Credential{Value: "1"})

	if got := s.identities(base); !slices.Equal(got, []string{"a@x.test", "b@x.test"}) {
		t.Errorf("identities = %q, want them sorted", got)
	}
	if !s.drop(base, "A@X.test") {
		t.Error("drop should report the removal")
	}
	if s.drop(base, "absent@x.test") {
		t.Error("dropping something absent should report nothing")
	}
	s.drop(base, "b@x.test")
	if _, ok := s[base]; ok {
		t.Error("the server entry should go with its last credential")
	}
}

// The <env> segment is what keeps a development run and a production run from
// ever sharing a credential.
func TestCredentialsPathIsScopedByEnvironment(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/config")
	t.Setenv("EARLTEST_CREDENTIALS", "")

	dev := &Config{EnvPrefix: "EARLTEST", StateDir: "earl", Env: "development"}
	prod := &Config{EnvPrefix: "EARLTEST", StateDir: "earl", Env: "production"}

	a, err := credentialsPath(dev)
	if err != nil {
		t.Fatal(err)
	}
	b, err := credentialsPath(prod)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("both environments resolved to %s", a)
	}
	if want := "/config/earl/development/credentials.json"; a != want {
		t.Errorf("got %s, want %s", a, want)
	}
}

func TestCredentialsPathOverride(t *testing.T) {
	t.Setenv("EARLTEST_CREDENTIALS", "/tmp/somewhere.json")
	got, err := credentialsPath(&Config{EnvPrefix: "EARLTEST", StateDir: "earl", Env: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/somewhere.json" {
		t.Errorf("got %s, want the override", got)
	}
}

// An environment that escaped its validation must not escape the config
// directory with it.
func TestConfigRejectsAnEnvironmentThatIsAPath(t *testing.T) {
	for _, env := range []string{"../../etc", "a/b", ".."} {
		cfg := Config{Program: "earl", EnvPrefix: "E", BaseURL: "http://x", Auth: basicAuth{}, Env: env}
		if err := cfg.normalize(); err == nil {
			t.Errorf("Env %q was accepted", env)
		}
	}
}
