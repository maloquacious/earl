// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// store maps a base URL to the credentials saved against it, keyed by
// lowercased identity (SPEC §10.2).
//
// Keying by identity is what lets one file hold several accounts against one
// server at once - an administrator and an ordinary user, say - with the
// identity flag selecting between them.
type store map[string]map[string]Credential

const (
	credentialsFile = "credentials.json"
	dirMode         = 0o700
	fileMode        = 0o600
)

// credentialsPath returns the file the credentials live in (SPEC §10.1).
//
// It deliberately does not use os.UserConfigDir, which resolves to
// ~/Library/Application Support on macOS. This is a file a person edits,
// inspects, and deletes; it belongs where the rest of their tooling keeps
// state.
func credentialsPath(cfg *Config) (string, error) {
	if p := os.Getenv(cfg.EnvPrefix + "_CREDENTIALS"); p != "" {
		return p, nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, cfg.StateDir, cfg.Env, credentialsFile), nil
}

// loadStore reads the credential store. A missing file is not an error - it
// yields an empty store, so the first login has somewhere to write.
func loadStore(path string) (store, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	s := store{}
	if len(data) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return s, nil
}

// saveStore writes the store to path (SPEC §10.4).
//
// A saved value is a live credential: anyone holding it is signed in as that
// account until it expires, so the file permissions are load-bearing. The write
// goes to a temporary file and is renamed, so an interrupted write cannot leave
// a truncated credential file - and so a file that already existed with a
// looser mode is replaced rather than reused.
func saveStore(path string, s store) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".credentials-*.json")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op once the rename has succeeded

	if err := tmp.Chmod(fileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temporary credential file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary credential file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary credential file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// put records cred for (baseURL, identity), replacing whatever was there.
func (s store) put(baseURL, identity string, cred Credential) {
	perServer := s[baseURL]
	if perServer == nil {
		perServer = map[string]Credential{}
		s[baseURL] = perServer
	}
	perServer[strings.ToLower(identity)] = cred
}

// drop removes the credential for (baseURL, identity), and the server entry
// when it was the last one.
func (s store) drop(baseURL, identity string) bool {
	perServer := s[baseURL]
	if perServer == nil {
		return false
	}
	key := strings.ToLower(identity)
	if _, ok := perServer[key]; !ok {
		return false
	}
	delete(perServer, key)
	if len(perServer) == 0 {
		delete(s, baseURL)
	}
	return true
}

// identities returns the identities saved for baseURL, sorted so that
// successive runs are diffable.
func (s store) identities(baseURL string) []string {
	return slices.Sorted(maps.Keys(s[baseURL]))
}

// resolve picks the credential to use against baseURL (SPEC §10.3):
//
//  1. an explicit identity selects that entry, and only that entry;
//  2. with no identity and exactly one saved entry, that entry;
//  3. otherwise - none saved, or several and no identity - the zero Credential.
//
// It never errors. A verb request with no usable credential is sent
// anonymously and the server decides: public routes succeed, protected ones
// return 401. That is what makes --no-auth unnecessary for bootstrapping.
func (s store) resolve(baseURL, identity string) (string, Credential) {
	perServer := s[baseURL]
	if len(perServer) == 0 {
		return "", Credential{}
	}
	if identity != "" {
		key := strings.ToLower(identity)
		return key, perServer[key]
	}
	if len(perServer) == 1 {
		for who, cred := range perServer {
			return who, cred
		}
	}
	return "", Credential{}
}
