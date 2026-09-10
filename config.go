// Copyright (c) 2026 Michael D Henderson. All rights reserved.

// Package earl is a command-line client for a JSON HTTP API. The verb and path
// you would send are what you type:
//
//	earl get /session
//	earl post /accounts -d '{"email":"t@x.com","secret":"hunter2hunter2"}'
//	earl patch /games/1 -d @game.json
//	earl put /me/password -d @- < body.json
//
// It exists because curl does not know your API's auth model. Everything earl
// adds over curl is that knowledge: it signs in, saves the credential, attaches
// it to every request, renews it when the server rejects it, and forgets it on
// sign-out.
//
// Because it is a passthrough it covers the whole API without per-endpoint code
// and stays correct as endpoints are added. This package opens no database,
// imports no store, and knows no domain rules; anything it appears to know
// about an application is the shape of a JSON body passing through.
//
// An application supplies its defaults and one Auth implementation:
//
//	func main() {
//		earl.Main(earl.Config{
//			Program:    "earl",
//			Version:    version.String(),
//			EnvPrefix:  "EARL",
//			BaseURL:    "http://localhost:8080/api",
//			WhoamiPath: "/me",
//			Env:        env,
//			Auth: auth.NewBearer(auth.Bearer{
//				LoginPath:  "/auth/login",
//				LogoutPath: "/auth/logout",
//				Fields: auth.Fields{
//					Identity: "email", Secret: "secret",
//					Token: "token", Expires: "expiresAt",
//				},
//			}),
//		})
//	}
//
// SPEC.md is normative; doc comments cite its sections.
package earl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

// Config is everything earl needs that it cannot work out for itself.
type Config struct {
	// Program is the binary's name, used in usage text and diagnostics and as
	// the default StateDir. Required.
	Program string

	// Version is printed by the version command. When empty, no version
	// command is registered.
	Version string

	// EnvPrefix prefixes every environment variable earl reads, so --base-url
	// is fed by <EnvPrefix>_BASE_URL. Required.
	//
	// It should not be the server's own prefix: pointing a client at another
	// host must not mean editing, or risk disturbing, the variables a server
	// reads. It should be shared between sibling clients meant to share a
	// credential file, because credentials are keyed by base URL - two clients
	// reading two different variables can be pointed at two different servers,
	// and the shared file would quietly stop being shared.
	EnvPrefix string

	// StateDir is the directory name under the user config root. Defaults to
	// Program. It names the project, not a command, when several commands
	// share one credential file.
	StateDir string

	// BaseURL is the default for --base-url. Required.
	BaseURL string

	// APIPath is appended to a --base-url carrying no path, so that
	// https://host and https://host/api/v1 address the same endpoint.
	APIPath string

	// IdentityName names the flag and environment variable that select a saved
	// identity: "email" gives --email and <EnvPrefix>_EMAIL. Defaults to
	// "email".
	IdentityName string

	// WhoamiPath is the path the whoami command requests. When empty, no
	// whoami command is registered.
	WhoamiPath string

	// Auth obtains, attaches, and revokes the credential. Required.
	Auth Auth

	// ReloginOnExpiry allows a full re-login, using the configured identity and
	// secret, when a 401 cannot be resolved by renewal. Off by default: it
	// requires a usable secret in the environment of every invocation, which is
	// a choice an application makes deliberately.
	ReloginOnExpiry bool

	// Env scopes the credential file and is resolved by the application before
	// flags are parsed. Required, and required to be validated against a closed
	// set by the application - that validation is what lets earl use it as a
	// path segment without further checking.
	Env string

	// Extra registers application subcommands (SPEC §11). It is for operations
	// that are not a request an operator can type; a typed wrapper around an
	// endpoint a verb could already reach does not belong here.
	Extra []*ff.Command

	// Stdin, Stdout, and Stderr default to the process's own. They are
	// injectable so tests can drive and capture a whole run.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

const defaultIdentityName = "email"

// normalize fills in defaults and rejects a Config the program got wrong.
//
// It validates only what the application supplies in code. --base-url is not
// checked here: a --help request must not be refused for a base URL it would
// never use (SPEC §6.2), so that check belongs where the client is built.
func (cfg *Config) normalize() error {
	cfg.Program = strings.TrimSpace(cfg.Program)
	cfg.EnvPrefix = strings.TrimSpace(cfg.EnvPrefix)
	cfg.Env = strings.TrimSpace(cfg.Env)

	switch {
	case cfg.Program == "":
		return errors.New("earl: Config.Program is required")
	case cfg.EnvPrefix == "":
		return errors.New("earl: Config.EnvPrefix is required")
	case cfg.BaseURL == "":
		return errors.New("earl: Config.BaseURL is required")
	case cfg.Auth == nil:
		return errors.New("earl: Config.Auth is required")
	case cfg.Env == "":
		return errors.New("earl: Config.Env is required")
	}

	// Env becomes a path segment. The application is required to have
	// validated it against a closed set; this is the cheap guard that keeps a
	// missed validation from escaping the config directory.
	if strings.ContainsAny(cfg.Env, `/\`) || cfg.Env == "." || cfg.Env == ".." {
		return fmt.Errorf("earl: Config.Env %q is not usable as a path segment", cfg.Env)
	}

	cfg.StateDir = cmpOr(cfg.StateDir, cfg.Program)
	cfg.IdentityName = cmpOr(cfg.IdentityName, defaultIdentityName)
	if cfg.Stdin == nil {
		cfg.Stdin = os.Stdin
	}
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	return nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Main runs one command line and exits with the code from SPEC §8.4.
func Main(cfg Config) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := Run(ctx, cfg, os.Args[1:])
	stop()
	os.Exit(ExitCode(err))
}

// Run executes one command line and returns its error, after rendering it to
// cfg.Stderr. It never calls os.Exit, so tests can call it directly.
func Run(ctx context.Context, cfg Config, args []string) error {
	if err := cfg.normalize(); err != nil {
		// A malformed Config is a programming error, not a user error, so it
		// is reported before there is anywhere configured to report it to.
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	root, arity, err := build(&cfg)
	if err != nil {
		return cfg.report(err)
	}

	parseErr := root.Parse(reorder(args, arity), ff.WithEnvVarPrefix(cfg.EnvPrefix))
	selected := root.GetSelected()
	if selected == nil {
		selected = root
	}

	switch {
	case parseErr == nil:
	case errors.Is(parseErr, ff.ErrHelp):
		// Help is what a caller reaches for when they do not yet know what to
		// write, so it succeeds whatever else is wrong.
		fmt.Fprint(cfg.Stderr, ffhelp.Command(selected))
		return nil
	default:
		fmt.Fprint(cfg.Stderr, ffhelp.Command(selected))
		return cfg.report(&UsageError{Err: parseErr})
	}

	if selected.Exec == nil {
		fmt.Fprint(cfg.Stderr, ffhelp.Command(selected))
		if extra := selected.Flags.GetArgs(); len(extra) != 0 {
			return cfg.report(usagef("unknown command %q", extra[0]))
		}
		return cfg.report(usagef("no command given"))
	}
	return cfg.report(root.Run(ctx))
}

// report renders err per SPEC §8.2 and §12 and returns it unchanged.
func (cfg *Config) report(err error) error {
	if err == nil {
		return nil
	}
	if status, ok := errors.AsType[*StatusError](err); ok {
		fmt.Fprintf(cfg.Stderr, "%s: %s\n", cfg.Program, status.Error())
		if len(status.Body) > 0 {
			fmt.Fprintln(cfg.Stderr, strings.TrimRight(formatJSON(status.Body, isTerminal(cfg.Stderr)), "\n"))
		}
		return err
	}
	fmt.Fprintf(cfg.Stderr, "%s: %v\n", cfg.Program, err)
	return err
}
