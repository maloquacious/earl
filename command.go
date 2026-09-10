// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/peterbourgon/ff/v4"
)

// defaultTimeout bounds a request. earl is interactive, and a hung command with
// no timeout is a command somebody kills with the wrong signal.
const defaultTimeout = 30 * time.Second

// rootValues holds the pointers the root flags write into. Construction is
// deferred to each Exec, so the pointers are authoritative by then.
type rootValues struct {
	baseURL  *string
	identity *string
	timeout  *time.Duration
	insecure *bool
	verbose  *bool
}

// build assembles the command tree and the arity table reordering needs. cfg
// must already have been normalized.
//
// The arity of every flag earl registers is stated here, at registration, so it
// cannot drift from the flag it describes (SPEC §5.4).
func build(cfg *Config) (*ff.Command, arity, error) {
	known := arity{}
	value := func(tokens ...string) {
		for _, t := range tokens {
			known[t] = true
		}
	}
	boolean := func(tokens ...string) {
		for _, t := range tokens {
			known[t] = false
		}
	}

	rootFlags := ff.NewFlagSet(cfg.Program)
	rv := &rootValues{
		baseURL:  rootFlags.StringLong("base-url", cfg.BaseURL, "API base URL"),
		identity: rootFlags.StringLong(cfg.IdentityName, "", "identity selecting the saved credential"),
		timeout:  rootFlags.DurationLong("timeout", defaultTimeout, "per-request timeout"),
		insecure: rootFlags.BoolLong("insecure", "skip TLS certificate verification"),
		verbose:  rootFlags.Bool('v', "verbose", "log request and response metadata to stderr"),
	}
	value("--base-url", "--"+cfg.IdentityName, "--timeout")
	boolean("--insecure", "--verbose", "-v")

	root := &ff.Command{
		Name:      cfg.Program,
		Usage:     cfg.Program + " [FLAGS] <COMMAND> ...",
		ShortHelp: "command-line client for the API at " + cfg.BaseURL,
		LongHelp: "The verb and path you would send are what you type:\n" +
			"\n" +
			"  " + cfg.Program + " get /session\n" +
			"  " + cfg.Program + " post /accounts -d '{\"email\":\"t@x.com\"}'\n" +
			"  " + cfg.Program + " patch /games/1 -d @game.json\n" +
			"\n" +
			"Paths are relative to --base-url. A credential captured by `" + cfg.Program + " login`\n" +
			"is saved per base URL and identity and attached automatically; --" + cfg.IdentityName + "\n" +
			"picks between several. Flags are fed by " + cfg.EnvPrefix + "_-prefixed environment\n" +
			"variables: --base-url by " + cfg.EnvPrefix + "_BASE_URL.",
		Flags: rootFlags,
	}

	// verb builds one method command: a positional PATH, an optional body, and
	// repeatable headers.
	//
	// -d is registered on every verb, including get and delete. Whether an
	// endpoint reads a body on those methods is the server's business, and a
	// client that refuses to send one cannot be used to find out.
	verb := func(name, method string) *ff.Command {
		fs := ff.NewFlagSet(name).SetParent(rootFlags)
		data := fs.String('d', "data", "", "request body: inline JSON, @file, or @- for stdin")
		headers := fs.StringList('H', "header", "extra request header, \"Name: value\"; repeatable")
		noAuth := fs.BoolLong("no-auth", "send without the saved credential, to exercise what an anonymous caller sees")
		value("-d", "--data", "-H", "--header")
		boolean("--no-auth")

		return &ff.Command{
			Name:      name,
			Usage:     cfg.Program + " " + name + " [FLAGS] PATH",
			ShortHelp: method + " the given API path",
			Flags:     fs,
			Exec: func(ctx context.Context, args []string) error {
				path, err := pathArg(name, args)
				if err != nil {
					return err
				}
				body, err := ReadValue(cfg.Stdin, *data)
				if err != nil {
					return &UsageError{Err: fmt.Errorf("%s: %w", name, err)}
				}
				c, err := newClient(cfg, rv)
				if err != nil {
					return err
				}
				return c.request(ctx, method, path, body, *headers, *noAuth)
			},
		}
	}

	loginFlags := ff.NewFlagSet("login").SetParent(rootFlags)
	loginSecret := loginFlags.StringLong("secret", "", "secret; @- reads stdin, @file reads a file, or set "+cfg.EnvPrefix+"_SECRET")
	value("--secret")
	login := &ff.Command{
		Name:      "login",
		Usage:     cfg.Program + " login [--" + cfg.IdentityName + " NAME] [--secret SECRET]",
		ShortHelp: "authenticate and save the credential for later commands",
		LongHelp: "A secret given on the command line is visible to anyone who can list\n" +
			"processes. Prefer " + cfg.EnvPrefix + "_SECRET, or --secret @- to read it from stdin.",
		Flags: loginFlags,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 0 {
				return usagef("login takes no positional arguments")
			}
			secret, err := readSecret(cfg.Stdin, *loginSecret)
			if err != nil {
				return &UsageError{Err: fmt.Errorf("login: %w", err)}
			}
			c, err := newClient(cfg, rv)
			if err != nil {
				return err
			}
			return c.login(ctx, secret)
		},
	}

	logout := &ff.Command{
		Name:      "logout",
		Usage:     cfg.Program + " logout [--" + cfg.IdentityName + " NAME]",
		ShortHelp: "revoke the saved credential and forget it",
		Flags:     ff.NewFlagSet("logout").SetParent(rootFlags),
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 0 {
				return usagef("logout takes no positional arguments")
			}
			c, err := newClient(cfg, rv)
			if err != nil {
				return err
			}
			return c.logout(ctx)
		},
	}

	identities := &ff.Command{
		Name:      "identities",
		Usage:     cfg.Program + " identities",
		ShortHelp: "list the credentials saved for this base URL",
		Flags:     ff.NewFlagSet("identities").SetParent(rootFlags),
		Exec: func(_ context.Context, args []string) error {
			if len(args) != 0 {
				return usagef("identities takes no positional arguments")
			}
			c, err := newClient(cfg, rv)
			if err != nil {
				return err
			}
			return c.identities()
		},
	}

	root.Subcommands = append(root.Subcommands,
		verb("get", http.MethodGet),
		verb("post", http.MethodPost),
		verb("put", http.MethodPut),
		verb("patch", http.MethodPatch),
		verb("delete", http.MethodDelete),
		login, logout, identities,
	)

	// whoami is the one convenience alias, and it is a verb request against
	// WhoamiPath and nothing else: the server decides what a session is, and an
	// answer assembled locally would not be evidence of anything.
	if cfg.WhoamiPath != "" {
		root.Subcommands = append(root.Subcommands, &ff.Command{
			Name:      "whoami",
			Usage:     cfg.Program + " whoami",
			ShortHelp: "show the current identity (GET " + cfg.WhoamiPath + ")",
			Flags:     ff.NewFlagSet("whoami").SetParent(rootFlags),
			Exec: func(ctx context.Context, args []string) error {
				if len(args) != 0 {
					return usagef("whoami takes no positional arguments")
				}
				c, err := newClient(cfg, rv)
				if err != nil {
					return err
				}
				return c.request(ctx, http.MethodGet, cfg.WhoamiPath, nil, nil, false)
			},
		})
	}

	if cfg.Version != "" {
		root.Subcommands = append(root.Subcommands, &ff.Command{
			Name:      "version",
			Usage:     cfg.Program + " version",
			ShortHelp: "print the build version",
			Flags:     ff.NewFlagSet("version").SetParent(rootFlags),
			Exec: func(_ context.Context, args []string) error {
				if len(args) != 0 {
					return usagef("version takes no positional arguments")
				}
				fmt.Fprintln(cfg.Stdout, cfg.Version)
				return nil
			},
		})
	}

	root.Subcommands = append(root.Subcommands, cfg.Extra...)

	a, err := deriveArity(root, known)
	if err != nil {
		return nil, nil, err
	}
	return root, a, nil
}

// pathArg returns the single PATH positional for a verb command, or an error
// naming the command.
func pathArg(cmd string, args []string) (string, error) {
	if len(args) != 1 {
		return "", usagef("%s requires exactly one PATH argument", cmd)
	}
	return args[0], nil
}
