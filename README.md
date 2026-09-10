# earl

`earl` is a command-line client for a JSON HTTP API. The verb and path you would
send are what you type:

```sh
earl get /session
earl post /accounts -d '{"email":"t@x.com","secret":"hunter2hunter2"}'
earl patch /games/1 -d @game.json
earl put /me/password -d @- < body.json
```

It exists because `curl` does not know your API's auth model. Everything `earl`
adds over `curl` is that knowledge: it signs in, saves the credential, attaches
it to every request, renews it when the server rejects it, and forgets it on
sign-out.

Because it is a passthrough, it covers the whole API without per-endpoint code
and stays correct as endpoints are added. It opens no database, imports no
store, and knows no domain rules — which is what lets it be used as a test
harness. A client that reimplements the server's rules stops being evidence that
the server implements them.

[SPEC.md](SPEC.md) is normative.

## Using it

`earl` is a library plus a per-application `main`. The library owns the command
tree, transport, output, argument handling, and credential store; the
application supplies its defaults and one `Auth`:

```go
package main

import (
	"github.com/mdhender/earl"
	"github.com/mdhender/earl/auth"
)

func main() {
	earl.Main(earl.Config{
		Program:    "earl",
		Version:    version.String(),
		EnvPrefix:  "EARL",
		BaseURL:    "http://localhost:8080/api",
		WhoamiPath: "/me",
		Env:        env, // resolved and validated before this call
		Auth: auth.NewBearer(auth.Bearer{
			LoginPath:  "/auth/login",
			LogoutPath: "/auth/logout",
			Fields: auth.Fields{
				Identity: "email", Secret: "secret",
				Token: "token", Expires: "expiresAt",
			},
		}),
	})
}
```

That is the entire integration. There is no stock binary: what differs per API
is the login exchange, and making it a compile-time seam means a mismatch is a
build failure rather than a runtime message.

## Commands

| Command | |
| --- | --- |
| `get`, `post`, `put`, `patch`, `delete` | one positional `PATH`, `-d` body, `-H` headers, `--no-auth` |
| `login` | authenticate and save the credential |
| `logout` | revoke it and forget it |
| `whoami` | `get <WhoamiPath>`, and nothing else |
| `identities` | what is saved for this base URL |
| `version` | the build version |

Bodies and secrets resolve the same three ways: inline, `@file`, or `@-` for
stdin. The sigil is required — a mistyped path is an error, not a literal body.

## Auth schemes

`auth.NewBearer` for a token in a header, with optional renewal on 401.
`auth.NewCookie` for a session cookie captured from `Set-Cookie` at login.
Anything else implements `earl.Auth` directly; nothing in `auth` is privileged.

## Behaviour worth knowing

- **stdout is the response.** A 2xx writes the body there and nothing else.
  Everything earl says about itself goes to stderr, so `earl get /x | jq` works.
- **Indented for a terminal, raw for a pipe.** Non-JSON passes through either
  way.
- **Exit codes:** `0` 2xx · `1` usage or local error · `2` no answer ·
  `3` an answer that was not 2xx. A runner that exits 0 on a 500 cannot fail a
  build.
- **Redirects are not followed.** A 302 is reported, not chased.
- **A credential is never printed.** Not at any verbosity. There is a test whose
  only job is to keep that true.
- **Credentials live in** `$XDG_CONFIG_HOME/<StateDir>/<Env>/credentials.json`,
  mode 0600, keyed by base URL and identity so one file can hold several
  accounts. `<Env>` keeps development and production from ever sharing one.

## Development

```sh
go test ./...          # includes the SPEC §13 conformance tests
go test -race ./...
```

`appendix_test.go` drives the three implementations catalogued in
[others.md](others.md) — ecv4, ecv6, ecv8 — end to end as `Config` values, which
is what keeps SPEC Appendix A.1 honest.
