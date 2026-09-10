# earl — Specification

**Status:** accepted
**Version:** 1.0
**Accepted:** 2026-09-10
**Module:** `github.com/mdhender/earl`
**Go:** 1.26

---

## 1. Purpose

`earl` is a command-line client for a JSON HTTP API. The verb and path you would
send are what you type:

```
earl get /session
earl post /accounts -d '{"email":"t@x.com","secret":"hunter2hunter2"}'
earl patch /games/1 -d @game.json
earl put /me/password -d @- < body.json
```

It exists because `curl` does not know your API's auth model. Everything `earl`
adds over `curl` is that knowledge: it signs in, saves the credential, attaches
it to every request, renews it when the server rejects it, and forgets it on
sign-out.

Because it is a passthrough, `earl` covers the entire API without per-endpoint
code and stays correct as endpoints are added. This is the property to defend.
A client that grows a typed command per endpoint has to be updated whenever the
server changes, and when it is used as a test harness it stops being evidence
that the server implements its own rules — it starts reimplementing them.

## 2. Non-goals

`earl` **MUST NOT**:

- open a database, import a server's store packages, or link a server's route
  constants;
- know any application's domain rules;
- interpret a response beyond what §8 requires (status class, JSON validity)
  and what an `Auth` implementation extracts from a login response;
- provide a typed subcommand per endpoint. Applications that want one **SHOULD**
  build a separate command; §11 covers the narrow exception.

Explicitly deferred, with rationale, in Appendix B.

## 3. Conformance language

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used per RFC 2119. Requirements
apply to a conforming implementation of this module unless attributed to an
embedding application.

## 4. Architecture

`earl` is a Go library plus a per-application `main`. The library owns the
command tree, transport, output, argument handling, and credential store. The
application supplies its defaults and one `Auth` implementation.

```
github.com/mdhender/earl            command tree, transport, store, Auth contract
github.com/mdhender/earl/auth       Bearer, Cookie
<app>/cmd/earl                      ~40 lines: Config literal, earl.Main
```

The application binary is the whole integration point:

```go
func main() {
	earl.Main(earl.Config{
		Program:   "earl",
		Version:   version.Version.String(),
		EnvPrefix: "EARL",
		BaseURL:   "http://localhost:8080/api",
		WhoamiPath: "/me",
		Auth: auth.NewBearer(auth.Bearer{
			LoginPath:  "/auth/login",
			LogoutPath: "/auth/logout",
			Fields: auth.Fields{
				Identity: "email",
				Secret:   "secret",
				Token:    "token",
				Expires:  "expiresAt",
			},
		}),
		Extra: []*ff.Command{impersonateCmd()},
	})
}
```

Auth is a compile-time seam rather than a configuration file because the login
request and response shapes differ per API in ways a schema would have to model
anyway, and because a mismatch should be a build failure rather than a runtime
error message. Appendix B records what a file-driven strategy would need if that
trade is ever revisited.

## 5. Command-line surface

### 5.1 Grammar

```
<program> [GLOBAL FLAGS] <command> [FLAGS] [ARGS]
```

### 5.2 Verb commands

An implementation **MUST** register one command per method: `get`, `post`,
`put`, `patch`, `delete`.

```
<program> get    [FLAGS] PATH
<program> post   [FLAGS] PATH
<program> put    [FLAGS] PATH
<program> patch  [FLAGS] PATH
<program> delete [FLAGS] PATH
```

Each takes exactly one positional `PATH`. Zero or two or more **MUST** be a
usage error naming the command.

Flags on every verb command:

| Flag | Type | Meaning |
| --- | --- | --- |
| `-d`, `--data` | value | request body; see §7.4 |
| `-H`, `--header` | value, repeatable | extra request header, `Name: value` |
| `--no-auth` | bool | send anonymously, to exercise what an unauthenticated caller sees |

`-d` **MUST** be accepted by `post`, `put`, and `patch`. It **MUST** be accepted
by `get` and `delete` as well: whether an endpoint reads a body on those methods
is the server's business, and a client that refuses to send one cannot be used
to find out. (This differs from ecv8, which omitted `-d` on `delete` because no
endpoint then used it. A generic runner does not get to make that call.)

### 5.3 Session commands

| Command | Registered when | Behaviour |
| --- | --- | --- |
| `login` | always | §9.1, §10 |
| `logout` | always | §9.1, §10 |
| `whoami` | `Config.WhoamiPath != ""` | exactly `get <WhoamiPath>`, nothing else |
| `identities` | always | §10.5 |
| `version` | `Config.Version != ""` | prints the version, exits 0 |

`login` **MUST** accept `--identity` (see §6.2 for the name) and `--secret`, and
**MUST** take no positional arguments. `--secret` **MUST** accept the same
`@file` / `@-` indirection as `-d` (§7.4), so a secret need never appear in the
process table or the shell history.

`whoami` is the only convenience alias permitted, and it **MUST** be implemented
as a verb request against `WhoamiPath`. An answer assembled locally from the
saved credential would not be evidence of anything.

### 5.4 Argument reordering

`ff`, like the standard `flag` package, stops parsing flags at the first
positional argument. Without intervention `post /accounts -d '{…}'` treats `-d`
as a stray argument.

An implementation **MUST** rewrite `os.Args` before parsing so that each
subcommand's flags precede its positional arguments. The rewrite:

1. copies leading root flags — and the values they consume — through unchanged,
   up to and including the first positional, which is the subcommand name (`ff`
   routes on it, so it **MUST** stay first);
2. partitions the remaining tokens into flags (each with any value it consumes)
   and positionals, and emits flags first;
3. treats a literal `--` as ending flag processing, matching `ff`, and copies it
   and everything after it verbatim;
4. treats a bare `-` as a positional.

**Flag arity MUST be derived from the command tree, never from a hand-maintained
list.** ecv6 and ecv8 both carry a literal `valueFlags` map that must be kept in
step with the flags by hand, and both need a test whose only job is to catch the
drift. An implementation **MUST** instead build the arity set by walking the
root flag set and every subcommand's flag set with `ff.Flags.WalkFlags`,
recording each flag's short and long spellings.

`ff` v4.0.0-beta.1 does not expose bool-ness on the exported `Flag` interface
(`isBoolFlag` is unexported on `coreFlag`), so arity **MUST** be determined as:

- for flags the library registers, by construction — the library knows which of
  its own flags take values;
- for flags on `Config.Extra` commands, by `Flag.GetPlaceholder() == ""`, which
  `ff` returns only for a bool flag defaulting to false.

Two consequences are normative:

- A flag name **MUST** have the same arity everywhere it appears in one command
  tree. Reordering runs before the subcommand is known, so the arity set is a
  union over the whole tree.
- An extension flag that takes a value **MUST** have a non-empty placeholder.
  `ff` supplies one automatically from the value's type; an extension **MUST
  NOT** suppress it.

A conforming implementation **SHOULD** fail at tree-construction time on an
arity conflict, rather than mis-parsing at run time.

## 6. Configuration

### 6.1 Config

```go
type Config struct {
	// Program is the binary's name, used in usage text and as the default
	// StateDir. Required.
	Program string

	// Version is printed by the version command. When empty, no version
	// command is registered.
	Version string

	// EnvPrefix prefixes every environment variable earl reads, so that
	// --base-url is fed by <EnvPrefix>_BASE_URL. Required.
	//
	// It SHOULD NOT be the server's own prefix. Pointing a client at another
	// host must not mean editing, or risk disturbing, the variables a server
	// reads. It SHOULD be shared between sibling clients that are meant to
	// share a credential file, because credentials are keyed by base URL:
	// two clients reading two different variables can be pointed at two
	// different servers, and the shared file would quietly stop being shared.
	EnvPrefix string

	// StateDir is the directory name under the user config root. Defaults to
	// Program. It names the project, not a command, when several commands
	// share one credential file.
	StateDir string

	// BaseURL is the default for --base-url. Required.
	BaseURL string

	// APIPath is appended to a --base-url that carries no path, so that
	// https://host and https://host/api/v1 address the same endpoint.
	APIPath string

	// IdentityName names the flag and environment variable that select a
	// saved identity: "email" gives --email and <EnvPrefix>_EMAIL. Defaults
	// to "email".
	IdentityName string

	// WhoamiPath is the path the whoami command requests. When empty, no
	// whoami command is registered.
	WhoamiPath string

	// Auth obtains, attaches, and revokes the credential. Required.
	Auth Auth

	// ReloginOnExpiry allows a full re-login, using the configured identity
	// and secret, when a 401 cannot be resolved by renewal. Off by default:
	// it requires a secret to be sitting in the environment, which is a
	// choice an application makes deliberately.
	ReloginOnExpiry bool

	// Env scopes the credential file and is resolved before flags are
	// parsed. Required.
	Env string

	// Extra registers application subcommands. See §11.
	Extra []*ff.Command

	// Stdin, Stdout, and Stderr default to the process's own. They are
	// injectable so that tests can drive and capture a whole run.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// Main resolves configuration, runs the command, and exits with the code
// from §8.4.
func Main(cfg Config)

// Run executes one command line and returns its error. It never calls
// os.Exit, so tests can call it directly.
func Run(ctx context.Context, cfg Config, args []string) error
```

`Main` **MUST** install a signal handler that cancels the context on `SIGINT`
and `SIGTERM`.

### 6.2 Flags and environment variables

Every flag **MUST** be fed by `<EnvPrefix>_<FLAG>` with hyphens as underscores.

Root flags, inherited by every subcommand:

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--base-url` | `_BASE_URL` | `Config.BaseURL` | API root |
| `--<IdentityName>` | `_<IDENTITYNAME>` | *(none)* | selects among saved identities |
| `--timeout` | `_TIMEOUT` | `30s` | per-request timeout |
| `--insecure` | `_INSECURE` | false | skip TLS verification |
| `-v`, `--verbose` | `_VERBOSE` | false | log request and response metadata to stderr |

`login` additionally reads `--secret` / `<EnvPrefix>_SECRET`.

A `--help` request **MUST** succeed regardless of configuration validity. A
malformed `--base-url` **MUST NOT** turn `--help` into an error, because help is
how a caller finds out what to write instead.

### 6.3 Environment resolution

`<EnvPrefix>_ENV` (or an application's own project-wide variable) selects the
runtime environment. It **MUST** be read from the process environment before any
flag is parsed, because it selects the dotenv files that populate the
environment `ff` then reads, and because it becomes a path segment in the
credential file.

An application **MUST** validate it against a closed set before passing it as
`Config.Env`. That validation is what lets `earl` use it as a path segment
without further checking. An unset value **SHOULD** resolve to a development
default.

Dotenv loading is the application's responsibility and happens before
`earl.Main`.

### 6.4 Precedence

Highest to lowest: command-line flag, environment variable, dotenv file,
`Config` default.

## 7. Requests

### 7.1 Base URL

`--base-url` **MUST** be parsed and validated. It **MUST** have a scheme and a
host. When it carries no path and `Config.APIPath` is set, the API path **MUST**
be appended, so these address the same endpoint:

```
--base-url https://ec.example.com
--base-url https://ec.example.com/api/v1
```

A trailing slash **MUST** be trimmed.

### 7.2 Path joining

The request URL **MUST** be the base URL and the given path joined with exactly
one slash between them. The path is used verbatim, including any query string,
so `earl get '/games?status=active'` works and quoting is the caller's business.

The path **MUST NOT** be escaped or normalized. A client that rewrites a path
cannot be used to find out what the server does with an odd one.

### 7.3 Headers

An implementation **MUST** set:

- `Accept: application/json`
- `Content-Type: application/json`, when and only when there is a body
- `User-Agent: <Program>/<Version>`
- the credential header, via `Auth.Attach`, unless `--no-auth`

`-H` values **MUST** be applied last and **MUST** be able to override any of the
above. A `-H` with an empty value (`-H 'Accept:'`) **MUST** remove the header.

### 7.4 Body resolution

`-d`, and any other flag documented as taking an indirect value (`--secret`),
**MUST** resolve as:

| Value | Result |
| --- | --- |
| `""` | no body |
| `@-` | read stdin |
| `@name` | read the file `name` |
| anything else | the literal bytes |

A value read from stdin for a secret **MUST** have trailing `\r` and `\n`
trimmed; a body **MUST NOT** be trimmed.

The `@` sigil is required. ecv4 instead auto-detected a file with `os.Stat`,
which sends a mistyped path to the server as a literal body and answers with a
confusing 4xx. An implementation **MUST NOT** auto-detect.

A body **MUST NOT** be validated as JSON. Sending malformed JSON to see what the
server does is a legitimate use.

### 7.5 Transport

- The client **MUST** apply `--timeout` to each request.
- Redirects **MUST NOT** be followed. These are tools for seeing what an
  endpoint returns, and silently following a 302 hides it — and would risk
  carrying the credential to wherever the redirect pointed.
- A response body **MUST** be read through a limit. 8 MiB is the RECOMMENDED
  cap: larger than any response a person reads, small enough that a
  misconfigured server cannot exhaust the process.
- `--insecure` **MUST** disable TLS verification and **SHOULD** print a warning
  to stderr.

## 8. Responses

### 8.1 Success

A 2xx **MUST** write the response body to stdout and nothing else to stdout. An
empty body — a 204 — writes nothing.

### 8.2 Failure

A non-2xx **MUST** write to stderr the request line, the status, and the
response body, and **MUST** exit non-zero (§8.4). It **MUST NOT** write the body
to stdout: a failed request must not feed a pipeline as though it succeeded.

### 8.3 Formatting

A body that is valid JSON **MUST** be indented with two spaces when the
destination stream is a terminal, and **MUST** be written unchanged when it is
not, so `earl get /x | jq` stays machine-readable. A body that is not valid JSON
**MUST** pass through unchanged in both cases.

Terminal detection is `os.ModeCharDevice` on an `*os.File`. Anything that is not
an `*os.File` is not a terminal.

Diagnostics — "logged in as …", "credential renewed", verbose logging, warnings
— **MUST** go to stderr, always, so that stdout carries only the response.

**An implementation MUST NOT print, log, or include in an error message the
value of a credential.** Not at any verbosity. A terminal scrollback, a screen
recording, or a CI log is not a place to leave a live session.

### 8.4 Exit codes

| Code | Meaning |
| --- | --- |
| 0 | 2xx, or a successful non-request command |
| 1 | usage, configuration, or local error — bad flags, unreadable file, no saved credential |
| 2 | transport failure — the request did not get an answer |
| 3 | the request got an answer and it was not 2xx |

Distinguishing 2 from 3 is what lets a smoke test tell "the server is down" from
"the server said no". ecv4 returned 0 for a non-2xx, printing it and moving on;
this specification does not, because a runner that exits 0 on a 500 cannot fail
a build.

## 9. Authentication

### 9.1 The Auth contract

```go
// Auth supplies the parts of authentication that differ between APIs: how a
// credential is obtained, how it is attached to a request, and how it is
// revoked. It is the only thing an application must implement or configure.
type Auth interface {
	// Attach adds cred to req. A zero Credential MUST leave req unchanged,
	// so that an anonymous request is sent as-is and the server decides.
	Attach(req *http.Request, cred Credential)

	// Login exchanges an identity and a secret for the credential to save.
	Login(ctx context.Context, tr Transport, identity, secret string) (Credential, error)

	// Logout revokes cred on the server. An error MUST NOT prevent earl from
	// dropping the local copy: a credential the server has forgotten is not
	// one worth keeping, and leaving it produces confusing 401s later.
	Logout(ctx context.Context, tr Transport, cred Credential) error
}

// Refresher is implemented by an Auth that can renew a credential without the
// secret. earl calls Refresh at most once per invocation.
type Refresher interface {
	Refresh(ctx context.Context, tr Transport, cred Credential) (Credential, error)
}

// SelfAuthenticator is implemented by an Auth whose own endpoints authenticate
// from the request body rather than from the attached credential. earl MUST
// NOT react to a 401 from such a path by renewing and retrying: the 401 means
// bad credentials, and retrying would be both pointless and misleading.
type SelfAuthenticator interface {
	SelfAuthenticating(path string) bool
}
```

```go
// Transport sends one request against the configured base URL. earl hands it
// to an Auth so that login and logout reach the server exactly as every other
// command does — same base URL, timeout, redirect policy, limit, and
// User-Agent — without an Auth building a client of its own.
type Transport interface {
	Do(ctx context.Context, method, path string, body []byte, cred Credential) (*Response, error)
}

type Response struct {
	Status  int
	Header  http.Header
	Cookies []*http.Cookie
	Body    []byte
}
```

### 9.2 Credential

```go
// Credential is one saved authentication, whatever its scheme. Value is the
// live secret; everything else is metadata for attaching or renewing it.
type Credential struct {
	Value     string            `json:"value"`
	Name      string            `json:"name,omitempty"`       // cookie name, when the scheme has one
	Renew     string            `json:"renew,omitempty"`      // refresh token, when the scheme has one
	ExpiresAt time.Time         `json:"expires_at,omitzero"`
	Extra     map[string]string `json:"extra,omitempty"`      // scheme-specific, opaque to earl
}

func (c Credential) IsZero() bool  { return c.Value == "" }
func (c Credential) Expired() bool { return !c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt) }
```

`Expired` is advisory. An implementation **MUST NOT** refuse to send an expired
credential: clocks disagree, and the server is the authority on whether a
credential is still good. It is used to label `identities` output and to decide
whether to renew pre-emptively where §9.3 allows it.

### 9.3 Renewal and retry

When a request returns 401, an implementation **MUST** renew and retry once if
and only if all of the following hold:

1. a credential was attached — a 401 on an anonymous request is the endpoint
   legitimately refusing, and **MUST** be reported as-is;
2. `Config.Auth` implements `Refresher`;
3. the request path is not self-authenticating per `SelfAuthenticator`;
4. no renewal has been attempted in this invocation.

On success it **MUST** save the renewed credential (§10.4), write a diagnostic
to stderr naming how the credential was renewed, and reissue the identical
request. On failure it **MUST** write a diagnostic to stderr and report the
original 401 unchanged.

When renewal fails and `Config.ReloginOnExpiry` is set and both an identity and
a secret are configured, an implementation **MAY** log in afresh and retry. This
is ecv4's behaviour and it is off by default, because it means a usable secret
is sitting in the environment of every invocation.

Renewal **MUST NOT** be attempted more than once per invocation, whatever the
outcome.

A `Refresher` that finds it has nothing to renew from — no renewal credential
saved — **MUST** return `ErrNoRenewal` rather than an error of its own. earl
treats it as "nothing to try" and reports the 401 as itself, instead of printing
a renewal-failed diagnostic for a renewal that was never possible.

### 9.4 Field paths

Both supplied implementations extract values from a login response by path.

```go
// Fields names the JSON keys of a login exchange. Response entries are dotted
// paths, so an enveloped body ("data.token") needs no code.
type Fields struct {
	Identity string // request key for the identity:  "email", "username"
	Secret   string // request key for the secret:    "secret", "password"
	Token    string // response path to the credential: "token", "accessToken", "data.token"
	Renew    string // response path to the renewal credential: "refreshToken"
	Expires  string // response path to an RFC 3339 expiry: "expiresAt", "data.expires_at"
	TTL      string // response path to a lifetime in seconds: "expiresInSeconds"
}
```

`Expires` and `TTL` are alternatives; when both are set and both present,
`Expires` wins. A missing or unparseable expiry **MUST NOT** fail a login — it
is metadata, not the credential.

### 9.5 Bearer

```go
type Bearer struct {
	LoginPath  string // required
	LogoutPath string // optional; when empty, logout is local-only
	RenewPath  string // optional; when empty, Bearer does not implement Refresher
	RenewField string // request key for the renewal credential; defaults to "refreshToken"
	Header     string // defaults to "Authorization"
	Prefix     string // defaults to "Bearer "
	Fields     Fields
	Skip       func(path string) bool // extra self-authenticating paths
}
```

`Attach` sets `Header` to `Prefix + cred.Value`, and does nothing for a zero
credential.

`SelfAuthenticating` **MUST** return true for `LoginPath`, `RenewPath`, and
`LogoutPath`, and for any path `Skip` accepts. ecv4 needed this as a prefix test
on `/auth/` — its `/auth/*` endpoints all authenticate from the body — which is
what `Skip` is for.

`Bearer` implements `Refresher` only when `RenewPath` is set. A scheme is
therefore built with a constructor (`auth.NewBearer`, `auth.NewCookie`) rather
than taken as a struct literal: whether the returned `Auth` satisfies
`Refresher` is decided by configuration, which is what makes §9.3's second
condition literally true instead of a method that has to fail at run time.

`Header` and `Prefix` default together. A caller who names their own header — an
API-key scheme — is stating exactly what goes in it, so an empty `Prefix` there
is honoured rather than defaulted back to `Bearer `.

### 9.6 Cookie

```go
type Cookie struct {
	LoginPath    string // required
	LogoutPath   string // defaults to LoginPath
	LogoutMethod string // defaults to DELETE
	Name         string // tie-breaker; see below
	Fields       Fields
}
```

For an API that authenticates with an `HttpOnly` session cookie, the credential
is returned exactly once, in the `Set-Cookie` header of a successful login, and
never in a response body. `Login` **MUST** capture it from that header; there
will be no second chance.

The server's cookie name is configurable and a client does not have to be told
it: a successful login sets exactly one cookie, so whatever arrives is the
session, and its name **MUST** be saved in `Credential.Name` for later requests.

When a login response sets more than one cookie — a load balancer adding a
routing cookie — an implementation **MUST NOT** guess. Sending a routing cookie
as a credential and saving the real session nowhere is worse than failing. It
**MUST** fail with an error naming the candidate cookie *names* and asking for
`Name`. Cookie values **MUST NOT** appear in that message.

An explicit `Name` **MUST** win outright, so a caller who knows never depends on
this reasoning.

When attaching, the name **MUST** be resolved as: `Credential.Name` first, then
`Cookie.Name`. A credential file written before names were saved therefore still
works, instead of failing in a way that looks like an expired session.

Expiry **SHOULD** be taken from the cookie's own `Expires`, which is what the
server enforces, falling back to `Fields.Expires` in the body.

## 10. Credential store

### 10.1 Location

```
$XDG_CONFIG_HOME/<StateDir>/<Env>/credentials.json
~/.config/<StateDir>/<Env>/credentials.json      # when XDG_CONFIG_HOME is unset
```

`<EnvPrefix>_CREDENTIALS` **MUST** override the path entirely. Tests need it,
and so does anyone driving two configurations at once.

An implementation **MUST NOT** use `os.UserConfigDir`, which resolves to
`~/Library/Application Support` on macOS. The file is one a person edits,
inspects, and deletes; it belongs where the rest of their tooling keeps state.

The `<Env>` segment is what keeps a run against development and a run against
production from ever sharing a credential.

### 10.2 Format

```json
{
  "http://localhost:8080/api": {
    "admin@example.com": {
      "value": "…",
      "expires_at": "2026-09-11T04:00:00Z"
    },
    "player@example.com": {
      "value": "…",
      "name": "ec_session",
      "expires_at": "2026-09-11T04:00:00Z"
    }
  }
}
```

Keyed by base URL, then by lowercased identity. Keying by identity is what lets
one file hold several accounts against one server at once — an administrator and
an ordinary user, say — with `--<IdentityName>` selecting between them.

### 10.3 Resolution

Given a base URL and a possibly-empty identity, an implementation **MUST**
resolve as:

1. an explicit identity selects that entry, and only that entry;
2. with no identity and exactly one saved entry for the base URL, that entry;
3. otherwise — none saved, or several and no identity — the zero `Credential`.

A verb command **MUST** treat the zero credential as "send anonymously" and let
the server decide: public routes succeed, protected ones return 401. This is the
right default because it is what makes `--no-auth` unnecessary for bootstrapping.

A session command (`logout`) **MUST** instead fail, and the error **MUST**
distinguish the two causes: "several saved, pass `--<IdentityName>` (one of: …)"
and "none saved, run `<program> login`". Naming the choices is the difference
between an error a caller can act on and one they have to investigate.

### 10.4 Writing

- The directory **MUST** be created with mode `0700` if absent.
- The file **MUST** be written with mode `0600`, and an existing file's mode
  **MUST** be reset, since a file that already existed keeps its old mode.
- The write **MUST** go to a temporary file in the same directory followed by a
  rename, so that an interrupted write cannot leave a truncated credential file.

A saved value is a live credential. Anyone holding it is signed in as that
account until it expires; the file permissions are load-bearing.

### 10.5 identities

`identities` **MUST** list the identities saved for the current base URL, each
with its expiry, marking expired ones. It **MUST** print the credential file's
path — the path is how it becomes obvious which file, and which environment, is
in play. It **MUST NOT** print any credential value.

Identities **MUST** be listed in sorted order, so successive runs are diffable.

The list goes to stdout; the path and any "several saved, pass `--email`" note go
to stderr.

## 11. Extension commands

`Config.Extra` registers application subcommands on the root. It exists for
operations that are not a request an operator can type — ecv6's `impersonate`
mints a token by calling an admin endpoint and then *saves it to the credential
store under the subject's identity*, which no passthrough verb can do.

An extension command:

- **MUST NOT** be a typed wrapper around an endpoint that `get`/`post`/`patch`
  could already reach. If `earl post /admin/impersonation -d '{"accountId":2}'`
  did the whole job, that is the command;
- **MUST** obey §8 for output, exit codes, and credential secrecy;
- **MUST** satisfy the flag-arity rules of §5.4;
- **SHOULD** reach the server through the same `Transport` the library uses.

Test that this line is holding: if `Extra` has grown past a handful of commands,
the application has stopped using a generic runner and started writing a bespoke
client, and it **SHOULD** become its own binary. Appendix A records the case
that prompted this rule.

## 12. Errors and diagnostics

An implementation **MUST** prefix every message it writes to stderr with
`<Program>: `.

Errors **MUST** name what to do next where there is an obvious next step: which
flag to pass, which command to run, which values were available. `no saved
session for http://…; run "earl login" first` is the standard to hold.

Typed errors **MUST** be exported so that callers can distinguish causes:

```go
// StatusError is a request that was answered with a non-2xx status.
type StatusError struct {
	Method, Path string
	Status       int
	Body         []byte
}

// TransportError is a request that got no answer at all.
type TransportError struct {
	Method, Path string
	Err          error
}
```

Callers match with `errors.AsType[*earl.StatusError](err)`. `UsageError` wraps a
command line earl could not act on, and `ErrNoRenewal` is the sentinel of §9.3.

## 13. Conformance tests

A conforming implementation **MUST** carry tests for at least:

1. **Reordering.** `post /p -d @f --no-auth`, `--` handling, a bare `-`
   positional, `--data={"k":"v"}` consuming nothing further, and root flags
   before the subcommand keeping their place. Arity is derived, so a test that
   adds a flag and asserts reordering follows **MUST** exist in place of ecv6's
   and ecv8's drift-guard over a literal map.
2. **Body resolution.** All four forms of §7.4, plus the assertion that a
   non-existent `@path` is an error rather than a literal body.
3. **Output contract.** 2xx to stdout; non-2xx to stderr with the right exit
   code; a non-TTY writer receiving unindented bytes; a 204 writing nothing; a
   non-JSON body passing through.
4. **Credential secrecy.** Drive `login`, `identities`, `logout`, a 401 renewal,
   and a multi-cookie login failure against a test server, and assert that the
   credential value appears in neither captured stream at any verbosity. This
   test **MUST** exist; it is the one invariant that cannot be recovered after
   it is broken.
5. **Store.** Round-trip; all three resolution branches of §10.3; file mode
   `0600` after writing over an existing `0644`; env-scoped paths differing.
6. **Renewal.** All four conditions of §9.3, each denied in turn, and the
   at-most-once guarantee.
7. **Cookie capture.** Single-cookie success, multi-cookie refusal naming only
   names, and attach preferring the saved name over the configured one.

Tests **MUST** run against an `httptest.Server` and **MUST NOT** require a real
API.

---

## Appendix A: the existing implementations

Four implementations preceded this specification; see `others.md` for paths.

### A.1 Coverage

Each generic implementation expressed as a `Config`:

| | ecv4 | ecv6 | ecv8 |
| --- | --- | --- | --- |
| `EnvPrefix` | `EARL` | `EARL` | `ECV8` |
| `BaseURL` | `http://localhost:9987` | `http://localhost:8080/api` | `http://localhost:3000` |
| `APIPath` | — | — | `/api/v1` |
| `IdentityName` | `authn-email` | `email` | `email` |
| `WhoamiPath` | *(no command; `get /me`)* | `/me` | `/session` |
| `Auth` | `Bearer` | `Bearer` | `Cookie` |
| `LoginPath` | `/auth/login` | `/auth/login` | `/session` |
| `RenewPath` | `/auth/refresh` | — | — |
| `Fields.Identity` | `username` | `email` | `email` |
| `Fields.Secret` | `password` | `secret` | `password` |
| `Fields.Token` | `accessToken` | `token` | *(cookie)* |
| `Fields.Renew` | `refreshToken` | — | — |
| `Fields.Expires` | — | `expiresAt` | `data.expires_at` |
| `Fields.TTL` | `expiresInSeconds` | — | — |
| `Skip` | `/auth/` prefix | — | — |
| `ReloginOnExpiry` | true | false | false |
| `Extra` | — | `impersonate` | — |

Every difference between the three is a `Config` value. Nothing in them requires
a code path this specification does not have.

### A.2 What each contributed

- **ecv4** — the passthrough premise, and renewal: 401 → refresh → re-login →
  rewrite the file → retry once, with `/auth/*` excluded. §9.3 and §9.5's `Skip`
  are its.
- **ecv6** — the multi-identity store keyed by `(base URL, identity)` with its
  three-branch resolution, the env-scoped XDG path, the atomic write, the `@`
  body sigil, and `reorderArgs`. §5.4 and §10 are its.
- **ecv8** — the cookie strategy and its single-cookie discovery rule, base-URL
  normalization, refusing redirects, response limits, the shared credential file
  between sibling commands, and the discipline in §2. Most of §7, §8, and §9.6
  are its.

### A.3 What was corrected

- ecv4's `os.Stat` body auto-detection (§7.4) — a mistyped path becomes a
  literal body.
- ecv4's unused `readBody` alongside `resolveBody`, two functions for one job
  with different sigil rules, one of them dead.
- ecv4 exiting 0 on a non-2xx (§8.4).
- ecv6's and ecv8's hand-maintained `valueFlags` map (§5.4).
- ecv8 omitting `-d` on `delete` (§5.2).

### A.4 assemblage

`assemblage/cmd/earl` shares the name and almost nothing else: ~4,900 lines of
cobra, about seventy typed noun-verb commands (`doc publish`, `alert create`,
`invite redeem`, `queue`, `element-type update`), each with its own request and
response structs and `tabwriter` output. There is no verb passthrough at all.

It is out of scope, and it is why §11 exists. Its credential handling is also
weaker than the others' — a single identity with no `(server, identity)` keying,
no environment scoping, a direct write instead of an atomic one, and
`os.UserConfigDir` — which is what §10 is written against.

---

## Appendix B: deferred

| Deferred | Why, and what would change if revisited |
| --- | --- |
| File-driven auth profiles | A single installed binary usable against any API, at the cost of a config format to design and version, and shape mismatches becoming runtime errors. `Auth` is an interface precisely so this can arrive later as one more implementation, without touching anything else. |
| `--expect STATUS` | Asserting an expected status in a smoke script. Genuinely useful; deferred only because `[ $? -eq 3 ]` covers most of it and the flag needs a story for ranges and for several acceptable statuses. |
| Non-JSON bodies, multipart, file upload | No implementation has needed one. `Content-Type` is already overridable with `-H`, so the gap is real but narrow. |
| Response streaming | The 8 MiB limit (§7.5) is deliberate. Streaming would trade a bounded-memory guarantee for a case no implementation has had. |
| Request/response recording | A `--trace` writing a replayable transcript would make earl a golden-test harness. It needs a format decision that should not be made in the same pass as the rest of this. |
| Shell completion | Free from `ff`; omitted only until the command tree stops moving. |
