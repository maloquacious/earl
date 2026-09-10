// Copyright (c) 2026 Michael D Henderson. All rights reserved.

package earl

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/peterbourgon/ff/v4"
)

// arity records, for every flag token in a command tree, whether it consumes
// the following argument as its value.
//
// It is derived from the tree, never hand-maintained (SPEC §5.4). ecv6 and ecv8
// both carry a literal map that has to be kept in step with the flags by hand,
// and both need a test whose only job is to catch the drift.
type arity map[string]bool

// deriveArity walks the root flag set and every subcommand's flag set,
// recording each flag's short and long spellings.
//
// Bool-ness is not on ff's exported Flag interface (isBoolFlag is unexported on
// coreFlag as of v4.0.0-beta.1), so it comes from two places:
//
//   - known, for the flags earl registers: earl knows which of its own flags
//     take values, and says so at registration;
//   - Flag.GetPlaceholder() == "", for flags on Config.Extra commands, which ff
//     returns only for a bool flag defaulting to false.
//
// Reordering runs before the subcommand is known, so the result is a union over
// the whole tree. A flag name must therefore have the same arity everywhere it
// appears, and a conflict is reported here rather than mis-parsed later.
func deriveArity(root *ff.Command, known arity) (arity, error) {
	// observed is what the tree says about each token; known is what earl says
	// about its own. They are kept apart so that a disagreement between two
	// flags sharing a name is a conflict, while a disagreement between the
	// placeholder heuristic and earl's own knowledge is simply earl winning.
	observed := map[string]bool{}
	seen := map[string]bool{}
	conflicts := map[string]bool{}

	record := func(token string, takesValue bool) {
		if was, ok := observed[token]; ok && was != takesValue {
			conflicts[token] = true
			return
		}
		observed[token] = takesValue
		seen[token] = true
	}

	var walk func(cmd *ff.Command) error
	walk = func(cmd *ff.Command) error {
		if cmd.Flags != nil {
			err := cmd.Flags.WalkFlags(func(f ff.Flag) error {
				takesValue := f.GetPlaceholder() != ""
				if long, ok := f.GetLongName(); ok {
					record("--"+long, takesValue)
				}
				if short, ok := f.GetShortName(); ok {
					record("-"+string(short), takesValue)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		for _, sub := range cmd.Subcommands {
			if err := walk(sub); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	if len(conflicts) > 0 {
		return nil, fmt.Errorf("flag %s takes a value in one command and not in another; "+
			"a flag name must mean the same thing everywhere in one tree, because reordering "+
			"runs before the subcommand is known", strings.Join(slices.Sorted(maps.Keys(conflicts)), ", "))
	}

	out := arity{}
	for token := range seen {
		if v, ok := known[token]; ok {
			out[token] = v
			continue
		}
		out[token] = observed[token]
	}
	return out, nil
}

// reorder rewrites a command line so each subcommand's flags precede its
// positional arguments (SPEC §5.4).
//
// ff, like the standard flag package, stops parsing flags at the first
// positional, so `post /accounts -d '{...}'` would treat -d as a stray
// argument. That is how anyone who has used curl expects to be able to type it,
// so the line is rewritten rather than the expectation.
//
// It is section-aware: the leading root flags and the subcommand name keep
// their place - ff routes on the subcommand name, which must stay the first
// positional - and only the tokens after it are hoisted.
func reorder(args []string, a arity) []string {
	out := make([]string, 0, len(args))

	// Root section: copy root flags, and any values they consume, through to
	// and including the subcommand name.
	i := 0
	for i < len(args) {
		tok := args[i]
		if tok == "--" {
			return append(out, args[i:]...)
		}
		if isFlag(tok) {
			out = append(out, tok)
			i++
			if a.takesValue(tok) && i < len(args) {
				out = append(out, args[i])
				i++
			}
			continue
		}
		out = append(out, tok) // the subcommand name
		i++
		break
	}

	// Subcommand section: hoist flags ahead of positionals.
	var flags, positionals []string
	for i < len(args) {
		tok := args[i]
		if tok == "--" {
			positionals = append(positionals, args[i:]...)
			break
		}
		if isFlag(tok) {
			flags = append(flags, tok)
			i++
			if a.takesValue(tok) && i < len(args) {
				flags = append(flags, args[i])
				i++
			}
			continue
		}
		positionals = append(positionals, tok)
		i++
	}
	out = append(out, flags...)
	return append(out, positionals...)
}

// isFlag reports whether tok is a flag token rather than a positional. A bare
// "-" is a positional - it is how a caller names stdin - and "--" is handled by
// the caller.
func isFlag(tok string) bool {
	return len(tok) >= 2 && tok[0] == '-' && tok != "--"
}

// takesValue reports whether a flag token consumes the following argument.
//
// A flag written with "=" carries its own value and consumes nothing more. In a
// short-flag cluster (-vd) only the last rune can take a value, which is how
// getopt has always worked and how ff parses one.
func (a arity) takesValue(tok string) bool {
	if strings.Contains(tok, "=") {
		return false
	}
	if v, ok := a[tok]; ok {
		return v
	}
	if strings.HasPrefix(tok, "--") || len(tok) <= 2 {
		return false
	}
	last, _ := utf8.DecodeLastRuneInString(tok)
	return a["-"+string(last)]
}
