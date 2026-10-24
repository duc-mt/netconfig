// ==============================================================================
// File name:     usage.go
// Description:   Grouped, alias-folding help output for commands with many flags.
// License:       MIT
// ==============================================================================
package main

import (
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// flagGroup is a titled section of a command's help.
type flagGroup struct {
	title string
	names []string
}

// aliasUsage marks a flag that is another spelling of an existing one. Only the
// exact form "alias for -name" counts: "-update-known-hosts" is a shortcut that
// *sets* -host-key-policy, so it is a flag in its own right and is listed as one.
var aliasUsage = regexp.MustCompile(`^alias for -([a-z0-9-]+)$`)

// printFlagGroups writes fs's flags in titled sections, in the order given,
// with each alias folded into its flag's line ("also -out"). It never hides a
// flag: anything not named in a group (or named wrongly) is listed afterwards
// under "Other flags". flag.PrintDefaults would list all of them alphabetically,
// which for a command with 50 flags and a dozen aliases is not readable.
func printFlagGroups(w io.Writer, fs *flag.FlagSet, groups []flagGroup) {
	aliasesOf := make(map[string][]string)
	isAlias := make(map[string]bool)
	fs.VisitAll(func(f *flag.Flag) {
		if m := aliasUsage.FindStringSubmatch(f.Usage); m != nil && fs.Lookup(m[1]) != nil {
			aliasesOf[m[1]] = append(aliasesOf[m[1]], f.Name)
			isAlias[f.Name] = true
		}
	})

	printed := make(map[string]bool)
	section := func(title string, names []string) {
		var list []*flag.Flag
		for _, name := range names {
			if f := fs.Lookup(name); f != nil && !isAlias[name] && !printed[name] {
				printed[name] = true
				list = append(list, f)
			}
		}
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s:\n", title)
		for _, f := range list {
			printFlag(w, f, aliasesOf[f.Name])
		}
	}

	for _, g := range groups {
		section(g.title, g.names)
	}
	var rest []string
	fs.VisitAll(func(f *flag.Flag) {
		if !printed[f.Name] && !isAlias[f.Name] {
			rest = append(rest, f.Name)
		}
	})
	section("Other flags", rest)
}

// printFlag writes one flag in the layout of flag.PrintDefaults, with its
// non-zero default and its aliases appended to the description.
func printFlag(w io.Writer, f *flag.Flag, aliases []string) {
	typ, usage := flag.UnquoteUsage(f)
	head := "  -" + f.Name
	if typ != "" {
		head += " " + typ
	}

	var notes []string
	switch f.DefValue {
	case "", "0", "false", "0s":
	default:
		if typ == "string" {
			notes = append(notes, fmt.Sprintf("default %q", f.DefValue))
		} else {
			notes = append(notes, "default "+f.DefValue)
		}
	}
	if len(aliases) > 0 {
		notes = append(notes, "also -"+strings.Join(aliases, ", -"))
	}
	if len(notes) > 0 {
		usage += " (" + strings.Join(notes, "; ") + ")"
	}
	fmt.Fprintf(w, "%s\n    \t%s\n", head, usage)
}
