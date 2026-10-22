// ==============================================================================
// File name:     show_backup_cmd.go
// Description:   The "show-backup" subcommand: view or locate a saved backup.
// License:       MIT
// ==============================================================================
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"netconfig/internal/backup"
	"netconfig/internal/credentials"
	"netconfig/internal/task"
)

const showBackupUsageText = `Usage:
  netconfig show-backup [flags] <node-name>
  netconfig show-backup -l

View or locate the newest saved configuration of a device. <node-name> may be
part of a name (case-insensitive); if several devices match, you are asked to
choose. The file is shown with $PAGER (or less) on a terminal and printed
as-is otherwise.

Examples:
  netconfig show-backup core-sw1
  netconfig show-backup gw-01            (asks which one if several match)
  netconfig show-backup -d core-sw1      (the latest diff instead)
  netconfig show-backup -p core-sw1      (only print the file's path)
  netconfig show-backup -l               (list every device with a backup)

Flags:
`

// runShowBackup is "netconfig show-backup".
func runShowBackup(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var (
		dir                  string
		diff, pathOnly, list bool
	)
	fs := flag.NewFlagSet("netconfig show-backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, showBackupUsageText)
		fs.PrintDefaults()
	}
	fs.StringVar(&dir, "backup-dir", "backups", "directory holding the backups")
	fs.StringVar(&dir, "out", "backups", "alias for -backup-dir")
	fs.BoolVar(&diff, "d", false, "show the latest diff instead of the full configuration")
	fs.BoolVar(&diff, "diff", false, "alias for -d")
	fs.BoolVar(&pathOnly, "p", false, "only print the file's path; do not open a pager")
	fs.BoolVar(&pathOnly, "path", false, "alias for -p")
	fs.BoolVar(&list, "l", false, "list all devices that have a backup")
	fs.BoolVar(&list, "list", false, "alias for -l")

	// Flags may come before or after the node name ("show-backup -d gw-01",
	// "show-backup gw-01 -d"); the flag package stops at the first non-flag.
	var positional []string
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return task.ExitOK
			}
			return task.ExitFatal
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, format+"\n", a...)
		return task.ExitFatal
	}

	listFn, kind := backup.ListNodes, "config"
	if diff {
		listFn, kind = backup.ListDiffNodes, "diff"
	}

	if list {
		nodes, err := backup.ListNodes(dir)
		if err != nil {
			return fail("netconfig show-backup: %v", err)
		}
		fmt.Fprintln(stdout, "Available nodes in backup history:")
		for _, n := range nodes {
			fmt.Fprintf(stdout, "  - %s\n", n)
		}
		return task.ExitOK
	}

	switch len(positional) {
	case 0:
		fmt.Fprintln(stderr, "Error: Node name or substring is required.")
		fmt.Fprintln(stderr)
		fs.Usage()
		return task.ExitFatal
	case 1:
	default:
		fmt.Fprintf(stderr, "Unexpected argument: %s\n", positional[1])
		fs.Usage()
		return task.ExitFatal
	}
	query := positional[0]

	nodes, err := listFn(dir)
	if err != nil {
		return fail("Error: %v", err)
	}
	exact, matches := backup.MatchNodes(nodes, query)
	if len(matches) == 0 {
		fmt.Fprintf(stderr, "No %s files found matching '%s' in %s.\n", kind, query, dir)
		fmt.Fprintln(stderr, "Run 'netconfig show-backup -l' to view all available devices.")
		return task.ExitFatal
	}

	selected := exact
	if selected == "" {
		if len(matches) == 1 {
			selected = matches[0]
		} else {
			if !credentials.IsTerminal(stdin) || (pathOnly && !isTerminalWriter(stdout)) {
				fmt.Fprintf(stderr, "Error: Multiple nodes match '%s':\n", query)
				for _, m := range matches {
					fmt.Fprintf(stderr, "  - %s\n", m)
				}
				fmt.Fprintln(stderr, "Please be more specific.")
				return task.ExitFatal
			}
			var ok bool
			if selected, ok = selectNode(stdin, stdout, matches, query); !ok {
				fmt.Fprintln(stdout, "Aborted.")
				return task.ExitOK
			}
		}
	}

	file, err := backup.Latest(dir, selected, diff)
	if err != nil {
		return fail("%v", err)
	}
	if pathOnly {
		fmt.Fprintln(stdout, file)
		return task.ExitOK
	}

	fmt.Fprintf(stdout, "==> Latest %s for '%s': %s\n", kind, selected, file)
	if err := display(file, stdin, stdout, stderr); err != nil {
		return fail("netconfig show-backup: %v", err)
	}
	return task.ExitOK
}

// selectNode asks which of several matching nodes is meant. It returns false
// when the user quits or the input ends.
func selectNode(in io.Reader, out io.Writer, candidates []string, query string) (string, bool) {
	fmt.Fprintf(out, "Multiple nodes match '%s':\n", query)
	for i, c := range candidates {
		fmt.Fprintf(out, "  [%d] %s\n", i+1, c)
	}
	r := bufio.NewReader(in)
	for {
		fmt.Fprintf(out, "Select a node [1-%d] (or 'q' to quit): ", len(candidates))
		line, err := r.ReadString('\n')
		choice := strings.TrimSpace(line)
		if strings.EqualFold(choice, "q") || (err != nil && choice == "") {
			return "", false
		}
		if n, convErr := strconv.Atoi(choice); convErr == nil && n >= 1 && n <= len(candidates) {
			return candidates[n-1], true
		}
		fmt.Fprintf(out, "Invalid selection. Please enter a number between 1 and %d.\n", len(candidates))
		if err != nil {
			return "", false
		}
	}
}

// pagerCommand picks the viewer for a terminal: $PAGER if set, otherwise
// "less -R" when it is installed, otherwise none (the file is just printed).
func pagerCommand(pager string, hasLess bool) []string {
	if fields := strings.Fields(pager); len(fields) > 0 {
		return fields
	}
	if hasLess {
		return []string{"less", "-R"}
	}
	return nil
}

// display shows a file: through a pager when stdout is a terminal, printed
// as-is otherwise (so it can be piped or redirected).
func display(path string, stdin *os.File, stdout, stderr io.Writer) error {
	if isTerminalWriter(stdout) {
		_, lessErr := exec.LookPath("less")
		if argv := pagerCommand(os.Getenv("PAGER"), lessErr == nil); argv != nil {
			cmd := exec.Command(argv[0], append(argv[1:], path)...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
			err := cmd.Run()
			if err == nil {
				return nil
			}
			fmt.Fprintf(stderr, "netconfig show-backup: pager %q failed (%v); printing the file instead\n", argv[0], err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(stdout, f)
	return err
}
