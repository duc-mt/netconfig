// ==============================================================================
// Package main implements Implementation and logic for credentials..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run credentials.go [options]
// Notes:         Go package implementation
// ==============================================================================
// Package credentials resolves SSH credentials per credential group.
//
// Sources, in priority order:
//
//  1. the .env file          (NETCONFIG_<GROUP>_USERNAME, NETCONFIG_USERNAME, ...)
//  2. process environment    (same names)
//  3. an interactive, non-echoing terminal prompt
//
// Within a source, a group-specific key (NETCONFIG_DC1_PASSWORD) overrides the
// global key (NETCONFIG_PASSWORD), and that specificity rule is applied across
// sources: a per-site override in the environment beats a global default in
// .env. Empty values count as unset. Passwords are never accepted as
// command-line flags and never appear in String()/%v/%#v output.
package credentials

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync"
)

// ErrNotFound means no complete credential could be resolved for a group.
var ErrNotFound = errors.New("credentials not found")

// Credential is the login for one device group.
type Credential struct {
	Username       string
	Password       string
	EnablePassword string // optional; falls back to Password where an enable secret is needed
	KeyFile        string // optional; path to SSH private key file
}

// JumpCredentials holds connection details for a bastion / jump host.
type JumpCredentials struct {
	Host     string // host[:port]; empty disables jump
	Username string
	Password string
	KeyFile  string // optional; path to SSH private key file
}

// String redacts the secrets so JumpCredentials can be logged safely.
func (j JumpCredentials) String() string {
	return fmt.Sprintf("JumpCredentials{host=%q, user=%q, keyFile=%q, password=<redacted>}", j.Host, j.Username, j.KeyFile)
}

// String redacts the secrets so a Credential can be logged by accident safely.
func (c Credential) String() string {
	return fmt.Sprintf("Credential{user=%q, keyFile=%q, password=<redacted>}", c.Username, c.KeyFile)
}

// GoString covers %#v.
func (c Credential) GoString() string { return c.String() }

// Prompter asks a human for missing credentials.
type Prompter interface {
	Username(group string) (string, error)
	Password(group, username string) (string, error)
}

type outcome struct {
	cred Credential
	err  error
}

// Resolver implements the three-tier lookup. It is safe for concurrent use;
// prompts are serialised, and each group is resolved (or fails) only once.
type Resolver struct {
	DotEnv    map[string]string           // tier 1 (values of the .env file; never exported to the process env)
	LookupEnv func(string) (string, bool) // tier 2 (os.LookupEnv); nil disables the tier
	Prompter  Prompter                    // tier 3; nil disables prompting
	Overrides map[string]string           // explicit overrides (e.g. from CLI flags, highest priority)

	mu    sync.Mutex
	cache map[string]outcome
}

// EnvKey builds the variable name for a group and field, e.g.
// EnvKey("dc-1", "PASSWORD") == "NETCONFIG_DC_1_PASSWORD".
func EnvKey(group, field string) string {
	if group == "" {
		return globalKey(field)
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(group) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return "NETCONFIG_" + b.String() + "_" + field
}

func globalKey(field string) string { return "NETCONFIG_" + field }

func (r *Resolver) lookup(group, field string) (string, bool) {
	for _, key := range []string{EnvKey(group, field), globalKey(field)} {
		if r.Overrides != nil {
			if v := r.Overrides[key]; v != "" {
				return v, true
			}
		}
		if v := r.DotEnv[key]; v != "" {
			return v, true
		}
		if r.LookupEnv != nil {
			if v, ok := r.LookupEnv(key); ok && v != "" {
				return v, true
			}
		}
	}
	return "", false
}

// Username returns the login name configured for group in the file and
// environment tiers without prompting or caching; "" when none is configured.
// It lets pre-flight checks know which account a run will log in with.
func (r *Resolver) Username(group string) string {
	u, _ := r.lookup(group, "USERNAME")
	return u
}

// Resolve returns the credential for group, prompting only for the fields that
// the file and environment tiers did not provide.
func (r *Resolver) Resolve(group string) (Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if o, ok := r.cache[group]; ok {
		return o.cred, o.err
	}
	cred, err := r.resolveLocked(group)
	if r.cache == nil {
		r.cache = make(map[string]outcome)
	}
	r.cache[group] = outcome{cred: cred, err: err}
	return cred, err
}

func (r *Resolver) resolveLocked(group string) (Credential, error) {
	var c Credential
	c.Username, _ = r.lookup(group, "USERNAME")
	c.Password, _ = r.lookup(group, "PASSWORD")
	c.EnablePassword, _ = r.lookup(group, "ENABLE_PASSWORD")
	c.KeyFile, _ = r.lookup(group, "KEY_FILE")

	if c.Username == "" && r.Prompter != nil {
		u, err := r.Prompter.Username(group)
		if err != nil {
			return Credential{}, fmt.Errorf("prompt for username (group %q): %w", group, err)
		}
		c.Username = strings.TrimSpace(u)
	}
	if c.Password == "" && c.KeyFile == "" && c.Username != "" && r.Prompter != nil {
		p, err := r.Prompter.Password(group, c.Username)
		if err != nil {
			return Credential{}, fmt.Errorf("prompt for password (group %q): %w", group, err)
		}
		c.Password = p
	}
	if c.Username == "" || (c.Password == "" && c.KeyFile == "") {
		return Credential{}, fmt.Errorf("%w for group %q (set %s and %s/%s in .env or the environment, or run interactively)",
			ErrNotFound, group, EnvKey(group, "USERNAME"), EnvKey(group, "PASSWORD"), EnvKey(group, "KEY_FILE"))
	}
	return c, nil
}

// JumpDefaults returns the global bastion / jump host connection details
// loaded from NETCONFIG_JUMP_HOST / NETCONFIG_JUMP_USERNAME / NETCONFIG_JUMP_PASSWORD / NETCONFIG_JUMP_KEY_FILE
// (or their .env equivalents).
func (r *Resolver) JumpDefaults() JumpCredentials {
	host, _ := r.lookupJump("", "HOST")
	u, _ := r.lookupJump("", "USERNAME")
	p, _ := r.lookupJump("", "PASSWORD")
	k, _ := r.lookupJump("", "KEY_FILE")
	return JumpCredentials{Host: host, Username: u, Password: p, KeyFile: k}
}

// IsDirect reports whether a jump_host value explicitly indicates a direct
// connection bypassing any jump host or bastion ("direct", "none", "-", "off",
// "false", "no").
func IsDirect(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "direct", "none", "-", "off", "false", "no":
		return true
	default:
		return false
	}
}

// ForJumpHost resolves credentials for a named jump host.
// It checks NETCONFIG_JUMP_<NAME>_HOST / USERNAME / PASSWORD / KEY_FILE first,
// falling back to the global NETCONFIG_JUMP_* variables, and finally
// to the global device username/keyfile if jump credentials are unset.
// If name explicitly indicates a direct connection (IsDirect), it returns an
// empty JumpCredentials{} with Host == "".
func (r *Resolver) ForJumpHost(name string) JumpCredentials {
	if IsDirect(name) {
		return JumpCredentials{}
	}
	cleanName := cleanGroupName(name)
	host, _ := r.lookupJump(cleanName, "HOST")
	u, _ := r.lookupJump(cleanName, "USERNAME")
	p, _ := r.lookupJump(cleanName, "PASSWORD")
	k, _ := r.lookupJump(cleanName, "KEY_FILE")

	def := r.JumpDefaults()
	if host == "" {
		if strings.Contains(name, ":") {
			host = strings.TrimSpace(name)
		} else {
			host = def.Host
		}
	}
	if u == "" {
		u = def.Username
	}
	if u == "" {
		// Fallback to global device username
		if devUser, ok := r.lookup("", "USERNAME"); ok {
			u = devUser
		}
	}
	if p == "" {
		p = def.Password
	}
	if k == "" {
		k = def.KeyFile
	}
	if k == "" && p == "" {
		if devKey, ok := r.lookup("", "KEY_FILE"); ok {
			k = devKey
		}
	}
	return JumpCredentials{Host: host, Username: u, Password: p, KeyFile: k}
}

func (r *Resolver) lookupJump(cleanName, field string) (string, bool) {
	var keys []string
	if cleanName != "" {
		keys = append(keys, "NETCONFIG_JUMP_"+cleanName+"_"+field)
	}
	keys = append(keys, "NETCONFIG_JUMP_"+field)

	for _, key := range keys {
		if r.Overrides != nil {
			if v := r.Overrides[key]; v != "" {
				return v, true
			}
		}
		if v := r.DotEnv[key]; v != "" {
			return v, true
		}
		if r.LookupEnv != nil {
			if v, ok := r.LookupEnv(key); ok && v != "" {
				return v, true
			}
		}
	}
	return "", false
}

func cleanGroupName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// DotEnv is a parsed .env file.
type DotEnv struct {
	Values   map[string]string
	Warnings []string
}

// LoadDotEnv reads path. A missing file is not an error (the tier is simply empty).
func LoadDotEnv(path string) (*DotEnv, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &DotEnv{Values: map[string]string{}}, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	d := &DotEnv{}
	if st, err := f.Stat(); err == nil && runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		d.Warnings = append(d.Warnings,
			fmt.Sprintf("%s is accessible by group/others (mode %04o); it holds passwords - run: chmod 600 %s", path, st.Mode().Perm(), path))
	}
	d.Values, err = ParseDotEnv(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return d, nil
}

// ParseDotEnv parses KEY=VALUE lines. Supported: blank lines, '#' comments, an
// optional "export " prefix, single-quoted (literal) and double-quoted (\n \t
// \" \\ escapes) values, and trailing " # comments" on unquoted values. A '#'
// inside an unquoted value is kept unless preceded by whitespace, so
// pass#word works. Error messages never include values.
func ParseDotEnv(r io.Reader) (map[string]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read env stream: %w", err)
	}
	out := make(map[string]string)
	for i, raw := range strings.Split(string(data), "\n") {
		n := i + 1
		line := strings.TrimRight(raw, "\r")
		if n == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") || strings.HasPrefix(line, "export\t") {
			line = strings.TrimSpace(line[len("export"):])
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", n)
		}
		key := strings.TrimSpace(line[:eq])
		if !validKey(key) {
			return nil, fmt.Errorf("line %d: invalid variable name %q", n, key)
		}
		val, err := parseValue(strings.TrimSpace(line[eq+1:]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out[key] = val
	}
	return out, nil
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func parseValue(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	switch s[0] {
	case '"':
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			c := s[i]
			switch c {
			case '\\':
				if i+1 >= len(s) {
					return "", errors.New("dangling backslash in quoted value")
				}
				i++
				switch s[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '"', '\\':
					b.WriteByte(s[i])
				default:
					b.WriteByte('\\')
					b.WriteByte(s[i])
				}
			case '"':
				rest := strings.TrimSpace(s[i+1:])
				if rest != "" && !strings.HasPrefix(rest, "#") {
					return "", errors.New("unexpected text after closing quote")
				}
				return b.String(), nil
			default:
				b.WriteByte(c)
			}
		}
		return "", errors.New("unterminated double-quoted value")
	case '\'':
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return "", errors.New("unterminated single-quoted value")
		}
		rest := strings.TrimSpace(s[end+2:])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return "", errors.New("unexpected text after closing quote")
		}
		return s[1 : end+1], nil
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimSpace(s[:i]), nil
		}
	}
	return s, nil
}
