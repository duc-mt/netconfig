// ==============================================================================
// File name:     yaml.go
// Description:   Reader and writer for the audit rules file (a small YAML subset).
// License:       MIT
// ==============================================================================
package audit

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// The rules file is a deliberately small subset of YAML, parsed here so the
// binary needs no third-party library:
//
//	# comment
//	rules:
//	  - id: ntp
//	    title: NTP server configured
//	    severity: medium            # high | medium | low
//	    vendors: [cisco, arista]    # optional; omit for every platform
//	    block: '^line vty'          # optional
//	    require: '^\s*ntp server\s+\S+'
//	    forbid: 'transport input (all|telnet)'
//	    remediation: Configure an NTP server
//
// Values are plain, 'single-quoted' (write regular expressions this way: no
// escaping is needed) or "double-quoted" (\\ \" \n \t only). Anything else
// (anchors, multi-line scalars, nested maps) is rejected with a line number.

var ruleKeys = map[string]bool{
	"id": true, "title": true, "severity": true, "vendors": true,
	"block": true, "require": true, "forbid": true, "remediation": true,
}

// ParseRules reads a rules file and compiles it.
func ParseRules(r io.Reader) ([]Rule, error) {
	var (
		rules      []Rule
		cur        *Rule
		seenRules  bool
		itemIndent = -1
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		raw := strings.TrimRight(sc.Text(), "\r")
		if n == 1 {
			raw = strings.TrimPrefix(raw, "\ufeff")
		}
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line[:len(line)-len(strings.TrimLeft(line, " \t"))], "\t") {
			return nil, fmt.Errorf("line %d: tabs are not allowed for indentation", n)
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		text := strings.TrimSpace(line)

		if !seenRules {
			if text != "rules:" {
				return nil, fmt.Errorf("line %d: the file must start with \"rules:\"", n)
			}
			seenRules = true
			continue
		}
		if strings.HasPrefix(text, "- ") || text == "-" {
			rules = append(rules, Rule{})
			cur = &rules[len(rules)-1]
			itemIndent = indent
			text = strings.TrimSpace(strings.TrimPrefix(text, "-"))
			if text == "" {
				continue
			}
		} else if cur == nil || indent <= itemIndent {
			return nil, fmt.Errorf("line %d: expected a list item starting with \"- \"", n)
		}
		key, val, ok := strings.Cut(text, ":")
		key = strings.TrimSpace(key)
		if !ok || !ruleKeys[key] {
			return nil, fmt.Errorf("line %d: unknown or malformed key %q (allowed: %s)", n, key, allowedKeys())
		}
		if err := setField(cur, key, strings.TrimSpace(val)); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !seenRules || len(rules) == 0 {
		return nil, fmt.Errorf("the file defines no rules")
	}
	if err := Compile(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func allowedKeys() string {
	return "id, title, severity, vendors, block, require, forbid, remediation"
}

func setField(r *Rule, key, raw string) error {
	if key == "vendors" {
		list, err := parseList(raw)
		r.Vendors = list
		return err
	}
	val, err := parseScalar(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	switch key {
	case "id":
		r.ID = val
	case "title":
		r.Title = val
	case "severity":
		r.Severity = strings.ToLower(val)
	case "block":
		r.Block = val
	case "require":
		r.Require = val
	case "forbid":
		r.Forbid = val
	case "remediation":
		r.Remediation = val
	}
	return nil
}

// stripComment removes a trailing "# comment" that is outside quotes.
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '\'' || c == '"':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return s
}

func parseScalar(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	switch raw[0] {
	case '\'':
		var b strings.Builder
		for i := 1; i < len(raw); i++ {
			if raw[i] == '\'' {
				if i+1 < len(raw) && raw[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				if rest := strings.TrimSpace(raw[i+1:]); rest != "" {
					return "", fmt.Errorf("unexpected text after the closing quote: %q", rest)
				}
				return b.String(), nil
			}
			b.WriteByte(raw[i])
		}
		return "", fmt.Errorf("unterminated single-quoted value")
	case '"':
		var b strings.Builder
		for i := 1; i < len(raw); i++ {
			switch raw[i] {
			case '\\':
				i++
				if i >= len(raw) {
					return "", fmt.Errorf("unterminated escape")
				}
				switch raw[i] {
				case '\\', '"':
					b.WriteByte(raw[i])
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					return "", fmt.Errorf("unsupported escape \\%c in a double-quoted value (put regular expressions in 'single quotes')", raw[i])
				}
			case '"':
				if rest := strings.TrimSpace(raw[i+1:]); rest != "" {
					return "", fmt.Errorf("unexpected text after the closing quote: %q", rest)
				}
				return b.String(), nil
			default:
				b.WriteByte(raw[i])
			}
		}
		return "", fmt.Errorf("unterminated double-quoted value")
	case '[', '{', '|', '>', '&', '*', '!':
		return "", fmt.Errorf("%q values are not supported; quote the text", string(raw[0]))
	}
	return raw, nil
}

func parseList(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	if raw[0] != '[' || raw[len(raw)-1] != ']' {
		return nil, fmt.Errorf("vendors: expected an inline list like [cisco, junos]")
	}
	inner := strings.TrimSpace(raw[1 : len(raw)-1])
	if inner == "" {
		return nil, nil
	}
	var out []string
	for _, p := range strings.Split(inner, ",") {
		s, err := parseScalar(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("vendors: %w", err)
		}
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// WriteRules prints rules in the file format ParseRules reads.
func WriteRules(w io.Writer, rules []Rule) error {
	var b strings.Builder
	b.WriteString("# netconfig audit rules. Several rules may share an id: on each device the\n")
	b.WriteString("# first rule whose vendors cover it applies; a platform with none is N/A.\n")
	b.WriteString("rules:\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "  - id: %s\n", r.ID)
		put := func(k, v string) {
			if v != "" {
				fmt.Fprintf(&b, "    %s: %s\n", k, quote(v))
			}
		}
		put("title", r.Title)
		fmt.Fprintf(&b, "    severity: %s\n", r.Severity)
		if len(r.Vendors) > 0 {
			fmt.Fprintf(&b, "    vendors: [%s]\n", strings.Join(r.Vendors, ", "))
		}
		put("block", r.Block)
		put("require", r.Require)
		put("forbid", r.Forbid)
		put("remediation", r.Remediation)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
