// ==============================================================================
// Package main implements Implementation and logic for inventory..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run inventory.go [options]
// Notes:         Go package implementation
// ==============================================================================
// Package inventory parses the device inventory CSV:
//
//	hostname,address,port,vendor,credential_group
//
// A header row, blank lines and '#' comment lines are allowed. An empty port
// defaults to 22 and an empty credential_group defaults to "default".
package inventory

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	DefaultPort  = 22
	DefaultGroup = "default"
)

// Device is one target row of the inventory.
type Device struct {
	Hostname string
	Address  string
	Port     int
	Vendor   string // as written in the CSV (trimmed, lower-cased); resolved by package vendor
	Group    string // credential group
	Line     int    // 1-based source line, for diagnostics
}

// Endpoint returns host:port for net.Dial (IPv6-safe).
func (d Device) Endpoint() string {
	return net.JoinHostPort(d.Address, strconv.Itoa(d.Port))
}

// Load reads and parses the inventory file at p.
func Load(p string) ([]Device, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open inventory: %w", err)
	}
	defer f.Close()
	devs, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("inventory %s: %w", p, err)
	}
	return devs, nil
}

// Parse reads an inventory from r. All row errors are collected and returned
// together (with line numbers) so an operator can fix the file in one pass.
func Parse(r io.Reader) ([]Device, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true

	var (
		devices []Device
		errs    []error
		seen    = make(map[string]int)
		first   = true
	)
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			errs = append(errs, err)
			break
		}
		line, _ := cr.FieldPos(0)

		if first {
			first = false
			rec[0] = strings.TrimPrefix(rec[0], "\ufeff")
			if strings.EqualFold(strings.TrimSpace(rec[0]), "hostname") {
				continue // header row
			}
		}
		if len(rec) < 4 || len(rec) > 5 {
			errs = append(errs, fmt.Errorf("line %d: expected 4 or 5 fields (hostname,address,port,vendor[,credential_group]), got %d", line, len(rec)))
			continue
		}
		for i := range rec {
			rec[i] = strings.TrimSpace(rec[i])
		}

		d := Device{
			Hostname: rec[0],
			Address:  rec[1],
			Port:     DefaultPort,
			Vendor:   strings.ToLower(rec[3]),
			Group:    DefaultGroup,
			Line:     line,
		}
		if len(rec) == 5 && rec[4] != "" {
			d.Group = rec[4]
		}

		var problems []string
		switch {
		case d.Hostname == "":
			problems = append(problems, "hostname is empty")
		case strings.ContainsAny(d.Hostname, " \t/\\"):
			problems = append(problems, fmt.Sprintf("hostname %q must not contain whitespace or path separators", d.Hostname))
		}
		if d.Address == "" {
			problems = append(problems, "address is empty")
		}
		if rec[2] != "" {
			p, perr := strconv.Atoi(rec[2])
			if perr != nil || p < 1 || p > 65535 {
				problems = append(problems, fmt.Sprintf("invalid port %q (want 1-65535)", rec[2]))
			} else {
				d.Port = p
			}
		}
		if d.Vendor == "" {
			problems = append(problems, "vendor is empty")
		}
		if len(problems) > 0 {
			errs = append(errs, fmt.Errorf("line %d: %s", line, strings.Join(problems, "; ")))
			continue
		}

		key := strings.ToLower(d.Hostname)
		if prev, dup := seen[key]; dup {
			errs = append(errs, fmt.Errorf("line %d: duplicate hostname %q (first defined on line %d)", line, d.Hostname, prev))
			continue
		}
		seen[key] = line
		devices = append(devices, d)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(devices) == 0 {
		return nil, errors.New("inventory contains no devices")
	}
	return devices, nil
}

// Filter keeps the devices selected by patterns. A pattern is a case-insensitive
// glob matched against the hostname ("core-*"), or against the credential group
// when prefixed with '@' ("@dc1"). No patterns means "everything". A pattern
// that matches nothing is an error, which catches typos before anything runs.
func Filter(devs []Device, patterns []string) ([]Device, error) {
	var pats []string
	for _, p := range patterns {
		if p = strings.TrimSpace(p); p != "" {
			pats = append(pats, p)
		}
	}
	if len(pats) == 0 {
		return devs, nil
	}
	for _, p := range pats {
		if _, err := path.Match(strings.TrimPrefix(p, "@"), ""); err != nil {
			return nil, fmt.Errorf("invalid -limit pattern %q: %w", p, err)
		}
	}
	used := make([]bool, len(pats))
	var out []Device
	for _, d := range devs {
		matched := false
		for i, p := range pats {
			if matches(d, p) {
				used[i] = true
				matched = true
			}
		}
		if matched {
			out = append(out, d)
		}
	}
	for i, p := range pats {
		if !used[i] {
			return nil, fmt.Errorf("-limit pattern %q matches no device", p)
		}
	}
	return out, nil
}

func matches(d Device, pattern string) bool {
	pattern = strings.ToLower(pattern)
	subject := strings.ToLower(d.Hostname)
	if strings.HasPrefix(pattern, "@") {
		pattern = pattern[1:]
		subject = strings.ToLower(d.Group)
	}
	ok, err := path.Match(pattern, subject)
	return err == nil && ok
}
