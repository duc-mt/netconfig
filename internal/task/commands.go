// ==============================================================================
// Package main implements Implementation and logic for commands..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run commands.go [options]
// Notes:         Go package implementation
// ==============================================================================
package task

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/template"

	"netconfig/internal/inventory"
	"netconfig/internal/vendor"
)

// CommandSource yields the configuration commands for one device.
type CommandSource func(d inventory.Device) ([]string, error)

// ParseCommands splits text into commands: one per line, surrounding
// whitespace removed, blank lines and lines starting with '#' or '!' skipped.
func ParseCommands(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// ReadCommandsFile loads a plain commands file; an empty file is an error.
func ReadCommandsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read commands file: %w", err)
	}
	cmds := ParseCommands(string(data))
	if len(cmds) == 0 {
		return nil, fmt.Errorf("commands file %s contains no commands", path)
	}
	return cmds, nil
}

// StaticCommands applies the same commands to every device.
func StaticCommands(cmds []string) CommandSource {
	return func(inventory.Device) ([]string, error) { return cmds, nil }
}

// TemplateData is what a command template can reference.
//
//	{{ .Hostname }} {{ .Address }} {{ .Port }} {{ .Vendor }} {{ .Group }}
//	{{ .Vars.name }}   (values given with -var name=value)
//
// .Vendor is the canonical vendor name (cisco, junos, huawei, fortinet,
// arista), so templates can branch with {{ if eq .Vendor "junos" }}.
type TemplateData struct {
	Hostname string
	Address  string
	Port     int
	Vendor   string
	Group    string
	Vars     map[string]string
}

// TemplateCommands renders text/template source once per device. A reference
// to an undefined variable is an error rather than silently rendering
// "<no value>" into a device configuration.
func TemplateCommands(text string, vars map[string]string) (CommandSource, error) {
	funcs := template.FuncMap{"upper": strings.ToUpper, "lower": strings.ToLower}
	tmpl, err := template.New("commands").Funcs(funcs).Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	if vars == nil {
		vars = map[string]string{}
	}
	return func(d inventory.Device) ([]string, error) {
		data := TemplateData{
			Hostname: d.Hostname,
			Address:  d.Address,
			Port:     d.Port,
			Vendor:   canonicalVendor(d.Vendor),
			Group:    d.Group,
			Vars:     vars,
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("render template for %s: %w", d.Hostname, err)
		}
		return ParseCommands(buf.String()), nil
	}, nil
}

// ReadTemplateFile loads a template file and prepares its CommandSource.
func ReadTemplateFile(path string, vars map[string]string) (CommandSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("template file is empty")
	}
	return TemplateCommands(string(data), vars)
}

func canonicalVendor(raw string) string {
	if p, ok := vendor.Lookup(raw); ok {
		return p.Name
	}
	return raw
}
