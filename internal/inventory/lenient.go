// ==============================================================================
// File name:     lenient.go
// Description:   Forgiving inventory loader used by "netops log": a malformed
//                row is reported and skipped instead of aborting the load.
// License:       MIT
// ==============================================================================

package inventory

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// DefaultLogVendor is the platform assumed for a lenient row that omits the
// vendor column; it selects the generic log parser.
const DefaultLogVendor = "generic"

// LoadLenient reads the inventory file at path for the log monitor. Unlike
// Load, one bad row never stops the run: malformed rows are returned as
// warnings (with line numbers) and the valid rows are still returned. The
// error slice also carries a failure to open the file, in which case no
// devices are returned.
//
// Rules, chosen to make hand-editing forgiving:
//   - blank lines and lines starting with '#' are skipped
//   - the header line is detected and skipped automatically
//   - only hostname and address are required; port defaults to 22, vendor to
//     "generic" and credential_group to "default"
//   - credential_group and jump_host are stored lower-cased
func LoadLenient(path string) ([]Device, []error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, []error{fmt.Errorf("opening inventory file %q: %w", path, err)}
	}
	defer f.Close()
	return ParseLenient(f)
}

// ParseLenient is LoadLenient over an arbitrary reader.
func ParseLenient(r io.Reader) ([]Device, []error) {
	var (
		devices  []Device
		warnings []error
	)

	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.Comment = '#'
	cr.TrimLeadingSpace = true

	lineNo := 0
	headerSkipped := false
	for {
		lineNo++
		record, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			warnings = append(warnings, fmt.Errorf("line %d: parsing CSV: %w", lineNo, err))
			continue
		}
		if len(record) == 0 {
			continue
		}

		fields := make([]string, len(record))
		for i, v := range record {
			fields[i] = strings.TrimSpace(v)
		}
		if len(fields) == 1 && fields[0] == "" {
			continue
		}

		if !headerSkipped && strings.EqualFold(strings.TrimPrefix(fields[0], "\ufeff"), "hostname") {
			headerSkipped = true
			continue
		}
		headerSkipped = true

		dev, err := parseLenientRow(fields, lineNo)
		if err != nil {
			warnings = append(warnings, err)
			continue
		}
		devices = append(devices, dev)
	}
	return devices, warnings
}

func parseLenientRow(fields []string, lineNo int) (Device, error) {
	if len(fields) < 2 {
		return Device{}, fmt.Errorf("line %d: expected at least hostname,address -- got %q", lineNo, strings.Join(fields, ","))
	}

	dev := Device{
		Hostname: fields[0],
		Address:  fields[1],
		Port:     DefaultPort,
		Vendor:   DefaultLogVendor,
		Group:    DefaultGroup,
		Line:     lineNo,
	}
	if dev.Hostname == "" || dev.Address == "" {
		return Device{}, fmt.Errorf("line %d: hostname and address are required", lineNo)
	}

	if len(fields) >= 3 && fields[2] != "" {
		port, err := strconv.Atoi(fields[2])
		if err != nil || port <= 0 || port > 65535 {
			return Device{}, fmt.Errorf("line %d: invalid port %q", lineNo, fields[2])
		}
		dev.Port = port
	}
	if len(fields) >= 4 && fields[3] != "" {
		dev.Vendor = strings.ToLower(fields[3])
	}
	if len(fields) >= 5 && fields[4] != "" {
		dev.Group = strings.ToLower(fields[4])
	}
	if len(fields) >= 6 && fields[5] != "" {
		dev.JumpHost = strings.ToLower(fields[5])
	}
	return dev, nil
}
