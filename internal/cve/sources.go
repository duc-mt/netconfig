// ==============================================================================
// File name:     sources.go
// Description:   Online advisory sources (NIST NVD 2.0, Cisco PSIRT openVuln,
//                OSV.dev) and the aggregator that merges them by CVE ID.
// License:       MIT
// ==============================================================================

package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Endpoints and limits.
const (
	// DefaultHTTPTimeout bounds every single HTTP request to an online source.
	DefaultHTTPTimeout = 8 * time.Second

	NVDBaseURL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	CiscoBaseURL  = "https://apix.cisco.com/security/advisories/v2"
	CiscoTokenURL = "https://id.cisco.com/oauth2/default/v1/token" // #nosec G101 -- an endpoint URL, not a credential
	OSVBaseURL    = "https://api.osv.dev"

	maxRetryWait = 2 * time.Minute
)

// maxResponseBytes caps what is read from any source: far above a real NVD
// page, small enough that a misbehaving server cannot exhaust memory.
var maxResponseBytes int64 = 64 << 20

// Scope says how a source's answer is keyed in the offline cache.
type Scope int

const (
	// ScopeProduct sources return everything known about a product (all
	// versions, with their ranges), so one answer serves every version.
	ScopeProduct Scope = iota
	// ScopeVersion sources evaluate one concrete version server-side, so the
	// answer is only valid for the version that was asked about.
	ScopeVersion
)

// ErrNotConfigured is returned by a source that needs credentials which were
// not supplied. It is not a failure: the source is simply skipped.
var ErrNotConfigured = errors.New("source not configured")

// Source is one online provider of advisories.
type Source interface {
	// Name is the value stored in Advisory.Source ("NVD", "CISCO", "OSV").
	Name() string
	Scope() Scope
	// Supports reports whether the source covers the product at all.
	Supports(p Product) bool
	// Fetch returns the advisories for the product. version is ignored by
	// ScopeProduct sources.
	Fetch(ctx context.Context, p Product, version string) ([]Record, error)
}

var defaultClient = &http.Client{Timeout: DefaultHTTPTimeout}

func clientOrDefault(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return defaultClient
}

// readBody reads a response body up to maxResponseBytes.
func readBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxResponseBytes {
		return nil, fmt.Errorf("response larger than %d MiB", maxResponseBytes>>20)
	}
	return body, nil
}

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryAfter parses a Retry-After header (seconds or an HTTP date).
func retryAfter(h http.Header) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(0, time.Until(t)), true
	}
	return 0, false
}

// parseTime reads the timestamp shapes used by the sources.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339Nano, "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// headline derives a short title from a description: its first sentence,
// shortened to 160 characters.
func headline(desc string) string {
	s := strings.Join(strings.Fields(desc), " ")
	if i := strings.Index(s, ". "); i >= 0 {
		s = s[:i+1]
	}
	if r := []rune(s); len(r) > 160 {
		s = string(r[:159]) + "…"
	}
	return s
}

// ---- NIST NVD API 2.0 -------------------------------------------------------------

// NVD queries the NIST National Vulnerability Database API 2.0 for every CVE
// filed against a product (virtualMatchString with a wildcard version) and
// keeps the version ranges NVD lists for it; Match then evaluates the device's
// version against those ranges. NVD is the baseline source: it covers every
// platform and is the only source whose absence makes a result untrustworthy.
type NVD struct {
	BaseURL    string        // default NVDBaseURL
	APIKey     string        // optional; raises NVD's rate limit tenfold
	Client     *http.Client  // default: DefaultHTTPTimeout per request
	MaxRetries int           // retries after HTTP 429/503; 0 means 4, negative means none
	Backoff    time.Duration // first retry delay, doubled each time; 0 means 2s
	PageGap    time.Duration // pause between pages; 0 means 6s (700ms with an API key)
	PageSize   int           // results per page; 0 means 500
}

// Name implements Source.
func (n *NVD) Name() string { return SourceNVD }

// Scope implements Source.
func (n *NVD) Scope() Scope { return ScopeProduct }

// Supports implements Source: NVD covers every product.
func (n *NVD) Supports(Product) bool { return true }

func (n *NVD) baseURL() string {
	if n.BaseURL != "" {
		return n.BaseURL
	}
	return NVDBaseURL
}

func (n *NVD) pageSize() int {
	if n.PageSize > 0 {
		return n.PageSize
	}
	return 500
}

func (n *NVD) pageGap() time.Duration {
	switch {
	case n.PageGap > 0:
		return n.PageGap
	case n.APIKey != "":
		return 700 * time.Millisecond
	}
	return 6 * time.Second
}

func (n *NVD) retries() int {
	switch {
	case n.MaxRetries > 0:
		return n.MaxRetries
	case n.MaxRetries < 0:
		return 0
	}
	return 4
}

func (n *NVD) backoff() time.Duration {
	if n.Backoff > 0 {
		return n.Backoff
	}
	return 2 * time.Second
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics        nvdMetrics `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			Negate   bool         `json:"negate"`
			CPEMatch []nvdCPEHash `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdCPEHash struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdMetrics struct {
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
	V40 []nvdMetric `json:"cvssMetricV40"`
	V2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdMetric struct {
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"` // CVSS v2 keeps it here
	CVSSData     struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"` // CVSS v3/v4 keep it here
	} `json:"cvssData"`
}

// Fetch implements Source. It pages through every result and refuses an empty
// answer: a platform that really has no CVEs in NVD is far less likely than a
// wrong product mapping or an outage, and an empty list would read as "clean".
func (n *NVD) Fetch(ctx context.Context, p Product, _ string) ([]Record, error) {
	var out []Record
	total := 0
	for start := 0; ; {
		page, err := n.page(ctx, p, start)
		if err != nil {
			return nil, err
		}
		total = page.TotalResults
		for _, v := range page.Vulnerabilities {
			if r, ok := nvdRecord(v.CVE, p); ok {
				out = append(out, r)
			}
		}
		start += len(page.Vulnerabilities)
		if len(page.Vulnerabilities) == 0 || start >= total {
			break
		}
		if err := sleepCtx(ctx, n.pageGap()); err != nil {
			return nil, err
		}
	}
	if total == 0 {
		return nil, fmt.Errorf("NVD returned no CVEs for %s; refusing to read an empty answer as \"not vulnerable\"", p.CPE())
	}
	return out, nil
}

func (n *NVD) page(ctx context.Context, p Product, start int) (nvdResponse, error) {
	q := url.Values{}
	q.Set("virtualMatchString", p.CPE())
	q.Set("resultsPerPage", strconv.Itoa(n.pageSize()))
	q.Set("startIndex", strconv.Itoa(start))
	body, err := n.get(ctx, n.baseURL()+"?"+q.Encode())
	if err != nil {
		return nvdResponse{}, err
	}
	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nvdResponse{}, fmt.Errorf("NVD: malformed response: %w", err)
	}
	return r, nil
}

// get performs one GET, retrying HTTP 429 and 503 with exponential backoff
// (or the server's Retry-After). Timeouts and other network errors are not
// retried: the caller falls back to the offline cache instead of stalling.
func (n *NVD) get(ctx context.Context, u string) ([]byte, error) {
	delay := n.backoff()
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "netops-cve")
		if n.APIKey != "" {
			req.Header.Set("apiKey", n.APIKey)
		}
		resp, err := clientOrDefault(n.Client).Do(req)
		if err != nil {
			return nil, fmt.Errorf("NVD request: %w", err)
		}
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
		if retryable && attempt < n.retries() {
			wait := delay
			if ra, ok := retryAfter(resp.Header); ok {
				wait = ra
			}
			_ = resp.Body.Close()
			if err := sleepCtx(ctx, min(wait, maxRetryWait)); err != nil {
				return nil, err
			}
			delay *= 2
			continue
		}
		if resp.StatusCode != http.StatusOK {
			msg := strings.TrimSpace(resp.Header.Get("message")) // NVD explains errors in this header
			_ = resp.Body.Close()
			if msg != "" {
				return nil, fmt.Errorf("NVD: HTTP %d: %s", resp.StatusCode, msg)
			}
			return nil, fmt.Errorf("NVD: HTTP %d", resp.StatusCode)
		}
		body, err := readBody(resp)
		if err != nil {
			return nil, fmt.Errorf("NVD: reading response: %w", err)
		}
		return body, nil
	}
}

// nvdRecord converts one NVD CVE into a Record holding only the version ranges
// that concern product p. Rejected CVEs and CVEs with nothing vulnerable for p
// (e.g. p appears only as the platform something else runs on) are dropped.
func nvdRecord(c nvdCVE, p Product) (Record, bool) {
	if strings.EqualFold(c.VulnStatus, "Rejected") || c.ID == "" {
		return Record{}, false
	}
	desc := ""
	for _, d := range c.Descriptions {
		if desc == "" || d.Lang == "en" {
			desc = d.Value
		}
		if d.Lang == "en" {
			break
		}
	}
	if strings.HasPrefix(desc, "** REJECT **") {
		return Record{}, false
	}

	var affects []Affect
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			if node.Negate {
				continue
			}
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				_, vend, prod, ver, upd, ok := parseCPE23(m.Criteria)
				if !ok || vend != p.Vendor || prod != p.Name {
					continue
				}
				a := Affect{
					Vendor: vend, Product: prod,
					StartIncluding: m.VersionStartIncluding, StartExcluding: m.VersionStartExcluding,
					EndIncluding: m.VersionEndIncluding, EndExcluding: m.VersionEndExcluding,
					Fixed: m.VersionEndExcluding, // NVD's exclusive end is the first fixed release
				}
				if ver != "*" && ver != "-" && ver != "" {
					a.Version = ver
					if upd != "" && upd != "*" && upd != "-" {
						a.Version += upd // Junos "20.4"+"r3-s2", PAN-OS "10.2.3"+"h4"
					}
				}
				if !containsAffect(affects, a) {
					affects = append(affects, a)
				}
			}
		}
	}
	if len(affects) == 0 {
		return Record{}, false
	}

	score, sev := nvdScore(c.Metrics)
	return Record{
		Advisory: Advisory{
			ID: c.ID, Source: SourceNVD, Title: headline(desc), Description: desc,
			Severity: sev, CVSS: score, Published: parseTime(c.Published),
			URL: "https://nvd.nist.gov/vuln/detail/" + c.ID,
		},
		Affects: affects,
	}, true
}

func containsAffect(list []Affect, a Affect) bool {
	for _, e := range list {
		if e == a {
			return true
		}
	}
	return false
}

// nvdScore picks the CVSS metric to report: v3.1, then v3.0, v4.0 and v2,
// preferring NVD's own (Primary) assessment over a CNA's (Secondary).
func nvdScore(m nvdMetrics) (float64, Severity) {
	for _, list := range [][]nvdMetric{m.V31, m.V30, m.V40, m.V2} {
		if len(list) == 0 {
			continue
		}
		pick := list[0]
		for _, x := range list {
			if strings.EqualFold(x.Type, "Primary") {
				pick = x
				break
			}
		}
		score := pick.CVSSData.BaseScore
		sev, ok := ParseSeverity(pick.CVSSData.BaseSeverity)
		if !ok {
			sev, ok = ParseSeverity(pick.BaseSeverity)
		}
		if !ok {
			sev = SeverityFromScore(score)
		}
		return score, sev
	}
	return 0, SeverityUnknown
}

// splitCPE splits a CPE 2.3 formatted string on its unescaped colons.
func splitCPE(s string) []string {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
		case s[i] == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(fields, cur.String())
}

// parseCPE23 reads "cpe:2.3:o:cisco:ios_xe:17.6.1:*:...". Backslash escapes
// ("15.2\(4\)m11") are removed from every field.
func parseCPE23(s string) (part, vend, prod, ver, upd string, ok bool) {
	f := splitCPE(s)
	if len(f) < 6 || f[0] != "cpe" || f[1] != "2.3" {
		return "", "", "", "", "", false
	}
	for i := range f {
		f[i] = strings.ReplaceAll(f[i], `\`, "")
	}
	part, vend, prod, ver = f[2], f[3], f[4], f[5]
	if len(f) > 6 {
		upd = f[6]
	}
	return part, vend, prod, ver, upd, true
}

// ---- Cisco PSIRT openVuln ----------------------------------------------------------

// CiscoPSIRT queries the Cisco PSIRT openVuln API, which lists Cisco security
// advisories for a given software version, often before NVD has analysed them.
// It needs OAuth2 client credentials (https://apiconsole.cisco.com); without
// them it reports ErrNotConfigured and is skipped.
type CiscoPSIRT struct {
	BaseURL      string       // default CiscoBaseURL
	TokenURL     string       // default CiscoTokenURL
	ClientID     string       // CISCO_PSIRT_CLIENT_ID
	ClientSecret string       // CISCO_PSIRT_CLIENT_SECRET
	Client       *http.Client // default: DefaultHTTPTimeout per request

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Name implements Source.
func (c *CiscoPSIRT) Name() string { return SourceCisco }

// Scope implements Source: openVuln answers for one version.
func (c *CiscoPSIRT) Scope() Scope { return ScopeVersion }

// Supports implements Source.
func (c *CiscoPSIRT) Supports(p Product) bool {
	_, ok := ciscoOSType(p)
	return ok
}

// ciscoOSType maps a product to the openVuln OSType path element.
func ciscoOSType(p Product) (string, bool) {
	if p.Vendor != "cisco" {
		return "", false
	}
	switch p.Name {
	case "ios":
		return "ios", true
	case "ios_xe":
		return "iosxe", true
	case "adaptive_security_appliance_software":
		return "asa", true
	case "firepower_threat_defense":
		return "ftd", true
	}
	return "", false
}

// ciscoVersion writes a version the way the openVuln API expects it: IOS XE
// without zero padding ("17.06.01" -> "17.6.1"), ASA with dots instead of
// parentheses ("9.16(2)" -> "9.16.2"), classic IOS unchanged.
func ciscoVersion(p Product, version string) string {
	v := strings.TrimSpace(version)
	switch p.Name {
	case "ios_xe":
		parts := strings.Split(v, ".")
		for i, part := range parts {
			j := 0
			for j < len(part) && isDigit(part[j]) {
				j++
			}
			if j == 0 {
				continue
			}
			d := strings.TrimLeft(part[:j], "0")
			if d == "" {
				d = "0"
			}
			parts[i] = d + part[j:]
		}
		return strings.Join(parts, ".")
	case "adaptive_security_appliance_software":
		return strings.NewReplacer("(", ".", ")", "").Replace(v)
	}
	return v
}

type ciscoAdvisories struct {
	Advisories []struct {
		AdvisoryID     string    `json:"advisoryId"`
		Title          string    `json:"advisoryTitle"`
		CVEs           []string  `json:"cves"`
		CVSS           flexFloat `json:"cvssBaseScore"`
		FirstFixed     []string  `json:"firstFixed"`
		FirstPublished string    `json:"firstPublished"`
		PublicationURL string    `json:"publicationUrl"`
		SIR            string    `json:"sir"`
		Summary        string    `json:"summary"`
	} `json:"advisories"`
}

// flexFloat reads a JSON number, a numeric string ("9.8") or junk ("NA", null,
// "") as 0 without failing the whole document.
type flexFloat float64

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if v, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
		*f = flexFloat(v)
	} else {
		*f = 0
	}
	return nil
}

// Fetch implements Source.
func (c *CiscoPSIRT) Fetch(ctx context.Context, p Product, version string) ([]Record, error) {
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, fmt.Errorf("%w: set CISCO_PSIRT_CLIENT_ID and CISCO_PSIRT_CLIENT_SECRET to enable Cisco PSIRT", ErrNotConfigured)
	}
	osType, ok := ciscoOSType(p)
	if !ok {
		return nil, fmt.Errorf("Cisco PSIRT does not cover %s", p.Key())
	}
	base := c.BaseURL
	if base == "" {
		base = CiscoBaseURL
	}
	u := strings.TrimRight(base, "/") + "/OSType/" + osType + "?" + url.Values{"version": {ciscoVersion(p, version)}}.Encode()

	var body []byte
	for attempt := 0; ; attempt++ {
		tok, err := c.accessToken(ctx)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := clientOrDefault(c.Client).Do(req)
		if err != nil {
			return nil, fmt.Errorf("Cisco PSIRT request: %w", err)
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			_ = resp.Body.Close()
			c.forgetToken() // expired or revoked: get a new one once
			continue
		case resp.StatusCode == http.StatusNotFound:
			_ = resp.Body.Close()
			return nil, nil // openVuln answers 404 when no advisory lists the version
		case resp.StatusCode != http.StatusOK:
			_ = resp.Body.Close()
			return nil, fmt.Errorf("Cisco PSIRT: HTTP %d", resp.StatusCode)
		}
		if body, err = readBody(resp); err != nil {
			return nil, fmt.Errorf("Cisco PSIRT: reading response: %w", err)
		}
		break
	}

	var doc ciscoAdvisories
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("Cisco PSIRT: malformed response: %w", err)
	}
	var out []Record
	for _, a := range doc.Advisories {
		var ids []string
		for _, id := range a.CVEs {
			if id = strings.ToUpper(strings.TrimSpace(id)); strings.HasPrefix(id, "CVE-") {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 && a.AdvisoryID != "" {
			ids = []string{a.AdvisoryID}
		}
		sev, ok := ParseSeverity(a.SIR)
		if !ok {
			sev = SeverityFromScore(float64(a.CVSS))
		}
		for _, id := range ids {
			out = append(out, Record{
				Advisory: Advisory{
					ID: id, Source: SourceCisco, Title: a.Title, Description: a.Summary,
					Severity: sev, CVSS: float64(a.CVSS), Published: parseTime(a.FirstPublished), URL: a.PublicationURL,
				},
				Affects: []Affect{{Vendor: p.Vendor, Product: p.Name, Version: strings.TrimSpace(version), Fixed: trainFix(a.FirstFixed, version)}},
			})
		}
	}
	return out, nil
}

// trainFix picks, from the first-fixed releases of every train, those of the
// device's own train (same major.minor); with none of them it lists them all.
func trainFix(fixes []string, version string) string {
	var all, same []string
	vt := tokenize(version)
	for _, f := range fixes {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		all = append(all, f)
		ft := tokenize(f)
		if len(vt) >= 2 && len(ft) >= 2 && cmpToken(vt[0], ft[0]) == 0 && cmpToken(vt[1], ft[1]) == 0 {
			same = append(same, f)
		}
	}
	if len(same) > 0 {
		return strings.Join(same, ", ")
	}
	return strings.Join(all, ", ")
}

func (c *CiscoPSIRT) forgetToken() {
	c.mu.Lock()
	c.token, c.expires = "", time.Time{}
	c.mu.Unlock()
}

// accessToken returns a cached OAuth2 client-credentials token, fetching a new
// one when it is missing or about to expire.
func (c *CiscoPSIRT) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	tokenURL := c.TokenURL
	if tokenURL == "" {
		tokenURL = CiscoTokenURL
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.ClientID}, "client_secret": {c.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := clientOrDefault(c.Client).Do(req)
	if err != nil {
		return "", fmt.Errorf("Cisco PSIRT token request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return "", fmt.Errorf("Cisco PSIRT token request: HTTP %d (check CISCO_PSIRT_CLIENT_ID/SECRET)", resp.StatusCode)
	}
	body, err := readBody(resp)
	if err != nil {
		return "", fmt.Errorf("Cisco PSIRT token response: %w", err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", errors.New("Cisco PSIRT token response has no access_token")
	}
	c.token = tok.AccessToken
	c.expires = time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)
	return c.token, nil
}

// ---- OSV.dev -------------------------------------------------------------------------

// OSVPackage names a package in an OSV ecosystem.
type OSVPackage struct {
	Name      string
	Ecosystem string
}

// OSV queries https://osv.dev for the advisories that affect one version of a
// package. OSV indexes open-source ecosystems (Go, PyPI, Debian, ...), not
// proprietary network operating systems, so it only engages for products that
// have an entry in Packages (keyed by Product.Key()); none of the built-in
// platforms do today. Map a product here when an OSV package tracks it.
type OSV struct {
	BaseURL  string // default OSVBaseURL
	Client   *http.Client
	Packages map[string]OSVPackage
}

// Name implements Source.
func (o *OSV) Name() string { return SourceOSV }

// Scope implements Source: OSV answers for one version.
func (o *OSV) Scope() Scope { return ScopeVersion }

// Supports implements Source.
func (o *OSV) Supports(p Product) bool {
	_, ok := o.Packages[p.Key()]
	return ok
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Modified string   `json:"modified"`
	// Published is the first publication time.
	Published string `json:"published"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// Fetch implements Source.
func (o *OSV) Fetch(ctx context.Context, p Product, version string) ([]Record, error) {
	pkg, ok := o.Packages[p.Key()]
	if !ok {
		return nil, fmt.Errorf("OSV has no package mapped for %s", p.Key())
	}
	base := o.BaseURL
	if base == "" {
		base = OSVBaseURL
	}
	endpoint := strings.TrimRight(base, "/") + "/v1/query"

	var out []Record
	token := ""
	for page := 0; page < 50; page++ { // a hard stop against a server that never ends the paging
		payload := map[string]any{
			"version": strings.TrimSpace(version),
			"package": map[string]string{"name": pkg.Name, "ecosystem": pkg.Ecosystem},
		}
		if token != "" {
			payload["page_token"] = token
		}
		buf, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := clientOrDefault(o.Client).Do(req)
		if err != nil {
			return nil, fmt.Errorf("OSV request: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("OSV: HTTP %d", resp.StatusCode)
		}
		body, err := readBody(resp)
		if err != nil {
			return nil, fmt.Errorf("OSV: reading response: %w", err)
		}
		var doc struct {
			Vulns         []osvVuln `json:"vulns"`
			NextPageToken string    `json:"next_page_token"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("OSV: malformed response: %w", err)
		}
		for _, v := range doc.Vulns {
			out = append(out, osvRecord(v, p, version))
		}
		if token = doc.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

func osvRecord(v osvVuln, p Product, version string) Record {
	id := v.ID
	for _, a := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			id = strings.ToUpper(a)
			break
		}
	}
	var score float64
	for _, s := range v.Severity {
		if sc, ok := cvss3Score(s.Score); ok {
			score = sc
			break
		}
	}
	sev, ok := ParseSeverity(v.DatabaseSpecific.Severity)
	if score > 0 {
		sev = SeverityFromScore(score)
	} else if !ok {
		sev = SeverityUnknown
	}
	u := "https://osv.dev/vulnerability/" + v.ID
	if len(v.References) > 0 && v.References[0].URL != "" {
		u = v.References[0].URL
	}
	fixed := ""
fixes:
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixed = e.Fixed
					break fixes
				}
			}
		}
	}
	title := v.Summary
	if title == "" {
		title = headline(v.Details)
	}
	return Record{
		Advisory: Advisory{
			ID: id, Source: SourceOSV, Title: title, Description: v.Details, Severity: sev, CVSS: score,
			Published: parseTime(v.Published), URL: u,
		},
		Affects: []Affect{{Vendor: p.Vendor, Product: p.Name, Version: strings.TrimSpace(version), Fixed: fixed}},
	}
}

// cvss3Score computes the base score of a CVSS v3.0/v3.1 vector such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (9.8). OSV publishes the
// vector, not the number. Other versions and malformed vectors report false.
func cvss3Score(vector string) (float64, bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 9 || (parts[0] != "CVSS:3.1" && parts[0] != "CVSS:3.0") {
		return 0, false
	}
	m := map[string]string{}
	for _, kv := range parts[1:] {
		k, v, ok := strings.Cut(kv, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	changed := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return 0, false
	}
	pick := func(key string, table map[string]float64) (float64, bool) {
		v, ok := table[m[key]]
		return v, ok
	}
	av, ok1 := pick("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := pick("AC", map[string]float64{"L": 0.77, "H": 0.44})
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok3 := pick("PR", prTable)
	ui, ok4 := pick("UI", map[string]float64{"N": 0.85, "R": 0.62})
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, ok5 := pick("C", cia)
	i, ok6 := pick("I", cia)
	a, ok7 := pick("A", cia)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp1(math.Min(1.08*(impact+expl), 10)), true
	}
	return roundUp1(math.Min(impact+expl, 10)), true
}

// roundUp1 is the CVSS v3.1 "Roundup": the smallest number with one decimal
// that is >= x, immune to floating point noise.
func roundUp1(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// ---- aggregation -----------------------------------------------------------------------

var sourceOrder = []string{SourceNVD, SourceCisco, SourceOSV, SourceCache}

func sourceRank(s string) int {
	for i, n := range sourceOrder {
		if n == s {
			return i
		}
	}
	return len(sourceOrder)
}

// Merge combines the records of several sources, one Record per CVE ID: the
// highest CVSS score (and its severity) wins, descriptions keep the longest
// text, the earliest publication date is kept, reference URLs and affected
// versions are united, Source lists every contributor ("NVD+CISCO"), and a
// Cisco-published title replaces NVD's derived headline. The result is sorted
// by ID.
func Merge(sets ...[]Record) []Record {
	byID := map[string]*Record{}
	var ids []string
	for _, set := range sets {
		for _, r := range set {
			key := strings.ToUpper(strings.TrimSpace(r.ID))
			if key == "" {
				continue
			}
			dst, ok := byID[key]
			if !ok {
				cp := r
				cp.Affects = append([]Affect(nil), r.Affects...)
				byID[key] = &cp
				ids = append(ids, key)
				continue
			}
			mergeInto(dst, r)
		}
	}
	sort.Strings(ids)
	out := make([]Record, 0, len(ids))
	for _, id := range ids {
		out = append(out, *byID[id])
	}
	return out
}

func mergeInto(dst *Record, src Record) {
	if src.Source == SourceCisco && !strings.Contains(dst.Source, SourceCisco) && src.Title != "" {
		dst.Title = src.Title
	} else if dst.Title == "" {
		dst.Title = src.Title
	}
	if len(src.Description) > len(dst.Description) {
		dst.Description = src.Description
	}
	switch {
	case src.CVSS > dst.CVSS:
		dst.CVSS, dst.Severity = src.CVSS, src.Severity
	case src.CVSS == dst.CVSS && src.Severity.Rank() > dst.Severity.Rank():
		dst.Severity = src.Severity
	}
	if dst.Published.IsZero() || (!src.Published.IsZero() && src.Published.Before(dst.Published)) {
		dst.Published = src.Published
	}
	dst.Source = joinSources(dst.Source, src.Source)
	dst.URL = joinURLs(dst.URL, src.URL)
	for _, a := range src.Affects {
		if !containsAffect(dst.Affects, a) {
			dst.Affects = append(dst.Affects, a)
		}
	}
}

func joinSources(a, b string) string {
	set := map[string]bool{}
	for _, s := range strings.Split(a+"+"+b, "+") {
		if s != "" {
			set[s] = true
		}
	}
	names := make([]string, 0, len(set))
	for s := range set {
		names = append(names, s)
	}
	sort.Slice(names, func(i, j int) bool {
		if ri, rj := sourceRank(names[i]), sourceRank(names[j]); ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	return strings.Join(names, "+")
}

func joinURLs(a, b string) string {
	var out []string
	for _, u := range strings.Fields(a + " " + b) {
		out = appendUnique(out, u)
	}
	return strings.Join(out, " ")
}
