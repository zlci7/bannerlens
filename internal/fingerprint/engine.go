// Package fingerprint identifies services from observed banner contents.
package fingerprint

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/zlci7/bannerlens/internal/model"
)

type rule struct {
	ID           string  `json:"id"`
	Priority     int     `json:"priority"`
	Source       string  `json:"source"`
	Pattern      string  `json:"pattern"`
	Protocol     string  `json:"protocol"`
	Product      string  `json:"product"`
	VersionGroup int     `json:"version_group"`
	ProductGroup int     `json:"product_group"`
	Confidence   float64 `json:"confidence"`
	re           *regexp.Regexp
}

type osRule struct {
	Pattern string `json:"pattern"`
	Hint    string `json:"hint"`
	re      *regexp.Regexp
}

type config struct {
	Rules   []rule   `json:"rules"`
	OSRules []osRule `json:"os_rules"`
}

// Engine is immutable after loading and safe for concurrent requests.
type Engine struct {
	rules   []rule
	osRules []osRule
}

// Load compiles and validates a rule file before the server becomes healthy.
func Load(path string) (*Engine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg config
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("rules must contain one JSON document")
	}
	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("rules must not be empty")
	}
	ids := make(map[string]bool)
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.ID == "" || ids[r.ID] {
			return nil, fmt.Errorf("rule %d: missing or duplicate id", i)
		}
		ids[r.ID] = true
		if r.Source != "banner" && r.Source != "http_headers" && r.Source != "mysql_version" {
			return nil, fmt.Errorf("rule %s: unsupported source %q", r.ID, r.Source)
		}
		if r.Protocol == "" || r.Protocol == "unknown" || r.Pattern == "" || math.IsNaN(r.Confidence) || r.Confidence <= 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("rule %s: invalid protocol, pattern or confidence", r.ID)
		}
		r.re, err = regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		if r.re.MatchString("") {
			return nil, fmt.Errorf("rule %s: pattern matches empty input", r.ID)
		}
		if r.VersionGroup < 0 || r.VersionGroup > r.re.NumSubexp() || r.ProductGroup < 0 || r.ProductGroup > r.re.NumSubexp() {
			return nil, fmt.Errorf("rule %s: capture group out of range", r.ID)
		}
	}
	for i := range cfg.OSRules {
		r := &cfg.OSRules[i]
		if r.Pattern == "" || r.Hint == "" {
			return nil, fmt.Errorf("OS rule %d: missing pattern or hint", i)
		}
		r.re, err = regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("OS rule %d: %w", i, err)
		}
		if r.re.MatchString("") {
			return nil, fmt.Errorf("OS rule %d: pattern matches empty input", i)
		}
	}
	sort.SliceStable(cfg.Rules, func(i, j int) bool { return cfg.Rules[i].Priority > cfg.Rules[j].Priority })
	return &Engine{rules: cfg.Rules, osRules: cfg.OSRules}, nil
}

// Identify returns unknown when the banner provides no supported evidence.
func (e *Engine) Identify(record model.Record) model.Result {
	result := model.Result{IP: record.IP, Port: record.Port, Protocol: "unknown"}
	if e == nil {
		return result
	}
	sources := map[string]string{"banner": record.Banner, "http_headers": httpHeaders(record.Banner), "mysql_version": mysqlVersion(record.Banner)}
	for _, r := range e.rules {
		// A recognized HTTP response owns its body; body text is not a new
		// transport greeting and must not select another protocol.
		if sources["http_headers"] != "" && r.Source != "http_headers" {
			continue
		}
		source := sources[r.Source]
		if source == "" {
			continue
		}
		m := r.re.FindStringSubmatch(source)
		if m == nil {
			continue
		}
		result.Protocol, result.Product, result.Confidence = r.Protocol, r.Product, r.Confidence
		if r.ProductGroup > 0 {
			result.Product = m[r.ProductGroup]
		}
		if r.VersionGroup > 0 {
			result.Version = m[r.VersionGroup]
		}
		// HTTP OS hints come only from headers, never from the response body.
		for _, o := range e.osRules {
			if o.re.MatchString(source) {
				result.OSHint = o.Hint
				break
			}
		}
		return result
	}
	return result
}

// IdentifyBatch preserves input order and returns a JSON-array-compatible empty slice.
func (e *Engine) IdentifyBatch(records []model.Record) []model.Result {
	results := make([]model.Result, len(records))
	for i, record := range records {
		results[i] = e.Identify(record)
	}
	return results
}

var httpStatus = regexp.MustCompile(`^HTTP/[0-9]+(?:\.[0-9]+)? [1-5][0-9]{2}(?:[ \t]|$)`)

func httpHeaders(banner string) string {
	// Scanners may supply headers without a terminating blank line.
	s := strings.ReplaceAll(banner, "\r\n", "\n")
	first, _, _ := strings.Cut(s, "\n")
	if !httpStatus.MatchString(first) {
		return ""
	}
	if i := strings.Index(s, "\n\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

func mysqlVersion(banner string) string {
	if version := mysqlPacketVersion([]byte(banner)); version != "" {
		return version
	}
	// JSON uses Unicode escapes. Scanners exporting bytes as \u00XX yield
	// UTF-8 after JSON decoding; reconstruct Latin-1 bytes for the header.
	b := make([]byte, 0, len(banner))
	for _, r := range banner {
		if r > 255 {
			return ""
		}
		b = append(b, byte(r))
	}
	return mysqlPacketVersion(b)
}

func mysqlPacketVersion(b []byte) string {
	// Protocol 10 greeting: 3-byte little-endian payload size, sequence 0,
	// protocol byte 10, followed by a NUL-terminated server version.
	// A scan can truncate later handshake fields while preserving the version.
	if len(b) < 7 || b[3] != 0 || b[4] != 10 {
		return ""
	}
	payloadLen := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	if payloadLen < 3 {
		return ""
	}
	end := len(b)
	if end > payloadLen+4 {
		end = payloadLen + 4
	}
	for i := 5; i < end; i++ {
		if b[i] == 0 {
			return string(b[5:i])
		}
	}
	return ""
}
