package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/strongdm/leash/internal/lsm"
)

// HeaderRewriteRule represents a single header rewrite rule
type HeaderRewriteRule struct {
	Host   string
	Header string
	Value  string
}

// String returns the canonical string representation of a HeaderRewriteRule
func (hr *HeaderRewriteRule) String() string {
	return fmt.Sprintf("allow http.rewrite %s header:%s:%s", hr.Host, hr.Header, hr.Value)
}

// headerTokenTable mirrors the RFC 7230 tchar grammar used by valid HTTP
// header field names. A header name is a token: one or more tchar bytes.
var headerTokenTable = [256]bool{
	'!': true, '#': true, '$': true, '%': true, '&': true, '\'': true,
	'*': true, '+': true, '-': true, '.': true, '^': true, '_': true,
	'`': true, '|': true, '~': true,
	'0': true, '1': true, '2': true, '3': true, '4': true,
	'5': true, '6': true, '7': true, '8': true, '9': true,
	'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true,
	'g': true, 'h': true, 'i': true, 'j': true, 'k': true, 'l': true,
	'm': true, 'n': true, 'o': true, 'p': true, 'q': true, 'r': true,
	's': true, 't': true, 'u': true, 'v': true, 'w': true, 'x': true,
	'y': true, 'z': true,
	'A': true, 'B': true, 'C': true, 'D': true, 'E': true, 'F': true,
	'G': true, 'H': true, 'I': true, 'J': true, 'K': true, 'L': true,
	'M': true, 'N': true, 'O': true, 'P': true, 'Q': true, 'R': true,
	'S': true, 'T': true, 'U': true, 'V': true, 'W': true, 'X': true,
	'Y': true, 'Z': true,
}

// validHeaderRewriteName reports whether name is a syntactically valid HTTP
// header field name (RFC 7230 token). CR/LF and any other non-token byte are
// rejected so a rule can never inject or split headers on the wire.
func validHeaderRewriteName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b >= 128 || !headerTokenTable[b] {
			return false
		}
	}
	return true
}

// validHeaderRewriteValue reports whether value is a safe HTTP header field
// value. Control characters (including CR and LF) are rejected outright;
// obs-text (0x80-0xFF) and horizontal tabs are permitted as the wire format
// allows them within a field value.
func validHeaderRewriteValue(value string) bool {
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b == '\t' {
			continue
		}
		if b < ' ' || b == 0x7f {
			return false
		}
	}
	return true
}

// ValidateHeaderRewriteRule checks a single header rewrite rule for ambiguous
// or otherwise unsafe header content that must never reach the proxy.
func ValidateHeaderRewriteRule(rule HeaderRewriteRule) error {
	host := strings.TrimSpace(rule.Host)
	header := strings.TrimSpace(rule.Header)
	if host == "" {
		return fmt.Errorf("header rewrite rule has empty host: %q", rule.String())
	}
	if header == "" {
		return fmt.Errorf("header rewrite rule for host %q has empty header name", host)
	}
	if !validHeaderRewriteName(header) {
		return fmt.Errorf("header rewrite rule for host %q has invalid header name %q (CR/LF and non-token characters are not allowed)", host, header)
	}
	if !validHeaderRewriteValue(rule.Value) {
		return fmt.Errorf("header rewrite rule for host %q header %q has an invalid value (CR/LF and control characters are not allowed)", host, header)
	}
	return nil
}

// ValidateHeaderRewriteRules validates a full rule set. It rejects any rule
// containing ambiguous header content as well as duplicate rules targeting the
// same host and header, since the last writer would silently win and leave the
// effective behavior ambiguous. Validation is all-or-nothing: callers must not
// publish any of the rules when an error is returned.
func ValidateHeaderRewriteRules(rules []HeaderRewriteRule) error {
	seen := make(map[string]struct{}, len(rules))
	for i, rule := range rules {
		if err := ValidateHeaderRewriteRule(rule); err != nil {
			return fmt.Errorf("invalid header rewrite rule at index %d: %w", i, err)
		}
		key := rule.Host + "\x00" + http.CanonicalHeaderKey(rule.Header)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate header rewrite target for host %q header %q: each host/header pair may be rewritten by at most one rule", rule.Host, rule.Header)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// HeaderRewriter manages header rewriting rules
type HeaderRewriter struct {
	rules        []HeaderRewriteRule
	mutex        sync.RWMutex
	sharedLogger *lsm.SharedLogger
}

func NewHeaderRewriter() *HeaderRewriter {
	return &HeaderRewriter{
		rules: make([]HeaderRewriteRule, 0),
	}
}

// SetSharedLogger sets the shared logger for event logging
func (hr *HeaderRewriter) SetSharedLogger(logger *lsm.SharedLogger) {
	hr.mutex.Lock()
	defer hr.mutex.Unlock()
	hr.sharedLogger = logger
}

func (hr *HeaderRewriter) LoadRulesFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		// If file doesn't exist, just continue with no rules
		if os.IsNotExist(err) {
			log.Printf("Header rewrite config file %s not found, continuing without header rewriting", filename)
			return nil
		}
		return fmt.Errorf("failed to open config file %s: %w", filename, err)
	}
	defer file.Close()

	hr.mutex.Lock()
	defer hr.mutex.Unlock()

	parsed := make([]HeaderRewriteRule, 0)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			log.Printf("Warning: Invalid rule format at line %d: %s (expected host:header:value)", lineNum, line)
			continue
		}

		rule := HeaderRewriteRule{
			Host:   strings.TrimSpace(parts[0]),
			Header: strings.TrimSpace(parts[1]),
			Value:  strings.TrimSpace(parts[2]),
		}

		if rule.Host == "" || rule.Header == "" {
			log.Printf("Warning: Empty host or header at line %d: %s", lineNum, line)
			continue
		}

		parsed = append(parsed, rule)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}

	// Validate the entire batch before publishing: ambiguous headers (CR/LF,
	// invalid names/values) and duplicate host/header targets fail the whole
	// load so the previously active rules remain in place.
	if err := ValidateHeaderRewriteRules(parsed); err != nil {
		return fmt.Errorf("refusing to load header rewrite config %s: %w", filename, err)
	}

	hr.rules = parsed
	return nil
}

// SetRules replaces the current rule set atomically. The full candidate set
// is validated first; when any rule is ambiguous (CR/LF content, invalid
// header name/value, or a duplicate host/header target) the existing rules
// are left untouched and an error is returned, so a failed update never
// publishes a partial rule set.
func (hr *HeaderRewriter) SetRules(rules []HeaderRewriteRule) error {
	if err := ValidateHeaderRewriteRules(rules); err != nil {
		return fmt.Errorf("rejecting header rewrite rule update: %w", err)
	}

	hr.mutex.Lock()
	defer hr.mutex.Unlock()

	// Copy to avoid external mutation
	newRules := make([]HeaderRewriteRule, len(rules))
	copy(newRules, rules)
	hr.rules = newRules

	return nil
}

// ApplyRules modifies the request headers based on the loaded rules
func (hr *HeaderRewriter) ApplyRules(req *http.Request) {
	hr.mutex.RLock()
	defer hr.mutex.RUnlock()

	// Debug logging
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}

	if len(hr.rules) == 0 {
		log.Printf("HeaderRewriter: No rules to apply")
		return
	}

	// Remove port if present
	if hostWithoutPort, _, err := net.SplitHostPort(host); err == nil {
		host = hostWithoutPort
	}

	for _, rule := range hr.rules {
		if rule.Host == host {
			// Defense in depth: rule ingestion validates every rule, but never
			// apply an ambiguous header even if one reaches the data plane.
			if err := ValidateHeaderRewriteRule(rule); err != nil {
				log.Printf("Warning: skipping unsafe header rewrite rule for host %q: %v", host, err)
				continue
			}
			// always rewrite the header, even if it's empty
			oldValue := req.Header.Get(rule.Header)
			req.Header.Set(rule.Header, rule.Value)

			// Log to shared event log
			if hr.sharedLogger != nil {
				timestamp := time.Now().Format(time.RFC3339)
				logEntry := fmt.Sprintf("time=%s event=http.rewrite addr=\"%s\" header=\"%s\" from=\"%s\" to=\"%s\" decision=allowed",
					timestamp, host, rule.Header, oldValue, rule.Value)
				_ = hr.sharedLogger.Write(logEntry)
			}
		}
	}
}
