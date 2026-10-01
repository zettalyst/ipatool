// Package authdiag writes opt-in authentication metadata. It never accepts raw
// payloads, header maps, cookie values, account identifiers, or errors.
package authdiag

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Kind                       string `json:"kind"`
	LoginID                    uint64 `json:"loginId,omitempty"`
	RequestID                  uint64 `json:"requestId,omitempty"`
	Stage                      string `json:"stage,omitempty"`
	Attempt                    int    `json:"attempt,omitempty"`
	Retry                      int    `json:"retry,omitempty"`
	Host                       string `json:"host,omitempty"`
	RedirectHost               string `json:"redirectHost,omitempty"`
	Status                     int    `json:"status,omitempty"`
	DurationMS                 int64  `json:"durationMs,omitempty"`
	WaitMS                     int64  `json:"waitMs,omitempty"`
	BodyBytes                  int64  `json:"bodyBytes"`
	BodyKind                   string `json:"bodyKind,omitempty"`
	ContentType                string `json:"contentType,omitempty"`
	CookieCountBefore          int    `json:"cookieCountBefore"`
	CookieCountAfter           int    `json:"cookieCountAfter"`
	SetCookieCount             int    `json:"setCookieCount"`
	SignaturePresent           bool   `json:"signaturePresent,omitempty"`
	AuthPathTrailingSlash      bool   `json:"authPathTrailingSlash,omitempty"`
	LocationPresent            bool   `json:"locationPresent,omitempty"`
	LocationAuthPath           bool   `json:"locationAuthPath,omitempty"`
	CorrelationIDPresent       bool   `json:"correlationIdPresent,omitempty"`
	RetryAfterPresent          bool   `json:"retryAfterPresent,omitempty"`
	Protocol                   string `json:"protocol,omitempty"`
	TLSVersion                 string `json:"tlsVersion,omitempty"`
	Outcome                    string `json:"outcome,omitempty"`
	FailureTypePresent         bool   `json:"failureTypePresent,omitempty"`
	PasswordTokenPresent       bool   `json:"passwordTokenPresent,omitempty"`
	DirectoryServicesIDPresent bool   `json:"directoryServicesIdPresent,omitempty"`
}

var state struct {
	sync.Mutex
	file    *os.File
	started time.Time
	err     error
}
var loginSequence atomic.Uint64
var requestSequence atomic.Uint64
var podHost = regexp.MustCompile(`^p[0-9]{1,3}-buy\.itunes\.apple\.com$`)

func Start(path string) error {
	state.Lock()
	defer state.Unlock()
	if state.file != nil {
		return errors.New("authentication diagnostics already active")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create new private authentication diagnostic file")
	}
	state.file, state.started, state.err = f, time.Now(), nil
	return nil
}

func Enabled() bool {
	state.Lock()
	defer state.Unlock()
	return state.file != nil
}

func NextLoginID() uint64   { return loginSequence.Add(1) }
func NextRequestID() uint64 { return requestSequence.Add(1) }

func enum(value string, allowed ...string) string {
	if value == "" {
		return ""
	}
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "other"
}

// Host accepts a URL or hostname but emits only canonical root/numeric pod
// names. Arbitrary subdomains, userinfo, paths, queries, ports and fragments
// cannot reach the log. Unknown destinations receive a constant category.
func Host(raw string) string {
	host := raw
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "other"
		}
		host = u.Hostname()
	}
	host = strings.ToLower(host)
	if host == "buy.itunes.apple.com" || podHost.MatchString(host) {
		return host
	}
	return enum(host, "other", "none")
}

func Emit(e Event) {
	state.Lock()
	defer state.Unlock()
	if state.file == nil || state.err != nil {
		return
	}
	e.Kind = enum(e.Kind, "diagnostic_started", "diagnostic_finished", "login_started", "bag_completed", "signer_ready", "signer_closed", "login_request", "login_response", "retry_wait", "login_finished", "http_request", "http_response", "http_error")
	e.Stage = enum(e.Stage, "sign-in", "2fa")
	e.Outcome = enum(e.Outcome, "ok", "error", "challenge", "credential_error", "invalid_response", "bag_error", "signer_error", "network_error", "timeout", "dns_error", "tls_error", "body_read_error", "cookie_save_error", "request_error")
	if e.Host != "" {
		e.Host = Host(e.Host)
	}
	if e.RedirectHost != "" {
		e.RedirectHost = Host(e.RedirectHost)
	}
	e.ContentType = enum(strings.ToLower(strings.TrimSpace(strings.SplitN(e.ContentType, ";", 2)[0])), "text/html", "text/xml", "application/xml", "application/x-plist", "application/octet-stream", "text/plain", "application/json")
	e.BodyKind = enum(e.BodyKind, "empty", "html", "plist", "other")
	e.Protocol = enum(e.Protocol, "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0")
	e.TLSVersion = enum(e.TLSVersion, "TLS1.2", "TLS1.3", "none")
	row := struct {
		ElapsedMS int64 `json:"elapsedMs"`
		Event
	}{time.Since(state.started).Milliseconds(), e}
	state.err = json.NewEncoder(state.file).Encode(row)
}

// Close reports write/flush failures using a fixed message, never an underlying
// error that could contain a pathname or transport data.
func Close() error {
	state.Lock()
	defer state.Unlock()
	if state.file == nil {
		return nil
	}
	writeErr := state.err
	syncErr := state.file.Sync()
	closeErr := state.file.Close()
	state.file = nil
	state.err = nil
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("authentication diagnostic write or close failed")
	}
	return nil
}
