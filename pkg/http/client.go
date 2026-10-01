package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/majd/ipatool/v2/pkg/authdiag"
	"howett.net/plist"
)

const appStoreAuthPath = "/WebObjects/MZFinance.woa/wa/authenticate"

func isAppStoreAuthenticationPath(path string) bool {
	return path == appStoreAuthPath || path == appStoreAuthPath+"/"
}

var (
	documentXMLPattern = regexp.MustCompile(`(?is)<Document\b[^>]*>(.*)</Document>`)
	plistXMLPattern    = regexp.MustCompile(`(?is)<plist\b[^>]*>.*?</plist>`)
	dictXMLPattern     = regexp.MustCompile(`(?is)<dict\b[^>]*>.*</dict>`)
	htmlTagPattern     = regexp.MustCompile(`(?is)<[^>]*>`)
)

//go:generate go run go.uber.org/mock/mockgen -source=client.go -destination=client_mock.go -package=http
type Client[R interface{}] interface {
	Send(request Request) (Result[R], error)
	Do(req *http.Request) (*http.Response, error)
	NewRequest(method, url string, body io.Reader) (*http.Request, error)
}

type client[R interface{}] struct {
	internalClient http.Client
	cookieJar      CookieJar
	authentication bool
}

type Args struct {
	CookieJar CookieJar
	// Authentication isolates login connections and reports only allowlisted response diagnostics.
	Authentication bool
}

// UnexpectedResponseError preserves the HTTP status when Apple returns an
// HTML or empty response where an XML plist was expected.
type UnexpectedResponseError struct {
	StatusCode    int
	Snippet       string
	Reason        string
	BodyLength    int
	ContentType   string
	CorrelationID string
	RetryAfter    string
}

func (e *UnexpectedResponseError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("unexpected response from Apple (HTTP %d): %s (body length=%d, content type=%q, correlation ID=%q)", e.StatusCode, e.Reason, e.BodyLength, e.ContentType, e.CorrelationID)
	}

	if e.Snippet == "" {
		return fmt.Sprintf("unexpected response from Apple (HTTP %d): empty or non-plist body", e.StatusCode)
	}

	return fmt.Sprintf("unexpected response from Apple (HTTP %d): %s", e.StatusCode, e.Snippet)
}

type AddHeaderTransport struct {
	T http.RoundTripper
}

func (t *AddHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}

	res, err := t.T.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make round trip: %w", err)
	}

	return res, nil
}

func NewClient[R interface{}](args Args) Client[R] {
	transport := http.DefaultTransport

	if args.Authentication {
		// Keep the cookie jar, but do not share pooled connections with other
		// Store operations or reuse a connection for the next login attempt.
		isolated := http.DefaultTransport.(*http.Transport).Clone()
		isolated.DisableKeepAlives = true
		transport = isolated
	}

	return &client[R]{
		authentication: args.Authentication,
		internalClient: http.Client{
			Timeout: 0,
			Jar:     args.CookieJar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 && isAppStoreAuthenticationPath(via[len(via)-1].URL.Path) {
					return http.ErrUseLastResponse
				}

				return nil
			},
			Transport: &AddHeaderTransport{transport},
		},
		cookieJar: args.CookieJar,
	}
}

func (c *client[R]) Send(req Request) (result Result[R], sendErr error) {
	diagnostic := c.authenticationDiagnostic(req)
	if diagnostic != nil {
		defer func() { diagnostic.finish(sendErr) }()
	}
	var (
		data []byte
		err  error
	)

	if req.Payload != nil {
		data, err = req.Payload.data()
		if err != nil {
			return Result[R]{}, fmt.Errorf("failed to get payload data: %w", err)
		}
	}

	request, err := http.NewRequest(req.Method, req.URL, bytes.NewReader(data))
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to create request: %w", err)
	}

	for key, val := range req.Headers {
		request.Header.Set(key, val)
	}

	if req.ActionSigner != nil {
		signature, err := req.ActionSigner.Sign(data)
		if err != nil {
			return Result[R]{}, fmt.Errorf("failed to sign Apple action: %w", err)
		}

		request.Header.Set(HeaderAppleActionSignature, base64.StdEncoding.EncodeToString(signature))
	}

	if diagnostic != nil {
		diagnostic.event.SignaturePresent = request.Header.Get(HeaderAppleActionSignature) != ""
		if c.internalClient.Jar != nil {
			diagnostic.event.CookieCountBefore = len(c.internalClient.Jar.Cookies(request.URL))
		}
		event := diagnostic.event
		event.Kind = "http_request"
		authdiag.Emit(event)
		diagnostic.outcome = "network_error"
	}
	res, err := c.internalClient.Do(request)
	if err != nil {
		if diagnostic != nil {
			diagnostic.outcome = authenticationTransportOutcome(err)
			if c.internalClient.Jar != nil {
				diagnostic.event.CookieCountAfter = len(c.internalClient.Jar.Cookies(request.URL))
			}
		}
		return Result[R]{}, fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()
	if diagnostic != nil {
		diagnostic.response(res)
		if c.internalClient.Jar != nil {
			diagnostic.event.CookieCountAfter = len(c.internalClient.Jar.Cookies(request.URL))
		}
		diagnostic.outcome = "cookie_save_error"
	}

	err = c.cookieJar.Save()
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to save cookies: %w", err)
	}
	if diagnostic != nil {
		diagnostic.outcome = "error"
	}

	if req.ResponseFormat == ResponseFormatJSON {
		return c.handleJSONResponse(res, diagnostic)
	}

	if req.ResponseFormat == ResponseFormatRaw {
		return c.handleRawResponse(res, diagnostic)
	}

	if req.ResponseFormat == ResponseFormatXML {
		return c.handleXMLResponse(res, diagnostic)
	}

	return Result[R]{}, fmt.Errorf("content type is not supported (%s)", req.ResponseFormat)
}

// This context contains only allowlisted observations. Raw bodies, header
// values, URLs, errors and account identifiers must never be retained in it.
type authenticationHTTPDiagnostic struct {
	event    authdiag.Event
	started  time.Time
	received bool
	outcome  string
}

func (c *client[R]) authenticationDiagnostic(req Request) *authenticationHTTPDiagnostic {
	if !c.authentication || !authdiag.Enabled() {
		return nil
	}
	authPathTrailingSlash := false
	if parsed, err := url.Parse(req.URL); err == nil {
		authPathTrailingSlash = parsed.Path == appStoreAuthPath+"/"
	}
	return &authenticationHTTPDiagnostic{
		event: authdiag.Event{
			LoginID: req.DiagnosticLoginID, RequestID: authdiag.NextRequestID(),
			Stage: req.DiagnosticStage, Attempt: req.DiagnosticAttempt, Retry: req.DiagnosticRetry,
			Host: authdiag.Host(req.URL), AuthPathTrailingSlash: authPathTrailingSlash,
		},
		started: time.Now(), outcome: "request_error",
	}
}

func (d *authenticationHTTPDiagnostic) response(res *http.Response) {
	d.received = true
	d.event.Status = res.StatusCode
	d.event.ContentType = authenticationContentType(res.Header.Get("Content-Type"))
	d.event.SetCookieCount = len(res.Header.Values("Set-Cookie"))
	d.event.LocationPresent = len(res.Header.Values("Location")) != 0
	d.event.CorrelationIDPresent = len(res.Header.Values("X-Apple-Jingle-Correlation-Key")) != 0
	d.event.RetryAfterPresent = len(res.Header.Values("Retry-After")) != 0
	if d.event.LocationPresent {
		location := res.Header.Get("Location")
		d.event.RedirectHost = authdiag.Host(location)
		if parsed, err := url.Parse(location); err == nil {
			d.event.LocationAuthPath = isAppStoreAuthenticationPath(parsed.Path)
		}
	}
	switch res.Proto {
	case "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0":
		d.event.Protocol = res.Proto
	default:
		d.event.Protocol = "other"
	}
	d.event.TLSVersion = "none"
	if res.TLS != nil {
		switch res.TLS.Version {
		case tls.VersionTLS12:
			d.event.TLSVersion = "TLS1.2"
		case tls.VersionTLS13:
			d.event.TLSVersion = "TLS1.3"
		default:
			d.event.TLSVersion = "other"
		}
	}
}

func (d *authenticationHTTPDiagnostic) finish(err error) {
	d.event.Kind = "http_error"
	if d.received {
		d.event.Kind = "http_response"
	}
	d.event.Outcome = d.outcome
	if err == nil {
		d.event.Outcome = "ok"
	}
	d.event.DurationMS = time.Since(d.started).Milliseconds()
	authdiag.Emit(d.event)
}

func authenticationContentType(value string) string {
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	switch mediaType {
	case "", "text/html", "text/xml", "application/xml", "application/x-plist", "application/octet-stream", "text/plain", "application/json":
		return mediaType
	default:
		return "other"
	}
}

func observeAuthenticationBody(body []byte, readErr error, contexts []*authenticationHTTPDiagnostic) {
	if len(contexts) == 0 || contexts[0] == nil {
		return
	}
	d := contexts[0]
	d.event.BodyBytes = int64(len(body))
	d.event.BodyKind = authenticationBodyKind(body)
	if readErr != nil {
		d.outcome = "body_read_error"
	}
}

func authenticationBodyKind(body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return "empty"
	}
	// Classify a prefix using slices of the bytes already read for decoding;
	// do not make a second body copy or persist a sample or digest.
	for _, prefix := range []string{"<!doctype html", "<html", "<head", "<body"} {
		if len(body) >= len(prefix) && bytes.EqualFold(body[:len(prefix)], []byte(prefix)) {
			return "html"
		}
	}
	for _, prefix := range []string{"bplist", "<?xml", "<plist", "<dict", "<document"} {
		if len(body) >= len(prefix) && bytes.EqualFold(body[:len(prefix)], []byte(prefix)) {
			return "plist"
		}
	}
	return "other"
}

func authenticationTransportOutcome(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns_error"
	}
	var certificateErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	var authorityErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidCertificateErr x509.CertificateInvalidError
	if errors.As(err, &certificateErr) || errors.As(err, &recordErr) ||
		errors.As(err, &authorityErr) || errors.As(err, &hostnameErr) || errors.As(err, &invalidCertificateErr) {
		return "tls_error"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "network_error"
}

func (c *client[R]) handleRawResponse(res *http.Response, diagnostic ...*authenticationHTTPDiagnostic) (Result[R], error) {
	body, err := io.ReadAll(res.Body)
	observeAuthenticationBody(body, err, diagnostic)
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to read response body: %w", err)
	}

	data, ok := any(body).(R)
	if !ok {
		return Result[R]{}, errors.New("raw response format requires a []byte result type")
	}

	return Result[R]{
		StatusCode: res.StatusCode,
		Headers:    responseHeaders(res),
		Data:       data,
	}, nil
}

func (c *client[R]) Do(req *http.Request) (*http.Response, error) {
	res, err := c.internalClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("received error: %w", err)
	}

	return res, nil
}

func (*client[R]) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	return req, nil
}

func (c *client[R]) handleJSONResponse(res *http.Response, diagnostic ...*authenticationHTTPDiagnostic) (Result[R], error) {
	body, err := io.ReadAll(res.Body)
	observeAuthenticationBody(body, err, diagnostic)
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var data R

	err = json.Unmarshal(body, &data)
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to unmarshal json: %w", err)
	}

	return Result[R]{
		StatusCode: res.StatusCode,
		Data:       data,
	}, nil
}

func (c *client[R]) handleXMLResponse(res *http.Response, diagnostic ...*authenticationHTTPDiagnostic) (Result[R], error) {
	body, err := io.ReadAll(res.Body)
	observeAuthenticationBody(body, err, diagnostic)
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to read response body: %w", err)
	}

	if c.authentication && res.StatusCode == http.StatusFound && strings.TrimSpace(res.Header.Get("Location")) == "" {
		return Result[R]{}, authenticationResponseError(res, body, "authentication redirect is missing Location")
	}

	if !c.authentication && res.StatusCode == http.StatusTooManyRequests {
		return Result[R]{}, fmt.Errorf("rate limited by Apple (HTTP %d): %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	// The legacy authentication endpoint redirects to an assigned Store pod.
	// Preserve the redirect response and its Location header so callers can
	// repeat the original POST request at that pod.
	if res.StatusCode >= http.StatusMultipleChoices && res.StatusCode < http.StatusBadRequest {
		return Result[R]{
			StatusCode: res.StatusCode,
			Headers:    responseHeaders(res),
		}, nil
	}

	var data R

	normalizedBody := normalizeXMLPlistBody(body)

	if !looksLikePropertyList(normalizedBody) {
		if c.authentication {
			if res.StatusCode == http.StatusTooManyRequests {
				return Result[R]{}, authenticationResponseError(res, body, "rate limited by Apple")
			}

			return Result[R]{}, authenticationResponseError(res, body, "empty or non-plist authentication response")
		}

		snippet := bodySnippet(body)

		return Result[R]{}, &UnexpectedResponseError{
			StatusCode: res.StatusCode,
			Snippet:    snippet,
		}
	}

	_, err = plist.Unmarshal(normalizedBody, &data)
	if err != nil {
		if c.authentication {
			return Result[R]{}, authenticationResponseError(res, body, "malformed authentication plist")
		}

		return Result[R]{}, fmt.Errorf("failed to unmarshal xml: %w", err)
	}

	return Result[R]{
		StatusCode: res.StatusCode,
		Headers:    responseHeaders(res),
		Data:       data,
	}, nil
}

func responseHeaders(res *http.Response) map[string]string {
	headers := map[string]string{}
	for key, val := range res.Header {
		headers[key] = strings.Join(val, "; ")
	}

	return headers
}

func normalizeXMLPlistBody(body []byte) []byte {
	normalized := bytes.TrimSpace(body)
	if len(normalized) == 0 {
		return normalized
	}

	if documentBody := extractDocumentInnerBody(normalized); len(documentBody) > 0 {
		normalized = documentBody
	}

	if embeddedPlist := extractEmbeddedPlist(normalized); len(embeddedPlist) > 0 {
		normalized = embeddedPlist
	}

	if dictBody := extractEmbeddedDict(normalized); len(dictBody) > 0 {
		return dictBody
	}

	if bytes.Contains(normalized, []byte("<key>")) {
		return []byte("<dict>" + string(normalized) + "</dict>")
	}

	return normalized
}

// looksLikePropertyList reports whether body appears to be a (binary or XML)
// property list. Apple occasionally answers with an HTML error page or a plain
// text message; those must not be handed to plist.Unmarshal, which would
// misinterpret a leading "<h..." as an OpenStep hex-data block and fail with an
// opaque "unexpected hex digit" error instead of surfacing Apple's actual response.
func looksLikePropertyList(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}

	if bytes.HasPrefix(trimmed, []byte("bplist")) {
		return true
	}

	lower := bytes.ToLower(trimmed)
	for _, marker := range [][]byte{
		[]byte("<?xml"),
		[]byte("<plist"),
		[]byte("<dict"),
		[]byte("<key"),
	} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}

	return false
}

// bodySnippet returns a compact, single-line excerpt of a non-plist response
// body suitable for embedding in an error message. HTML markup is stripped so
// the underlying message (if any) is readable.
func bodySnippet(body []byte) string {
	text := htmlTagPattern.ReplaceAll(body, []byte(" "))
	snippet := strings.Join(strings.Fields(string(text)), " ")

	const maxLen = 200
	if len(snippet) > maxLen {
		snippet = snippet[:maxLen] + "…"
	}

	return snippet
}

func extractEmbeddedPlist(body []byte) []byte {
	plistMatch := plistXMLPattern.Find(body)
	if len(plistMatch) == 0 {
		return nil
	}

	return bytes.TrimSpace(plistMatch)
}

func extractEmbeddedDict(body []byte) []byte {
	dictMatch := dictXMLPattern.Find(body)
	if len(dictMatch) == 0 {
		return nil
	}

	return bytes.TrimSpace(dictMatch)
}

func extractDocumentInnerBody(body []byte) []byte {
	documentMatch := documentXMLPattern.FindSubmatch(body)
	if len(documentMatch) < 2 {
		return nil
	}

	documentBody := bytes.TrimSpace(documentMatch[1])
	if len(documentBody) == 0 {
		return nil
	}

	return documentBody
}

// Do not retain bodies or arbitrary response headers: authentication responses
// can contain credentials, tokens and cookies, including on failure.
func authenticationResponseError(res *http.Response, body []byte, reason string) *UnexpectedResponseError {
	return &UnexpectedResponseError{
		StatusCode:    res.StatusCode,
		Reason:        reason,
		BodyLength:    len(body),
		ContentType:   bodySnippet([]byte(res.Header.Get("Content-Type"))),
		CorrelationID: bodySnippet([]byte(res.Header.Get("X-Apple-Jingle-Correlation-Key"))),
		RetryAfter:    res.Header.Get("Retry-After"),
	}
}
