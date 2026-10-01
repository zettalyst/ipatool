package http

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/majd/ipatool/v2/pkg/authdiag"
)

type diagnosticRoundTripper func(*http.Request) (*http.Response, error)

func (f diagnosticRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type diagnosticCookieJar struct {
	*cookiejar.Jar
	cookieReads int
	saves       int
	saveError   error
}

func (j *diagnosticCookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.cookieReads++
	return j.Jar.Cookies(u)
}

func (j *diagnosticCookieJar) Save() error {
	j.saves++
	return j.saveError
}

func newDiagnosticClient(t *testing.T, authentication bool, transport diagnosticRoundTripper) (*client[map[string]string], *diagnosticCookieJar) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	j := &diagnosticCookieJar{Jar: jar}
	c := NewClient[map[string]string](Args{CookieJar: j, Authentication: authentication}).(*client[map[string]string])
	// Every request is intercepted in memory, including any attempted redirect.
	c.internalClient.Transport = transport
	return c, j
}

func beginDiagnosticLog(t *testing.T) func() ([]authdiag.Event, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "diagnostic.jsonl")
	if err := authdiag.Start(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authdiag.Close(); err != nil {
			t.Error(err)
		}
	})
	return func() ([]authdiag.Event, string) {
		t.Helper()
		if err := authdiag.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var events []authdiag.Event
		decoder := json.NewDecoder(bytes.NewReader(data))
		for {
			var event authdiag.Event
			if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			events = append(events, event)
		}
		return events, string(data)
	}
}

func diagnosticRequest() Request {
	return Request{
		URL:    "https://buy.itunes.apple.com" + appStoreAuthPath + "?SENTINEL_REQUEST_QUERY",
		Method: MethodPOST, ResponseFormat: ResponseFormatXML,
		DiagnosticLoginID: 37, DiagnosticStage: "sign-in", DiagnosticAttempt: 2, DiagnosticRetry: 3,
	}
}

func diagnosticResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)),
		Proto: "HTTP/2.0", ProtoMajor: 2, TLS: &tls.ConnectionState{Version: tls.VersionTLS13},
	}
}

func assertDiagnosticRedaction(t *testing.T, log string, extra ...string) {
	t.Helper()
	for _, forbidden := range append([]string{"SENTINEL", "sentinel", appStoreAuthPath, "?", "<dict", "<html"}, extra...) {
		if strings.Contains(log, forbidden) {
			t.Errorf("diagnostic log leaked forbidden marker %q", forbidden)
		}
	}
}

func TestAuthenticationDiagnosticsPreserveSignedRequestAndResponse(t *testing.T) {
	finish := beginDiagnosticLog(t)
	body := "<dict><key>token</key><string>SENTINEL_RESPONSE_TOKEN</string></dict>"
	signer := &recordingActionSigner{signature: []byte("SENTINEL_ACTION_SIGNATURE")}
	payload := []byte("<dict><key>password</key><string>SENTINEL_PASSWORD</string></dict>")
	calls := 0
	c, jar := newDiagnosticClient(t, true, func(r *http.Request) (*http.Response, error) {
		calls++
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if r.Method != MethodPOST || !bytes.Equal(data, payload) || !bytes.Equal(signer.data, payload) {
			t.Fatal("diagnostics changed the signed request method or payload")
		}
		if r.Header.Get(HeaderAppleActionSignature) != base64.StdEncoding.EncodeToString(signer.signature) {
			t.Fatal("diagnostics changed the action signature")
		}
		res := diagnosticResponse(http.StatusOK, body)
		res.Header.Set("Content-Type", "application/xml; SENTINEL_CONTENT_TYPE_PARAMETER")
		res.Header.Set("Location", "https://SENTINEL_USER:SENTINEL_PASS@p42-buy.itunes.apple.com"+appStoreAuthPath+"?SENTINEL_LOCATION_QUERY#SENTINEL_FRAGMENT")
		res.Header.Add("Set-Cookie", "SENTINEL_COOKIE_NAME=SENTINEL_COOKIE_VALUE; Path=/; Secure")
		res.Header.Add("Set-Cookie", "SENTINEL_SECOND_COOKIE=SENTINEL_SECOND_VALUE; Path=/; Secure")
		res.Header.Set("X-Apple-Jingle-Correlation-Key", "SENTINEL_CORRELATION")
		res.Header.Set("Retry-After", "SENTINEL_RETRY_AFTER")
		return res, nil
	})
	u, _ := url.Parse(diagnosticRequest().URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "SENTINEL_EXISTING_COOKIE", Value: "SENTINEL_EXISTING_VALUE", Path: "/", Secure: true}})
	req := diagnosticRequest()
	req.Payload = &RawPayload{Content: payload}
	req.ActionSigner = signer
	req.Headers = map[string]string{"Authorization": "SENTINEL_AUTHORIZATION"}
	result, err := c.Send(req)
	if err != nil || result.Data["token"] != "SENTINEL_RESPONSE_TOKEN" || calls != 1 || signer.calls != 1 || jar.saves != 1 {
		t.Fatalf("authentication behavior changed: err=%v calls=%d signs=%d saves=%d", err, calls, signer.calls, jar.saves)
	}
	events, log := finish()
	assertDiagnosticRedaction(t, log, base64.StdEncoding.EncodeToString(signer.signature))
	if len(events) != 2 || events[0].Kind != "http_request" || events[1].Kind != "http_response" {
		t.Fatalf("unexpected event sequence: %#v", events)
	}
	e := events[1]
	if e.RequestID == 0 || e.RequestID != events[0].RequestID || e.LoginID != 37 || e.Stage != "sign-in" || e.Attempt != 2 || e.Retry != 3 {
		t.Fatalf("missing request correlation: %#v", e)
	}
	if e.Host != "buy.itunes.apple.com" || e.RedirectHost != "p42-buy.itunes.apple.com" || e.Status != 200 || e.Outcome != "ok" {
		t.Fatalf("incorrect safe response metadata: %#v", e)
	}
	if e.BodyBytes != int64(len(body)) || e.BodyKind != "plist" || e.ContentType != "application/xml" || e.CookieCountBefore != 1 || e.CookieCountAfter != 3 || e.SetCookieCount != 2 {
		t.Fatalf("incorrect body or cookie observations: %#v", e)
	}
	if !e.SignaturePresent || !e.LocationPresent || !e.LocationAuthPath || !e.CorrelationIDPresent || !e.RetryAfterPresent || e.Protocol != "HTTP/2.0" || e.TLSVersion != "TLS1.3" || e.DurationMS < 0 {
		t.Fatalf("missing protocol/header presence observations: %#v", e)
	}
}

func TestAuthenticationDiagnosticsClassifyWithoutLoggingResponseContent(t *testing.T) {
	for _, tc := range []struct {
		name, body, kind string
		status           int
		wantError        bool
	}{
		{"html", "<html>SENTINEL_HTML_BODY</html>", "html", 403, true},
		{"empty", "", "empty", 204, true},
		{"redirect", "SENTINEL_REDIRECT_BODY", "other", 301, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			finish := beginDiagnosticLog(t)
			calls := 0
			c, _ := newDiagnosticClient(t, true, func(r *http.Request) (*http.Response, error) {
				calls++
				res := diagnosticResponse(tc.status, tc.body)
				res.Header.Set("Content-Type", "SENTINEL_MALICIOUS_CONTENT_TYPE")
				res.Header.Set("Location", "https://SENTINEL_HOST.example/SENTINEL_PATH?SENTINEL_QUERY")
				res.Header.Set("Set-Cookie", "SENTINEL_COOKIE=SENTINEL_VALUE")
				return res, nil
			})
			result, err := c.Send(diagnosticRequest())
			if (err != nil) != tc.wantError || calls != 1 {
				t.Fatalf("response behavior changed: err=%v calls=%d", err, calls)
			}
			if !tc.wantError && result.StatusCode != tc.status {
				t.Fatal("redirect status was not preserved")
			}
			events, log := finish()
			assertDiagnosticRedaction(t, log)
			if len(events) != 2 {
				t.Fatalf("unexpected event count: %d", len(events))
			}
			e := events[1]
			if e.BodyKind != tc.kind || e.BodyBytes != int64(len(tc.body)) || e.ContentType != "other" || e.RedirectHost != "other" || e.LocationAuthPath || !e.LocationPresent || e.Status != tc.status {
				t.Fatalf("incorrect safe response classification: %#v", e)
			}
		})
	}
}

func TestAuthenticationDiagnosticsReportOnlyExactAuthPathShapes(t *testing.T) {
	for _, tc := range []struct {
		name, requestSuffix, locationSuffix string
		wantTrailingSlash, wantLocationAuth bool
	}{
		{"base", "", "", false, true},
		{"single slash", "/", "/", true, true},
		{"slash request base redirect", "/", "", true, true},
		{"base request double slash redirect", "", "//", false, false},
		{"double slash request", "//", "", false, true},
		{"extra path component", "/SENTINEL_REQUEST_PATH", "/SENTINEL_LOCATION_PATH", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			finish := beginDiagnosticLog(t)
			c, _ := newDiagnosticClient(t, true, func(*http.Request) (*http.Response, error) {
				res := diagnosticResponse(http.StatusOK, "<dict><key>ok</key><string>yes</string></dict>")
				res.Header.Set("Location", "https://p42-buy.itunes.apple.com"+appStoreAuthPath+tc.locationSuffix+"?SENTINEL_QUERY")
				return res, nil
			})
			req := diagnosticRequest()
			req.URL = "https://buy.itunes.apple.com" + appStoreAuthPath + tc.requestSuffix + "?SENTINEL_REQUEST_QUERY"
			if _, err := c.Send(req); err != nil {
				t.Fatal(err)
			}
			events, log := finish()
			assertDiagnosticRedaction(t, log)
			if len(events) != 2 {
				t.Fatalf("got %d events; want request and response", len(events))
			}
			for _, event := range events {
				if event.AuthPathTrailingSlash != tc.wantTrailingSlash {
					t.Fatal("request path classification accepted an incorrect path shape")
				}
			}
			if events[1].LocationAuthPath != tc.wantLocationAuth {
				t.Fatal("redirect path classification accepted an incorrect path shape")
			}
			if strings.Contains(log, `"authPathTrailingSlash":true`) != tc.wantTrailingSlash {
				t.Fatal("serialized trailing-slash flag did not match request path")
			}
		})
	}
}

func TestAuthenticationDiagnosticsSanitizeTransportFailures(t *testing.T) {
	for _, tc := range []struct {
		name, outcome string
		err           error
	}{
		{"generic", "network_error", errors.New("SENTINEL_TRANSPORT_ERROR")},
		{"dns", "dns_error", &net.DNSError{Err: "SENTINEL_DNS_ERROR", Name: "SENTINEL_DNS_NAME"}},
		{"timeout", "timeout", os.ErrDeadlineExceeded},
		{"tls", "tls_error", &tls.CertificateVerificationError{Err: errors.New("SENTINEL_TLS_ERROR")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			finish := beginDiagnosticLog(t)
			c, jar := newDiagnosticClient(t, true, func(*http.Request) (*http.Response, error) { return nil, tc.err })
			_, err := c.Send(diagnosticRequest())
			if err == nil || !errors.Is(err, tc.err) || jar.saves != 0 {
				t.Fatal("transport error behavior changed")
			}
			events, log := finish()
			assertDiagnosticRedaction(t, log)
			if len(events) != 2 || events[1].Kind != "http_error" || events[1].Outcome != tc.outcome || events[1].Status != 0 {
				t.Fatalf("incorrect transport classification: %#v", events)
			}
		})
	}
}

type diagnosticErrorBody struct {
	reads, closes int
}

func (b *diagnosticErrorBody) Read(p []byte) (int, error) {
	b.reads++
	return copy(p, "SENTINEL_PARTIAL_BODY"), errors.New("SENTINEL_BODY_READ_ERROR")
}

func (b *diagnosticErrorBody) Close() error { b.closes++; return nil }

func TestAuthenticationDiagnosticsPreserveReadAndCookieSaveFailures(t *testing.T) {
	for _, saveFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "body", true: "cookies"}[saveFailure], func(t *testing.T) {
			finish := beginDiagnosticLog(t)
			body := &diagnosticErrorBody{}
			c, jar := newDiagnosticClient(t, true, func(*http.Request) (*http.Response, error) {
				res := diagnosticResponse(200, "")
				res.Body = body
				return res, nil
			})
			if saveFailure {
				jar.saveError = errors.New("SENTINEL_COOKIE_SAVE_ERROR")
			}
			_, err := c.Send(diagnosticRequest())
			if err == nil || body.closes != 1 || jar.saves != 1 {
				t.Fatal("error/close/save behavior changed")
			}
			events, log := finish()
			assertDiagnosticRedaction(t, log)
			if len(events) != 2 || events[1].Kind != "http_response" {
				t.Fatalf("unexpected event sequence: %#v", events)
			}
			e := events[1]
			if saveFailure {
				if body.reads != 0 || e.Outcome != "cookie_save_error" || e.BodyBytes != 0 || e.BodyKind != "" {
					t.Fatalf("cookie failure caused a body read or wrong observation: %#v", e)
				}
			} else if body.reads != 1 || e.Outcome != "body_read_error" || e.BodyBytes != int64(len("SENTINEL_PARTIAL_BODY")) || e.BodyKind != "other" {
				t.Fatalf("incorrect partial body observation: %#v", e)
			}
		})
	}
}

func TestAuthenticationDiagnosticsRequireBothAuthenticationAndOptIn(t *testing.T) {
	for _, authentication := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary-client", true: "disabled"}[authentication], func(t *testing.T) {
			var finish func() ([]authdiag.Event, string)
			if !authentication {
				finish = beginDiagnosticLog(t)
			}
			c, jar := newDiagnosticClient(t, authentication, func(*http.Request) (*http.Response, error) {
				return diagnosticResponse(200, "<dict><key>ok</key><string>yes</string></dict>"), nil
			})
			_, err := c.Send(diagnosticRequest())
			if err != nil || jar.cookieReads != 1 || jar.saves != 1 {
				t.Fatalf("disabled diagnostics changed cookie calls: err=%v reads=%d saves=%d", err, jar.cookieReads, jar.saves)
			}
			if finish != nil {
				events, _ := finish()
				if len(events) != 0 {
					t.Fatal("ordinary client emitted authentication diagnostics")
				}
			}
		})
	}
}
