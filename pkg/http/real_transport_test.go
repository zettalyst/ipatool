package http

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/majd/ipatool/v2/pkg/authdiag"
)

type realTransportCookieJar struct{ *cookiejar.Jar }

func (realTransportCookieJar) Save() error { return nil }

type realTransportSigner struct {
	calls int
	input []byte
}

func (s *realTransportSigner) Sign(input []byte) ([]byte, error) {
	s.calls++
	s.input = append([]byte(nil), input...)
	return []byte("SENTINEL_SIGNATURE"), nil
}

// Exercise the real TLS transport and HTTP header decoder, not a fake
// RoundTripper. The redirect target stays on the same loopback server, so even
// a regression that follows the redirect cannot contact a remote endpoint.
func TestRealTLSTransportPreservesAuthenticationRedirects(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, status := range []int{nethttp.StatusMovedPermanently, nethttp.StatusFound} {
			for _, trailingSlash := range []bool{false, true} {
				t.Run(fmt.Sprintf("HTTP%d/status%d/trailingSlash%t", version, status, trailingSlash), func(t *testing.T) {
					authPath := appStoreAuthPath
					if trailingSlash {
						authPath += "/"
					}
					// The diagnostic sink is process-wide; subtests must stay serial.
					if err := authdiag.Close(); err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(t.TempDir(), "diagnostic.jsonl")
					if err := authdiag.Start(path); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = authdiag.Close() })

					payload := &XMLPayload{Content: map[string]interface{}{"password": "SENTINEL_PASSWORD"}}
					expectedBody, err := payload.data()
					if err != nil {
						t.Fatal(err)
					}
					signer := &realTransportSigner{}
					var requests atomic.Int32
					var redirectLocation string
					server := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
						call := requests.Add(1)
						if call > 1 {
							// Terminate an accidental automatic redirect immediately.
							w.Header().Set("Content-Type", "application/xml")
							_, _ = io.WriteString(w, "<dict><key>followed</key><string>yes</string></dict>")
							return
						}
						if r.ProtoMajor != version {
							t.Errorf("negotiated HTTP/%d, want HTTP/%d", r.ProtoMajor, version)
						}
						wantALPN := map[int]string{1: "http/1.1", 2: "h2"}[version]
						if r.TLS == nil || r.TLS.NegotiatedProtocol != wantALPN {
							t.Errorf("TLS ALPN did not match %s", wantALPN)
						}
						if r.Method != nethttp.MethodPost || r.URL.Path != authPath {
							t.Error("request method or authentication path changed")
						}
						body, readErr := io.ReadAll(r.Body)
						if readErr != nil || !bytes.Equal(body, expectedBody) {
							t.Error("request body changed before reaching the TLS server")
						}
						if r.Header.Get(HeaderAppleActionSignature) != base64.StdEncoding.EncodeToString([]byte("SENTINEL_SIGNATURE")) {
							t.Error("action signature changed before reaching the TLS server")
						}
						w.Header().Set("Content-Type", "text/html")
						// HTTP/2 sends lower-case header names on the wire. Both
						// protocols must reach the same canonical Location lookup.
						w.Header().Set("location", redirectLocation)
						w.WriteHeader(status)
						_, _ = io.WriteString(w, "<html>SENTINEL_REDIRECT_BODY</html>")
					}))
					server.EnableHTTP2 = version == 2
					server.StartTLS()
					t.Cleanup(server.Close)
					redirectLocation = server.URL + authPath + "?token=SENTINEL_LOCATION"

					jar, err := cookiejar.New(nil)
					if err != nil {
						t.Fatal(err)
					}
					client := NewClient[map[string]string](Args{CookieJar: realTransportCookieJar{jar}, Authentication: true}).(*client[map[string]string])
					transport := client.internalClient.Transport.(*AddHeaderTransport).T.(*nethttp.Transport)
					// Trust only this server's certificate and force the test's
					// intended protocol without modifying any global transport.
					transport.TLSClientConfig = server.Client().Transport.(*nethttp.Transport).TLSClientConfig.Clone()
					transport.Protocols = new(nethttp.Protocols)
					transport.Protocols.SetHTTP1(version == 1)
					transport.Protocols.SetHTTP2(version == 2)
					if version == 1 {
						// A cloned default transport can already advertise h2.
						// Disabling the protocol handler alone is insufficient.
						transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
						transport.TLSNextProto = map[string]func(string, *tls.Conn) nethttp.RoundTripper{}
						transport.ForceAttemptHTTP2 = false
					} else {
						transport.TLSClientConfig.NextProtos = []string{"h2"}
						transport.ForceAttemptHTTP2 = true
					}
					t.Cleanup(transport.CloseIdleConnections)

					result, err := client.Send(Request{
						Method: MethodPOST, URL: server.URL + authPath,
						Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
						Payload: payload, ActionSigner: signer, ResponseFormat: ResponseFormatXML,
						DiagnosticLoginID: 7, DiagnosticStage: "sign-in", DiagnosticAttempt: 1, DiagnosticRetry: 1,
					})
					if err != nil {
						t.Fatalf("real TLS request failed: %v", err)
					}
					if requests.Load() != 1 {
						t.Fatalf("automatic redirect followed: got %d requests", requests.Load())
					}
					if result.StatusCode != status {
						t.Fatalf("status = %d; want %d", result.StatusCode, status)
					}
					location, err := result.GetHeader("location")
					if err != nil || location != redirectLocation {
						t.Fatal("Location was lost or changed by transport/response conversion")
					}
					if signer.calls != 1 || !bytes.Equal(signer.input, expectedBody) {
						t.Fatal("signing call count or signed bytes changed")
					}
					if err := authdiag.Close(); err != nil {
						t.Fatal(err)
					}
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(data), "SENTINEL") || strings.Contains(string(data), appStoreAuthPath) {
						t.Fatal("diagnostics exposed request, signature, body, or redirect details")
					}
					lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
					if len(lines) != 2 {
						t.Fatalf("got %d events; want request and response", len(lines))
					}
					var event authdiag.Event
					if err := json.Unmarshal(lines[1], &event); err != nil {
						t.Fatal(err)
					}
					wantProtocol := map[int]string{1: "HTTP/1.1", 2: "HTTP/2.0"}[version]
					if event.Kind != "http_response" || event.Status != status || event.Protocol != wantProtocol || event.Outcome != "ok" {
						t.Fatal("response diagnostic did not preserve status, protocol, or outcome")
					}
					if !event.LocationPresent || !event.LocationAuthPath || !event.SignaturePresent || event.RedirectHost != "other" {
						t.Fatal("Location/signature presence was lost or non-Apple host was disclosed")
					}
					if event.AuthPathTrailingSlash != trailingSlash {
						t.Fatal("request path shape was not preserved in diagnostic metadata")
					}
					if event.BodyKind != "html" || event.BodyBytes != int64(len("<html>SENTINEL_REDIRECT_BODY</html>")) {
						t.Fatal("redirect body observations changed")
					}
				})
			}
		}
	}
}
