package appstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	gohttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	"github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"howett.net/plist"
)

var _ = Describe("AppStore (Login)", func() {
	const (
		testPassword  = "test-password"
		testEmail     = "test-email"
		testFirstName = "test-first-name"
		testLastName  = "test-last-name"
		testPod       = "42"
	)

	var (
		ctrl          *gomock.Controller
		as            *appstore
		mockKeychain  *keychain.MockKeychain
		mockClient    *http.MockClient[loginResult]
		mockBagClient *http.MockClient[bagResult]
		mockMachine   *machine.MockMachine
		signer        *stubActionSigner
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mockKeychain = keychain.NewMockKeychain(ctrl)
		mockClient = http.NewMockClient[loginResult](ctrl)
		mockBagClient = http.NewMockClient[bagResult](ctrl)
		mockMachine = machine.NewMockMachine(ctrl)
		signer = &stubActionSigner{}
		as = &appstore{
			keychain:       mockKeychain,
			loginClient:    mockClient,
			bagClient:      mockBagClient,
			machine:        mockMachine,
			authRetrySleep: func(time.Duration) {},
			actionSignerFactory: func(config SAPConfig, machineID []byte) (ActionSigner, error) {
				Expect(config).To(Equal(validSAPConfig()))
				Expect(machineID).To(Equal([]byte{0, 0, 0, 0, 0, 0}))

				return signer, nil
			},
		}
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("transient authentication responses", func() {
		It("retries the same request until it succeeds", func() {
			request := as.loginRequest(testEmail, testPassword, "", "guid", testAuthEndpoint, 1, signer)
			responses := []struct {
				result http.Result[loginResult]
				err    error
			}{
				{err: &http.UnexpectedResponseError{StatusCode: 204}},
				{err: &http.UnexpectedResponseError{StatusCode: 404}},
				{result: http.Result[loginResult]{StatusCode: 200}},
			}
			call := 0
			mockClient.EXPECT().
				Send(gomock.Any()).
				DoAndReturn(func(actual http.Request) (http.Result[loginResult], error) {
					Expect(actual.URL).To(Equal(request.URL))
					Expect(actual.Payload.(*http.XMLPayload).Content).To(HaveKeyWithValue("attempt", "1"))
					response := responses[call]
					call++

					return response.result, response.err
				}).
				Times(3)

			result, err := as.sendAuthenticationRequest(request)

			Expect(err).ToNot(HaveOccurred())
			Expect(result.StatusCode).To(Equal(200))
		})

		DescribeTable("bounds retries to transient statuses",
			func(status, expectedCalls int) {
				request := as.loginRequest(testEmail, testPassword, "", "guid", testAuthEndpoint, 1, signer)
				responseErr := &http.UnexpectedResponseError{StatusCode: status}
				mockClient.EXPECT().
					Send(gomock.Any()).
					Return(http.Result[loginResult]{}, responseErr).
					Times(expectedCalls)

				_, err := as.sendAuthenticationRequest(request)

				Expect(errors.Is(err, responseErr)).To(BeTrue())
				if expectedCalls == maxAuthenticationRequestAttempts {
					Expect(err.Error()).To(ContainSubstring("after 3 attempts"))
					Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("HTTP %d, %d, %d", status, status, status)))
				}
			},
			Entry("retries and then stops for HTTP 204", 204, maxAuthenticationRequestAttempts),
			Entry("retries and then stops for HTTP 503", 503, maxAuthenticationRequestAttempts),
			Entry("does not retry HTTP 403", 403, 1),
		)
	})

	DescribeTable("redacts sensitive redirect locations from authentication errors",
		func(status int, location, diagnostic string) {
			response := http.Result[loginResult]{StatusCode: status, Headers: map[string]string{"Location": location}}

			retry, _, err := as.parseLoginResponse(&response, 1, "")

			Expect(retry).To(BeFalse())
			Expect(err).To(MatchError(fmt.Sprintf("invalid authentication redirect (HTTP %d): %s", status, diagnostic)))
			for _, secret := range []string{"account-secret", "password-secret", "path-secret", "query-secret", "fragment-secret"} {
				Expect(err.Error()).NotTo(ContainSubstring(secret))
			}
		},
		Entry("301 omits userinfo, arbitrary path, query and fragment", 301,
			"https://account-secret:password-secret@example.test/path-secret?token=query-secret#fragment-secret",
			`scheme="https" host="example.test" expected-auth-path=false`),
		Entry("302 omits userinfo, arbitrary path, query and fragment", 302,
			"https://account-secret:password-secret@example.test/path-secret?token=query-secret#fragment-secret",
			`scheme="https" host="example.test" expected-auth-path=false`),
		Entry("301 omits the URL embedded in a parse error", 301,
			"https://account-secret:password-secret@example.test/path-secret%zz?token=query-secret#fragment-secret",
			"malformed Location"),
		Entry("302 omits the URL embedded in a parse error", 302,
			"https://account-secret:password-secret@example.test/path-secret%zz?token=query-secret#fragment-secret",
			"malformed Location"),
	)

	When("fails to read Machine's MAC address", func() {
		BeforeEach(func() {
			mockMachine.EXPECT().
				MacAddress().
				Return("", errors.New(""))
		})

		It("returns error", func() {
			_, err := as.Login(LoginInput{
				Password: testPassword,
			})
			Expect(err).To(HaveOccurred())
		})
	})

	When("successfully reads machine's MAC address", func() {
		BeforeEach(func() {
			mockMachine.EXPECT().
				MacAddress().
				Return("00:00:00:00:00:00", nil)
			mockBagClient.EXPECT().
				Send(gomock.Any()).
				Do(func(req http.Request) {
					Expect(req.URL).To(Equal("https://init.itunes.apple.com/bag.xml?guid=000000000000"))
				}).
				Return(http.Result[bagResult]{
					StatusCode: 200,
					Data:       validBagResult(),
				}, nil)
		})

		When("client returns error", func() {
			var clientErr error

			BeforeEach(func() {
				clientErr = errors.New("client error")
				mockClient.EXPECT().
					Send(gomock.Any()).
					Do(func(req http.Request) {
						Expect(req.URL).To(Equal(testAuthEndpoint + "/"))
						Expect(req.ActionSigner).To(BeIdenticalTo(signer))
					}).
					Return(http.Result[loginResult]{}, clientErr)
			})

			It("returns wrapped error", func() {
				_, err := as.Login(LoginInput{
					Password: testPassword,
				})
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, clientErr)).To(BeTrue())
				Expect(signer.closeCalls).To(Equal(1))
			})

			It("preserves both the request and cleanup errors", func() {
				cleanupErr := errors.New("cleanup failed")
				signer.closeErr = cleanupErr

				_, err := as.Login(LoginInput{Password: testPassword})
				Expect(errors.Is(err, clientErr)).To(BeTrue())
				Expect(errors.Is(err, cleanupErr)).To(BeTrue())
				Expect(err.Error()).To(ContainSubstring("failed to close SAP action signer"))
				Expect(signer.closeCalls).To(Equal(1))
			})
		})

		When("the SAP signer fails to initialize", func() {
			BeforeEach(func() {
				as.actionSignerFactory = func(SAPConfig, []byte) (ActionSigner, error) {
					return nil, errors.New("signer error")
				}
			})

			It("returns a wrapped error", func() {
				_, err := as.Login(LoginInput{Password: testPassword})
				Expect(err).To(MatchError("failed to initialize SAP action signer: signer error"))
			})
		})

		When("store API returns invalid credentials on first attempt", func() {
			BeforeEach(func() {
				mockClient.EXPECT().
					Send(gomock.Any()).
					Do(func(req http.Request) {
						Expect(req.ActionSigner).To(BeIdenticalTo(signer))
					}).
					Return(http.Result[loginResult]{
						Data: loginResult{
							FailureType: FailureTypeInvalidCredentials,
						},
					}, nil).
					Times(2)
			})

			It("retries once then returns an error", func() {
				_, err := as.Login(LoginInput{
					Password: testPassword,
				})
				Expect(err).To(HaveOccurred())
			})
		})

		When("store API returns error", func() {
			BeforeEach(func() {
				mockClient.EXPECT().
					Send(gomock.Any()).
					Return(http.Result[loginResult]{
						Data: loginResult{
							FailureType: "random-error",
						},
					}, nil)
			})

			It("returns error", func() {
				_, err := as.Login(LoginInput{
					Password: testPassword,
				})
				Expect(err).To(HaveOccurred())
			})
		})

		When("store API indicates account is disabled", func() {
			BeforeEach(func() {
				mockClient.EXPECT().
					Send(gomock.Any()).
					Return(http.Result[loginResult]{
						Data: loginResult{
							CustomerMessage: CustomerMessageAccountDisabled,
						},
					}, nil)
			})

			It("returns account disabled error", func() {
				_, err := as.Login(LoginInput{
					Password: testPassword,
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("account is disabled"))
			})
		})

		When("store API requires 2FA code", func() {
			BeforeEach(func() {
				mockClient.EXPECT().
					Send(gomock.Any()).
					Return(http.Result[loginResult]{
						Data: loginResult{
							FailureType:     "",
							CustomerMessage: CustomerMessageBadLogin,
						},
					}, nil)
			})

			It("returns ErrAuthCodeRequired error", func() {
				_, err := as.Login(LoginInput{
					Password: testPassword,
				})
				Expect(err).To(Equal(ErrAuthCodeRequired))
			})
		})

		DescribeTable("follows authentication pod redirects with the same signed POST body",
			func(status int) {
				const podURL = "https://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"
				jar, err := cookiejar.New(nil)
				Expect(err).NotTo(HaveOccurred())
				client := http.NewClient[loginResult](http.Args{CookieJar: loginSessionJar{jar}, Authentication: true})
				bodies := make(chan []byte, 2)
				var serverCalls atomic.Int32
				srv := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, req *gohttp.Request) {
					defer GinkgoRecover()
					call := serverCalls.Add(1)
					Expect(req.Method).To(Equal(gohttp.MethodPost))
					Expect(req.Header.Get("Content-Type")).To(Equal("application/x-www-form-urlencoded"))
					body, err := io.ReadAll(req.Body)
					Expect(err).NotTo(HaveOccurred())
					signature, err := base64.StdEncoding.DecodeString(req.Header.Get(http.HeaderAppleActionSignature))
					Expect(err).NotTo(HaveOccurred())
					// The stub signer returns its input, so this verifies that each
					// POST is signed over the bytes actually sent by the HTTP client.
					Expect(signature).To(Equal(body))
					var payload map[string]string
					_, err = plist.Unmarshal(body, &payload)
					Expect(err).NotTo(HaveOccurred())
					Expect(payload).To(Equal(map[string]string{
						"appleId": testEmail, "password": testPassword + "123456",
						"attempt": "1", "guid": "000000000000", "rmp": "0", "why": "signIn",
					}))
					bodies <- append([]byte(nil), body...)
					if call == 1 {
						w.Header().Set("Location", podURL)
						w.WriteHeader(status)
						return
					}
					Expect(call).To(Equal(int32(2)))
					w.Header().Set(HTTPHeaderStoreFront, "test-storefront")
					w.Header().Set(HTTPHeaderPod, testPod)
					_, err = w.Write([]byte("<dict><key>passwordToken</key><string>test-token</string><key>dsPersonId</key><string>test-id</string></dict>"))
					Expect(err).NotTo(HaveOccurred())
				}))
				DeferCleanup(srv.Close)
				adaptedCalls := 0
				mockClient.EXPECT().Send(gomock.Any()).
					DoAndReturn(func(req http.Request) (http.Result[loginResult], error) {
						adaptedCalls++
						Expect(req.URL).To(Equal([]string{testAuthEndpoint + "/", podURL}[adaptedCalls-1]))
						Expect(req.ActionSigner).To(BeIdenticalTo(signer))
						// Validate the advertised Apple URL in login, but send every
						// test request to the loopback server instead of Apple.
						req.URL = srv.URL + PrivateAppStoreAPIPathAuth
						return client.Send(req)
					}).Times(2)
				mockKeychain.EXPECT().Set("account", gomock.Any()).Return(nil).Times(1)

				out, err := as.Login(LoginInput{Email: testEmail, Password: testPassword, AuthCode: "123 456"})

				Expect(err).NotTo(HaveOccurred())
				Expect(out.Account.PasswordToken).To(Equal("test-token"))
				Expect(out.Account.Pod).To(Equal(testPod))
				Expect(serverCalls.Load()).To(Equal(int32(2)))
				Expect(<-bodies).To(Equal(<-bodies))
				Expect(signer.closeCalls).To(Equal(1))
			},
			Entry("HTTP 301", gohttp.StatusMovedPermanently),
			Entry("HTTP 302 regression", gohttp.StatusFound),
		)

		DescribeTable("rejects invalid redirects before reposting credentials",
			func(status int, headers map[string]string, message string) {
				mockClient.EXPECT().
					Send(gomock.Any()).
					Return(http.Result[loginResult]{
						StatusCode: status,
						Headers:    headers,
					}, nil).Times(1)
				mockKeychain.EXPECT().Set(gomock.Any(), gomock.Any()).Times(0)

				_, err := as.Login(LoginInput{Email: testEmail, Password: testPassword})

				Expect(err).To(MatchError(ContainSubstring(message)))
				Expect(signer.closeCalls).To(Equal(1))
			},
			Entry("301 rejects HTTP", 301, map[string]string{"Location": "http://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"}, "invalid authentication redirect"),
			Entry("301 rejects a non-Apple host", 301, map[string]string{"Location": "https://p42-buy.itunes.apple.com.example.test/WebObjects/MZFinance.woa/wa/authenticate"}, "invalid authentication redirect"),
			Entry("301 rejects the wrong path", 301, map[string]string{"Location": "https://p42-buy.itunes.apple.com/steal"}, "invalid authentication redirect"),
			Entry("301 rejects a missing Location", 301, map[string]string{}, "failed to retrieve redirect location"),
			Entry("302 rejects HTTP", 302, map[string]string{"Location": "http://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"}, "invalid authentication redirect"),
			Entry("302 rejects a non-Apple host", 302, map[string]string{"Location": "https://p42-buy.itunes.apple.com.example.test/WebObjects/MZFinance.woa/wa/authenticate"}, "invalid authentication redirect"),
			Entry("302 rejects the wrong path", 302, map[string]string{"Location": "https://p42-buy.itunes.apple.com/steal"}, "invalid authentication redirect"),
			Entry("302 rejects a missing Location", 302, map[string]string{}, "failed to retrieve redirect location"),
		)

		DescribeTable("stops an authentication redirect loop after four requests",
			func(status int) {
				const redirectLocation = testAuthEndpoint + "?authToken=SENTINEL_AUTH_TOKEN"
				mockClient.EXPECT().Send(gomock.Any()).
					Do(func(req http.Request) {
						Expect(req.Method).To(Equal(http.MethodPOST))
						Expect(req.ActionSigner).To(BeIdenticalTo(signer))
						Expect(req.Payload.(*http.XMLPayload).Content).To(HaveKeyWithValue("attempt", "1"))
					}).
					Return(http.Result[loginResult]{
						StatusCode: status,
						Headers: map[string]string{
							"Location":   redirectLocation,
							"Set-Cookie": "session=SENTINEL_COOKIE; Secure; HttpOnly",
						},
					}, nil).Times(4)
				mockKeychain.EXPECT().Set(gomock.Any(), gomock.Any()).Times(0)

				_, err := as.Login(LoginInput{Email: testEmail, Password: testPassword})

				Expect(err).To(MatchError(fmt.Sprintf("too many attempts (authentication HTTP %d)", status)))
				var metadataErr *Error
				Expect(errors.As(err, &metadataErr)).To(BeFalse())
				Expect(metadataErr).To(BeNil())
				encodedError, marshalErr := json.Marshal(err)
				Expect(marshalErr).NotTo(HaveOccurred())
				for _, secret := range []string{"SENTINEL_AUTH_TOKEN", "SENTINEL_COOKIE"} {
					Expect(err.Error()).NotTo(ContainSubstring(secret))
					Expect(string(encodedError)).NotTo(ContainSubstring(secret))
				}
				Expect(signer.closeCalls).To(Equal(1))
			},
			Entry("HTTP 301", gohttp.StatusMovedPermanently),
			Entry("HTTP 302 regression", gohttp.StatusFound),
		)

		When("store API returns valid response", func() {
			const (
				testPasswordToken       = "test-password-token"
				testDirectoryServicesID = "directory-services-id"
				testStoreFront          = "test-storefront"
			)

			BeforeEach(func() {
				mockClient.EXPECT().
					Send(gomock.Any()).
					Return(http.Result[loginResult]{
						StatusCode: 200,
						Headers: map[string]string{
							HTTPHeaderStoreFront: testStoreFront,
							HTTPHeaderPod:        testPod,
						},
						Data: loginResult{
							PasswordToken:       testPasswordToken,
							DirectoryServicesID: testDirectoryServicesID,
							Account: loginAccountResult{
								Email: testEmail,
								Address: loginAddressResult{
									FirstName: testFirstName,
									LastName:  testLastName,
								},
							},
						},
					}, nil)
			})

			When("successfully saves account in keychain", func() {
				BeforeEach(func() {
					mockKeychain.EXPECT().
						Set("account", gomock.Any()).
						Do(func(key string, data []byte) {
							want := Account{
								Name:                fmt.Sprintf("%s %s", testFirstName, testLastName),
								Email:               testEmail,
								PasswordToken:       testPasswordToken,
								Password:            testPassword,
								DirectoryServicesID: testDirectoryServicesID,
								StoreFront:          testStoreFront,
								Pod:                 testPod,
							}

							var got Account
							Expect(json.Unmarshal(data, &got)).To(Succeed())
							Expect(got).To(Equal(want))
						}).
						Return(nil)
				})

				It("returns nil", func() {
					out, err := as.Login(LoginInput{
						Password: testPassword,
					})
					Expect(err).ToNot(HaveOccurred())
					Expect(out.Account.Email).To(Equal(testEmail))
					Expect(out.Account.Name).To(Equal(strings.Join([]string{testFirstName, testLastName}, " ")))
				})

				It("returns the persisted account with a signer cleanup error", func() {
					cleanupErr := errors.New("cleanup failed")
					signer.closeErr = cleanupErr

					out, err := as.Login(LoginInput{Password: testPassword})
					Expect(errors.Is(err, cleanupErr)).To(BeTrue())
					Expect(err.Error()).To(ContainSubstring("failed to close SAP action signer"))
					Expect(out.Account.Email).To(Equal(testEmail))
					Expect(signer.closeCalls).To(Equal(1))
				})
			})
		})
	})
})

type stubActionSigner struct {
	closeCalls int
	closeErr   error
}

func (*stubActionSigner) Sign(data []byte) ([]byte, error) {
	return append([]byte(nil), data...), nil
}

func (s *stubActionSigner) Close() error {
	s.closeCalls++

	return s.closeErr
}
