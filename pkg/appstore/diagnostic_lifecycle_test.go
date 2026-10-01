package appstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/majd/ipatool/v2/pkg/authdiag"
	"github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"go.uber.org/mock/gomock"
)

// This exercises two public Login calls, as the interactive CLI does. All
// machine, bag, authentication and keychain operations are mocks; it does not
// establish that Apple accepts restarting authentication after a challenge.
func TestDiagnosticPublicLoginLifecycle(t *testing.T) {
	for _, failVerification := range []bool{false, true} {
		name := "challenge then 2FA success"
		if failVerification {
			name = "challenge then 2FA HTTP 500 500 404"
		}
		t.Run(name, func(t *testing.T) {
			const (
				email    = "lifecycle-fake@example.invalid"
				password = "lifecycle-fake-password"
				code     = "654321"
				token    = "lifecycle-fake-token"
				dsid     = "lifecycle-fake-dsid"
				podURL   = "https://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate?Pod=42&PRH=42"
			)
			path := filepath.Join(t.TempDir(), "lifecycle.jsonl")
			if err := authdiag.Start(path); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := authdiag.Close(); err != nil {
					t.Error(err)
				}
			})

			ctrl := gomock.NewController(t)
			mockMachine := machine.NewMockMachine(ctrl)
			mockBag := http.NewMockClient[bagResult](ctrl)
			mockLogin := http.NewMockClient[loginResult](ctrl)
			mockKeychain := keychain.NewMockKeychain(ctrl)
			var signers []*stubActionSigner
			var waits []time.Duration
			as := &appstore{
				machine: mockMachine, bagClient: mockBag, loginClient: mockLogin, keychain: mockKeychain,
				authRetrySleep: func(delay time.Duration) { waits = append(waits, delay) },
				actionSignerFactory: func(config SAPConfig, machineID []byte) (ActionSigner, error) {
					if !reflect.DeepEqual(config, validSAPConfig()) || !bytes.Equal(machineID, make([]byte, 6)) {
						t.Fatal("public Login changed the bag configuration or machine identity")
					}
					if len(signers) == 1 && signers[0].closeCalls != 1 {
						t.Fatal("initial signer was not closed before the 2FA signer was created")
					}
					signer := &stubActionSigner{}
					signers = append(signers, signer)
					return signer, nil
				},
			}
			mockMachine.EXPECT().MacAddress().Return("00:00:00:00:00:00", nil).Times(2)
			mockBag.EXPECT().Send(gomock.Any()).DoAndReturn(func(req http.Request) (http.Result[bagResult], error) {
				if req.URL != "https://init.itunes.apple.com/bag.xml?guid=000000000000" {
					t.Fatal("public Login did not refetch the bag with the same machine GUID")
				}
				return http.Result[bagResult]{StatusCode: 200, Data: validBagResult()}, nil
			}).Times(2)

			if !failVerification {
				mockKeychain.EXPECT().Set("account", gomock.Any()).DoAndReturn(func(_ string, data []byte) error {
					if len(signers) != 2 {
						t.Fatal("account was persisted before the 2FA public Login")
					}
					var account Account
					if err := json.Unmarshal(data, &account); err != nil {
						t.Fatal(err)
					}
					if account.Email != email || account.PasswordToken != token || account.Password != password {
						t.Fatal("successful verification did not persist the mocked account")
					}
					return nil
				})
			}

			calls := 0
			wantCalls := 3
			if failVerification {
				wantCalls = 5
			}
			var loginIDs []uint64
			mockLogin.EXPECT().Send(gomock.Any()).DoAndReturn(func(req http.Request) (http.Result[loginResult], error) {
				call := calls
				calls++
				phase := 0
				stage, requestURL, requestPassword := "sign-in", testAuthEndpoint+"/", password
				outerAttempt, retry := 1, 1
				if call == 1 {
					requestURL, outerAttempt = podURL, 2
				} else if call >= 2 {
					phase, stage, requestPassword, retry = 1, "2fa", password+code, call-1
				}
				if req.URL != requestURL || req.Method != http.MethodPOST || req.ActionSigner != signers[phase] {
					t.Fatal("unexpected endpoint, method or signer across the two public Login calls")
				}
				payload, ok := req.Payload.(*http.XMLPayload)
				if !ok || payload.Content["appleId"] != email || payload.Content["password"] != requestPassword || payload.Content["attempt"] != "1" {
					t.Fatal("redirect or 2FA changed the expected signed payload")
				}
				if req.DiagnosticLoginID == 0 || req.DiagnosticStage != stage || req.DiagnosticAttempt != outerAttempt || req.DiagnosticRetry != retry {
					t.Fatal("request diagnostics lost the public Login phase or attempt/retry distinction")
				}
				if call == 0 || call == 2 {
					loginIDs = append(loginIDs, req.DiagnosticLoginID)
				}
				if req.DiagnosticLoginID != loginIDs[phase] {
					t.Fatal("redirect or transient retry changed the public Login ID")
				}
				switch call {
				case 0:
					return http.Result[loginResult]{StatusCode: 301, Headers: map[string]string{"Location": podURL}}, nil
				case 1:
					return http.Result[loginResult]{StatusCode: 200, Data: loginResult{CustomerMessage: CustomerMessageBadLogin}}, nil
				default:
					if failVerification {
						return http.Result[loginResult]{}, &http.UnexpectedResponseError{
							StatusCode: []int{500, 500, 404}[call-2], Reason: "empty or non-plist authentication response", BodyLength: 146, ContentType: "text/html",
						}
					}
					return http.Result[loginResult]{
						StatusCode: 200,
						Headers:    map[string]string{HTTPHeaderStoreFront: "143441-1,34", HTTPHeaderPod: "42"},
						Data:       loginResult{Account: loginAccountResult{Email: email}, PasswordToken: token, DirectoryServicesID: dsid},
					}, nil
				}
			}).Times(wantCalls)

			if _, err := as.Login(LoginInput{Email: email, Password: password}); !errors.Is(err, ErrAuthCodeRequired) {
				t.Fatalf("first public Login did not return the challenge: %v", err)
			}
			if len(signers) != 1 || signers[0].closeCalls != 1 || as.loginClient != mockLogin {
				t.Fatal("initial challenge did not close its signer while retaining the login client")
			}
			out, err := as.Login(LoginInput{Email: email, Password: password, AuthCode: code})
			if failVerification {
				if err == nil || !strings.Contains(err.Error(), "2FA verification request failed") || !strings.Contains(err.Error(), "HTTP 500, 500, 404") || strings.Contains(err.Error(), "at Store pod") {
					t.Fatalf("unexpected verification failure: %v", err)
				}
				if !reflect.DeepEqual(waits, []time.Duration{10 * time.Second, 20 * time.Second}) {
					t.Fatalf("unexpected transient retry delays: %v", waits)
				}
			} else if err != nil || out.Account.PasswordToken != token || len(waits) != 0 {
				t.Fatalf("mocked verification did not complete without retries: %v", err)
			}
			if len(signers) != 2 || signers[0] == signers[1] || signers[0].closeCalls != 1 || signers[1].closeCalls != 1 || as.loginClient != mockLogin {
				t.Fatal("public Login calls did not create/close distinct signers and share the login client")
			}
			if loginIDs[0] == loginIDs[1] {
				t.Fatal("2FA reused the initial public Login diagnostic ID")
			}
			if err := authdiag.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{email, password, code, token, dsid, "Pod=42", "PRH=42", "000000000000"} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatal("diagnostics leaked a fake credential, identifier or redirect query")
				}
			}
			groups := map[uint64][]authdiag.Event{}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			for {
				var event authdiag.Event
				if err := decoder.Decode(&event); err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal(err)
				}
				groups[event.LoginID] = append(groups[event.LoginID], event)
			}
			if len(groups) != 2 {
				t.Fatalf("expected two fully correlated public Login event streams, got %d", len(groups))
			}
			for phase, id := range loginIDs {
				events := groups[id]
				stage, outcome := "sign-in", "challenge"
				wantKinds := []string{"login_started", "bag_completed", "signer_ready", "login_request", "login_response", "login_request", "login_response", "signer_closed", "login_finished"}
				if phase == 1 {
					stage, outcome = "2fa", "ok"
					wantKinds = []string{"login_started", "bag_completed", "signer_ready", "login_request", "login_response", "signer_closed", "login_finished"}
					if failVerification {
						outcome = "error"
						wantKinds = []string{"login_started", "bag_completed", "signer_ready", "login_request", "retry_wait", "retry_wait", "signer_closed", "login_finished"}
					}
				}
				var kinds []string
				for _, event := range events {
					kinds = append(kinds, event.Kind)
					if event.Stage != stage {
						t.Fatalf("event %s lost its phase %s", event.Kind, stage)
					}
				}
				if !reflect.DeepEqual(kinds, wantKinds) {
					t.Fatalf("unexpected %s diagnostic lifecycle: %v", stage, kinds)
				}
				if events[len(events)-1].Outcome != outcome || events[len(events)-2].Outcome != "ok" {
					t.Fatalf("unexpected %s completion or signer-close outcome", stage)
				}
				if events[1].Host != "buy.itunes.apple.com" || events[3].Host != "buy.itunes.apple.com" || events[3].Attempt != 1 {
					t.Fatal("diagnostics do not show that each public Login starts from the bag endpoint")
				}
				if phase == 0 && (events[5].Host != "p42-buy.itunes.apple.com" || events[5].Attempt != 2 || events[6].Outcome != "challenge") {
					t.Fatal("diagnostics lost the initial pod redirect and challenge")
				}
				if phase == 1 && failVerification {
					for retry := 1; retry <= 2; retry++ {
						event := events[3+retry]
						if event.Retry != retry || event.Attempt != 1 || event.Status != 500 || event.WaitMS != int64(retry)*10000 {
							t.Fatal("retry diagnostics confused HTTP retries with redirect attempts")
						}
					}
				} else if phase == 1 && (!events[4].PasswordTokenPresent || !events[4].DirectoryServicesIDPresent || events[4].Status != 200) {
					t.Fatal("successful verification diagnostics lost token-presence metadata")
				}
			}
		})
	}
}
