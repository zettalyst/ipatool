package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/authdiag"
	"github.com/majd/ipatool/v2/pkg/log"
)

type diagnosticFakeStore struct {
	appstore.AppStore
	calls int
}

func (s *diagnosticFakeStore) Login(input appstore.LoginInput) (appstore.LoginOutput, error) {
	s.calls++
	return appstore.LoginOutput{Account: appstore.Account{Name: "SENTINEL_NAME", Email: "SENTINEL_EMAIL", PasswordToken: "SENTINEL_TOKEN"}}, nil
}

func TestDiagnosticCommandLifecycle(t *testing.T) {
	for _, success := range []bool{false, true} {
		name := "validation failure closes log"
		if success {
			name = "success omits account from console"
		}
		t.Run(name, func(t *testing.T) {
			previous := dependencies
			t.Cleanup(func() { dependencies = previous })
			store := &diagnosticFakeStore{}
			var console bytes.Buffer
			dependencies.AppStore = store
			dependencies.Logger = log.NewLogger(log.Args{Writer: &console})
			path := filepath.Join(t.TempDir(), "diag.jsonl")
			t.Setenv("IPATOOL_AUTH_DIAGNOSTICS", path)
			cmd := loginCmd()
			cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
			cmd.SilenceErrors, cmd.SilenceUsage = true, true
			if success {
				cmd.SetArgs([]string{"--email", "SENTINEL_EMAIL", "--password", "SENTINEL_PASSWORD"})
			} else {
				cmd.SetArgs([]string{})
			}
			err := cmd.Execute()
			if (err == nil) != success {
				t.Fatalf("unexpected success state: %t", err == nil)
			}
			if authdiag.Enabled() {
				t.Fatal("diagnostic file was not closed")
			}
			if !success && store.calls != 0 {
				t.Fatal("validation failure reached authentication")
			}
			if success && store.calls != 1 {
				t.Fatal("unexpected authentication count")
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte("SENTINEL")) || strings.Contains(console.String(), "SENTINEL") {
				t.Fatal("credential sentinel escaped into diagnostic or console output")
			}
			lines := bytes.Split(bytes.TrimSpace(body), []byte("\n"))
			if len(lines) != 2 {
				t.Fatalf("got %d diagnostic lines; expected start and finish", len(lines))
			}
			var last struct {
				Kind    string
				Outcome string
			}
			if err := json.Unmarshal(lines[1], &last); err != nil {
				t.Fatal(err)
			}
			want := "error"
			if success {
				want = "ok"
			}
			if last.Kind != "diagnostic_finished" || last.Outcome != want {
				t.Fatal("missing final outcome")
			}
		})
	}
}
