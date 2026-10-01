package authdiag

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// These tests deliberately remain serial because diagnostics are process-wide.
func resetDiagnosticForTest(t *testing.T) {
	t.Helper()
	if err := Close(); err != nil {
		t.Fatalf("reset diagnostics: %v", err)
	}
	t.Cleanup(func() { _ = Close() })
}

func startDiagnosticForTest(t *testing.T) string {
	t.Helper()
	resetDiagnosticForTest(t)
	path := filepath.Join(t.TempDir(), "diagnostic.jsonl")
	if err := Start(path); err != nil {
		t.Fatalf("start diagnostics: %v", err)
	}
	return path
}

func readDiagnosticRows(t *testing.T, path string) ([]byte, []map[string]any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatalf("invalid JSONL row: %v", err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return data, rows
}

func TestDisabledDiagnosticsAreNoop(t *testing.T) {
	resetDiagnosticForTest(t)
	if Enabled() {
		t.Fatal("diagnostics unexpectedly enabled")
	}
	Emit(Event{Kind: "SENTINEL_DISABLED", Host: "SENTINEL_DISABLED"})
	state.Lock()
	hasFile, writeErr := state.file != nil, state.err
	state.Unlock()
	if hasFile || writeErr != nil {
		t.Fatal("disabled Emit created output state")
	}
	if err := Close(); err != nil {
		t.Fatalf("close disabled diagnostics: %v", err)
	}
}

func TestStartCreatesPrivateFileAndCloseWritesValidJSONL(t *testing.T) {
	path := startDiagnosticForTest(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file mode = %o; want 600", info.Mode().Perm())
	}
	if !Enabled() {
		t.Fatal("successful Start did not enable diagnostics")
	}
	Emit(Event{Kind: "diagnostic_started"})
	Emit(Event{Kind: "http_response", Status: 500, Host: "buy.itunes.apple.com", BodyBytes: 146, BodyKind: "html"})
	Emit(Event{Kind: "diagnostic_finished", Outcome: "error"})
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	if Enabled() {
		t.Fatal("Close did not disable diagnostics")
	}
	_, rows := readDiagnosticRows(t, path)
	if len(rows) != 3 {
		t.Fatalf("got %d rows; want 3", len(rows))
	}
	for i, kind := range []string{"diagnostic_started", "http_response", "diagnostic_finished"} {
		if rows[i]["kind"] != kind {
			t.Fatalf("row %d kind = %v; want %s", i, rows[i]["kind"], kind)
		}
		elapsed, ok := rows[i]["elapsedMs"].(float64)
		if !ok || elapsed < 0 {
			t.Fatalf("row %d lacks nonnegative elapsed time", i)
		}
	}
	if rows[1]["status"] != float64(500) || rows[1]["bodyBytes"] != float64(146) {
		t.Fatal("numeric response metadata was not retained")
	}
	if err := Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestStartRefusesExistingFilesWithoutOverwriting(t *testing.T) {
	resetDiagnosticForTest(t)
	path := filepath.Join(t.TempDir(), "SENTINEL_EXISTING.jsonl")
	original := []byte("SENTINEL_EXISTING_CONTENT")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	err := Start(path)
	if err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("expected redacted existing-file error; got %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != string(original) {
		t.Fatal("existing diagnostic was modified")
	}
	if Enabled() {
		t.Fatal("failed Start enabled diagnostics")
	}
}

func TestStartRefusesExistingAndDanglingSymlinks(t *testing.T) {
	for _, existingTarget := range []bool{false, true} {
		t.Run(map[bool]string{false: "dangling", true: "existing-target"}[existingTarget], func(t *testing.T) {
			resetDiagnosticForTest(t)
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			link := filepath.Join(dir, "SENTINEL_LINK")
			if existingTarget {
				if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			err := Start(link)
			if err == nil || strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("expected redacted symlink error; got %v", err)
			}
			if existingTarget {
				data, err := os.ReadFile(target)
				if err != nil || string(data) != "unchanged" {
					t.Fatal("symlink target was modified")
				}
			} else if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("dangling symlink target was created")
			}
			if Enabled() {
				t.Fatal("symlink Start enabled diagnostics")
			}
		})
	}
}

func TestStartErrorsDoNotExposePathsOrReplaceActiveFile(t *testing.T) {
	path := startDiagnosticForTest(t)
	second := filepath.Join(t.TempDir(), "SENTINEL_SECOND.jsonl")
	if err := Start(second); err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("expected redacted active-session error; got %v", err)
	}
	Emit(Event{Kind: "login_started"})
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	_, rows := readDiagnosticRows(t, path)
	if len(rows) != 1 {
		t.Fatal("active diagnostic destination was replaced")
	}
	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Fatal("second diagnostic path was created")
	}
	missingParent := filepath.Join(t.TempDir(), "SENTINEL_MISSING_PARENT", "diagnostic.jsonl")
	if err := Start(missingParent); err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("expected redacted creation error; got %v", err)
	}
}

func TestEmitAllStringFieldsUseAllowlist(t *testing.T) {
	path := startDiagnosticForTest(t)
	var event Event
	value := reflect.ValueOf(&event).Elem()
	for i := 0; i < value.NumField(); i++ {
		if value.Field(i).Kind() == reflect.String {
			value.Field(i).SetString("SENTINEL_" + value.Type().Field(i).Name)
		}
	}
	Emit(event)
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	data, rows := readDiagnosticRows(t, path)
	if strings.Contains(string(data), "SENTINEL") {
		t.Fatal("an unapproved string field reached the diagnostic log")
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows; want 1", len(rows))
	}
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if field.Type.Kind() == reflect.String {
			key := strings.Split(field.Tag.Get("json"), ",")[0]
			if rows[0][key] != "other" {
				t.Fatalf("unapproved field %s = %v; want other", key, rows[0][key])
			}
		}
	}
}

func TestHostAndContentTypeNeverRetainURLOrHeaderSecrets(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"https://SENTINEL_USER:SENTINEL_PASSWORD@p42-buy.itunes.apple.com:443/SENTINEL_PATH?token=SENTINEL_QUERY#SENTINEL_FRAGMENT", "p42-buy.itunes.apple.com"},
		{"https://SENTINEL_HOST.example/SENTINEL_PATH?token=SENTINEL_QUERY", "other"},
		{"https://p42-buy.itunes.apple.com.SENTINEL_HOST.example/authenticate", "other"},
		{"https://SENTINEL_HOST-buy.itunes.apple.com/authenticate", "other"},
		{"https://buy.itunes.apple.com/SENTINEL_PATH%zz?token=SENTINEL_QUERY", "other"},
		{"https://SENTINEL_USER@BUY.ITUNES.APPLE.COM/SENTINEL_PATH", "buy.itunes.apple.com"},
		{"p999-buy.itunes.apple.com", "p999-buy.itunes.apple.com"},
		{"p1000-buy.itunes.apple.com", "other"},
		{"none", "none"},
		{"", ""},
	}
	path := startDiagnosticForTest(t)
	for _, tc := range cases {
		if got := Host(tc.raw); got != tc.want {
			t.Errorf("Host classification = %q; want %q", got, tc.want)
		}
		Emit(Event{Kind: "http_response", Host: tc.raw, RedirectHost: tc.raw, ContentType: " Text/HTML; token=SENTINEL_HEADER"})
	}
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	data, rows := readDiagnosticRows(t, path)
	if strings.Contains(string(data), "SENTINEL") {
		t.Fatal("URL or content-type parameter secret reached diagnostic log")
	}
	if len(rows) != len(cases) {
		t.Fatalf("got %d rows; want %d", len(rows), len(cases))
	}
	for i, row := range rows {
		if row["contentType"] != "text/html" {
			t.Fatalf("row %d content type was not canonicalized", i)
		}
		for _, key := range []string{"host", "redirectHost"} {
			if cases[i].want == "" {
				if _, exists := row[key]; exists {
					t.Fatalf("empty %s was not omitted", key)
				}
			} else if row[key] != cases[i].want {
				t.Fatalf("row %d %s = %v; want %s", i, key, row[key], cases[i].want)
			}
		}
	}
}

func TestCloseSurfacesWriteAndFlushFailuresWithoutPaths(t *testing.T) {
	for _, emitAfterClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "flush-failure", true: "write-failure"}[emitAfterClose], func(t *testing.T) {
			startDiagnosticForTest(t)
			state.Lock()
			err := state.file.Close()
			state.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if emitAfterClose {
				Emit(Event{Kind: "http_response", Host: "SENTINEL_WRITE_ERROR"})
			}
			err = Close()
			if err == nil || err.Error() != "authentication diagnostic write or close failed" {
				t.Fatalf("expected fixed write/close error; got %v", err)
			}
			if Enabled() {
				t.Fatal("failed close left diagnostics enabled")
			}
			if err := Close(); err != nil {
				t.Fatalf("failure was not cleared after close: %v", err)
			}
		})
	}
}
