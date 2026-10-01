package http

type Request struct {
	Method         string
	URL            string
	Headers        map[string]string
	Payload        Payload
	ActionSigner   ActionSigner
	ResponseFormat ResponseFormat
	// Diagnostic fields correlate opt-in authentication metadata without
	// carrying account identifiers, payloads, or credentials.
	DiagnosticLoginID uint64
	DiagnosticStage   string
	DiagnosticAttempt int
	DiagnosticRetry   int
}

type ActionSigner interface {
	Sign(data []byte) ([]byte, error)
}
