# Authentication routing fix

Verified locally on 2026-10-02. This branch preserves a working patch against
[upstream v2.6.0](https://github.com/majd/ipatool/tree/747d66fc0acd896759f43a206a7ddfa2ab49e584).
It does not include later upstream main changes.

## Failure and cause

The bag supplied the initial authentication path
`/WebObjects/MZFinance.woa/wa/authenticate`, without a trailing slash. In the
observed environment, signed POST requests to that path returned empty or HTML
responses instead of the expected authentication plist. Merely adding HTTP 301
handling did not resolve the failure: a real 2FA attempt still ended with
HTTP 500, 500, and 404.

A controlled experiment reused one signed XML payload with empty account fields.
Each request used a fresh in-memory cookie jar, the same host, user agent, content
type, HTTP/2, and TLS 1.3. Only the final slash changed:

| Request path suffix | HTTP | Result |
| --- | --- | --- |
| `authenticate/` | 200 | XML plist, expected empty-account error |
| `authenticate` | 204 | Empty response |
| `authenticate/` | 200 | XML plist, expected empty-account error |
| `authenticate` | 302 | HTML response without a Location header |

The empty-account HTTP 200 responses establish that the structured handler was
reached; they are not successful logins. After applying the routing fix, a real
interactive sign-in reached the 2FA challenge, followed a valid Apple redirect,
received the required account credentials, and exited successfully. An owned app
was subsequently downloaded with purchasing disabled.

This isolates a client-side routing correction that worked in the tested
environment. Apple's internal reason for the different responses, behavior for
other accounts or regions, and future compatibility remain unverified.

## Changes

- Normalize only the initial bag authentication URL to the trailing-slash form.
  Preserve its host, query, and escaped path representation.
- Accept exactly the legacy authentication path and its single-slash variant
  within the existing Apple HTTPS endpoint restrictions.
- Handle HTTP 301 and 302 through the validated, signed POST flow. Use Apple's
  redirect target as supplied rather than adding another slash to it.
- Prevent Go's automatic redirect following for both authentication path forms,
  preserving the authentication POST flow.
- Report routing failures without dumping response metadata or redirect query
  values; mask interactive 2FA input.
- Add optional JSONL diagnostics and regression tests for routing, real loopback
  TLS transport, redaction, file creation, and diagnostic lifecycle behavior.

No TLS verification bypass or new authentication host permission was added.
Private network probe programs, credentials, session files, raw logs, downloaded
apps, and extracted app data are not included in this fork.

## Build and test

The module declares Go 1.25.0. Local validation used Go 1.27.1 on macOS arm64.
Keep the original `github.com/majd/ipatool/v2` module path.

```sh
git clone --branch codex/auth-trailing-slash https://github.com/zettalyst/ipatool.git
cd ipatool
go generate ./...
go test -count=1 -v ./cmd ./pkg/authdiag ./pkg/appstore ./pkg/http
mkdir -p build
go build -trimpath -buildvcs=false \
  -ldflags '-X github.com/majd/ipatool/v2/cmd.version=2.6.0-localroute' \
  -o build/ipatool .
./build/ipatool --version
```

`go generate` produces ignored mock files; it can download the mock generator and
dependencies on a fresh installation. The focused tests above use mocks or local
TLS servers. The broader `go test ./...` includes upstream SAP integration tests
that can contact Apple and was not used for this fork's offline validation.

Local package tests and a successful build are separate from live Apple
authentication and download verification. Linux, Windows, iOS builds, other
accounts, and GitHub Actions execution have not been verified for this patch.

Before publication, the focused tests passed again in a fresh upstream checkout:
67 command, 460 App Store, and 31 HTTP Ginkgo specs, plus the standard Go tests in
those packages and `pkg/authdiag`. All 14 modified or added Go files matched the
source used for the successful live run byte for byte. Rebuilding with the flags
above produced a binary identical to the successful login/download binary:

```text
Version: 2.6.0-localroute
SHA-256: 3af7b35dd3b5b08fe96fa6c8c8d266b086705e1dcf824bcfbddbd5f9d55403ac
```

This is a local macOS arm64 reproduction result, not a cross-platform hash guarantee.

## Optional authentication diagnostics

Enter credentials directly in the interactive terminal. To collect only the
allowlisted authentication observations, use a new filename in a private directory:

```sh
diag_dir="$(mktemp -d)"
IPATOOL_AUTH_DIAGNOSTICS="$diag_dir/auth.jsonl" ./build/ipatool auth login
```

The diagnostic file is created exclusively with mode `0600`. An existing file or
symlink is refused. Using `mktemp` to create the file itself would therefore fail;
the example creates a directory and supplies a new filename inside it.

The JSONL records stage, status, duration, response type and length, allowlisted
Apple host names, protocol/TLS version, cookie counts, and presence booleans. It
does not record credential values, account identifiers, request or response
bodies, cookie values, full URLs, arbitrary header values, or raw errors.
Successful console output in this diagnostic mode omits the account name and
email. File write or close failures are reported.

This guarantee applies to the dedicated JSONL diagnostic stream. Existing CLI
output, verbose logs, and download errors are separate surfaces and can contain
account information or signed URLs. Do not publish raw terminal captures or use
`--verbose` as a substitute for the structured diagnostics.

## Lessons

An HTTP redirect status is insufficient evidence of a usable redirect: verify
the Location header and retain the POST/signing semantics. Separate an expected
credential error from an empty or HTML routing response. Change one variable at
a time, and validate the candidate correction with real interactive authentication
after transport tests pass. Preserve the exact working source separately from
newer upstream changes so later regressions can be compared against a known base.
