package appstore

import (
	gohttp "net/http"
	"testing"

	"github.com/majd/ipatool/v2/pkg/http"
	"go.uber.org/mock/gomock"
)

func TestBagAuthenticationTrailingSlash(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"bag omits slash", testAuthEndpoint, testAuthEndpoint + "/"},
		{"bag includes slash", testAuthEndpoint + "/", testAuthEndpoint + "/"},
		{"query preserved", testAuthEndpoint + "?a=one%2Ftwo&b=three+four", testAuthEndpoint + "/?a=one%2Ftwo&b=three+four"},
		{"existing slash and query", testAuthEndpoint + "/?a=one%2Ftwo&b=three+four", testAuthEndpoint + "/?a=one%2Ftwo&b=three+four"},
		{"empty query preserved", testAuthEndpoint + "?", testAuthEndpoint + "/?"},
		{"bag selected pod preserved", "https://p42-buy.itunes.apple.com" + PrivateAppStoreAPIPathAuth, "https://p42-buy.itunes.apple.com" + PrivateAppStoreAPIPathAuth + "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			bagClient := http.NewMockClient[bagResult](ctrl)
			input := validBagResult()
			input.URLBag.AuthEndpoint = tc.input
			bagClient.EXPECT().Send(gomock.Any()).Return(http.Result[bagResult]{StatusCode: gohttp.StatusOK, Data: input}, nil).Times(1)
			store := &appstore{bagClient: bagClient}
			result, err := store.bag("000000000000")
			if err != nil {
				t.Fatal(err)
			}
			if result.AuthEndpoint != tc.want || result.SAPConfig.AuthEndpoint != tc.want {
				t.Fatalf("authentication URL = %q / %q, want %q", result.AuthEndpoint, result.SAPConfig.AuthEndpoint, tc.want)
			}
			if result.SAPConfig.SetupURL != input.URLBag.SAPSetupEndpoint || result.SAPConfig.CertificateURL != input.URLBag.SAPSetupCertEndpoint || result.SAPConfig.Version != 200 {
				t.Fatal("authentication URL normalization changed SAP configuration")
			}
			again, err := normalizeBagAuthenticationEndpoint(result.AuthEndpoint)
			if err != nil || again != result.AuthEndpoint {
				t.Fatalf("normalization is not idempotent: %q, %v", again, err)
			}
		})
	}
}

func TestAuthenticationEndpointPathBoundaries(t *testing.T) {
	for _, endpoint := range []string{
		testAuthEndpoint,
		testAuthEndpoint + "/",
		"https://p42-buy.itunes.apple.com" + PrivateAppStoreAPIPathAuth,
		"https://p42-buy.itunes.apple.com" + PrivateAppStoreAPIPathAuth + "/?route=preserved",
	} {
		if err := validateAuthenticationEndpoint(endpoint); err != nil {
			t.Errorf("valid authentication endpoint rejected: %v", err)
		}
	}
	for _, endpoint := range []string{
		testAuthEndpoint + "//",
		testAuthEndpoint + "/fast",
		testAuthEndpoint + "UnexpectedSuffix",
		"https://buy.itunes.apple.com/unrelated" + PrivateAppStoreAPIPathAuth,
		"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/other/",
		"https://buy.itunes.apple.com.evil.example" + PrivateAppStoreAPIPathAuth + "/",
		"https://example.com" + PrivateAppStoreAPIPathAuth + "/",
		"http://buy.itunes.apple.com" + PrivateAppStoreAPIPathAuth + "/",
		PrivateAppStoreAPIPathAuth + "/",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if err := validateAuthenticationEndpoint(endpoint); err == nil {
				t.Fatal("invalid authentication endpoint accepted")
			}
			if _, err := normalizeBagAuthenticationEndpoint(endpoint); err == nil {
				t.Fatal("invalid bag authentication endpoint normalized")
			}
		})
	}
}

func TestAuthenticationRedirectIsNotNormalized(t *testing.T) {
	store := &appstore{}
	for _, status := range []int{gohttp.StatusMovedPermanently, gohttp.StatusFound} {
		for _, endpoint := range []string{testAuthEndpoint, testAuthEndpoint + "/", testAuthEndpoint + "?route=unchanged"} {
			response := http.Result[loginResult]{StatusCode: status, Headers: map[string]string{"Location": endpoint}}
			retry, redirect, err := store.parseLoginResponse(&response, 1, "")
			if err != nil || !retry || redirect != endpoint {
				t.Fatalf("HTTP %d redirect changed: got %q, want %q; retry=%t err=%v", status, redirect, endpoint, retry, err)
			}
		}
	}
}
