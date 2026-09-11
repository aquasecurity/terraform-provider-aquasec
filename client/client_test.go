package client

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/parnurzeal/gorequest"
)

func TestAuthenticateWithAPIKey_SaasDevUsesDevProvisioningURL(t *testing.T) {
	cli, err := NewClientWithAPIKey(consts.SaasDevUrl, "test-api-key", "test-api-secret", true, nil)
	if err != nil {
		t.Fatalf("create API-key client: %v", err)
	}

	originalDisableTransportSwap := gorequest.DisableTransportSwap
	gorequest.DisableTransportSwap = true
	t.Cleanup(func() {
		gorequest.DisableTransportSwap = originalDisableTransportSwap
	})

	cli.gorequest.SetLogger(log.New(io.Discard, "", 0))
	var requestURLs []string
	cli.gorequest.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requestURL := req.URL.String()
		requestURLs = append(requestURLs, requestURL)

		var body string
		switch requestURL {
		case consts.SaasDevTokenUrl + "/v2/tokens":
			body = `{"data":"test-token"}`
		case consts.SaasDevProvUrl + "/v1/envs":
			body = `{"data":{"ese_url":"dev-tenant.example.test"}}`
		default:
			return nil, fmt.Errorf("unexpected request URL %s", requestURL)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})

	token, err := cli.AuthenticateWithAPIKey()
	if err != nil {
		if strings.Contains(err.Error(), "URL is not allowed") {
			t.Fatalf("SaaS development URL was rejected: %v", err)
		}
		t.Fatalf("authenticate with API key: %v", err)
	}
	if token != "test-token" {
		t.Fatalf("expected test token, got %q", token)
	}

	expectedURLs := []string{
		consts.SaasDevTokenUrl + "/v2/tokens",
		consts.SaasDevProvUrl + "/v1/envs",
	}
	if len(requestURLs) != len(expectedURLs) {
		t.Fatalf("expected request URLs %v, got %v", expectedURLs, requestURLs)
	}
	for i, expectedURL := range expectedURLs {
		if requestURLs[i] != expectedURL {
			t.Fatalf("request %d: expected URL %q, got %q", i, expectedURL, requestURLs[i])
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
