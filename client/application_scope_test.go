package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/parnurzeal/gorequest"
	"golang.org/x/time/rate"
)

// TestSLK128566_SaasClientUsesV2Endpoint verifies that SaaS and CSP clients both use
// /api/v2/access_management/scopes/ and NOT the legacy /api/access_mgmt/scopes/ path.
func TestSLK128566_SaasClientUsesV2Endpoint(t *testing.T) {
	scope := ApplicationScope{Name: "test-scope", Description: "test"}
	scopeJSON, _ := json.Marshal(scope)

	tests := []struct {
		name       string
		clientType string
	}{
		{"CSP client uses v2 endpoint", Csp},
		{"SaaS client uses v2 endpoint", Saas},
		{"SaasDev client uses v2 endpoint", SaasDev},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write(scopeJSON)
			}))
			defer srv.Close()

			cli := &Client{
				url:        srv.URL,
				clientType: tt.clientType,
				saasUrl:    srv.URL,
				gorequest:  gorequest.New(),
				limiter:    rate.NewLimiter(10, 3),
			}

			_, err := cli.GetApplicationScope("test-scope")
			if err != nil {
				t.Fatalf("GetApplicationScope returned unexpected error: %v", err)
			}

			const wantPath = "/api/v2/access_management/scopes/test-scope"
			const legacyPath = "/api/access_mgmt/scopes/test-scope"

			if capturedPath != wantPath {
				t.Errorf("expected path %q, got %q", wantPath, capturedPath)
			}
			if capturedPath == legacyPath {
				t.Errorf("used legacy SaaS path %q — regression of SLK-128566", legacyPath)
			}
		})
	}
}

// TestSLK128566_CreateUsesV2Endpoint verifies Create uses the v2 endpoint for all client types.
func TestSLK128566_CreateUsesV2Endpoint(t *testing.T) {
	tests := []struct {
		name       string
		clientType string
	}{
		{"CSP", Csp},
		{"SaaS", Saas},
		{"SaasDev", SaasDev},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedPath = r.URL.Path
				w.WriteHeader(http.StatusCreated)
			}))
			defer srv.Close()

			cli := &Client{
				url:        srv.URL,
				clientType: tt.clientType,
				saasUrl:    srv.URL,
				gorequest:  gorequest.New(),
				limiter:    rate.NewLimiter(10, 3),
			}

			err := cli.CreateApplicationScope(&ApplicationScope{Name: "scope1"})
			if err != nil {
				t.Fatalf("CreateApplicationScope returned unexpected error: %v", err)
			}

			const wantPath = "/api/v2/access_management/scopes"
			if capturedPath != wantPath {
				t.Errorf("expected path %q, got %q", wantPath, capturedPath)
			}
		})
	}
}
