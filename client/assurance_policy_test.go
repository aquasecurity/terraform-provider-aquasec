package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/parnurzeal/gorequest"
	"golang.org/x/time/rate"
)

func TestCreateAssurancePolicyErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		responseBody  interface{}
		expectError   bool
		errorContains string
	}{
		{
			name:        "Success 204",
			statusCode:  204,
			expectError: false,
		},
		{
			name:       "Error 201 - not a valid success code",
			statusCode: 201,
			responseBody: ErrorResponse{
				Message: "Unexpected status",
			},
			expectError:   true,
			errorContains: "failed creating Assurance Policy",
		},
		{
			name:       "Error 200 - not a valid success code",
			statusCode: 200,
			responseBody: ErrorResponse{
				Message: "Unexpected status",
			},
			expectError:   true,
			errorContains: "failed creating Assurance Policy",
		},
		{
			name:       "Error 400 - invalid Rego format",
			statusCode: 400,
			responseBody: ErrorResponse{
				Message: "The script uploaded is not in a correct Rego format.",
				Code:    400,
			},
			expectError:   true,
			errorContains: "not in a correct Rego format",
		},
		{
			name:       "Error 500 - internal error",
			statusCode: 500,
			responseBody: ErrorResponse{
				Message: "Internal server error",
				Code:    500,
			},
			expectError:   true,
			errorContains: "Internal server error",
		},
		{
			name:          "Error with empty body",
			statusCode:    400,
			responseBody:  nil,
			expectError:   true,
			errorContains: "failed creating Assurance Policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.responseBody != nil {
					json.NewEncoder(w).Encode(tt.responseBody)
				}
			}))
			defer server.Close()

			client := &Client{
				url:       server.URL,
				token:     "test-token",
				gorequest: gorequest.New(),
				limiter:   rate.NewLimiter(10, 3),
			}

			policy := &AssurancePolicy{
				Name: "test-policy",
			}

			err := client.CreateAssurancePolicy(policy, "kubernetes")

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %s", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %s", err.Error())
				}
			}
		})
	}
}
