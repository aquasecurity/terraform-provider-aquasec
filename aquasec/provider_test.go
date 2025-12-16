package aquasec

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/mitchellh/go-homedir"
)

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider
var testVersion = "1.0"

func init() {
	testAccProvider = Provider(testVersion)
	testAccProviders = map[string]*schema.Provider{
		"aquasec": testAccProvider,
	}
}

func TestProvider(t *testing.T) {
	t.Parallel()
	if err := Provider(testVersion).InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	t.Parallel()
	var _ *schema.Provider = Provider(testVersion)
}

func testAccPreCheck(t *testing.T) {
	configPath, _ := homedir.Expand("~/.aquasec/tf.config")
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		return
	}
	useAPIKeyStr := os.Getenv("AQUA_USE_API_KEY")
	useAPiKey, _ := strconv.ParseBool(useAPIKeyStr)

	if err := os.Getenv("AQUA_URL"); err == "" {
		t.Fatal("AQUA_URL must be set for acceptance tests")
	}

	if !useAPiKey {
		if err := os.Getenv("AQUA_USER"); err == "" {
			t.Fatal("AQUA_USER must be set for acceptance tests")
		}

		if err := os.Getenv("AQUA_PASSWORD"); err == "" {
			t.Fatal("AQUA_PASSWORD must be set for acceptance tests")
		}
	} else {
		if os.Getenv("AQUA_API_KEY") == "" {
			t.Fatal("AQUA_API_KEY must be set for API key authentication")
		}
		if os.Getenv("AQUA_API_SECRET") == "" {
			t.Fatal("AQUA_API_SECRET must be set for API key authentication")
		}
	}
}

func TestProviderConfigure_ValidationLogic(t *testing.T) {
	// Clear environment variables to test validation logic
	// Use LookupEnv to distinguish between unset and empty-string values
	oldURL, urlWasSet := os.LookupEnv("AQUA_URL")
	oldUser, userWasSet := os.LookupEnv("AQUA_USER")
	oldPass, passWasSet := os.LookupEnv("AQUA_PASSWORD")
	oldKey, keyWasSet := os.LookupEnv("AQUA_API_KEY")
	oldSecret, secretWasSet := os.LookupEnv("AQUA_API_SECRET")

	os.Unsetenv("AQUA_URL")
	os.Unsetenv("AQUA_USER")
	os.Unsetenv("AQUA_PASSWORD")
	os.Unsetenv("AQUA_API_KEY")
	os.Unsetenv("AQUA_API_SECRET")

	defer func() {
		// Restore to original state: set if was set, unset if was unset
		restoreEnv := func(key, val string, wasSet bool) {
			if wasSet {
				os.Setenv(key, val)
			} else {
				os.Unsetenv(key)
			}
		}
		restoreEnv("AQUA_URL", oldURL, urlWasSet)
		restoreEnv("AQUA_USER", oldUser, userWasSet)
		restoreEnv("AQUA_PASSWORD", oldPass, passWasSet)
		restoreEnv("AQUA_API_KEY", oldKey, keyWasSet)
		restoreEnv("AQUA_API_SECRET", oldSecret, secretWasSet)
	}()

	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid API key authentication",
			config: map[string]interface{}{
				"aqua_url":        "https://cloud.aquasec.com",
				"aqua_api_key":    "test_key",
				"aqua_api_secret": "test_secret",
				"validate":        false,
			},
			expectError: false,
		},
		{
			name: "Valid username/password authentication",
			config: map[string]interface{}{
				"aqua_url": "https://cloud.aquasec.com",
				"username": "test_user",
				"password": "test_pass",
				"validate": false,
			},
			expectError: false,
		},
		{
			name: "Missing API secret",
			config: map[string]interface{}{
				"aqua_url":     "https://cloud.aquasec.com",
				"aqua_api_key": "test_key",
				"validate":     true,
			},
			expectError: true,
			errorMsg:    "aqua_api_secret parameter is missing",
		},
		{
			name: "Missing API key",
			config: map[string]interface{}{
				"aqua_url":        "https://cloud.aquasec.com",
				"aqua_api_secret": "test_secret",
				"validate":        true,
			},
			expectError: true,
			errorMsg:    "aqua_api_key parameter is missing",
		},
		{
			name: "Missing password",
			config: map[string]interface{}{
				"aqua_url": "https://cloud.aquasec.com",
				"username": "test_user",
				"validate": true,
			},
			expectError: true,
			errorMsg:    "password parameter is missing",
		},
		{
			name: "Missing username",
			config: map[string]interface{}{
				"aqua_url": "https://cloud.aquasec.com",
				"password": "test_pass",
				"validate": true,
			},
			expectError: true,
			errorMsg:    "username parameter is missing",
		},
		{
			name: "No credentials provided",
			config: map[string]interface{}{
				"aqua_url": "https://cloud.aquasec.com",
				"validate": true,
			},
			expectError: true,
			errorMsg:    "credentials are missing",
		},
		{
			name: "Missing aqua_url",
			config: map[string]interface{}{
				"aqua_api_key":    "test_key",
				"aqua_api_secret": "test_secret",
				"validate":        true,
			},
			expectError: true,
			errorMsg:    "aqua_url parameter is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := Provider("test")
			d := schema.TestResourceDataRaw(t, provider.Schema, tt.config)

			_, diags := providerConfigure(context.Background(), d)

			if tt.expectError {
				if len(diags) == 0 {
					t.Errorf("Expected error containing '%s', but got no error", tt.errorMsg)
				} else {
					found := false
					for _, diag := range diags {
						if strings.Contains(diag.Summary, tt.errorMsg) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error containing '%s', but got: %v", tt.errorMsg, diags)
					}
				}
			} else {
				if len(diags) > 0 {
					t.Errorf("Expected no error, but got: %v", diags)
				}
			}
		})
	}
}

func TestProviderConfigure_BothAuthMethods(t *testing.T) {
	// Note: Not using t.Parallel() because this test modifies global environment variables
	// that other parallel tests depend on through testAccPreCheck

	// Save original environment variable values before any modifications
	// Use LookupEnv to distinguish between unset and empty-string values
	oldURL, urlWasSet := os.LookupEnv("AQUA_URL")
	oldUser, userWasSet := os.LookupEnv("AQUA_USER")
	oldPass, passWasSet := os.LookupEnv("AQUA_PASSWORD")
	oldKey, keyWasSet := os.LookupEnv("AQUA_API_KEY")
	oldSecret, secretWasSet := os.LookupEnv("AQUA_API_SECRET")

	// Helper to restore a single env var to its original state
	restoreEnv := func(key, val string, wasSet bool) {
		if wasSet {
			os.Setenv(key, val)
		} else {
			os.Unsetenv(key)
		}
	}

	// Restore all env vars to their original state when the test function completes
	defer func() {
		restoreEnv("AQUA_URL", oldURL, urlWasSet)
		restoreEnv("AQUA_USER", oldUser, userWasSet)
		restoreEnv("AQUA_PASSWORD", oldPass, passWasSet)
		restoreEnv("AQUA_API_KEY", oldKey, keyWasSet)
		restoreEnv("AQUA_API_SECRET", oldSecret, secretWasSet)
	}()

	// Helper to clear all AQUA env vars - ensures clean slate for each subtest
	clearAllEnvVars := func() {
		os.Unsetenv("AQUA_URL")
		os.Unsetenv("AQUA_USER")
		os.Unsetenv("AQUA_PASSWORD")
		os.Unsetenv("AQUA_API_KEY")
		os.Unsetenv("AQUA_API_SECRET")
	}

	// Test that both auth methods work independently
	tests := []struct {
		name          string
		setupEnv      func()
		expectSuccess bool
		description   string
	}{
		{
			name: "API Key from environment",
			setupEnv: func() {
				os.Setenv("AQUA_URL", "https://test.aquasec.com")
				os.Setenv("AQUA_API_KEY", "test_key")
				os.Setenv("AQUA_API_SECRET", "test_secret")
			},
			expectSuccess: true,
			description:   "Should work with API key from environment",
		},
		{
			name: "Username/Password from environment",
			setupEnv: func() {
				os.Setenv("AQUA_URL", "https://test.aquasec.com")
				os.Setenv("AQUA_USER", "test_user")
				os.Setenv("AQUA_PASSWORD", "test_pass")
			},
			expectSuccess: true,
			description:   "Should work with username/password from environment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all env vars at the start of each subtest for complete isolation
			clearAllEnvVars()
			// Setup test-specific environment
			tt.setupEnv()

			provider := Provider("test")
			config := map[string]interface{}{
				"validate": false,
			}
			d := schema.TestResourceDataRaw(t, provider.Schema, config)

			_, diags := providerConfigure(context.Background(), d)

			if tt.expectSuccess && len(diags) > 0 {
				t.Errorf("%s: Expected success but got errors: %v", tt.description, diags)
			}
			if !tt.expectSuccess && len(diags) == 0 {
				t.Errorf("%s: Expected error but got success", tt.description)
			}
		})
	}
}
