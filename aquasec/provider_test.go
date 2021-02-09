package aquasec

import (
	"os"
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
	if err := Provider(testVersion).InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = Provider(testVersion)
}

func testAccPreCheck(t *testing.T) {
	configPath, _ := homedir.Expand("~/.aquasec/tf.config")
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		return
	}
	if err := os.Getenv("AQUA_USER"); err == "" {
		t.Fatal("AQUA_USER must be set for acceptance tests")
	}

	if err := os.Getenv("AQUA_PASSWORD"); err == "" {
		t.Fatal("AQUA_PASSWORD must be set for acceptance tests")
	}

	if err := os.Getenv("AQUA_URL"); err == "" {
		t.Fatal("AQUA_URL must be set for acceptance tests")
	}
}
