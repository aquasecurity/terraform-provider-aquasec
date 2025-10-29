package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataSourceServerlessApplication(t *testing.T) {
	t.Skip("Skipping Serverless Application create test")
	t.Parallel()

	username := os.Getenv("AZURE_USERNAME")
	if username == "" {
		t.Fatal("AZURE_USERNAME must be set in environment")
	}
	password := os.Getenv("AZURE_PASSWORD")
	if password == "" {
		t.Fatal("AZURE_PASSWORD must be set in environment")
	}
	tenantId := os.Getenv("AZURE_TENANT_ID")
	if tenantId == "" {
		t.Fatal("AZURE_TENANT_ID must be set in environment")
	}
	subscriptionId := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subscriptionId == "" {
		t.Fatal("AZURE_SUBSCRIPTION_ID must be set in environment")
	}

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckServerlessApplicationDataSourceConfig(username, password, tenantId, subscriptionId),
				Check:  testAccCheckServerlessApplicationDataSourceExists("data.aquasec_serverless_applications.testapp"),
			},
		},
	})
}

func testAccCheckServerlessApplicationDataSourceConfig(username, password, tenantId, subscriptionId string) string {
	return fmt.Sprintf(`
resource "aquasec_serverless_application" "test" {
	name                  = "tf-test-sls"
	region                = "us-west-1"
	compute_provider      = 3
	username              = "%s"
	password              = "%s"
	tenant_id             = "%s"
	subscription_id       = "%s"
	scanner_type          = "specific"
	scanner_group_name    = "test-remote-scanner"
	description           = "Test serverless app"
	auto_pull             = true
	auto_pull_time        = "03:00"
}

data "aquasec_serverless_applications" "testapp" {}
`, username, password, tenantId, subscriptionId)
}

func testAccCheckServerlessApplicationDataSourceExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("data resource %q not found in state", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("no ID set for data resource %q", n)
		}
		return nil
	}
}
