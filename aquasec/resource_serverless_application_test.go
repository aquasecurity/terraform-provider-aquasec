package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccServerlessApplication(t *testing.T) {
	t.Skip("Skipping Serverless Application create test")
	t.Parallel()
	name := "tf-test-sls"
	region := "us-west-1"
	computeProviderType := 3
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
	scannerType := "specific"
	scannerGroupName := "test-remote-scanner"
	description := "Test serverless app"
	autoPullTime := "03:00"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_serverless_application.test"),
		Steps: []resource.TestStep{
			{
				Config: testAccServerlessApplicationConfig(name, region, computeProviderType, username, password, tenantId, subscriptionId, scannerType, scannerGroupName, description, autoPullTime),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckServerlessApplicationExists("aquasec_serverless_application.test", name),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "scanner_type", scannerType),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "description", description),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "scanner_group_name", scannerGroupName),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "compute_provider", fmt.Sprintf("%d", computeProviderType)),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "username", username),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "region", region),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "subscription_id", subscriptionId),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "tenant_id", tenantId),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "auto_pull_time", autoPullTime),
				),
			},
			{
				Config: testAccServerlessApplicationConfig(name, region, computeProviderType, username, password, tenantId, subscriptionId, "specific", scannerGroupName, description, autoPullTime),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckServerlessApplicationExists("aquasec_serverless_application.test", name),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "scanner_type", "specific"),
				),
			},
			{
				Config: testAccServerlessApplicationConfig(name, region, computeProviderType, username, password, tenantId, subscriptionId, "any", scannerGroupName, "Updated desc", autoPullTime),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckServerlessApplicationExists("aquasec_serverless_application.test", name),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "scanner_type", "any"),
					resource.TestCheckResourceAttr("aquasec_serverless_application.test", "description", "Updated desc"),
				),
			},
		},
	})
}

func testAccServerlessApplicationConfig(name, region string, computeProviderType int, username, password, tenantId, subscriptionId, scannerType, scannerGroupName, description, autoPullTime string) string {
	return fmt.Sprintf(`
resource "aquasec_serverless_application" "test" {
	name                  = "%s"
	region                = "%s"
	compute_provider      = %d
	username              = "%s"
	password              = "%s"
	tenant_id             = "%s"
	subscription_id       = "%s"
	scanner_type          = "%s"
	scanner_group_name    = "%s"
	description           = "%s"
	auto_pull             = true
	auto_pull_time        = "%s"
}
`, name, region, computeProviderType, username, password, tenantId, subscriptionId, scannerType, scannerGroupName, description, autoPullTime)
}

func testAccCheckServerlessApplicationExists(n string, expectedName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return NewNotFoundErrorf("%s in state", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("no ID set for %s", n)
		}
		if rs.Primary.ID != expectedName {
			return fmt.Errorf("unexpected ID: got %s, expected %s", rs.Primary.ID, expectedName)
		}
		return nil
	}
}

func testAccCheckServerlessApplicationDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_serverless_application" {
			continue
		}
		name := rs.Primary.ID
		client := testAccProvider.Meta().(*client.Client)
		_, err := client.GetServerlessApplication(name)
		if err == nil {
			return fmt.Errorf("serverless application %s still exists", name)
		}
	}
	return nil
}
