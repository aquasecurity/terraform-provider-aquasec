package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccAquaSecAPIKeysDataSource_byID(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping API Keys by-ID data source test in non-SaaS env")
	}
	t.Parallel()
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccAquaSecAPIKeyAndDataSourceByID(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquaSecAPIKeyCreated("aquasec_aqua_api_key.test"),
					testAccCheckAquaSecAPIKeyDataByID("output.aquasec_aqua_api_keys.test"),
				),
			},
		},
	})
}

func testAccAquaSecAPIKeyAndDataSourceByID() string {
	return `
	resource "aquasec_aqua_api_key" "test" {
		description  = "Terraform test key"
		enabled      = true
		roles        = ["role1"]
		ip_addresses = ["127.0.0.1"]
		expiration   = 30
	}

	output "aquasec_aqua_api_keys" "test" {
  		id = aquasec_api_key.test.id
	}`
}

func testAccCheckAquaSecAPIKeyCreated(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("resource %q not found in state", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("API Key wasn’t created (empty ID)")
		}
		return nil
	}
}

func testAccCheckAquaSecAPIKeyDataByID(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("data source %q not found in state", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("data source %q has no ID", n)
		}
		// ensure some key attributes were populated
		for _, attr := range []string{"access_key", "secret", "description"} {
			if v := rs.Primary.Attributes[attr]; v == "" {
				return fmt.Errorf("attribute %q is empty", attr)
			}
		}
		return nil
	}
}
