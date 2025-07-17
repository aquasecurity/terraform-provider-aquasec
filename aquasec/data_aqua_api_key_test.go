package aquasec

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccAquaSecAPIKeysDataSource_byID(t *testing.T) {
	t.Parallel()
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAquaSecAPIKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAquaSecAPIKeyAndDataSourceByID(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquaSecAPIKeyCreated("aquasec_aqua_api_key.test"),
					testAccCheckAquaSecAPIKeyDataByID("data.aquasec_aqua_api_keys.apikeys"),
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
	data "aquasec_aqua_api_keys" "apikeys" {
		id = aquasec_aqua_api_key.test.id
	}

	output "first_desc" {
		value = data.aquasec_aqua_api_keys.apikeys.apikeys[0].description
	}
	output "test_api_key_id" {
		value = data.aquasec_aqua_api_keys.apikeys.apikeys[0].id
	}
	`
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

		descKey := "apikeys.0.description"
		if v, ok := rs.Primary.Attributes[descKey]; !ok || v == "" {
			return fmt.Errorf("attribute %q is empty or not found", descKey)
		}
		return nil
	}
}

func testAccCheckAquaSecAPIKeyDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*client.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_aqua_api_key" {
			continue
		}

		id := rs.Primary.ID
		if id == "" {
			continue
		}

		// Try fetching the deleted key, expect failure
		keyID, err := strconv.Atoi(id)
		if err != nil {
			return fmt.Errorf("invalid ID %q: %v", id, err)
		}

		_, err = client.GetApiKey(keyID)
		if err == nil {
			return fmt.Errorf("API Key still exists (ID %d)", keyID)
		}
	}

	return nil
}
