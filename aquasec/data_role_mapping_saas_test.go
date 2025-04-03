package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecRolesMappingSaasDatasource(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping SaaS roles mapping data source test - not a SaaS environment")
	}

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecRolesMappingSaasBasicConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecRolesMappingSaasExists("data.aquasec_roles_mapping_saas.test"),
					resource.TestCheckResourceAttrSet("data.aquasec_roles_mapping_saas.test", "roles_mapping.#"),
				),
			},
		},
	})
}

func testAccCheckAquasecRolesMappingSaasBasicConfig() string {
	return `
	data "aquasec_roles_mapping_saas" "test" {}
	`
}

func testAccCheckAquasecRolesMappingSaasExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set for %s", n)
		}
		return nil
	}
}
