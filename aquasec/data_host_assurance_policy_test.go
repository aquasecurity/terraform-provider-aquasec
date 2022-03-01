package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataAquasecHostAssurancePolicy(t *testing.T) {
	name := "Default"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecHostAssurancePolicyDataSource(name),
				Check:  testAccCheckAquasecHostAssurancePolicyDataSourceExists("data.aquasec_host_assurance_policy.defaultiap"),
			},
		},
	})
}

func testAccCheckAquasecHostAssurancePolicyDataSource(name string) string {
	return fmt.Sprintf(`
	data "aquasec_host_assurance_policy" "defaultiap" {
		name = "%s"
	}
	`, name)

}

func testAccCheckAquasecHostAssurancePolicyDataSourceExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]

		if !ok {
			return NewNotFoundErrorf("%s in state", n)
		}

		if rs.Primary.ID == "" {
			return NewNotFoundErrorf("ID for %s in state", n)
		}

		return nil
	}
}
