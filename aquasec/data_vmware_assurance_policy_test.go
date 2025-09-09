package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataAquasecVmwareAssurancePolicy(t *testing.T) {
	t.Parallel()
	name := "Default"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecVmwareAssurancePolicyDataSource(name),
				Check:  testAccCheckAquasecVmwareAssurancePolicyDataSourceExists("data.aquasec_vmware_assurance_policy.defaultvmw"),
			},
		},
	})
}

func testAccCheckAquasecVmwareAssurancePolicyDataSource(name string) string {
	return fmt.Sprintf(`
	data "aquasec_vmware_assurance_policy" "defaultvmw" {
		name = "%s"
	}
	`, name)

}

func testAccCheckAquasecVmwareAssurancePolicyDataSourceExists(n string) resource.TestCheckFunc {
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
