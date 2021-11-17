package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecImageAssurancePolicyDatasource(t *testing.T) {
	name := "Default"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecImageAssurancePolicyDataSource(name),
				Check:  testAccCheckAquasecImageAssurancePolicyDataSourceExists("data.aquasec_image_assurance_policy.defaultiap"),
			},
		},
	})
}

func testAccCheckAquasecImageAssurancePolicyDataSource(name string) string {
	return fmt.Sprintf(`
	data "aquasec_image_assurance_policy" "defaultiap" {
		name = "%s"
	}
	`, name)

}

func testAccCheckAquasecImageAssurancePolicyDataSourceExists(n string) resource.TestCheckFunc {
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
