package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataApplicationScopePolicy(t *testing.T) {
	t.Parallel()
	name := "Global"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckApplicationScopePolicyDataSource(name),
				Check:  testAccCheckApplicationScopePolicyDataSourceExists("data.aquasec_application_scope.defaultiap"),
			},
		},
	})
}

func testAccCheckApplicationScopePolicyDataSource(name string) string {
	return fmt.Sprintf(`
	data "aquasec_application_scope" "defaultiap" {
		name = "%s"
	}
	output "appscopes" {
		value = data.aquasec_application_scope.defaultiap
	}
	`, name)

}

func testAccCheckApplicationScopePolicyDataSourceExists(n string) resource.TestCheckFunc {
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
