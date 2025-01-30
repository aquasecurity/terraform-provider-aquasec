package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataApplicationScopeSaas(t *testing.T) {
	t.Parallel()
	name := "Global"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckApplicationScopeSaasDataSource(name),
				Check:  testAccCheckApplicationScopeSaasDataSourceExists("data.aquasec_application_scope_saas.application_scope_saas"),
			},
		},
	})
}

func testAccCheckApplicationScopeSaasDataSource(name string) string {
	return fmt.Sprintf(`
		data "aquasec_application_scope_saas" "application_scope_saas" {
			name = "%s"
		}

		output "appscopes" {
			value = data.aquasec_application_scope_saas.application_scope_saas
		}
	`, name)
}

func testAccCheckApplicationScopeSaasDataSourceExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("%s not found in state", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("ID for %s not set in state", n)
		}
		return nil
	}
}
