package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecFunctionAssurancePolicy(t *testing.T) {
	t.Parallel()
	description := "Created using Terraform"
	name := acctest.RandomWithPrefix("terraform-test")
	application_scopes := "Global"
	assurance_type := "function"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_function_assurance_policy.terraformiap"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckFunctionAssurancePolicy(description, name, assurance_type, application_scopes),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFunctionAssurancePolicyExists("aquasec_function_assurance_policy.terraformiap"),
				),
			},
		},
	})
}

func testAccCheckFunctionAssurancePolicy(description string, name string, assurance_type, application_scopes string) string {
	return fmt.Sprintf(`
	resource "aquasec_function_assurance_policy" "terraformiap" {
		description = "%s"
		name = "%s"
		assurance_type = "%s"
		application_scopes = [
			"%s"
		]
	}`, description, name, assurance_type, application_scopes)

}

func testAccCheckFunctionAssurancePolicyExists(n string) resource.TestCheckFunc {
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
