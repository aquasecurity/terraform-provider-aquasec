package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecFunctionAssurancePolicy(t *testing.T) {
	assurance_type := "function"
	description := "Created using Terraform"
	name := acctest.RandomWithPrefix("terraform-test")
	application_scopes := "Global"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckFunctionAssurancePolicy(assurance_type, description, name, application_scopes),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFunctionAssurancePolicyExists("aquasec_function_assurance_policy.terraformiap"),
				),
			},
		},
	})
}

func testAccCheckFunctionAssurancePolicy(assurance_type string, description string, name string, application_scopes string) string {
	return fmt.Sprintf(`
	resource "aquasec_function_assurance_policy" "terraformiap" {
		assurance_type = "%s"
		description = "%s"
		name = "%s"
		application_scopes = [
		  "%s"
		]
	  }`, assurance_type, description, name, application_scopes)

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
