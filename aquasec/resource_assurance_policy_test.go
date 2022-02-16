package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecAssurancePolicy(t *testing.T) {
	assurance_type := "image"
	description := "Created using Terraform"
	name := acctest.RandomWithPrefix("terraform-test")
	application_scopes := "Global"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAssurancePolicy(assurance_type, description, name, application_scopes),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAssurancePolicyExists("aquasec_assurance_policy.terraformiap"),
				),
			},
		},
	})
}

func testAccCheckAssurancePolicy(assurance_type string, description string, name string, application_scopes string) string {
	return fmt.Sprintf(`
	resource "aquasec_assurance_policy" "terraformiap" {
		assurance_type = "%s"
		description = "%s"
		name = "%s"
		application_scopes = [
			"%s"
		]
	}`, assurance_type, description, name, application_scopes)

}

func testAccCheckAssurancePolicyExists(n string) resource.TestCheckFunc {
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
