package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecHostAssurancePolicy(t *testing.T) {
	t.Parallel()
	assurance_type := "host"
	description := "Created using Terraform"
	name := acctest.RandomWithPrefix("terraform-test")
	application_scopes := "Global"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckHostAssurancePolicy(assurance_type, description, name, application_scopes),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckHostAssurancePolicyExists("aquasec_host_assurance_policy.terraformiap"),
				),
			},
		},
	})
}

func testAccCheckHostAssurancePolicy(assurance_type string, description string, name string, application_scopes string) string {
	return fmt.Sprintf(`
	resource "aquasec_host_assurance_policy" "terraformiap" {
		assurance_type = "%s"
		description = "%s"
		name = "%s"
		application_scopes = [
			"%s"
		]
	}`, assurance_type, description, name, application_scopes)

}

func testAccCheckHostAssurancePolicyExists(n string) resource.TestCheckFunc {
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
