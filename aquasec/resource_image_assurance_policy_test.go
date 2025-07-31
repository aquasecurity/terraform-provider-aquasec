package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecImageAssurancePolicy(t *testing.T) {
	t.Parallel()
	description := "Created using Terraform"
	name := acctest.RandomWithPrefix("terraform-test")
	application_scopes := "Global"
	ignore_recently_published_fix_vln_period := 30
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_image_assurance_policy.terraformiap"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckImageAssurancePolicy(description, name, application_scopes, ignore_recently_published_fix_vln_period),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckImageAssurancePolicyExists("aquasec_image_assurance_policy.terraformiap"),
				),
			},
			{
				ResourceName:      "aquasec_image_assurance_policy.terraformiap",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckImageAssurancePolicy(description string, name string, application_scopes string, ignore_recently_published_fix_vln_period int) string {
	return fmt.Sprintf(`
	resource "aquasec_image_assurance_policy" "terraformiap" {
		description = "%s"
		name = "%s"
		application_scopes = [
			"%s"
		]
		ignore_recently_published_fix_vln_period = %d
	}`, description, name, application_scopes, ignore_recently_published_fix_vln_period)

}

func testAccCheckImageAssurancePolicyExists(n string) resource.TestCheckFunc {
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
