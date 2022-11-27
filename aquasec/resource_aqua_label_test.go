package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecresourceAquaLabel(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("terraform-test")
	description := "terraform-test"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_aqua_label.new"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecAquaLabel(name, description),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecAquaLabelExists("aquasec_aqua_label.new"),
				),
			},
			{
				ResourceName:      "aquasec_aqua_label.new",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckAquasecAquaLabel(name, description string) string {
	return fmt.Sprintf(`
	resource "aquasec_aqua_label" "new" {
		name = "%s"
		description = "%s"
	}`, name, description)

}

func testAccCheckAquasecAquaLabelExists(n string) resource.TestCheckFunc {
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
