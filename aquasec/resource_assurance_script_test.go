package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccAssuranceScript_basic(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("test-assurance-script")
	resourceName := "aquasec_assurance_script.test"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_assurance_script.test"),
		Steps: []resource.TestStep{
			{
				Config: testAccAssuranceScriptBasic(name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAssuranceScriptExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", "Test assurance script"),
					resource.TestCheckResourceAttr(resourceName, "engine", "yaml"),
					resource.TestCheckResourceAttr(resourceName, "kind", "kubernetes"),
					resource.TestCheckResourceAttr(resourceName, "path", "test.yaml"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccAssuranceScriptBasic(name string) string {
	return fmt.Sprintf(`
resource "aquasec_assurance_script" "test" {
	name        = "%s"
	description = "Test assurance script"
	engine      = "yaml"
	path        = "test.yaml"
	kind        = "kubernetes"
	snippet     = <<-EOT
		---
		controls:
		version: "aks-1.1"
		id: 1
		text: "Control Plane Components"
		type: "master"
	EOT
}
`, name)
}

func testAccCheckAssuranceScriptExists(n string) resource.TestCheckFunc {
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
