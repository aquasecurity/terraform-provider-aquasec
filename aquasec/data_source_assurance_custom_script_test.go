package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccDataSourceAssuranceScript_basic(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("test-assurance-script")
	resourceName := "data.aquasec_assurance_custom_script.test"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAssuranceScriptBasic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "script_id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", "Test assurance script"),
					resource.TestCheckResourceAttr(resourceName, "engine", "yaml"),
					resource.TestCheckResourceAttr(resourceName, "kind", "kubernetes"),
					resource.TestCheckResourceAttr(resourceName, "path", "test.yaml"),
				),
			},
		},
	})
}

func testAccDataSourceAssuranceScriptBasic(name string) string {
	return fmt.Sprintf(`
resource "aquasec_assurance_custom_script" "test" {
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

data "aquasec_assurance_custom_script" "test" {
	name = aquasec_assurance_custom_script.test.id
	depends_on = [aquasec_assurance_custom_script.test]
}
`, name)
}
