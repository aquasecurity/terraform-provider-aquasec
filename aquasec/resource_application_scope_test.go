package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecApplicationScope(t *testing.T) {
	name := acctest.RandomWithPrefix("terraform-test")
	description := "Created using Terraform"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckApplicationScope(name, description),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationScopeExists("aquasec_application_scope.terraformap"),
				),
			},
		},
	})
}

func testAccCheckApplicationScope(name string, description string) string {
	return fmt.Sprintf(`
	resource "aquasec_application_scope" "terraformiap" {
		description = "%s"
		name = "%s"
		categories {
			artifacts {
			  image {
				expression = "(v1 && v2)"
				variables {
					attribute = "aqua.registry"
				  	value     = "Docker Hub"
					}
				variables {
					attribute = "image.repo"
				  	value     = "koppula181809"
				}
			  }
			}
		  }
	}`, description, name)

}

func testAccCheckApplicationScopeExists(n string) resource.TestCheckFunc {
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
