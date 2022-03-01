package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecRoleManagement(t *testing.T) {
	roleName := acctest.RandomWithPrefix("roleTest")
	description := "roleTest1"
	newDescription := "roleTest2"
	permission := "Test"
	scope := "Global"
	//roleNewName := roleName + "new"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccRoleDestroy,
		Steps: []resource.TestStep{
			{
				// Config returns the test resource
				Config: testAccCheckAquasecRole(roleName, description, permission, scope),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecRolesExists("aquasec_role.new"),
				),
			},
			{
				// Config returns the test resource
				Config: testAccCheckAquasecRole(roleName, newDescription, permission, scope),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecRolesExists("aquasec_role.new"),
				),
			},
		},
	})
}

func testAccCheckAquasecRole(roleName, description, permission, scope string) string {
	return fmt.Sprintf(`
	resource "aquasec_role" "new" {
		role_name   = "%s"
		description = "%s"
		permission = "%s"
		scopes = ["%s"]
    }`, roleName, description, permission, scope)
}

func testAccCheckAquasecRolesExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]

		if !ok {
			return NewNotFoundErrorf("%s in state", n)
		}

		if rs.Primary.ID == "" {
			return NewNotFoundErrorf("Id for %s in state", n)
		}
		return nil
	}
}

func testAccRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_role.new" {
			continue
		}

		if rs.Primary.ID != "" {
			return fmt.Errorf("Object %q still exists", rs.Primary.ID)
		}
		return nil
	}
	return nil
}
