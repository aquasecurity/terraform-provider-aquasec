package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecPermissionSetManagement(t *testing.T) {
	name := "terraform"
	description := "created from terraform "
	author := "system"
	ui_access := true
	is_super := false
	actions := "risks.vulnerabilities.read"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccPermissionSetDestroy,
		Steps: []resource.TestStep{
			{
				// Config returns the test resource
				Config: testAccCheckAquasecPermissionSet(name, description, author, ui_access, is_super, actions),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecPermissionSetExists("aquasec_permission_set.new"),
				),
			},
		},
	})
}

func testAccCheckAquasecPermissionSet(name string, description string, author string, ui_access bool, is_super bool, actions string) string {
	return fmt.Sprintf(`
	resource "aquasec_permission_set" "new" {
		name = "%s"
		description     = "%s"
		author    = "%s"
		ui_access = "%v"
		is_super = "%v"
		actions = [
		  "%s"
		]
	  }`, name, description, author, ui_access, is_super, actions)
}

func testAccCheckAquasecPermissionSetExists(n string) resource.TestCheckFunc {
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

func testAccPermissionSetDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_permission_set.new" {
			continue
		}

		if rs.Primary.ID != "" {
			return fmt.Errorf("Object %q still exists", rs.Primary.ID)
		}
		return nil
	}
	return nil
}
