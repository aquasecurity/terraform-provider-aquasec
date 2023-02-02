package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecRoleMapping(t *testing.T) {

	if isSaasEnv() {
		t.Skip("Skipping prem role test because its on saas env")
	}
	t.Parallel()
	roleName := "Administrator"
	group := "roleTest1"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccRoleMappingDestroy,
		Steps: []resource.TestStep{
			{
				// Config returns the test resource
				Config: testAccCheckAquasecRoleMapping(roleName, group),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecRoleMappingExists("aquasec_role_mapping.new"),
				),
			},
			{
				ResourceName:      "aquasec_role.new",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckAquasecRoleMapping(roleName, group string) string {
	return fmt.Sprintf(`
	resource "aquasec_role_mapping" "new" {
		ldap {
			role_mapping = {
				%s = "%s"
			}
		}
    }`, roleName, group)
}

func testAccCheckAquasecRoleMappingExists(n string) resource.TestCheckFunc {
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

func testAccRoleMappingDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_role_mapping.new" {
			continue
		}

		if rs.Primary.ID != "" {
			return fmt.Errorf("Object %q still exists", rs.Primary.ID)
		}
		return nil
	}
	return nil
}
