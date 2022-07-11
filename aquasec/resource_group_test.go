package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecGroupManagement(t *testing.T) {

	if !isSaasEnv() {
		t.Skip("Skipping saas groups test because its on prem env")
	}
	t.Parallel()
	groupName := acctest.RandomWithPrefix("groupTest")
	groupNewName := groupName + "new"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccGroupDestroy,
		Steps: []resource.TestStep{
			{
				// Config returns the test resource
				Config: testAccCheckAquasecGroup(groupName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecGroupsExists("aquasec_group.new"),
				),
			},
			{
				// Config returns the test resource
				Config: testAccCheckAquasecGroup(groupNewName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecGroupsExists("aquasec_group.new"),
				),
			},
		},
	})
}

func testAccCheckAquasecGroup(groupName string) string {
	return fmt.Sprintf(`
	resource "aquasec_group" "new" {
		name    = "%s"
    }`, groupName)
}

func testAccCheckAquasecGroupsExists(n string) resource.TestCheckFunc {
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

func testAccGroupDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_group.new" {
			continue
		}

		if rs.Primary.ID != "" {
			return fmt.Errorf("Object %q still exists", rs.Primary.ID)
		}
		return nil
	}
	return nil
}
