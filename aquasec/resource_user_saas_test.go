package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecUsersSaasManagement(t *testing.T) {

	if !isSaasEnv() {
		t.Skip("Skipping saas user test because its on prem env")
	}

	t.Parallel()
	userID := acctest.RandomWithPrefix("terrafrom.user")
	email := fmt.Sprintf("%s@aquasec.com", userID)
	groups := acctest.RandomWithPrefix("firstGroup")
	newGroups := acctest.RandomWithPrefix("secondGroup")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccUsersSaasDestroy,
		Steps: []resource.TestStep{
			{
				// Config returns the test resource
				Config: testAccCheckAquasecUsersSaas(email, groups, true, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecUsersSaassExists("aquasec_user_saas.new"),
				),
			},
			{
				// Config returns the test resource
				Config: testAccCheckAquasecUsersSaas1(email, newGroups, true, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecUsersSaassExists("aquasec_user_saas.new"),
				),
			},
		},
	})
}

func testAccCheckAquasecUsersSaas(email, groups string, groupAdmin, accountAdmin bool) string {
	return fmt.Sprintf(`

	resource "aquasec_group" "new" {
		name    = "%s"
    }

	resource "aquasec_user_saas" "new" {
		email    = "%s"
		csp_roles = []
		groups {
			name = "%s"
			group_admin = %v
		}
		account_admin = %v
		depends_on = ["aquasec_group.new"]
	  }`, groups, email, groups, groupAdmin, accountAdmin)
}

func testAccCheckAquasecUsersSaas1(email, groups string, groupAdmin, accountAdmin bool) string {
	return fmt.Sprintf(`

	resource "aquasec_group" "new" {
		name    = "%s"
    }
	
	resource "aquasec_user_saas" "new" {
		email    = "%s"
		csp_roles = []
		groups {
			name = "%s"
			group_admin = %v
		}
		account_admin = %v
		depends_on = ["aquasec_group.new"]
	  }`, groups, email, groups, groupAdmin, accountAdmin)
}

func testAccCheckAquasecUsersSaassExists(n string) resource.TestCheckFunc {
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

func testAccUsersSaasDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_user.new" && rs.Type != "aquasec_group.new" {
			continue
		}

		if rs.Primary.ID != "" {
			return fmt.Errorf("Object %q still exists", rs.Primary.ID)
		}
		return nil
	}
	return nil
}
