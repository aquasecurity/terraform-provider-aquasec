package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecUserManagement(t *testing.T) {
	userID := acctest.RandomWithPrefix("terraform-test-user")
	password := "Pas5wo-d"
	name := "terraform"
	email := "terraform@test.com"
	newEmail := "terraform1@test.com"
	role := "Administrator"
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			//Skip if saas
			if os.Getenv("AQUA_URL") == "https://cloud.aquasec.com" {
				t.SkipNow()
			}
		},
		Providers:    testAccProviders,
		CheckDestroy: testAccUserDestroy,
		Steps: []resource.TestStep{
			{
				// Config returns the test resource
				Config: testAccCheckAquasecUser(userID, password, name, email, role),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecUsersExists("aquasec_user.new"),
				),
			},
			{
				// Config returns the test resource
				Config: testAccCheckAquasecUser(userID, password, name, newEmail, role),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecUsersExists("aquasec_user.new"),
				),
			},
		},
	})
}

func testAccCheckAquasecUser(userID string, password string, name string, email string, role string) string {
	return fmt.Sprintf(`
	resource "aquasec_user" "new" {
		user_id  = "%s"
		password = "%s"
		name     = "%s"
		email    = "%s"
		roles = [
		  "%s"
		]
	  }`, userID, password, name, email, role)
}

func testAccCheckAquasecUsersExists(n string) resource.TestCheckFunc {
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

func testAccUserDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_user.new" {
			continue
		}

		if rs.Primary.ID != "" {
			return fmt.Errorf("Object %q still exists", rs.Primary.ID)
		}
		return nil
	}
	return nil
}
