package aquasec

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecNotification(t *testing.T) {
	t.Parallel()

	nameTeams := acctest.RandomWithPrefix("terraform-teams")
	nameEmail := acctest.RandomWithPrefix("terraform-email")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_notification.notificationTeams"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckNotificationTeams(nameTeams),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNotificationExists("aquasec_notification.notificationTeams"),
				),
			},
			{
				ResourceName:      "aquasec_notification.notificationTeams",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_notification.notificationEmail"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckNotificationEmail(nameEmail),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNotificationExists("aquasec_notification.notificationEmail"),
				),
			},
			{
				ResourceName:            "aquasec_notification.notificationEmail",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"properties.password", "properties.%"},
			},
		},
	})
}

func testAccCheckNotificationTeams(name string) string {
	return fmt.Sprintf(`
	resource "aquasec_notification" "notificationTeams" {
		name = "%s"
		type = "teams"
		properties = {
			url = "1.1.1.1"
		}
    }`, name)
}

func testAccCheckNotificationEmail(name string) string {
	return fmt.Sprintf(`
	resource "aquasec_notification" "notificationEmail" {
    	name = "%s"
    	type = "email"
    	properties = {
    	    user = "test"
    	    password = "password"
    	    host = "2.2.2.2"
    	    port = 25
    	    sender = "test@test.com"
    	    recipients = "test1@test.com,test2@test.com"
    	}
	}`, name)

}

func testAccCheckNotificationExists(n string) resource.TestCheckFunc {
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
