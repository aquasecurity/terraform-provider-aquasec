package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecNotification(t *testing.T) {
	user_name := "Aquasec"
	channel := "#general"
	webhook_url := "terraform-eg"
	enabled := true
	stype := "slack"
	name := "Slack"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckNotification(user_name, channel, webhook_url, enabled, stype, name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNotificationExists("aquasec_notification_slack.slacknew"),
				),
			},
		},
	})
}

func testAccCheckNotification(user_name string, channel string, webhook_url string, enabled bool, stype string, name string) string {
	return fmt.Sprintf(`
	resource "aquasec_notification_slack" "slacknew" {
		user_name = "%s"
		channel = "%s"
		webhook_url = "%s"
		enabled = "%v"
		type = "%s"
		name = "%s"
	  }`, user_name, channel, webhook_url, enabled, stype, name)

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
