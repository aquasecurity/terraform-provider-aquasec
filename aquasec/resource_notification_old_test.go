package aquasec

/*
func TestAquasecNotificationOld(t *testing.T) {
	t.Parallel()
	user_name := "Aquasec"
	channel := "#general"
	webhook_url := "terraform-eg"
	enabled := true
	stype := "slack"
	name := "Slack"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_notification_slack.slacknew"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckNotificationOld(user_name, channel, webhook_url, enabled, stype, name),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNotificationOldExists("aquasec_notification_slack.slacknew"),
				),
			},
			{
				ResourceName:      "aquasec_notification_slack.slacknew",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckNotificationOld(user_name string, channel string, webhook_url string, enabled bool, stype string, name string) string {
	return fmt.Sprintf(`
	resource "aquasec_notification_slack" "slacknew" {
		user_name = "%s"
		channel = "%s"
		webhook_url = "%s"
		enabled = %v
		type = "%s"
		name = "%s"
	  }`, user_name, channel, webhook_url, enabled, stype, name)

}

func testAccCheckNotificationOldExists(n string) resource.TestCheckFunc {
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
*/
