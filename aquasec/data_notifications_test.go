package aquasec

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecNotificationsDatasource(t *testing.T) {
	t.Parallel()
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecNotificationsDataSource(),
				Check:  testAccCheckAquasecNotificationsDataSourceExists("data.aquasec_notifications.testnotifications"),
			},
		},
	})
}

func testAccCheckAquasecNotificationsDataSource() string {
	return `
	data "aquasec_notifications" "testnotifications" {}
	`
}

func testAccCheckAquasecNotificationsDataSourceExists(n string) resource.TestCheckFunc {
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
