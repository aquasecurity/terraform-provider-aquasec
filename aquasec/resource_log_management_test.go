package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecResourceLogManagementCloudWatch(t *testing.T) {
	t.Skip("Skipping for AWS CloudWatch Log Management Resource test")
	t.Parallel()
	name := "CloudWatch"
	region := os.Getenv("AWS_REGION")
	loggroup := os.Getenv("AWS_LOG_GROUP")
	key := os.Getenv("AWS_SECRET_ACCESS_KEY")
	keyid := os.Getenv("AWS_ACCESS_KEY_ID")
	enable := true

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_log_management.logmanagement"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckLogManagementCloudWatch(name, region, loggroup, key, keyid, enable),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckLogManagementExists("aquasec_log_management.logmanagement"),
				),
			},
			{
				Config: testAccCheckLogManagementCloudWatch(name, region, loggroup, key, keyid, !enable), // toggle enable
				Check: resource.ComposeTestCheckFunc(
					testAccCheckLogManagementExists("aquasec_log_management.logmanagement"),
				),
			},
			{
				ResourceName:            "aquasec_log_management.logmanagement",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"client_secret", "password", "key"},
			},
		},
	})
}

func testAccCheckLogManagementCloudWatch(name, region, loggroup, key, keyid string, enable bool) string {
	return fmt.Sprintf(`
resource "aquasec_log_management" "logmanagement" {
  name   = "%s"
  region = "%s"
  loggroup = "%s"
  key    = "%s"
  keyid  = "%s"
  enable = %t
}
`, name, region, loggroup, key, keyid, enable)
}

func testAccCheckLogManagementExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("%s in state not found", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("ID for %s in state is empty", n)
		}

		return nil
	}
}
