package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAquasecDataSourceLogManagement(t *testing.T) {
	t.Skip("Skipping Log Management Data Source test")
	t.Parallel()
	name := "CloudWatch"
	key := os.Getenv("AWS_SECRET_ACCESS_KEY")
	keyid := os.Getenv("AWS_ACCESS_KEY_ID")

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckLogManagementDataSource(name, key, keyid),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.aquasec_log_managements.logmanagement", "name", "CloudWatch"),
				),
			},
		},
	})
}

func testAccCheckLogManagementDataSource(name, key, keyid string) string {
	return fmt.Sprintf(`
 resource "aquasec_log_management" "logmanagement" {
   name   = "%s"
   region = "us-west-1"
   loggroup = "terraform-provider-log-group"
   key    = "%s"
   keyid  = "%s"
   enable = true
`, name, key, keyid) + `
 }

  data "aquasec_log_managements" "logmanagement" {
    name = "CloudWatch"
  }`
}
