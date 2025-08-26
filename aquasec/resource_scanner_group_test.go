package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceScannerGroup_basic(t *testing.T) {
	resourceName := "aquasec_scanner_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) }, // your precheck to validate env vars, etc.
		Providers: testAccProviders,              // your provider setup
		Steps: []resource.TestStep{
			{
				Config: testAccResourceScannerGroupConfig_basic("tf-test-group-1", "Test Description 1", "linux", "remote"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", "tf-test-group-1"),
					resource.TestCheckResourceAttr(resourceName, "description", "Test Description 1"),
					resource.TestCheckResourceAttr(resourceName, "os_type", "linux"),
					resource.TestCheckResourceAttr(resourceName, "type", "remote"),
				),
			},
			{
				Config: testAccResourceScannerGroupConfig_basic("tf-test-group-1", "Updated Description", "linux", "remote"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated Description"),
					resource.TestCheckResourceAttr(resourceName, "os_type", "linux"),
					resource.TestCheckResourceAttr(resourceName, "type", "remote"),
				),
			},
		},
	})
}

func testAccResourceScannerGroupConfig_basic(name, description, osType, typ string) string {
	return fmt.Sprintf(`
		resource "aquasec_scanner_group" "test" {
			name        = "%s"
			description = "%s"
			os_type     = "%s"
			type        = "%s"
			application_scopes  = ["Global"]
		}
		`, name, description, osType, typ)
}
