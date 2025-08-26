package aquasec

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccDataSourceScannerGroup(t *testing.T) {
	t.Parallel()

	resourceName := "data.aquasec_scanner_group.single"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceScannerGroupSingleConfig(),
				Check:  testAccCheckDataSourceScannerGroupSingleExists(resourceName),
			},
		},
	})
}

func testAccDataSourceScannerGroupSingleConfig() string {
	return `
resource "aquasec_scanner_group" "test" {
  name               = "tf-ds-test-group"
  description        = "Created for data source test"
  os_type            = "linux"
  type               = "remote"
  application_scopes = ["Global"]
}

data "aquasec_scanner_group" "single" {
  name = aquasec_scanner_group.test.name
}
`
}

func testAccCheckDataSourceScannerGroupSingleExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return NewNotFoundErrorf("%s not found in state", n)
		}
		if rs.Primary.ID == "" {
			return NewNotFoundErrorf("ID for %s not set in state", n)
		}

		return resource.ComposeTestCheckFunc(
			resource.TestCheckResourceAttr(n, "name", "tf-ds-test-group"),
			resource.TestCheckResourceAttrSet(n, "description"),
			resource.TestCheckResourceAttrSet(n, "status"),
			resource.TestCheckResourceAttrSet(n, "tokens.#"),
			resource.TestCheckResourceAttrSet(n, "scanners.#"),
			resource.TestCheckResourceAttrSet(n, "deploy_command.#"),
		)(s)
	}
}
