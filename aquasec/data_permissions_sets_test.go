package aquasec

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecPermissionsSetDatasource(t *testing.T) {
	t.Parallel()
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecPermissionsSetDataSource(),
				Check:  testAccCheckAquasecPermissionsSetDataSourceExists("data.aquasec_permissions_sets.testpermissionsset"),
			},
		},
	})
}

func testAccCheckAquasecPermissionsSetDataSource() string {
	return `
	data "aquasec_permissions_sets" "testpermissionsset" {}
	`
}

func testAccCheckAquasecPermissionsSetDataSourceExists(n string) resource.TestCheckFunc {
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
