package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecEnforcerGroupDatasource(t *testing.T) {
	groupID := "local"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecEnforcerGroupDataSource(groupID),
				Check:  testAccCheckAquasecEnforcerGroupDataSourceExists("data.aquasec_enforcer_groups.testegdata"),
			},
		},
	})
}

func testAccCheckAquasecEnforcerGroupDataSource(groupID string) string {
	return fmt.Sprintf(`
	data "aquasec_enforcer_groups" "testegdata" {
		group_id = "%s"
	}
	`, groupID)

}

func testAccCheckAquasecEnforcerGroupDataSourceExists(n string) resource.TestCheckFunc {
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
