package aquasec

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecUserSaasManagementDatasource(t *testing.T) {

	if !isSaasEnv() {
		t.Skip("Skipping saas user test because its on prem env")
	}
	t.Parallel()
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecUserSaasDataSource(),
				Check:  testAccCheckAquasecUsersSaasDataSourceExists("data.aquasec_users_saas.testusers"),
			},
		},
	})
}

func testAccCheckAquasecUserSaasDataSource() string {
	return `
	data "aquasec_users_saas" "testusers" {}
	`
}

func testAccCheckAquasecUsersSaasDataSourceExists(n string) resource.TestCheckFunc {
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
