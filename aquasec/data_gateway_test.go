package aquasec

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecGatewayManagementDatasource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecGatewayDataSource(),
				Check:  testAccCheckAquasecGatewaysDataSourceExists("data.aquasec_gateways.testgateways"),
			},
		},
	})
}

func testAccCheckAquasecGatewayDataSource() string {
	return `
	data "aquasec_gateways" "testgateways" {}
	`

}

func testAccCheckAquasecGatewaysDataSourceExists(n string) resource.TestCheckFunc {
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
