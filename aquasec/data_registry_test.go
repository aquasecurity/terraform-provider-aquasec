package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
)

func TestAquasecRegistryDatasource(t *testing.T) {
	// name := "demo"
	image := client.Image{
		Name: "demo",
	}
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecRegistryDataSource(image),
				Check:  testAccCheckAquasecRegistryDataSourceExists("data.aquasec_integration_registries.testregistries"),
			},
		},
	})
}

func testAccCheckAquasecRegistryDataSource(image client.Image) string {
	return fmt.Sprintf(`
	data "aquasec_integration_registries" "testregistries" {
		name = "%s"
	}
	`, image.Name)

}

func testAccCheckAquasecRegistryDataSourceExists(n string) resource.TestCheckFunc {
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
