package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecRegistryAnyDatasourceAny(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("terraform-test")
	url := "https://docker.io"
	rtype := "HUB"
	username := ""
	password := ""
	autopull := false
	option := "status"
	value := "Connected"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecRegistryDataSourceAny(name, url, rtype, username, password, option, value, autopull),
				Check:  testAccCheckAquasecRegistryDataSourceExists("data.aquasec_integration_registries.testregistries"),
			},
		},
	})
}

func testAccCheckAquasecRegistryDataSourceAny(name, url, rtype, username, password, option, value string, autopull bool) string {
	return fmt.Sprintf(`
	resource "aquasec_integration_registry" "any" {
		name = "%s"
		url = "%s"
		type = "%s"
		username = "%s"
		password = "%s"
		auto_pull = "%v"

		options {
			option = "%s"
			value = "%s"
		}

	}

	data "aquasec_integration_registries" "testregistries" {
		name = aquasec_integration_registry.any.name
		depends_on = [
			aquasec_integration_registry.any
        ]
	}
	`, name, url, rtype, username, password, autopull, option, value)

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
