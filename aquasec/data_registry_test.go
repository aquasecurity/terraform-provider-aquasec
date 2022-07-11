package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecRegistryDatasource(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("terraform-test")
	url := "https://docker.io"
	rtype := "HUB"
	username := ""
	password := ""
	prefix := ""
	autopull := false
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecRegistryDataSource(name, url, rtype, username, password, prefix, autopull),
				Check:  testAccCheckAquasecRegistryDataSourceExists("data.aquasec_integration_registries.testregistries"),
			},
		},
	})
}

func testAccCheckAquasecRegistryDataSource(name, url, rtype, username, password, prefix string, autopull bool) string {
	return fmt.Sprintf(`
	resource "aquasec_integration_registry" "new" {
		name = "%s"
		url = "%s"
		type = "%s"
		username = "%s"
		password = "%s"
		prefixes = [
			"%s"
		]
		auto_pull = "%v"
	}

	data "aquasec_integration_registries" "testregistries" {
		name = aquasec_integration_registry.new.name
	}
	`, name, url, rtype, username, password, prefix, autopull)

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
