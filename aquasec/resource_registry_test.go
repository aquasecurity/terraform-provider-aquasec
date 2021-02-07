package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecresourceRegistry(t *testing.T) {
	name := "terraform-ecr"
	url := "us-east-1"
	rtype := "AWS"
	username := "APIKEY"
	password := "SECRETKEY"
	prefixes := "111111111111.dkr.ecr.us-east-1.amazonaws.com"
	autopull := true
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecRegistry(name, url, rtype, username, password, prefixes, autopull),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecRegistryExists("aquasec_integration_registry.name"),
				),
			},
		},
	})
}

func testAccCheckAquasecRegistry(name string, url string, rtype string, username string, password string, prefix string, autopull bool) string {
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
	  }`, name, url, rtype, username, password, prefix, autopull)

}

func testAccCheckAquasecRegistryExists(n string) resource.TestCheckFunc {
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
