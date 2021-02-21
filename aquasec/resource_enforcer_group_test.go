package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecenforcerGroup(t *testing.T) {
	group_id := "terraform"
	description := "Created"
	logical_name := "terraform-eg"
	enforce := false
	gateways := "demo"
	etype := "agent"
	otype := "kubernetes"
	service_account := "aqua-sa"
	namespace := "aquasec"
	master := false
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckEnforcerGroup(group_id, description, logical_name, enforce, gateways, etype, otype, service_account, namespace, master),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnforcerGroupExists("aquasec_enforcer_groups.terraformeg"),
				),
			},
		},
	})
}

func testAccCheckEnforcerGroup(group_id string, description string, logical_name string, enforce bool, gateways string, etype string, otype string, service_account string, namespace string, master bool) string {
	return fmt.Sprintf(`
	resource "aquasec_enforcer_groups" "terraformeg" {
		group_id = "%s"
		description = "%s"
		logical_name = "%s"
		enforce = "%v"
		gateways = [
		  "%s"
		]
		type = "%s"
		orchestrator {
		  type = "%s"
		  service_account = "%s"
		  namespace = "%s"
		  master = "%v"
		}
	  }`, group_id, description, logical_name, enforce, gateways, etype, otype, service_account, namespace, master)

}

func testAccCheckEnforcerGroupExists(n string) resource.TestCheckFunc {
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
