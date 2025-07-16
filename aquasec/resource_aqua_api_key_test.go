package aquasec

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecAPIKey_basic(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping API Key test because its saas env")
	}
	t.Parallel()

	descriptionCreate := "Initial API Key"
	enabledCreate := true
	rolesCreate := []string{"role1"}
	ip_addressesCreate := []string{"192.168.1.2"}
	expirationCreate := 60

	descriptionUpdate := "Updated API Key"
	enabledUpdate := false
	rolesUpdate := []string{"role1"}
	ip_addressesUpdate := []string{"192.168.1.2"}
	expirationUpdate := 60

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccAPIKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAPIKeyConfig(descriptionCreate, enabledCreate, rolesCreate, ip_addressesCreate, expirationCreate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("aquasec_api_key.test", "description", "Initial API Key"),
					resource.TestCheckResourceAttr("aquasec_api_key.test", "enabled", "true"),
					resource.TestCheckResourceAttr("aquasec_api_key.test", "roles.#", "1"),
					resource.TestCheckResourceAttr("aquasec_api_key.test", "ip_addresses.#", "1"),
				),
			},
			{
				Config: testAccAPIKeyConfig(descriptionUpdate, enabledUpdate, rolesUpdate, ip_addressesUpdate, expirationUpdate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("aquasec_api_key.test", "description", "Updated API Key"),
					resource.TestCheckResourceAttr("aquasec_api_key.test", "enabled", "false"),
					resource.TestCheckResourceAttr("aquasec_api_key.test", "roles.#", "1"),
					resource.TestCheckResourceAttr("aquasec_api_key.test", "ip_addresses.#", "1"),
				),
			},
			{
				Config: testAccAPIKeyConfig("Deleted API Key", false, []string{}, []string{}, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr("aquasec_api_key.test", "id"),
				),
			},
		},
	})
}

func testAccAPIKeyConfig(description string, enabled bool, roles []string, ipAddresses []string, expiration int) string {
	rolesStr := listToHclString(roles)
	ipsStr := listToHclString(ipAddresses)

	return fmt.Sprintf(`
  	resource "aquasec_aqua_api_key" "test" {
  		description  = "%s"
		enabled      = %t
		roles        = %s
		ip_addresses = %s
		expiration   = %d
		}`, description, enabled, rolesStr, ipsStr, expiration)
}

func testAccAPIKeyDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_aqua_api_key.test" {
			continue
		}

		if rs.Primary.ID != "" {
			return fmt.Errorf("Object %q still exists", rs.Primary.ID)
		}
		return nil
	}
	return nil
}

func listToHclString(lst []string) string {
	if len(lst) == 0 {
		return "[]"
	}
	items := make([]string, len(lst))
	for i, v := range lst {
		items[i] = fmt.Sprintf("%q", v)
	}
	return "[" + strings.Join(items, ", ") + "]"
}
