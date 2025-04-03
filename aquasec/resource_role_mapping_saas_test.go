package aquasec

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const (
	testRoleMappingSaasResourceName = "aquasec_role_mapping_saas.test"
)

func TestAccAquasecRoleMappingSaas_basic(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping role mapping SaaS test - not a SaaS environment")
	}

	roleName := acctest.RandomWithPrefix("tf-role")
	permSetName := acctest.RandomWithPrefix("tf-pset")
	samlGroups := []string{"DevTeam", "SecTeam"}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckRoleMappingSaasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRoleMappingSaasConfig(permSetName, roleName, samlGroups),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRoleMappingSaasExists(testRoleMappingSaasResourceName),
					resource.TestCheckResourceAttr(testRoleMappingSaasResourceName, "csp_role", roleName),
					resource.TestCheckResourceAttr(testRoleMappingSaasResourceName, "saml_groups.#", "2"),
				),
			},
			{
				ResourceName:      testRoleMappingSaasResourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccRoleMappingSaasConfig(permSetName, roleName string, groups []string) string {
	groupsStr := ""
	for _, g := range groups {
		groupsStr += fmt.Sprintf("\"%s\", ", g)
	}
	groupsStr = groupsStr[:len(groupsStr)-2]

	return fmt.Sprintf(`
resource "aquasec_permission_set_saas" "ps" {
  name        = "%s"
  description = "TF-generated permission set"
  actions     = ["account_mgmt.groups.read"]
}

resource "aquasec_role" "r" {
  role_name   = "%s"
  description = "TF-generated role"
  permission  = aquasec_permission_set_saas.ps.name
  scopes      = ["Global"]
}

resource "aquasec_role_mapping_saas" "test" {
  saml_groups = [%s]
  csp_role    = aquasec_role.r.role_name
}
`, permSetName, roleName, groupsStr)
}

func testAccCheckRoleMappingSaasExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Resource not found in state: %s", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("ID not set for resource: %s", n)
		}
		cli := testAccProvider.Meta().(*client.Client)
		_, err := cli.GetRoleMappingSaas(rs.Primary.ID)
		return err
	}
}

func testAccCheckRoleMappingSaasDestroy(s *terraform.State) error {
	cli := testAccProvider.Meta().(*client.Client)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_role_mapping_saas" {
			continue
		}
		_, err := cli.GetRoleMappingSaas(rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("role mapping %q still exists", rs.Primary.ID)
		}
	}
	return nil
}
