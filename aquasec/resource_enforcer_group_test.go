package aquasec

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAquasecEnforcerGroupResource(t *testing.T) {
	t.Parallel()
	var basicEnforcerGroup = client.EnforcerGroup{
		ID:          acctest.RandomWithPrefix("terraform-test"),
		Description: "Created",
		LogicalName: "terraform-eg",
		Enforce:     false,
		Gateways: []string{
			"3ef9a43f2693_gateway",
		},
		Type:              "agent",
		EnforcerImageName: "registry.aquasec.com/enforcer:6.5.22034",
		Orchestrator:      client.EnforcerOrchestrator{},
	}

	rootRef := enforcerGroupsRef(basicEnforcerGroup.ID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicEnforcerGroupResource(basicEnforcerGroup),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "group_id", basicEnforcerGroup.ID),
					resource.TestCheckResourceAttr(rootRef, "description", basicEnforcerGroup.Description),
					resource.TestCheckResourceAttr(rootRef, "logical_name", basicEnforcerGroup.LogicalName),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", basicEnforcerGroup.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "gateways.0", basicEnforcerGroup.Gateways[0]),
					resource.TestCheckResourceAttr(rootRef, "type", basicEnforcerGroup.Type),
				),
			},
			{
				ResourceName:      fmt.Sprintf("aquasec_enforcer_groups.%s", basicEnforcerGroup.ID),
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func getBasicEnforcerGroupResource(enforcerGroup client.EnforcerGroup) string {
	return fmt.Sprintf(`
	resource "aquasec_enforcer_groups" "%s" {
		group_id = "%s"
		description = "%s"
		logical_name = "%s"
		enforce = "%v"
		gateways = ["%s"]
		type = "%s"
		orchestrator {
			type = "%s"
            service_account = "%s"
			namespace = "%s"
			master = "%v"
		}
	}
	`, enforcerGroup.ID,
		enforcerGroup.ID,
		enforcerGroup.Description,
		enforcerGroup.LogicalName,
		enforcerGroup.Enforce,
		enforcerGroup.Gateways[0],
		enforcerGroup.Type,
		enforcerGroup.Orchestrator.Type,
		enforcerGroup.Orchestrator.ServiceAccount,
		enforcerGroup.Orchestrator.Namespace,
		enforcerGroup.Orchestrator.Master,
	)
}

func enforcerGroupsRef(name string) string {
	return fmt.Sprintf("aquasec_enforcer_groups.%v", name)
}
