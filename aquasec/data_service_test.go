package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestDataSourceServiceBasic(t *testing.T) {
	t.Parallel()
	rootRef := "data.aquasec_service.test-svc"
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicServiceData(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", basicService.Name),
					resource.TestCheckResourceAttr(rootRef, "description", basicService.Description),
					resource.TestCheckResourceAttr(rootRef, "monitoring", "false"),
					resource.TestCheckResourceAttr(rootRef, "policies.#", fmt.Sprintf("%d", len(basicService.Policies))),
					resource.TestCheckResourceAttr(rootRef, "policies.0", basicService.Policies[0]),
					resource.TestCheckResourceAttr(rootRef, "enforce", "false"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", fmt.Sprintf("%d", len(basicService.ApplicationScopes))),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", basicService.ApplicationScopes[0]),
					resource.TestCheckResourceAttr(rootRef, "priority", "100"),
					resource.TestCheckResourceAttr(rootRef, "target", basicService.MembershipRules.Target),
					resource.TestCheckResourceAttr(rootRef, "scope_expression", basicService.MembershipRules.Scope.Expression),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.#", fmt.Sprintf("%d", len(basicService.MembershipRules.Scope.Variables))),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.0.attribute", basicService.MembershipRules.Scope.Variables[0].Attribute),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.0.value", basicService.MembershipRules.Scope.Variables[0].Value),
					resource.TestCheckResourceAttrSet(rootRef, "containers_count"),
					resource.TestCheckResourceAttrSet(rootRef, "lastupdate"),
					resource.TestCheckResourceAttrSet(rootRef, "evaluated"),
					resource.TestCheckResourceAttrSet(rootRef, "is_registered"),

					// Assert no local policies
					resource.TestCheckResourceAttr(rootRef, "local_policies.#", "0"),
				),
			},
		},
	})
}

func getBasicServiceData() string {
	return getBasicServiceResource() + `
	data "aquasec_service" "test-svc" {
		name     = aquasec_service.test-basic-svc.id
		policies = aquasec_service.test-basic-svc.policies
	}
	`
}
func TestDataSourceServiceComplex(t *testing.T) {
	t.Parallel()
	rootRef := "data.aquasec_service.test-svc"
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getComplexServiceData(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", "test-complex-svc"),
					resource.TestCheckResourceAttr(rootRef, "description", "Test complex service"),
					resource.TestCheckResourceAttr(rootRef, "monitoring", "false"),
					resource.TestCheckResourceAttr(rootRef, "policies.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "policies.0", "local-policy-1"),
					resource.TestCheckResourceAttr(rootRef, "policies.1", "default"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.name", "local-policy-1"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.type", "access.control"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.description", "Local policy for testing"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.block_metadata_service", "true"),

					// Inbound Networks
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.inbound_networks.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.inbound_networks.0.port_range", "22-80"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.inbound_networks.0.resource_type", "anywhere"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.inbound_networks.0.allow", "true"),

					// Outbound Networks
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.outbound_networks.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.outbound_networks.0.port_range", "443"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.outbound_networks.0.resource_type", "anywhere"),
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.outbound_networks.0.allow", "false"),

					resource.TestCheckResourceAttr(rootRef, "priority", "1"),
					resource.TestCheckResourceAttr(rootRef, "target", "container"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttrSet(rootRef, "containers_count"),
					resource.TestCheckResourceAttrSet(rootRef, "lastupdate"),
					resource.TestCheckResourceAttrSet(rootRef, "evaluated"),
					resource.TestCheckResourceAttrSet(rootRef, "is_registered"),
				),
			},
		},
	})
}

func getComplexServiceData() string {
	return getComplexServiceResource() + fmt.Sprintf(`
	data "aquasec_service" "test-svc" {
		name = aquasec_service.test-complex-svc.id
		policies = aquasec_service.test-complex-svc.policies
	}
`)
}
