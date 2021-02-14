package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestDataSourceServiceBasic(t *testing.T) {
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
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", fmt.Sprintf("%v", len(basicService.ApplicationScopes))),
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
				),
			},
		},
	})
}

func TestDataSourceServiceComplex(t *testing.T) {
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
					resource.TestCheckResourceAttr(rootRef, "name", complexService.Name),
					resource.TestCheckResourceAttr(rootRef, "description", complexService.Description),
					resource.TestCheckResourceAttr(rootRef, "monitoring", "false"),
					resource.TestCheckResourceAttr(rootRef, "policies.#", fmt.Sprintf("%d", len(complexService.Policies))),
					resource.TestCheckResourceAttr(rootRef, "policies.0", complexService.Policies[0]),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", complexService.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", fmt.Sprintf("%d", len(complexService.ApplicationScopes))),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", complexService.ApplicationScopes[0]),
					resource.TestCheckResourceAttr(rootRef, "priority", fmt.Sprintf("%d", complexService.MembershipRules.Priority)),
					resource.TestCheckResourceAttr(rootRef, "target", complexService.MembershipRules.Target),
					resource.TestCheckResourceAttr(rootRef, "scope_expression", complexService.MembershipRules.Scope.Expression),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.#", fmt.Sprintf("%v", len(complexService.MembershipRules.Scope.Variables))),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.0.attribute", complexService.MembershipRules.Scope.Variables[0].Attribute),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.0.value", complexService.MembershipRules.Scope.Variables[0].Value),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.1.attribute", complexService.MembershipRules.Scope.Variables[1].Attribute),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.1.value", complexService.MembershipRules.Scope.Variables[1].Value),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.2.attribute", complexService.MembershipRules.Scope.Variables[2].Attribute),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.2.value", complexService.MembershipRules.Scope.Variables[2].Value),
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

func getBasicServiceData() string {
	return getBasicServiceResource() + fmt.Sprintf(`
	
	data "aquasec_service" "test-svc" {
		name = aquasec_service.test-basic-svc.id
	}
`)
}

func getComplexServiceData() string {
	return getComplexServiceResource() + fmt.Sprintf(`
	
	data "aquasec_service" "test-svc" {
		name = aquasec_service.test-complex-svc.id
	}
`)
}
