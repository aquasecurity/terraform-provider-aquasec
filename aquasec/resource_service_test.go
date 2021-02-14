package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var basicService = client.Service{
	Name:              acctest.RandomWithPrefix("basic-service-resource"),
	Description:       "this is a basic service resource created from terraform unit test",
	ApplicationScopes: []string{"Global"},
	Policies: []string{
		"default",
	},
	MembershipRules: client.MembershipRules{
		Target: "container",
		Scope: client.Scope{
			Expression: "v1",
			Variables: []client.Variable{
				{
					Attribute: "kubernetes.namespace",
					Value:     "kube-system",
				},
			},
		},
	},
}

var complexService = client.Service{
	Name:        acctest.RandomWithPrefix("complex-service-resource"),
	Description: "this is a complex service resource created from terraform unit test",
	ApplicationScopes: []string{
		"Global",
	},
	Policies: []string{
		"default",
		acctest.RandomWithPrefix("firewall-policy-for-service"),
	},
	Enforce: true,
	MembershipRules: client.MembershipRules{
		Priority: 84,
		Target:   "host",
		Scope: client.Scope{
			Expression: "v1 || (v2 && v3)",
			Variables: []client.Variable{
				{
					Attribute: "os.type",
					Value:     "Ubuntu",
				},
				{
					Attribute: "os.type",
					Value:     "Alpine",
				},
				{
					Attribute: "os.type",
					Value:     "Busybox",
				},
			},
		},
	},
}

func TestResourceAquasecServiceBasicCreate(t *testing.T) {
	rootRef := serviceResourceRef("test-basic-svc")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicServiceResource(),
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

func TestResourceAquasecServiceComplexCreate(t *testing.T) {
	rootRef := serviceResourceRef("test-complex-svc")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getComplexServiceResource(),
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

func TestResourceAquasecServiceUpdate(t *testing.T) {
	rootRef := serviceResourceRef("test-basic-svc")
	basicService.Name = acctest.RandomWithPrefix("updated-basic-service")
	updatedService := basicService
	updatedService.Description = "this description is updated version of the basic service description"
	updatedService.Policies = append(updatedService.Policies, acctest.RandomWithPrefix("another-firewall-policy"))
	updatedService.MembershipRules.Scope.Expression = "v1 || v2"
	updatedService.MembershipRules.Scope.Variables = append(updatedService.MembershipRules.Scope.Variables, client.Variable{
		Attribute: "kubernetes.namespace",
		Value:     "default",
	})
	updatedService.MembershipRules.Priority = 80
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicServiceResource(),
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
			{
				Config: getServiceResourceUpdate(&updatedService),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", updatedService.Name),
					resource.TestCheckResourceAttr(rootRef, "description", updatedService.Description),
					resource.TestCheckResourceAttr(rootRef, "monitoring", "false"),
					resource.TestCheckResourceAttr(rootRef, "policies.#", fmt.Sprintf("%d", len(updatedService.Policies))),
					resource.TestCheckResourceAttr(rootRef, "policies.0", updatedService.Policies[0]),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", updatedService.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", fmt.Sprintf("%d", len(updatedService.ApplicationScopes))),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", updatedService.ApplicationScopes[0]),
					resource.TestCheckResourceAttr(rootRef, "priority", fmt.Sprintf("%d", updatedService.MembershipRules.Priority)),
					resource.TestCheckResourceAttr(rootRef, "target", updatedService.MembershipRules.Target),
					resource.TestCheckResourceAttr(rootRef, "scope_expression", updatedService.MembershipRules.Scope.Expression),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.#", fmt.Sprintf("%v", len(updatedService.MembershipRules.Scope.Variables))),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.0.attribute", updatedService.MembershipRules.Scope.Variables[0].Attribute),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.0.value", updatedService.MembershipRules.Scope.Variables[0].Value),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.1.attribute", updatedService.MembershipRules.Scope.Variables[1].Attribute),
					resource.TestCheckResourceAttr(rootRef, "scope_variables.1.value", updatedService.MembershipRules.Scope.Variables[1].Value),
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

func serviceResourceRef(name string) string {
	return fmt.Sprintf("aquasec_service.%s", name)
}

func getBasicServiceResource() string {
	return fmt.Sprintf(`
	resource "aquasec_service" "test-basic-svc" {
		name = "%s"
		description = "%s"
		application_scopes = [
			"%s",
		]
		policies = [
			"%s"
		]
		target = "%s"
		scope_expression = "%s"
		scope_variables {
			attribute = "%s"
			value = "%s"
		}
	}`, basicService.Name,
		basicService.Description,
		basicService.ApplicationScopes[0],
		basicService.Policies[0],
		basicService.MembershipRules.Target,
		basicService.MembershipRules.Scope.Expression,
		basicService.MembershipRules.Scope.Variables[0].Attribute,
		basicService.MembershipRules.Scope.Variables[0].Value)
}

func getComplexServiceResource() string {
	return fmt.Sprintf(`
	resource "aquasec_firewall_policy" "test" {
		name = "%s"
		description = "this is created for the unit test of service resource"
	}

	resource "aquasec_service" "test-complex-svc" {
		name = "%s"
		description = "%s"
		application_scopes = [
			"%s"
		]
		policies = [
			"%s",
			aquasec_firewall_policy.test.id
		]
		priority = "%d"
		target = "%s"
		enforce = "%v"
		scope_expression = "%s"
		scope_variables {
			attribute = "%s"
			value = "%s"
		}
		scope_variables {
			attribute = "%s"
			value = "%s"
		}
		scope_variables {
			attribute = "%s"
			value = "%s"
		}
	}`,
		complexService.Policies[1],
		complexService.Name,
		complexService.Description,
		complexService.ApplicationScopes[0],
		complexService.Policies[0],
		complexService.MembershipRules.Priority,
		complexService.MembershipRules.Target,
		complexService.Enforce,
		complexService.MembershipRules.Scope.Expression,
		complexService.MembershipRules.Scope.Variables[0].Attribute,
		complexService.MembershipRules.Scope.Variables[0].Value,
		complexService.MembershipRules.Scope.Variables[1].Attribute,
		complexService.MembershipRules.Scope.Variables[1].Value,
		complexService.MembershipRules.Scope.Variables[2].Attribute,
		complexService.MembershipRules.Scope.Variables[2].Value,
	)
}

func getServiceResourceUpdate(updatedService *client.Service) string {
	return fmt.Sprintf(`
	resource "aquasec_firewall_policy" "test" {
		name = "%s"
		description = "this is created for the unit test of service resource"
	}

	resource "aquasec_service" "test-basic-svc" {
		name = "%s"
		description = "%s"
		application_scopes = [
			"%s"
		]
		policies = [
			"%s",
			aquasec_firewall_policy.test.id
		]
		priority = %d
		target = "%s"
		scope_expression = "%s"
		scope_variables {
			attribute = "%s"
			value = "%s"
		}
		scope_variables {
			attribute = "%s"
			value = "%s"
		}
	}`,
		updatedService.Policies[1],
		updatedService.Name,
		updatedService.Description,
		updatedService.ApplicationScopes[0],
		updatedService.Policies[0],
		updatedService.MembershipRules.Priority,
		updatedService.MembershipRules.Target,
		updatedService.MembershipRules.Scope.Expression,
		updatedService.MembershipRules.Scope.Variables[0].Attribute,
		updatedService.MembershipRules.Scope.Variables[0].Value,
		updatedService.MembershipRules.Scope.Variables[1].Attribute,
		updatedService.MembershipRules.Scope.Variables[1].Value,
	)
}
