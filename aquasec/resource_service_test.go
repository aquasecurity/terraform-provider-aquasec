package aquasec

import (
	"fmt"
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
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_service.test-basic-svc"),
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
				ResourceName:      "aquasec_service.test-basic-svc",
				ImportState:       true,
				ImportStateVerify: true,
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
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_service.test-complex-svc"),
		Steps: []resource.TestStep{
			{
				Config: getComplexServiceResource(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Basic Service Attributes
					resource.TestCheckResourceAttr(rootRef, "name", "test-complex-svc"),
					resource.TestCheckResourceAttr(rootRef, "description", "Test complex service"),
					resource.TestCheckResourceAttr(rootRef, "enforce", "true"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "policies.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "policies.0", "local-policy-1"),
					resource.TestCheckResourceAttr(rootRef, "priority", "1"),
					resource.TestCheckResourceAttr(rootRef, "target", "container"),

					// Local Policies
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
				),
			},
		},
	})
}
func TestResourceAquasecServiceUpdate(t *testing.T) {
	// Generate unique resource names and configurations dynamically
	basicService := struct {
		Name        string
		Description string
	}{
		Name:        acctest.RandomWithPrefix("update-service"),
		Description: "Basic service description",
	}

	updatedService := struct {
		Name        string
		Description string
	}{
		Name:        basicService.Name, // Name remains unchanged
		Description: "This description is the updated version of the basic service description",
	}

	defaultPolicyName := "default"
	localPolicyName := "local-policy-1"

	rootRef := serviceResourceRef(basicService.Name) // Reference for test assertions

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy(fmt.Sprintf("aquasec_service.%s", basicService.Name)),
		Steps: []resource.TestStep{
			// Step 1: Create a simple service with no local policies
			{
				Config: getBasicServiceResourcenolocalpolicy(basicService, defaultPolicyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", basicService.Name),               // Validate service name
					resource.TestCheckResourceAttr(rootRef, "description", basicService.Description), // Validate description
					resource.TestCheckResourceAttr(rootRef, "policies.#", "1"),                       // Only one global policy
					resource.TestCheckResourceAttr(rootRef, "policies.0", defaultPolicyName),         // Validate default global policy
					resource.TestCheckResourceAttr(rootRef, "local_policies.#", "0"),                 // No local policies initially
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),             // Validate application scope
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),        // Global scope
					resource.TestCheckResourceAttr(rootRef, "priority", "1"),                         // Validate priority
					resource.TestCheckResourceAttr(rootRef, "target", "container"),                   // Validate target
					resource.TestCheckResourceAttr(rootRef, "enforce", "false"),                      // Validate enforce flag
				),
			},
			// Step 2: Update the service to include a local policy
			{
				Config: getServiceResourceUpdate(updatedService, defaultPolicyName, localPolicyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", updatedService.Name),               // Name remains unchanged
					resource.TestCheckResourceAttr(rootRef, "description", updatedService.Description), // Updated description
					resource.TestCheckResourceAttr(rootRef, "policies.#", "2"),                         // Now two policies (default + local)
					resource.TestCheckResourceAttr(rootRef, "policies.0", defaultPolicyName),           // Validate default global policy
					resource.TestCheckResourceAttr(rootRef, "policies.1", localPolicyName),             // Validate added local policy
					resource.TestCheckResourceAttr(rootRef, "local_policies.#", "1"),                   // Local policies now present
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.name", localPolicyName),  // Validate local policy name
					resource.TestCheckResourceAttr(rootRef, "local_policies.0.type", "access.control"), // Validate local policy type
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
	resource "aquasec_service" "test-complex-svc" {
	name = "test-complex-svc"
	description = "Test complex service"
	application_scopes = [
	"Global"
	]
		policies = [
		"local-policy-1",
		"default"
		]
		priority = 1
		target = "container"
		enforce = true
		
		// Local Policies
		local_policies {
		name = "local-policy-1"
		type = "access.control"
		description = "Local policy for testing"
		block_metadata_service = true
		
		inbound_networks {
		port_range = "22-80"
		resource_type = "anywhere"
		allow = true
		}
		
		outbound_networks {
		port_range = "443"
		resource_type = "anywhere"
		allow = false
		}
		}
		}`)
}

func getBasicServiceResourcenolocalpolicy(basicService struct{ Name, Description string }, defaultPolicyName string) string {
	return fmt.Sprintf(`
	resource "aquasec_service" "%s" {
		name              = "%s"
		description       = "%s"
		application_scopes = [
			"Global"
		]
		policies = [
			"%s"
		]
		priority = 1
		target   = "container"
		enforce  = false
	}`, basicService.Name, basicService.Name, basicService.Description, defaultPolicyName)
}

func getServiceResourceUpdate(updatedService struct{ Name, Description string }, defaultPolicyName, localPolicyName string) string {
	return fmt.Sprintf(`
	resource "aquasec_service" "%s" {
		name              = "%s"
		description       = "%s"
		application_scopes = [
			"Global"
		]
		policies = [
			"%s",
			"%s"
		]
		priority = 1
		target   = "container"
		enforce  = false

		local_policies {
			name                  = "%s"
			type                  = "access.control"
			description           = "Local policy for testing"
			block_metadata_service = true

			inbound_networks {
				port_range    = "22-80"
				resource_type = "anywhere"
				allow         = true
			}

			outbound_networks {
				port_range    = "443"
				resource_type = "anywhere"
				allow         = false
			}
		}
	}`, updatedService.Name, updatedService.Name, updatedService.Description, defaultPolicyName, localPolicyName, localPolicyName)
}
