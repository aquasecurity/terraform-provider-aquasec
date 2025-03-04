package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestDataAquasecFunctionRuntimePolicy(t *testing.T) {
	t.Parallel()
	var runtimePolicy = client.RuntimePolicy{
		Name:        acctest.RandomWithPrefix("test-function-runtime-policy"),
		Description: "This is a test description of function runtime policy",
		Enabled:     true,
		Enforce:     true,
	}

	rootRef := dataFunctionRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getFunctionRuntimePolicyData(runtimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Basic information
					resource.TestCheckResourceAttr(rootRef, "name", runtimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", runtimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					
					// Policy control fields
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", runtimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", runtimePolicy.Enforce)),
					
					// Application scopes
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					
					// Function security controls
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.exec_lockdown", "true"),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.image_lockdown", "false"),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.exec_lockdown_white_list.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "executable_blacklist.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "executable_blacklist.0.executables.#", "2"),
					
					// Block settings
					resource.TestCheckResourceAttr(rootRef, "block_fileless_exec", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_non_compliant_workloads", "true"),
				),
			},
		},
	})
}

func dataFunctionRuntimePolicyRef(name string) string {
	return fmt.Sprintf("data.aquasec_function_runtime_policy.%v", name)
}

func getFunctionRuntimePolicyData(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_function_runtime_policy" "test" {
		name = "%s"
		description = "%s"
		enabled = "%v"
		enforce = "%v"
		
		# Drift prevention settings
		drift_prevention {
			enabled = true
			exec_lockdown = true
			image_lockdown = false
			exec_lockdown_white_list = ["test"]
		}
		
		# Executable blacklist
		executable_blacklist {
			enabled = true
			executables = ["exe1","exe2"]
		}
		
		# Block settings
		block_fileless_exec = true
		block_non_compliant_workloads = true
	}
	
	data "aquasec_function_runtime_policy" "test" {
		name = aquasec_function_runtime_policy.test.id
	}
`,
		policy.Name,
		policy.Description,
		policy.Enabled,
		policy.Enforce)
}