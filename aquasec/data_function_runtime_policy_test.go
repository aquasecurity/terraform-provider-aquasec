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
					resource.TestCheckResourceAttr(rootRef, "name", runtimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", runtimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", runtimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", runtimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "block_malicious_executables", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_running_executables_in_tmp_folder", "true"),
					//todo: bring back after we upgrade the testing env
					//resource.TestCheckResourceAttr(rootRef, "block_malicious_executables_allowed_processes.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_executables.#", "2"),
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
		block_malicious_executables = true
		block_running_executables_in_tmp_folder = true
		# block_malicious_executables_allowed_processes = [
		# 	"proc1",
		# 	"proc2"
		# ]
		blocked_executables = [
			"exe1",
			"exe2",
		]
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
