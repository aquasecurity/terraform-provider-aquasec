package aquasec

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestResourceAquasecBasicFunctionRuntimePolicyCreate(t *testing.T) {
	t.Parallel()
	var runtimePolicy = client.RuntimePolicy{
		Name:        acctest.RandomWithPrefix("test-func-policy"),
		Description: "This is a test description of function runtime policy",
		Enabled:     true,
		Enforce:     false, // Audit mode
		RuntimeType: "function",
	}

	rootRef := functionRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_function_runtime_policy.test"),
		Steps: []resource.TestStep{
			{
				Config: getBasicFunctionRuntimePolicyResource(runtimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", runtimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", runtimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", runtimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", runtimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "runtime_type", "function"),
				),
			},
			{
				ResourceName:      "aquasec_function_runtime_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestResourceAquasecFunctionRuntimePolicyUpgrade(t *testing.T) {
	t.Parallel()
	var runtimePolicy = client.RuntimePolicy{
		Name:        acctest.RandomWithPrefix("test-func-policy-upgrade"),
		Description: "This is a test description of function runtime policy",
		Enabled:     true,
		Enforce:     true, // Enforce mode
		RuntimeType: "function",
	}

	rootRef := functionRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_function_runtime_policy.test"),
		Steps: []resource.TestStep{
			{
				Config: getBasicFunctionRuntimePolicyResource(runtimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", runtimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", runtimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", runtimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", runtimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "runtime_type", "function"),
				),
			},
			{
				Config: getUpdatedFunctionRuntimePolicyResource(runtimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", runtimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", runtimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", runtimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", runtimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.exec_lockdown", "true"),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.image_lockdown", "false"),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.exec_lockdown_white_list.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "executable_blacklist.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "executable_blacklist.0.executables.#", "2"),
				),
			},
		},
	})
}

func TestResourceAquasecFunctionRuntimePolicyComprehensive(t *testing.T) {
	t.Parallel()
	policyName := acctest.RandomWithPrefix("test-func-policy-full")
	
	rootRef := functionRuntimePolicyRef("comprehensive")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_function_runtime_policy.comprehensive"),
		Steps: []resource.TestStep{
			{
				Config: getComprehensiveFunctionRuntimePolicyResource(policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Basic attributes
					resource.TestCheckResourceAttr(rootRef, "name", policyName),
					resource.TestCheckResourceAttr(rootRef, "description", "Comprehensive function runtime policy for testing"),
					resource.TestCheckResourceAttr(rootRef, "enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "enforce", "true"),
					resource.TestCheckResourceAttr(rootRef, "enforce_after_days", "7"),
					
					// Application scopes
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "exclude_application_scopes.#", "0"),
					
					// Security controls
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.0.allow_executables.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files.#", "1"),
					
					// Malware protection
					resource.TestCheckResourceAttr(rootRef, "malware_scan_options.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "malware_scan_options.0.action", "Alert"),
					
					// Additional security controls
					resource.TestCheckResourceAttr(rootRef, "block_fileless_exec", "true"),
				),
			},
			{
				ResourceName:      "aquasec_function_runtime_policy.comprehensive",
				ImportState:       true,
				ImportStateVerify: true,
				// Fields that can't be imported/verified
				ImportStateVerifyIgnore: []string{
					"enforce_after_days",
					"file_integrity_monitoring",
					"malware_scan_options",
				},
			},
		},
	})
}

func TestResourceAquasecFunctionRuntimePolicyScopeExpression(t *testing.T) {
	t.Parallel()
	policyName := acctest.RandomWithPrefix("test-func-scope")
	
	rootRef := functionRuntimePolicyRef("scope")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_function_runtime_policy.scope"),
		Steps: []resource.TestStep{
			{
				Config: getFunctionRuntimePolicyScopeExpressionResource(policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", policyName),
					resource.TestCheckResourceAttr(rootRef, "scope.0.expression", "v1 || v2"),
					resource.TestCheckResourceAttr(rootRef, "scope.0.variables.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "scope.0.variables.0.attribute", "kubernetes.namespace"),
					resource.TestCheckResourceAttr(rootRef, "scope.0.variables.0.name", "v1"),
					resource.TestCheckResourceAttr(rootRef, "scope.0.variables.0.value", "production"),
					resource.TestCheckResourceAttr(rootRef, "scope.0.variables.1.attribute", "kubernetes.label"),
					resource.TestCheckResourceAttr(rootRef, "scope.0.variables.1.name", "v2"),
					resource.TestCheckResourceAttr(rootRef, "scope.0.variables.1.value", "function=true"),
				),
			},
		},
	})
}

// Helper functions

func functionRuntimePolicyRef(name string) string {
	return fmt.Sprintf("aquasec_function_runtime_policy.%v", name)
}

func getBasicFunctionRuntimePolicyResource(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_function_runtime_policy" "test" {
		name = "%s"
		description = "%s"
		enabled = %v
		enforce = %v
		runtime_type = "function"
	}
`, policy.Name, policy.Description, policy.Enabled, policy.Enforce)
}

func getUpdatedFunctionRuntimePolicyResource(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_function_runtime_policy" "test" {
		name = "%s"
		description = "%s"
		enabled = %v
		enforce = %v
		runtime_type = "function"

		drift_prevention {
			enabled = true
			exec_lockdown = true
			image_lockdown = false
			exec_lockdown_white_list = ["allowed-exec"]
		}

		executable_blacklist {
			enabled = true
			executables = ["malicious1", "malicious2"]
		}
	}
`, policy.Name, policy.Description, policy.Enabled, policy.Enforce)
}

func getComprehensiveFunctionRuntimePolicyResource(name string) string {
	return fmt.Sprintf(`
	resource "aquasec_function_runtime_policy" "comprehensive" {
		name = "%s"
		description = "Comprehensive function runtime policy for testing"
		enabled = true
		enforce = true
		enforce_after_days = 7
		runtime_type = "function"
		
		# Application scopes
		application_scopes = ["Global"]
		# Using empty exclude_application_scopes to avoid errors
		
		# Function security controls
		drift_prevention {
			enabled = true
			exec_lockdown = true
			image_lockdown = false
			exec_lockdown_white_list = ["node", "python"]
		}
		
		allowed_executables {
			enabled = true
			allow_executables = ["node", "python"]
			separate_executables = true
		}
		
		file_integrity_monitoring {
			enabled = true
			monitored_files = ["/app/config.json"]
			monitored_files_read = true
			monitored_files_modify = true
			monitored_files_attributes = false
		}
		
		# Malware protection
		malware_scan_options {
			enabled = true
			action = "Alert"
			include_directories = ["/app"]
			exclude_directories = ["/tmp"]
		}
		
		# Additional security settings
		block_fileless_exec = true
	}
`, name)
}

func getFunctionRuntimePolicyScopeExpressionResource(name string) string {
	return fmt.Sprintf(`
	resource "aquasec_function_runtime_policy" "scope" {
		name = "%s"
		description = "Function runtime policy with complex scope expression"
		enabled = true
		enforce = false
		runtime_type = "function"
		application_scopes = ["Global"]
		
		# Scope expression method 1
		scope {
			expression = "v1 || v2"
			variables {
				attribute = "kubernetes.namespace"
				name = "v1"
				value = "production"
			}
			variables {
				attribute = "kubernetes.label"
				name = "v2"
				value = "function=true"
			}
		}
		
		# Basic security controls for this test
		executable_blacklist {
			enabled = true
			executables = ["malicious"]
		}
	}
`, name)
}