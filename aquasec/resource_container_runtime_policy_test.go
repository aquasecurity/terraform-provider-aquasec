package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestResourceAquasecBasicContainerRuntimePolicyCreate(t *testing.T) {
	var basicRuntimePolicy = client.RuntimePolicy{
		Name:             acctest.RandomWithPrefix("test-container-runtime-policy"),
		Description:      "This is a test description of container runtime policy",
		Enabled:          false,
		Enforce:          false,
		EnforceAfterDays: 5,
	}

	rootRef := containerRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicContainerRuntimePolicyResource(basicRuntimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", basicRuntimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", basicRuntimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", basicRuntimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", basicRuntimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "enforce_after_days", fmt.Sprintf("%v", basicRuntimePolicy.EnforceAfterDays)),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
				),
			},
		},
	})
}

func TestResourceAquasecComplexContainerRuntimePolicyCreate(t *testing.T) {
	var complexRuntimePolicy = client.RuntimePolicy{
		Name:                  acctest.RandomWithPrefix("test-container-runtime-policy"),
		Description:           "This is a test description of container runtime policy",
		Enabled:               true,
		Enforce:               true,
		ForkGuardProcessLimit: 13,
	}

	rootRef := containerRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getComplexContainerRuntimePolicyResource(complexRuntimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", complexRuntimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", complexRuntimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", complexRuntimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", complexRuntimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "enforce_after_days", fmt.Sprintf("%v", complexRuntimePolicy.EnforceAfterDays)),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "block_container_exec", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_non_compliant_workloads", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_non_compliant_images", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_unregistered_images", "true"),
					resource.TestCheckResourceAttr(rootRef, "enable_drift_prevention", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_all_processes_activity", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_all_network_activity", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_full_command_arguments", "true"),
					resource.TestCheckResourceAttr(rootRef, "enable_fork_guard", "true"),
					resource.TestCheckResourceAttr(rootRef, "fork_guard_process_limit", fmt.Sprintf("%v", complexRuntimePolicy.ForkGuardProcessLimit)),
					resource.TestCheckResourceAttr(rootRef, "enable_ip_reputation_security", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_new_privileges", "true"),
					resource.TestCheckResourceAttr(rootRef, "enable_port_scan_detection", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_access_host_network", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_adding_capabilities", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_use_pid_namespace", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_use_ipc_namespace", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_use_user_namespace", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_use_uts_namespace", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_privileged_containers", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_root_user", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_low_port_binding", "true"),
					resource.TestCheckResourceAttr(rootRef, "blocked_capabilities.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_executables.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_packages.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_inbound_ports.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_outbound_ports.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files_and_directories.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "exceptional_readonly_files_and_directories.#", "2"),
				),
			},
		},
	})
}

func TestResourceAquasecContainerRuntimePolicyUpgrade(t *testing.T) {
	var runtimePolicy = client.RuntimePolicy{
		Name:                  acctest.RandomWithPrefix("test-container-runtime-policy"),
		Description:           "This is a test description of container runtime policy",
		Enabled:               false,
		Enforce:               false,
		EnforceAfterDays:      5,
		ForkGuardProcessLimit: 10,
	}

	rootRef := containerRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicContainerRuntimePolicyResource(runtimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", runtimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", runtimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", runtimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", runtimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "enforce_after_days", fmt.Sprintf("%v", runtimePolicy.EnforceAfterDays)),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
				),
			},
			{
				Config: getComplexContainerRuntimePolicyResource(runtimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", runtimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", runtimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", runtimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", runtimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "block_container_exec", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_non_compliant_workloads", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_non_compliant_images", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_unregistered_images", "true"),
					resource.TestCheckResourceAttr(rootRef, "enable_drift_prevention", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_all_processes_activity", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_all_network_activity", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_full_command_arguments", "true"),
					resource.TestCheckResourceAttr(rootRef, "enable_fork_guard", "true"),
					resource.TestCheckResourceAttr(rootRef, "fork_guard_process_limit", fmt.Sprintf("%v", runtimePolicy.ForkGuardProcessLimit)),
					resource.TestCheckResourceAttr(rootRef, "enable_ip_reputation_security", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_new_privileges", "true"),
					resource.TestCheckResourceAttr(rootRef, "enable_port_scan_detection", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_access_host_network", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_adding_capabilities", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_use_pid_namespace", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_use_ipc_namespace", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_use_user_namespace", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_use_uts_namespace", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_privileged_containers", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_root_user", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_low_port_binding", "true"),
					resource.TestCheckResourceAttr(rootRef, "blocked_capabilities.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_executables.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_packages.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_inbound_ports.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_outbound_ports.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files_and_directories.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "exceptional_readonly_files_and_directories.#", "2"),
				),
			},
		},
	})
}

func containerRuntimePolicyRef(name string) string {
	return fmt.Sprintf("aquasec_container_runtime_policy.%v", name)
}

func getBasicContainerRuntimePolicyResource(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_container_runtime_policy" "test" {
		name = "%s"
		description = "%s"
		enabled = "%v"
		enforce = "%v"
		enforce_after_days = "%d"
	}
`, policy.Name, policy.Description, policy.Enabled, policy.Enforce, policy.EnforceAfterDays)
}

func getComplexContainerRuntimePolicyResource(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_container_runtime_policy" "test" {
		name = "%s"
		description = "%s"
		enabled = "%v"
		enforce = "%v"
		enforce_after_days = "%d"
		block_non_compliant_images    = true
		block_non_compliant_workloads = true
		block_container_exec          = true
		block_unregistered_images     = true
		enable_drift_prevention       = true
		allowed_executables = [
			"exe",
			"bin",
		]
		blocked_executables = [
			"exe1",
			"exe2",
		]
		
		blocked_files = [
			"test1",
			"test2"
		]
		audit_all_processes_activity = true
		audit_full_command_arguments = true
		audit_all_network_activity   = true
		enable_fork_guard        = true
		fork_guard_process_limit = %v
		enable_ip_reputation_security = true
		blocked_packages = [
			"pkg",
			"pkg2"
		]
		
		blocked_inbound_ports = [
			"80",
			"8080"
		]
		
		blocked_outbound_ports = [
			"90",
			"9090"
		]
		enable_port_scan_detection = true
		
		blocked_volumes = [
			"blocked",
			"vol"
		]
		
		readonly_files_and_directories = [
			"readonly",
			"/dir/"
		]
		
		exceptional_readonly_files_and_directories = [
			"readonly2",
			"/dir2/"
		]
		
		block_access_host_network   = true
		block_adding_capabilities   = true
		block_use_pid_namespace     = true
		block_use_ipc_namespace     = true
		block_use_user_namespace    = true
		block_use_uts_namespace     = true
		block_privileged_containers = true
		block_root_user             = true
		block_low_port_binding      = true
		
		limit_new_privileges = true
		
		blocked_capabilities = [
			"AUDIT_CONTROL",
			"AUDIT_WRITE"
		]
	}
`,
		policy.Name,
		policy.Description,
		policy.Enabled,
		policy.Enforce,
		policy.EnforceAfterDays,
		policy.ForkGuardProcessLimit)
}
