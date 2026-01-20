package aquasec

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestDataAquasecBasicContainerRuntimePolicy(t *testing.T) {
	t.Parallel()
	var basicRuntimePolicy = client.RuntimePolicy{
		Name:             acctest.RandomWithPrefix("test-container-runtime-policy"),
		Description:      "This is a test description of container runtime policy",
		Enabled:          false,
		Enforce:          false,
		EnforceAfterDays: 5,
	}

	rootRef := dataContainerRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicContainerRuntimePolicyData(basicRuntimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", basicRuntimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", basicRuntimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", basicRuntimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", basicRuntimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "enforce_after_days", fmt.Sprintf("%v", basicRuntimePolicy.EnforceAfterDays)),
					//resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
				),
			},
		},
	})
}

func TestDataAquasecComplexContainerRuntimePolicy(t *testing.T) {
	t.Parallel()
	var complexRuntimePolicy = client.RuntimePolicy{
		Name:        acctest.RandomWithPrefix("test-container-runtime-policy"),
		Description: "This is a test description of container runtime policy",
		Enabled:     true,
		Enforce:     true,
	}

	rootRef := dataContainerRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getComplexContainerRuntimePolicyData(complexRuntimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Basic attributes
					resource.TestCheckResourceAttr(rootRef, "name", complexRuntimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", complexRuntimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", complexRuntimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", complexRuntimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "enforce_after_days", fmt.Sprintf("%v", complexRuntimePolicy.EnforceAfterDays)),

					// Container exec
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.block_container_exec", "true"),
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.container_exec_proc_white_list.#", "2"),

					// Block settings
					resource.TestCheckResourceAttr(rootRef, "block_non_compliant_workloads", "true"),

					// Allowed executables
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.0.allow_executables.#", "2"),

					// File block
					resource.TestCheckResourceAttr(rootRef, "file_block.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_block.0.filename_block_list.#", "2"),

					// File integrity monitoring
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_create", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_read", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_modify", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_delete", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_attributes", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.exceptional_monitored_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_processes.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.exceptional_monitored_files_processes.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_users.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.exceptional_monitored_files_users.#", "2"),

					// Auditing
					resource.TestCheckResourceAttr(rootRef, "auditing.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "auditing.0.audit_all_processes", "true"),
					resource.TestCheckResourceAttr(rootRef, "auditing.0.audit_process_cmdline", "true"),
					resource.TestCheckResourceAttr(rootRef, "auditing.0.audit_all_network", "true"),

					// Container privileges
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.block_add_capabilities", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.prevent_root_user", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.privileged", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.ipcmode", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.pidmode", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.usermode", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.utsmode", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.prevent_low_port_binding", "true"),

					// Port block
					resource.TestCheckResourceAttr(rootRef, "port_block.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_inbound_ports.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_outbound_ports.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_inbound_ports.0", "1-11"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_outbound_ports.0", "1-11"),

					// Allowed registries
					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.allowed_registries.#", "2"),

					// Restricted volumes
					resource.TestCheckResourceAttr(rootRef, "restricted_volumes.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "restricted_volumes.0.volumes.#", "3"),
				),
			},
		},
	})
}

func dataContainerRuntimePolicyRef(name string) string {
	return fmt.Sprintf("data.aquasec_container_runtime_policy.%v", name)
}

func getBasicContainerRuntimePolicyData(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_container_runtime_policy" "test" {
		name = "%s"
		description = "%s"
		enabled = "%v"
		enforce = "%v"
		enforce_after_days = "%d"
	}

	data "aquasec_container_runtime_policy" "test" {
		name = aquasec_container_runtime_policy.test.id
	}
`, policy.Name, policy.Description, policy.Enabled, policy.Enforce, policy.EnforceAfterDays)
}

func getComplexContainerRuntimePolicyData(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_container_runtime_policy" "test" {
		name = "%s"
		description = "%s"
		enabled = "%v"
		enforce = "%v"
		enforce_after_days = "%d"

		container_exec {
			enabled = true
			block_container_exec = true
			container_exec_proc_white_list = ["proc1","proc2"]
		}

		block_non_compliant_workloads = true

		allowed_executables {
			enabled = true
			allow_executables = ["exe","bin"]
		}

		file_block {
			enabled = true
			filename_block_list = ["test1","test2"]
		}

		file_integrity_monitoring {
			enabled = true
			monitored_files_create = true
			monitored_files_read = true
			monitored_files_modify = true
			monitored_files_delete = true
			monitored_files_attributes = true
			monitored_files = ["paths", "paths2"]
			exceptional_monitored_files = ["expaths", "expaths2"]
			monitored_files_processes = ["/bin/bash", "/usr/bin/python"]
			exceptional_monitored_files_processes = ["/usr/sbin/sshd", "/usr/bin/dockerd"]
			monitored_files_users = ["root", "admin"]
			exceptional_monitored_files_users = ["app", "service"]
		}

		auditing {
			enabled = true
			audit_all_processes = true
			audit_process_cmdline = true
			audit_all_network = true
		}

		limit_container_privileges {
			enabled = true
			block_add_capabilities = true
			prevent_root_user = true
			privileged = true
			ipcmode = true
			pidmode = true
			usermode = true
			utsmode = true
			prevent_low_port_binding = true
		}

		port_block {
			enabled = true
			block_inbound_ports = ["1-11"]
			block_outbound_ports = ["1-11"]
		}

		# Note: readonly_files is deprecated for container runtime policies

		allowed_registries {
			enabled = true
			allowed_registries = ["registry1","registry2"]
		}

		restricted_volumes {
			enabled = true
			volumes = ["/var/run/docker.sock", "/proc", "/sys"]
		}
	}

	data "aquasec_container_runtime_policy" "test" {
		name = aquasec_container_runtime_policy.test.id
	}
`, policy.Name, policy.Description, policy.Enabled, policy.Enforce, policy.EnforceAfterDays)
}
