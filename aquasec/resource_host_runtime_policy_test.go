package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestResourceAquasecBasicHostRuntimePolicyCreate(t *testing.T) {
	var basicRuntimePolicy = client.RuntimePolicy{
		Name:             acctest.RandomWithPrefix("test-host-runtime-policy"),
		Description:      "This is a test description of host runtime policy",
		Enabled:          false,
		Enforce:          false,
		EnforceAfterDays: 5,
	}

	rootRef := hostRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicHostRuntimePolicyResource(basicRuntimePolicy),
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

func TestResourceAquasecComplexHostRuntimePolicyCreate(t *testing.T) {
	var complexRuntimePolicy = client.RuntimePolicy{
		Name:        acctest.RandomWithPrefix("test-host-runtime-policy"),
		Description: "This is a test description of host runtime policy",
		Enabled:     true,
		Enforce:     true,
	}

	rootRef := hostRuntimePolicyRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getComplexHostRuntimePolicyResource(complexRuntimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", complexRuntimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", complexRuntimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", complexRuntimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", complexRuntimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "enforce_after_days", fmt.Sprintf("%v", complexRuntimePolicy.EnforceAfterDays)),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "block_cryptocurrency_mining", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_brute_force_login", "true"),
					resource.TestCheckResourceAttr(rootRef, "enable_ip_reputation_security", "true"),
					resource.TestCheckResourceAttr(rootRef, "blocked_files.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitor_create", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitor_read", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitor_modify", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitor_delete", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitor_attributes", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_paths.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.excluded_paths.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.excluded_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.excluded_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "audit_all_os_user_activity", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_full_command_arguments", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_host_successful_login_events", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_host_failed_login_events", "true"),
					resource.TestCheckResourceAttr(rootRef, "audit_user_account_management", "true"),
					resource.TestCheckResourceAttr(rootRef, "os_users_allowed.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "os_groups_allowed.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "os_users_blocked.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "os_groups_blocked.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "package_block.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "port_scanning_detection", "true"),
					resource.TestCheckResourceAttr(rootRef, "monitor_system_time_changes", "true"),
					resource.TestCheckResourceAttr(rootRef, "monitor_windows_services", "true"),
					resource.TestCheckResourceAttr(rootRef, "monitor_system_log_integrity", "true"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.monitor_create", "true"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.monitor_read", "true"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.monitor_modify", "true"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.monitor_delete", "true"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.monitor_attributes", "true"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.monitored_paths.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.excluded_paths.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.monitored_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.excluded_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.monitored_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_monitoring.0.excluded_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_protection.0.protected_paths.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_protection.0.excluded_paths.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_protection.0.protected_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_protection.0.excluded_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_protection.0.protected_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "windows_registry_protection.0.excluded_users.#", "1"),
				),
			},
		},
	})
}

func hostRuntimePolicyRef(name string) string {
	return fmt.Sprintf("aquasec_host_runtime_policy.%v", name)
}

func getBasicHostRuntimePolicyResource(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_host_runtime_policy" "test" {
		name = "%s"
		description = "%s"
		enabled = "%v"
		enforce = "%v"
		enforce_after_days = "%d"
	}
`, policy.Name, policy.Description, policy.Enabled, policy.Enforce, policy.EnforceAfterDays)
}

func getComplexHostRuntimePolicyResource(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_host_runtime_policy" "test" {
		name = "%s"
		description = "%s"
		enabled = "%v"
		enforce = "%v"
		block_cryptocurrency_mining = true
		audit_brute_force_login = true
		enable_ip_reputation_security = true
		blocked_files = [
			"blocked",
		]
		file_integrity_monitoring {
			monitor_create      = true
			monitor_read        = true
			monitor_modify      = true
			monitor_delete      = true
			monitor_attributes  = true
			monitored_paths     = ["paths"]
			excluded_paths      = ["expaths"]
			monitored_processes = ["process"]
			excluded_processes  = ["exprocess"]
			monitored_users     = ["user"]
			excluded_users      = ["expuser"]
		}
		audit_all_os_user_activity    = true
		audit_full_command_arguments  = true
		audit_host_successful_login_events = true
		audit_host_failed_login_events = true
		audit_user_account_management = true
		os_users_allowed = [
			"user1",
		]
		os_groups_allowed = [
			"group1",
		]
		os_users_blocked = [
			"user2",
		]
		os_groups_blocked = [
			"group2",
		]
		package_block = [
			"package1"
		]
		port_scanning_detection = true
		monitor_system_time_changes = true
		monitor_windows_services    = true
		monitor_system_log_integrity = true
		windows_registry_monitoring {
			monitor_create      = true
			monitor_read        = true
			monitor_modify      = true
			monitor_delete      = true
			monitor_attributes  = true
			monitored_paths     = ["paths"]
			excluded_paths      = ["expaths"]
			monitored_processes = ["process"]
			excluded_processes  = ["exprocess"]
			monitored_users     = ["user"]
			excluded_users      = ["expuser"]
		}
		windows_registry_protection {
			protected_paths     = ["paths"]
			excluded_paths      = ["expaths"]
			protected_processes = ["process"]
			excluded_processes  = ["exprocess"]
			protected_users     = ["user"]
			excluded_users      = ["expuser"]
		}
	}
`,
		policy.Name,
		policy.Description,
		policy.Enabled,
		policy.Enforce)
}
