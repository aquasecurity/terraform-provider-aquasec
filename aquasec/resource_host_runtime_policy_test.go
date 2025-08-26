package aquasec

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestResourceAquasecBasicHostRuntimePolicyCreate(t *testing.T) {
	t.Parallel()
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
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_host_runtime_policy.test"),
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
					//resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
				),
			},
			{
				ResourceName:      "aquasec_host_runtime_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestResourceAquasecComplexHostRuntimePolicyCreate(t *testing.T) {
	t.Parallel()
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
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_host_runtime_policy.test"),
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
					//resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					//todo: bring back after we upgrade the testing env
					//resource.TestCheckResourceAttr(rootRef, "block_cryptocurrency_mining", "true"),
					//resource.TestCheckResourceAttr(rootRef, "audit_brute_force_login", "true"),
					resource.TestCheckResourceAttr(rootRef, "enable_ip_reputation", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_create", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_read", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_modify", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_delete", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_attributes", "false"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.exceptional_monitored_files.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.exceptional_monitored_files_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.exceptional_monitored_files_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "auditing.0.audit_os_user_activity", "true"),
					//resource.TestCheckResourceAttr(rootRef, "auditing.0.audit_full_command_arguments", "true"),
					//todo: bring back after we upgrade the testing env
					//resource.TestCheckResourceAttr(rootRef, "audit_host_successful_login_events", "true"),
					//resource.TestCheckResourceAttr(rootRef, "audit_host_failed_login_events", "true"),
					resource.TestCheckResourceAttr(rootRef, "auditing.0.audit_success_login", "true"),
					//resource.TestCheckResourceAttr(rootRef, "port_scanning_detection", "true"),
					//resource.TestCheckResourceAttr(rootRef, "monitor_system_time_changes", "true"),
					//resource.TestCheckResourceAttr(rootRef, "monitor_windows_services", "true"),
					resource.TestCheckResourceAttr(rootRef, "monitor_system_log_integrity", "true"),

					// Malware scan options
					resource.TestCheckResourceAttr(rootRef, "malware_scan_options.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "malware_scan_options.0.action", "alert"),
					resource.TestCheckResourceAttr(rootRef, "malware_scan_options.0.file_forensic_collection", "true"),
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
		# block_cryptocurrency_mining = true
		# audit_brute_force_login = true

	file_integrity_monitoring {
		enabled                                = true
		monitored_files_create                 = true
		monitored_files_read                   = true
		monitored_files_modify                 = true
		monitored_files_delete                 = true
		monitored_files_attributes             = false
		monitored_files                        = ["paths"]
		exceptional_monitored_files            = ["expaths"]
		monitored_files_processes              = ["process"]
		exceptional_monitored_files_processes  = ["exprocess"]
		monitored_files_users                  = ["user"]
		exceptional_monitored_files_users      = ["expuser"]
	  }
	  auditing {
		audit_os_user_activity        = true
		audit_user_account_management = true
		audit_success_login = true
	  }
	  malware_scan_options {
		enabled = true
		action = "alert"
		file_forensic_collection = true
		exclude_directories = []
		include_directories = ["%%SystemDrive%%\\*", "%%AllDrives%%\\*", "/*"]
		exclude_processes = ["systemd"]
	  }
	  enable_ip_reputation = true
	  enable_port_scan_protection      = true
	  monitor_system_log_integrity     = true
}
`,
		policy.Name,
		policy.Description,
		policy.Enabled,
		policy.Enforce)
}
