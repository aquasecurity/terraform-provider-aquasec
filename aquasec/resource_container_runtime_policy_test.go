package aquasec

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestResourceAquasecBasicContainerRuntimePolicyCreate(t *testing.T) {
	t.Parallel()
	var basicRuntimePolicy = client.RuntimePolicy{
		Name:             acctest.RandomWithPrefix("test-container-runtime-policy"),
		Description:      "This is a test description of container runtime policy",
		Enabled:          false,
		Enforce:          false,
		EnforceAfterDays: 5,
	}
	var chanegNameBasicRuntimePolicy = client.RuntimePolicy{
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
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_container_runtime_policy.test"),
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
					//resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
				),
			},
			{
				Config: getBasicContainerRuntimePolicyResource(chanegNameBasicRuntimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", chanegNameBasicRuntimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", chanegNameBasicRuntimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", chanegNameBasicRuntimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", chanegNameBasicRuntimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "enforce_after_days", fmt.Sprintf("%v", chanegNameBasicRuntimePolicy.EnforceAfterDays)),
					//resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
				),
			},
			{
				ResourceName:      "aquasec_container_runtime_policy.test",
				ImportState:       true,
				ImportStateVerify: true, //TODO: when read set up change to trye
			},
		},
	})
}

func TestResourceAquasecComplexContainerRuntimePolicyCreate(t *testing.T) {
	t.Parallel()
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
					//resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.block_container_exec", "true"),
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.container_exec_proc_white_list.#", "2"),
					//todo: bring back after we upgrade the testing env
					//resource.TestCheckResourceAttr(rootRef, "block_fileless_exec", "true"),
					//resource.TestCheckResourceAttr(rootRef, "block_non_compliant_images", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_non_compliant_workloads", "true"),
					//todo: bring back after we upgrade the testing env
					//resource.TestCheckResourceAttr(rootRef, "block_non_k8s_containers", "true"),
					//resource.TestCheckResourceAttr(rootRef, "block_reverse_shell", "true"),
					//resource.TestCheckResourceAttr(rootRef, "reverse_shell_allowed_processes.#", "2"),
					//resource.TestCheckResourceAttr(rootRef, "reverse_shell_allowed_ips.#", "2"),
					//resource.TestCheckResourceAttr(rootRef, "block_unregistered_images", "true"),
					//resource.TestCheckResourceAttr(rootRef, "blocked_capabilities.#", "2"),
					//resource.TestCheckResourceAttr(rootRef, "enable_ip_reputation_security", "true"),
					//resource.TestCheckResourceAttr(rootRef, "enable_drift_prevention", "true"),
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.0.allow_executables.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.0.enabled", "true"),

					//resource.TestCheckResourceAttr(rootRef, "blocked_executables.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_block.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_block.0.filename_block_list.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_create", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_modify", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_delete", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.exceptional_monitored_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_processes.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.exceptional_monitored_files_processes.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.monitored_files_users.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_integrity_monitoring.0.exceptional_monitored_files_users.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "auditing.0.audit_all_processes", "true"),
					resource.TestCheckResourceAttr(rootRef, "auditing.0.audit_process_cmdline", "true"),
					resource.TestCheckResourceAttr(rootRef, "auditing.0.audit_all_network", "true"),
					resource.TestCheckResourceAttr(rootRef, "auditing.0.enabled", "true"),

					resource.TestCheckResourceAttr(rootRef, "enable_fork_guard", "true"),
					resource.TestCheckResourceAttr(rootRef, "fork_guard_process_limit", fmt.Sprintf("%v", complexRuntimePolicy.ForkGuardProcessLimit)),

					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.block_add_capabilities", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.prevent_root_user", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.privileged", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.ipcmode", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.pidmode", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.usermode", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.utsmode", "true"),
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.prevent_low_port_binding", "true"),

					//resource.TestCheckResourceAttr(rootRef, "limit_new_privileges", "true"),
					//resource.TestCheckResourceAttr(rootRef, "blocked_packages.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_inbound_ports.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_outbound_ports.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_inbound_ports.0", "1-11"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_outbound_ports.0", "1-11"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.readonly_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.exceptional_readonly_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.exceptional_readonly_files_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.exceptional_readonly_files_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.readonly_files_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.readonly_files_users.#", "1"),

					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.allowed_registries.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.enabled", "true"),

					//todo: bring back after we upgrade the testing env
					//resource.TestCheckResourceAttr(rootRef, "monitor_system_time_changes", "true"),
					resource.TestCheckResourceAttr(rootRef, "restricted_volumes.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "restricted_volumes.0.volumes.#", "3"),
				),
			},
		},
	})
}

func TestResourceAquasecFullContainerRuntimePolicyCreate(t *testing.T) {
	t.Parallel()
	var fullRuntimePolicy = client.RuntimePolicy{
		Name:                       acctest.RandomWithPrefix("test-full-container-runtime-policy"),
		Description:                "This is a test description of full container runtime policy",
		RuntimeType:                "container",
		RuntimeMode:                0,
		Enabled:                    true,
		Enforce:                    false,
		EnforceAfterDays:           0,
		IsAutoGenerated:            false,
		IsOOTBPolicy:               false,
		BlockFilelessExec:          true,
		BlockNonCompliantWorkloads: true,
		BlockNonK8sContainers:      true,
		EnableForkGuard:            true,
		ForkGuardProcessLimit:      0,
		EnableIPReputation:         true,
		EnableCryptoMiningDns:      true,
		EnablePortScanProtection:   true,
		OnlyRegisteredImages:       true,
		BlockDisallowedImages:      true,
		NoNewPrivileges:            false,
	}

	rootRef := containerRuntimePolicyRef("full")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_container_runtime_policy.full"),
		Steps: []resource.TestStep{
			{
				Config: getFullContainerRuntimePolicyResource(fullRuntimePolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "name", fullRuntimePolicy.Name),
					resource.TestCheckResourceAttr(rootRef, "description", fullRuntimePolicy.Description),
					resource.TestCheckResourceAttr(rootRef, "runtime_type", fullRuntimePolicy.RuntimeType),
					resource.TestCheckResourceAttr(rootRef, "runtime_mode", fmt.Sprintf("%v", fullRuntimePolicy.RuntimeMode)),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(rootRef, "enabled", fmt.Sprintf("%v", fullRuntimePolicy.Enabled)),
					resource.TestCheckResourceAttr(rootRef, "enforce", fmt.Sprintf("%v", fullRuntimePolicy.Enforce)),
					resource.TestCheckResourceAttr(rootRef, "enforce_after_days", fmt.Sprintf("%v", fullRuntimePolicy.EnforceAfterDays)),
					resource.TestCheckResourceAttr(rootRef, "is_ootb_policy", fmt.Sprintf("%v", fullRuntimePolicy.IsOOTBPolicy)),

					// Container Exec
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.block_container_exec", "true"),
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.container_exec_proc_white_list.#", "3"),
					resource.TestCheckResourceAttr(rootRef, "container_exec.0.reverse_shell_ip_white_list.#", "0"),

					// Reverse Shell
					resource.TestCheckResourceAttr(rootRef, "reverse_shell.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "reverse_shell.0.block_reverse_shell", "true"),
					resource.TestCheckResourceAttr(rootRef, "reverse_shell.0.reverse_shell_ip_white_list.#", "0"),
					resource.TestCheckResourceAttr(rootRef, "reverse_shell.0.reverse_shell_proc_white_list.#", "0"),

					// Block settings
					resource.TestCheckResourceAttr(rootRef, "block_fileless_exec", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_non_compliant_workloads", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_non_k8s_containers", "true"),
					resource.TestCheckResourceAttr(rootRef, "only_registered_images", "true"),
					resource.TestCheckResourceAttr(rootRef, "block_disallowed_images", "true"),
					resource.TestCheckResourceAttr(rootRef, "no_new_privileges", "false"),
					resource.TestCheckResourceAttr(rootRef, "blocked_packages.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "blocked_packages.0", "netcat"),
					resource.TestCheckResourceAttr(rootRef, "blocked_packages.1", "telnet"),

					// Executable Blacklist
					resource.TestCheckResourceAttr(rootRef, "executable_blacklist.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "executable_blacklist.0.executables.#", "0"),

					// Allowed Executables
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.0.allow_executables.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "allowed_executables.0.allow_root_executables.#", "2"),

					// Allowed Registries
					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.allowed_registries.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.allowed_registries.0", "Docker Hub"),
					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.enabled", "true"),

					// Drift Prevention
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.exec_lockdown", "true"),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.image_lockdown", "false"),
					resource.TestCheckResourceAttr(rootRef, "drift_prevention.0.exec_lockdown_white_list.#", "2"),

					// Limit Container Privileges
					resource.TestCheckResourceAttr(rootRef, "limit_container_privileges.0.enabled", "true"),

					// File Block
					resource.TestCheckResourceAttr(rootRef, "file_block.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "file_block.0.filename_block_list.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_block.0.exceptional_block_files.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_block.0.block_files_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_block.0.block_files_processes.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "file_block.0.exceptional_block_files_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "file_block.0.exceptional_block_files_processes.#", "1"),

					// Package Block
					resource.TestCheckResourceAttr(rootRef, "package_block.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "package_block.0.packages_black_list.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "package_block.0.exceptional_block_packages_files.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "package_block.0.block_packages_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "package_block.0.block_packages_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "package_block.0.exceptional_block_packages_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "package_block.0.exceptional_block_packages_processes.#", "1"),

					// Port Block
					resource.TestCheckResourceAttr(rootRef, "port_block.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_inbound_ports.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_outbound_ports.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_inbound_ports.0", "1-11"),
					resource.TestCheckResourceAttr(rootRef, "port_block.0.block_outbound_ports.0", "1-11"),

					// Readonly Files
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.readonly_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.exceptional_readonly_files.#", "2"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.exceptional_readonly_files_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.exceptional_readonly_files_users.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.readonly_files_processes.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "readonly_files.0.readonly_files_users.#", "1"),

					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.allowed_registries.#", "1"),
					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.allowed_registries.0", "Docker Hub"),
					resource.TestCheckResourceAttr(rootRef, "allowed_registries.0.enabled", "true"),

					// Malware scan options
					resource.TestCheckResourceAttr(rootRef, "malware_scan_options.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "malware_scan_options.0.action", "alert"),
					resource.TestCheckResourceAttr(rootRef, "malware_scan_options.0.file_forensic_collection", "false"),

					//todo: bring back after we upgrade the testing env
					//resource.TestCheckResourceAttr(rootRef, "monitor_system_time_changes", "true"),
					resource.TestCheckResourceAttr(rootRef, "restricted_volumes.0.enabled", "true"),
					resource.TestCheckResourceAttr(rootRef, "restricted_volumes.0.volumes.#", "3"),
				),
			},
			{
				ResourceName:      "aquasec_container_runtime_policy.full",
				ImportState:       true,
				ImportStateVerify: true,
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

		container_exec {
			enabled = true
			block_container_exec          = true
			container_exec_proc_white_list = ["proc1","proc2"]
		}
		# block_cryptocurrency_mining = true
		# block_fileless_exec = true
		# block_non_compliant_images    = true
		block_non_compliant_workloads = true
        # block_non_k8s_containers = true
		# block_reverse_shell = true
		# reverse_shell_allowed_processes = [
		# 	"proc1",
		# 	"proc2"
		# ]
		# reverse_shell_allowed_ips = [
		# 	"ip1",
		# 	"ip2"
		# ]
		#block_unregistered_images     = true
		#enable_ip_reputation_security = true
		# enable_drift_prevention       = true
		allowed_executables {
			enabled = true
			allow_executables = ["exe","bin"]
	    }
		file_block{
			enabled = true
			filename_block_list = ["test1","test2"]
	    }

		file_integrity_monitoring {
			enabled                                = true
			monitored_files_create                 = true
			monitored_files_read                   = true
			monitored_files_modify                 = true
			monitored_files_delete                 = true
			monitored_files_attributes             = true
			monitored_files                        = ["paths", "paths2"]
			exceptional_monitored_files            = ["expaths", "expaths2"]
			monitored_files_processes              = ["/bin/bash", "/usr/bin/python"]
			exceptional_monitored_files_processes  = ["/usr/sbin/sshd", "/usr/bin/dockerd"]
			monitored_files_users                  = ["root", "admin"]
			exceptional_monitored_files_users      = ["app", "service"]
		}
		auditing{
			enabled = true
			audit_all_processes = true
			audit_process_cmdline = true
			audit_all_network   = true
	    }
		enable_fork_guard        = true
		fork_guard_process_limit = %v
		limit_container_privileges{
			enabled = true
			block_add_capabilities   = true
			prevent_root_user             = true
			privileged = true
			ipcmode     = true
			pidmode     = true
			usermode    = true
			utsmode     = true
			prevent_low_port_binding      = true
	    }
		port_block{
			enabled = true
			block_inbound_ports = ["1-11"]
			block_outbound_ports = ["1-11"]
		}
		# enable_port_scan_detection = true
		readonly_files{
			enabled = true
			readonly_files = ["readonly","/dir/"]
			exceptional_readonly_files = ["readonly2","/dir2/"]
			readonly_files_processes = ["test"]
			exceptional_readonly_files_processes = ["test"]
			readonly_files_users = ["test"]
			exceptional_readonly_files_users = ["test"]
		}
		allowed_registries{
			enabled = true
			allowed_registries = ["registry1","registry2"]
		}
		# monitor_system_time_changes = "true"
		
		restricted_volumes {
			enabled = true
			volumes = ["/var/run/docker.sock", "/proc", "/sys"]
		}

	}
`,
		policy.Name,
		policy.Description,
		policy.Enabled,
		policy.Enforce,
		policy.EnforceAfterDays,
		policy.ForkGuardProcessLimit)
}

func getFullContainerRuntimePolicyResource(policy client.RuntimePolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_container_runtime_policy" "full" {
		name = "%s"
		description = "%s"
		runtime_type = "container"
		runtime_mode = 0
		enabled = true
		enforce = false
		enforce_after_days = 0
		is_ootb_policy = false
		
		scope_expression = "v1 || v2"
		scope_variables {
			attribute = "image.name"
			value = "*"
		}
		scope_variables {
			attribute = "kubernetes.namespace"
			value = "*"
		}
		
		container_exec {
			enabled = true
			block_container_exec = true
			container_exec_proc_white_list = [
				"/ecs-execute-command-*/amazon-ssm-agent",
				"/ecs-execute-command-*/ssm-session-worker",
				"/ecs-execute-command-*/ssm-agent-worker"
			]
			reverse_shell_ip_white_list = []
		}
		
		reverse_shell {
			enabled = true
			block_reverse_shell = true
			reverse_shell_ip_white_list = []
			reverse_shell_proc_white_list = []
		}
		
		drift_prevention {
			enabled = true
			exec_lockdown = true
			image_lockdown = false
			exec_lockdown_white_list = ["/bin/bash", "/usr/bin/python"]
		}
		
		allowed_executables {
			enabled = true
			allow_executables = ["/usr/bin/curl", "/usr/bin/wget"]
			allow_root_executables = ["/sbin/iptables", "/sbin/modprobe"]
		}
		
		allowed_registries {
			enabled = true
			allowed_registries = ["Docker Hub"]
		}
		
		executable_blacklist {
			enabled = true
			executables = []
		}
		
		restricted_volumes {
			enabled = true
			volumes = ["/var/run/docker.sock", "/proc", "/sys"]
		}
		
		limit_container_privileges {
			enabled = true
		}
		
		block_fileless_exec = true
		block_non_compliant_workloads = true
		block_non_k8s_containers = true
		only_registered_images = true
		block_disallowed_images = true
		no_new_privileges = false
		blocked_packages = ["netcat", "telnet"]
		
		auditing {
			enabled = true
		}
		
		blacklisted_os_users {
			enabled = false
			group_black_list = ["wheel", "sudo"]
			user_black_list = ["root", "admin"]
		}
		
		whitelisted_os_users {
			enabled = false
			user_white_list = ["app", "service"]
			group_white_list = ["app", "service"]
		}
		
		file_block {
			enabled = true
			filename_block_list = ["/etc/shadow", "/etc/passwd"]
			exceptional_block_files = ["/var/log/*"]
			block_files_users = ["root"]
			block_files_processes = ["/bin/cat", "/bin/less"]
			exceptional_block_files_users = ["app"]
			exceptional_block_files_processes = ["/usr/bin/tail"]
		}
		
		file_integrity_monitoring {
			enabled = true
			monitored_files_create = true
			monitored_files_modify = true
			monitored_files_delete = true
			monitored_files = [
				"/etc/*.conf",
				"/etc/*.config"
			]
			exceptional_monitored_files = [
				"/var/lib/docker/*",
				"/var/lib/kubelet/pods/*"
			]
			monitored_files_processes = ["/bin/bash", "/usr/bin/python"]
			exceptional_monitored_files_processes = ["/usr/sbin/sshd", "/usr/bin/dockerd"]
			monitored_files_users = ["root", "admin"]
			exceptional_monitored_files_users = ["app", "service"]
		}
		
		package_block {
			enabled = true
			packages_black_list = ["netcat", "telnet"]
			exceptional_block_packages_files = ["/usr/bin/ssh"]
			block_packages_users = ["root"]
			block_packages_processes = ["/bin/bash"]
			exceptional_block_packages_users = ["app"]
			exceptional_block_packages_processes = ["/usr/bin/python"]
		}
		
		port_block {
			enabled = true
			block_inbound_ports = ["1-11"]
			block_outbound_ports = ["1-11"]
		}
		
		readonly_files {
			enabled = true
			readonly_files = ["readonly","/dir/"]
			exceptional_readonly_files = ["readonly2","/dir2/"]
			readonly_files_processes = ["test"]
			exceptional_readonly_files_processes = ["test"]
			readonly_files_users = ["test"]
			exceptional_readonly_files_users = ["test"]
		}
		
		malware_scan_options {
			enabled = true
			action = "alert"
			file_forensic_collection = false
			include_directories = ["C:\\*", "/*"]
			exclude_directories = ["/proc", "/sys", "/dev"]
			exclude_processes = ["sshd", "dockerd"]
		}
		
		system_integrity_protection {
			enabled = true
			audit_systemtime_change = true
			windows_services_monitoring = true
			monitor_audit_log_integrity = true
		}
		
		failed_kubernetes_checks {
			enabled = false
			failed_checks = ["CVE-2021-25741", "CVE-2022-0185"]
		}
		
		enable_fork_guard = true
		enable_ip_reputation = true
		enable_crypto_mining_dns = true
		enable_port_scan_protection = true
		monitor_system_time_changes = true
	}
`, policy.Name, policy.Description)
}
