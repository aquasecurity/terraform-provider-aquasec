package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataContainerRuntimePolicy() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataContainerRuntimePolicyRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the container runtime policy",
				Required:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The description of the container runtime policy",
				Computed:    true,
			},
			"application_scopes": {
				Type:        schema.TypeList,
				Description: "Indicates the application scope of the service.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"scope_expression": {
				Type:        schema.TypeString,
				Description: "Logical expression of how to compute the dependency of the scope variables.",
				Computed:    true,
			},
			"scope_variables": {
				Type:        schema.TypeList,
				Description: "List of scope attributes.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attribute": {
							Type:        schema.TypeString,
							Description: "Class of supported scope.",
							Computed:    true,
						},
						"value": {
							Type:        schema.TypeString,
							Description: "Value assigned to the attribute.",
							Computed:    true,
						},
					},
				},
				Computed: true,
			},
			"enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if the runtime policy is enabled or not.",
				Computed:    true,
			},
			"enforce": {
				Type:        schema.TypeBool,
				Description: "Indicates that policy should effect container execution (not just for audit).",
				Computed:    true,
			},
			"enforce_after_days": {
				Type:        schema.TypeInt,
				Description: "Indicates the number of days after which the runtime policy will be changed to enforce mode.",
				Computed:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the service.",
				Computed:    true,
			},
			//controls
			"block_container_exec": {
				Type:        schema.TypeBool,
				Description: "If true, exec into a container is prevented.",
				Computed:    true,
			},
			"container_exec_allowed_processes": {
				Type:        schema.TypeList,
				Description: "List of processes that will be allowed.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				RequiredWith: []string{"block_container_exec"},
				Computed:     true,
			},
			"block_cryptocurrency_mining": {
				Type:        schema.TypeBool,
				Description: "Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining",
				Computed:    true,
			},
			"block_fileless_exec": {
				Type:        schema.TypeBool,
				Description: "Detect and prevent running in-memory execution",
				Computed:    true,
			},
			"block_non_compliant_images": {
				Type:        schema.TypeBool,
				Description: "If true, running non-compliant image in the container is prevented.",
				Computed:    true,
			},
			"block_non_compliant_workloads": {
				Type:        schema.TypeBool,
				Description: "If true, running containers in non-compliant pods is prevented.",
				Computed:    true,
			},
			"block_non_k8s_containers": {
				Type:        schema.TypeBool,
				Description: "If true, running non-kubernetes containers is prevented.",
				Computed:    true,
			},
			"block_reverse_shell": {
				Type:        schema.TypeBool,
				Description: "If true, reverse shell is prevented.",
				Computed:    true,
			},
			"reverse_shell_allowed_processes": {
				Type:        schema.TypeList,
				Description: "List of processes that will be allowed",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				RequiredWith: []string{"block_reverse_shell"},
				Computed:     true,
			},
			"reverse_shell_allowed_ips": {
				Type:        schema.TypeList,
				Description: "List of IPs/ CIDRs that will be allowed",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				RequiredWith: []string{"block_reverse_shell"},
				Computed:     true,
			},
			"block_unregistered_images": {
				Type:        schema.TypeBool,
				Description: "If true, running images in the container that are not registered in Aqua is prevented.",
				Computed:    true,
			},
			"blocked_capabilities": {
				Type:        schema.TypeList,
				Description: "If true, prevents containers from using specific Unix capabilities.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"enable_ip_reputation_security": {
				Type:        schema.TypeBool,
				Description: "If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.",
				Computed:    true,
			},
			"enable_drift_prevention": {
				Type:        schema.TypeBool,
				Description: "If true, executables that are not in the original image is prevented from running.",
				Computed:    true,
			},
			"allowed_executables": {
				Type:        schema.TypeList,
				Description: "List of executables that are allowed for the user.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"blocked_executables": {
				Type:        schema.TypeList,
				Description: "List of executables that are prevented from running in containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"blocked_files": {
				Type:        schema.TypeList,
				Description: "List of files that are prevented from being read, modified and executed in the containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"malware_scan_options": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Configuration for Real-Time Malware Protection.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Defines if enabled or not",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"action": {
							Type:        schema.TypeString,
							Description: "Set Action, Defaults to 'Alert' when empty",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exclude_directories": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exclude_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"file_integrity_monitoring": {
				Type:        schema.TypeList,
				Description: "Configuration for file integrity monitoring.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"monitor_create": {
							Type:        schema.TypeBool,
							Description: "If true, create operations will be monitored.",
							Computed:    true,
						},
						"monitor_read": {
							Type:        schema.TypeBool,
							Description: "If true, read operations will be monitored.",
							Computed:    true,
						},
						"monitor_modify": {
							Type:        schema.TypeBool,
							Description: "If true, modification operations will be monitored.",
							Computed:    true,
						},
						"monitor_delete": {
							Type:        schema.TypeBool,
							Description: "If true, deletion operations will be monitored.",
							Computed:    true,
						},
						"monitor_attributes": {
							Type:        schema.TypeBool,
							Description: "If true, add attributes operations will be monitored.",
							Computed:    true,
						},
						"monitored_paths": {
							Type:        schema.TypeList,
							Description: "List of paths to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"excluded_paths": {
							Type:        schema.TypeList,
							Description: "List of paths to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"monitored_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"excluded_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"monitored_users": {
							Type:        schema.TypeList,
							Description: "List of users to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"excluded_users": {
							Type:        schema.TypeList,
							Description: "List of users to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
					},
				},
				Computed: true,
			},
			"audit_all_processes_activity": {
				Type:        schema.TypeBool,
				Description: "If true, all process activity will be audited.",
				Computed:    true,
			},
			"audit_full_command_arguments": {
				Type:        schema.TypeBool,
				Description: "If true, full command arguments will be audited.",
				Computed:    true,
			},
			"audit_all_network_activity": {
				Type:        schema.TypeBool,
				Description: "If true, all network activity will be audited.",
				Computed:    true,
			},
			"enable_fork_guard": {
				Type:        schema.TypeBool,
				Description: "If true, fork bombs are prevented in the containers.",
				Computed:    true,
			},
			"fork_guard_process_limit": {
				Type:        schema.TypeInt,
				Description: "Process limit for the fork guard.",
				Computed:    true,
			},
			"block_access_host_network": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with access to host network.",
				Computed:    true,
			},
			"block_adding_capabilities": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with adding capabilities with `--cap-add` privilege.",
				Computed:    true,
			},
			"block_root_user": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with root user.",
				Computed:    true,
			},
			"block_privileged_containers": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with privileged container capability.",
				Computed:    true,
			},
			"block_use_ipc_namespace": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the privilege to use the IPC namespace.",
				Computed:    true,
			},
			"block_use_pid_namespace": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the privilege to use the PID namespace.",
				Computed:    true,
			},
			"block_use_user_namespace": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the privilege to use the user namespace.",
				Computed:    true,
			},
			"block_use_uts_namespace": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the privilege to use the UTS namespace.",
				Computed:    true,
			},
			"block_low_port_binding": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the capability to bind in port lower than 1024.",
				Computed:    true,
			},
			"limit_new_privileges": {
				Type:        schema.TypeBool,
				Description: "If true, prevents the container from obtaining new privileges at runtime. (only enabled in enforce mode)",
				Computed:    true,
			},
			"blocked_packages": {
				Type:        schema.TypeList,
				Description: "Prevent containers from reading, writing, or executing all files in the list of packages.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"blocked_inbound_ports": {
				Type:        schema.TypeList,
				Description: "List of blocked inbound ports.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"blocked_outbound_ports": {
				Type:        schema.TypeList,
				Description: "List of blocked outbound ports.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"enable_port_scan_detection": {
				Type:        schema.TypeBool,
				Description: "If true, detects port scanning behavior in the container.",
				Computed:    true,
			},
			"readonly_files_and_directories": {
				Type:        schema.TypeList,
				Description: "List of files and directories to be restricted as read-only",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"exceptional_readonly_files_and_directories": {
				Type:        schema.TypeList,
				Description: "List of files and directories to be excluded from the read-only list.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				RequiredWith: []string{"readonly_files_and_directories"},
				Computed:     true,
			},
			"allowed_registries": {
				Type:        schema.TypeList,
				Description: "List of registries that allowed for running containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"monitor_system_time_changes": {
				Type:        schema.TypeBool,
				Description: "If true, system time changes will be monitored.",
				Computed:    true,
			},
			"blocked_volumes": {
				Type:        schema.TypeList,
				Description: "List of volumes that are prevented from being mounted in the containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
		},
	}
}

func dataContainerRuntimePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	crp, err := c.GetRuntimePolicy(name)
	if err == nil {
		d.Set("description", crp.Description)
		d.Set("application_scopes", crp.ApplicationScopes)
		d.Set("scope_expression", crp.Scope.Expression)
		d.Set("scope_variables", flattenScopeVariables(crp.Scope.Variables))
		d.Set("enabled", crp.Enabled)
		d.Set("enforce", crp.Enforce)
		d.Set("enforce_after_days", crp.EnforceAfterDays)
		d.Set("author", crp.Author)
		//controls
		d.Set("block_container_exec", crp.ContainerExec.BlockContainerExec)
		d.Set("container_exec_allowed_processes", crp.ContainerExec.ContainerExecProcWhiteList)
		d.Set("block_cryptocurrency_mining", crp.EnableCryptoMiningDns)
		d.Set("block_fileless_exec", crp.BlockFilelessExec)
		d.Set("block_non_compliant_images", crp.BlockDisallowedImages)
		d.Set("block_non_compliant_workloads", crp.BlockNonCompliantWorkloads)
		d.Set("block_non_k8s_containers", crp.BlockNonK8sContainers)
		d.Set("block_reverse_shell", crp.ReverseShell.BlockReverseShell)
		d.Set("reverse_shell_allowed_processes", crp.ReverseShell.ReverseShellProcWhiteList)
		d.Set("reverse_shell_allowed_ips", crp.ReverseShell.ReverseShellIpWhiteList)
		d.Set("block_unregistered_images", crp.OnlyRegisteredImages)
		d.Set("blocked_capabilities", crp.LinuxCapabilities.RemoveLinuxCapabilities)
		d.Set("enable_ip_reputation_security", crp.EnableIPReputation)
		d.Set("enable_drift_prevention", crp.DriftPrevention.Enabled && crp.DriftPrevention.ExecLockdown)
		d.Set("allowed_executables", crp.AllowedExecutables.AllowExecutables)
		d.Set("blocked_executables", crp.ExecutableBlacklist.Executables)
		d.Set("blocked_files", crp.FileBlock.FilenameBlockList)
		d.Set("file_integrity_monitoring", flattenFileIntegrityMonitoring(crp.FileIntegrityMonitoring))
		d.Set("audit_all_processes_activity", crp.Auditing.AuditAllProcesses)
		d.Set("audit_full_command_arguments", crp.Auditing.AuditProcessCmdline)
		d.Set("audit_all_network_activity", crp.Auditing.AuditAllNetwork)
		d.Set("enable_fork_guard", crp.EnableForkGuard)
		d.Set("fork_guard_process_limit", crp.ForkGuardProcessLimit)
		d.Set("block_access_host_network", crp.LimitContainerPrivileges.Netmode)
		d.Set("block_adding_capabilities", crp.LimitContainerPrivileges.BlockAddCapabilities)
		d.Set("block_root_user", crp.LimitContainerPrivileges.PreventRootUser)
		d.Set("block_privileged_containers", crp.LimitContainerPrivileges.Privileged)
		d.Set("block_use_ipc_namespace", crp.LimitContainerPrivileges.Ipcmode)
		d.Set("block_use_pid_namespace", crp.LimitContainerPrivileges.Pidmode)
		d.Set("block_use_user_namespace", crp.LimitContainerPrivileges.Usermode)
		d.Set("block_use_uts_namespace", crp.LimitContainerPrivileges.Utsmode)
		d.Set("block_low_port_binding", crp.LimitContainerPrivileges.PreventLowPortBinding)
		d.Set("limit_new_privileges", crp.NoNewPrivileges)
		d.Set("blocked_packages", crp.PackageBlock.PackagesBlackList)
		d.Set("blocked_inbound_ports", crp.PortBlock.BlockInboundPorts)
		d.Set("blocked_outbound_ports", crp.PortBlock.BlockOutboundPorts)
		d.Set("enable_port_scan_detection", crp.EnablePortScanProtection)
		d.Set("readonly_files_and_directories", crp.ReadonlyFiles.ReadonlyFiles)
		d.Set("malware_scan_options", flattenMalwareScanOptions(crp.MalwareScanOptions))
		d.Set("exceptional_readonly_files_and_directories", crp.ReadonlyFiles.ExceptionalReadonlyFiles)
		d.Set("allowed_registries", crp.AllowedRegistries.AllowedRegistries)
		d.Set("monitor_system_time_changes", crp.SystemIntegrityProtection.MonitorAuditLogIntegrity)
		d.Set("blocked_volumes", crp.RestrictedVolumes.Volumes)
		d.SetId(name)
	} else {
		return diag.FromErr(err)
	}

	return nil
}
