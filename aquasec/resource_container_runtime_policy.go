package aquasec

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceContainerRuntimePolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceContainerRuntimePolicyCreate,
		ReadContext:   resourceContainerRuntimePolicyRead,
		UpdateContext: resourceContainerRuntimePolicyUpdate,
		DeleteContext: resourceContainerRuntimePolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the container runtime policy",
				Required:    true,
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The description of the container runtime policy",
				Optional:    true,
			},
			"application_scopes": {
				Type:        schema.TypeList,
				Description: "Indicates the application scope of the service.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"scope_expression": {
				Type:        schema.TypeString,
				Description: "Logical expression of how to compute the dependency of the scope variables.",
				Optional:    true,
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
							Required:    true,
						},
						"name": {
							Type:        schema.TypeString,
							Description: "Name assigned to the attribute.",
							Optional:    true,
						},
						"value": {
							Type:        schema.TypeString,
							Description: "Value assigned to the attribute.",
							Required:    true,
						},
					},
				},
				Optional: true,
				Computed: true,
			},
			"enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if the runtime policy is enabled or not.",
				Default:     true,
				Optional:    true,
			},
			"enforce": {
				Type:        schema.TypeBool,
				Description: "Indicates that policy should effect container execution (not just for audit).",
				Default:     false,
				Optional:    true,
			},
			"enforce_after_days": {
				Type:        schema.TypeInt,
				Description: "Indicates the number of days after which the runtime policy will be changed to enforce mode.",
				Optional:    true,
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
				Optional:    true,
			},
			"container_exec_allowed_processes": {
				Type:        schema.TypeList,
				Description: "List of processes that will be allowed.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				RequiredWith: []string{"block_container_exec"},
				Optional:     true,
			},
			"block_cryptocurrency_mining": {
				Type:        schema.TypeBool,
				Description: "Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining",
				Optional:    true,
			},
			"block_fileless_exec": {
				Type:        schema.TypeBool,
				Description: "Detect and prevent running in-memory execution",
				Optional:    true,
			},
			"block_non_compliant_images": {
				Type:        schema.TypeBool,
				Description: "If true, running non-compliant image in the container is prevented.",
				Optional:    true,
			},
			"block_non_compliant_workloads": {
				Type:        schema.TypeBool,
				Description: "If true, running containers in non-compliant pods is prevented.",
				Optional:    true,
			},
			"block_non_k8s_containers": {
				Type:        schema.TypeBool,
				Description: "If true, running non-kubernetes containers is prevented.",
				Optional:    true,
			},
			"block_reverse_shell": {
				Type:        schema.TypeBool,
				Description: "If true, reverse shell is prevented.",
				Optional:    true,
			},
			"reverse_shell_allowed_processes": {
				Type:        schema.TypeList,
				Description: "List of processes that will be allowed",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				RequiredWith: []string{"reverse_shell_allowed_processes"},
				Optional:     true,
			},
			"reverse_shell_allowed_ips": {
				Type:        schema.TypeList,
				Description: "List of IPs/ CIDRs that will be allowed",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				RequiredWith: []string{"reverse_shell_allowed_processes"},
				Optional:     true,
			},
			"block_unregistered_images": {
				Type:        schema.TypeBool,
				Description: "If true, running images in the container that are not registered in Aqua is prevented.",
				Optional:    true,
			},
			"blocked_capabilities": {
				Type:        schema.TypeList,
				Description: "If true, prevents containers from using specific Unix capabilities.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"enable_ip_reputation_security": {
				Type:        schema.TypeBool,
				Description: "If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.",
				Optional:    true,
			},
			"enable_drift_prevention": {
				Type:        schema.TypeBool,
				Description: "If true, executables that are not in the original image is prevented from running.",
				Optional:    true,
			},
			"exec_lockdown_white_list": {
				Type:        schema.TypeList,
				Description: "Specify processes that will be allowed",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:     true,
				RequiredWith: []string{"enable_drift_prevention"},
			},
			"allowed_executables": {
				Type:        schema.TypeList,
				Description: "List of executables that are allowed for the user.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"blocked_executables": {
				Type:        schema.TypeList,
				Description: "List of executables that are prevented from running in containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"blocked_files": {
				Type:        schema.TypeList,
				Description: "List of files that are prevented from being read, modified and executed in the containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
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
				MaxItems:    1,
				Description: "Configuration for file integrity monitoring.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"monitor_create": {
							Type:         schema.TypeBool,
							Description:  "If true, create operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitor_read": {
							Type:         schema.TypeBool,
							Description:  "If true, read operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitor_modify": {
							Type:         schema.TypeBool,
							Description:  "If true, modification operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitor_delete": {
							Type:         schema.TypeBool,
							Description:  "If true, deletion operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitor_attributes": {
							Type:         schema.TypeBool,
							Description:  "If true, add attributes operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitored_paths": {
							Type:        schema.TypeList,
							Description: "List of paths to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"excluded_paths": {
							Type:        schema.TypeList,
							Description: "List of paths to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitored_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"excluded_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitored_users": {
							Type:        schema.TypeList,
							Description: "List of users to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"excluded_users": {
							Type:        schema.TypeList,
							Description: "List of users to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
					},
				},
				Optional: true,
			},
			"audit_all_processes_activity": {
				Type:        schema.TypeBool,
				Description: "If true, all process activity will be audited.",
				Optional:    true,
			},
			"audit_full_command_arguments": {
				Type:        schema.TypeBool,
				Description: "If true, full command arguments will be audited.",
				Optional:    true,
			},
			"audit_all_network_activity": {
				Type:        schema.TypeBool,
				Description: "If true, all network activity will be audited.",
				Optional:    true,
			},
			"enable_fork_guard": {
				Type:        schema.TypeBool,
				Description: "If true, fork bombs are prevented in the containers.",
				Optional:    true,
			},
			"fork_guard_process_limit": {
				Type:        schema.TypeInt,
				Description: "Process limit for the fork guard.",
				Optional:    true,
			},
			"block_access_host_network": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with access to host network.",
				Optional:    true,
			},
			"block_adding_capabilities": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with adding capabilities with `--cap-add` privilege.",
				Optional:    true,
			},
			"block_root_user": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with root user.",
				Optional:    true,
			},
			"block_privileged_containers": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with privileged container capability.",
				Optional:    true,
			},
			"block_use_ipc_namespace": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the privilege to use the IPC namespace.",
				Optional:    true,
			},
			"block_use_pid_namespace": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the privilege to use the PID namespace.",
				Optional:    true,
			},
			"block_use_user_namespace": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the privilege to use the user namespace.",
				Optional:    true,
			},
			"block_use_uts_namespace": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the privilege to use the UTS namespace.",
				Optional:    true,
			},
			"block_low_port_binding": {
				Type:        schema.TypeBool,
				Description: "If true, prevent containers from running with the capability to bind in port lower than 1024.",
				Optional:    true,
			},
			"limit_new_privileges": {
				Type:        schema.TypeBool,
				Description: "If true, prevents the container from obtaining new privileges at runtime. (only enabled in enforce mode)",
				Optional:    true,
			},
			"blocked_packages": {
				Type:        schema.TypeList,
				Description: "Prevent containers from reading, writing, or executing all files in the list of packages.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"blocked_inbound_ports": {
				Type:        schema.TypeList,
				Description: "List of blocked inbound ports.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"blocked_outbound_ports": {
				Type:        schema.TypeList,
				Description: "List of blocked outbound ports.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"enable_port_scan_detection": {
				Type:        schema.TypeBool,
				Description: "If true, detects port scanning behavior in the container.",
				Optional:    true,
			},
			"readonly_files_and_directories": {
				Type:        schema.TypeList,
				Description: "List of files and directories to be restricted as read-only",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"exceptional_readonly_files_and_directories": {
				Type:        schema.TypeList,
				Description: "List of files and directories to be excluded from the read-only list.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				RequiredWith: []string{"readonly_files_and_directories"},
				Optional:     true,
			},
			"allowed_registries": {
				Type:        schema.TypeList,
				Description: "List of registries that allowed for running containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"monitor_system_time_changes": {
				Type:        schema.TypeBool,
				Description: "If true, system time changes will be monitored.",
				Optional:    true,
			},
			"blocked_volumes": {
				Type:        schema.TypeList,
				Description: "List of volumes that are prevented from being mounted in the containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
		},
	}
}

func resourceContainerRuntimePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	crp := expandContainerRuntimePolicy(d)
	err := c.CreateRuntimePolicy(crp)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)
	return resourceContainerRuntimePolicyRead(ctx, d, m)
}

func resourceContainerRuntimePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	crp, err := c.GetRuntimePolicy(d.Id())

	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404 Not Found") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.Set("name", crp.Name)
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
	d.Set("exec_lockdown_white_list", crp.DriftPrevention.ExecLockdownWhiteList)
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
	d.Set("exceptional_readonly_files_and_directories", crp.ReadonlyFiles.ExceptionalReadonlyFiles)
	d.Set("allowed_registries", crp.AllowedRegistries.AllowedRegistries)
	d.Set("monitor_system_time_changes", crp.SystemIntegrityProtection.MonitorAuditLogIntegrity)
	d.Set("blocked_volumes", crp.RestrictedVolumes.Volumes)
	d.Set("malware_scan_options", flattenMalwareScanOptions(crp.MalwareScanOptions))
	d.SetId(crp.Name)

	return nil
}

func resourceContainerRuntimePolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	if d.HasChanges("description",
		"application_scopes",
		"scope_expression",
		"scope_variables",
		"enabled",
		"enforce",
		"enforce_after_days",
		"author",
		"block_container_exec",
		"container_exec_allowed_processes",
		"block_cryptocurrency_mining",
		"block_fileless_exec",
		"block_non_compliant_images",
		"block_non_compliant_workloads",
		"block_non_k8s_containers",
		"block_reverse_shell",
		"reverse_shell_allowed_processes",
		"reverse_shell_allowed_ips",
		"block_unregistered_images",
		"blocked_capabilities",
		"enable_ip_reputation_security",
		"enable_drift_prevention",
		"exec_lockdown_white_list",
		"allowed_executables",
		"blocked_executables",
		"blocked_files",
		"file_integrity_monitoring",
		"audit_all_processes_activity",
		"audit_full_command_arguments",
		"audit_all_network_activity",
		"enable_fork_guard",
		"fork_guard_process_limit",
		"block_access_host_network",
		"block_adding_capabilities",
		"block_root_user",
		"block_privileged_containers",
		"block_use_ipc_namespace",
		"block_use_pid_namespace",
		"block_use_user_namespace",
		"block_use_uts_namespace",
		"block_low_port_binding",
		"limit_new_privileges",
		"blocked_packages",
		"blocked_inbound_ports",
		"blocked_outbound_ports",
		"enable_port_scan_detection",
		"readonly_files_and_directories",
		"exceptional_readonly_files_and_directories",
		"allowed_registries",
		"monitor_system_time_changes",
		"malware_scan_options",
		"blocked_volumes") {

		crp := expandContainerRuntimePolicy(d)
		err := c.UpdateRuntimePolicy(crp)
		if err == nil {
			d.SetId(crp.Name)
		} else {
			return diag.FromErr(err)
		}
	}

	return nil
}

func resourceContainerRuntimePolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	err := c.DeleteRuntimePolicy(name)
	if err == nil {
		d.SetId("")
	} else {
		return diag.FromErr(err)
	}

	//d.SetId("")

	return nil
}

func expandContainerRuntimePolicy(d *schema.ResourceData) *client.RuntimePolicy {
	crp := client.RuntimePolicy{
		Name:        d.Get("name").(string),
		RuntimeType: "container",
	}

	description, ok := d.GetOk("description")
	if ok {
		crp.Description = description.(string)
	}

	applicationScopes, ok := d.GetOk("application_scopes")
	if ok {
		crp.ApplicationScopes = convertStringArr(applicationScopes.([]interface{}))
	}

	scopeExpression, ok := d.GetOk("scope_expression")
	if ok {
		crp.Scope.Expression = scopeExpression.(string)
	}

	variables := make([]client.Variable, 0)
	variableMap, ok := d.GetOk("scope_variables")
	if ok {
		for _, v := range variableMap.([]interface{}) {
			ifc := v.(map[string]interface{})
			variables = append(variables, client.Variable{
				Attribute: ifc["attribute"].(string),
				Name:      ifc["name"].(string),
				Value:     ifc["value"].(string),
			})
		}
	}
	crp.Scope.Variables = variables

	enabled, ok := d.GetOk("enabled")
	if ok {
		crp.Enabled = enabled.(bool)
	}

	enforce, ok := d.GetOk("enforce")
	if ok {
		crp.Enforce = enforce.(bool)
	}

	enforceAfterDays, ok := d.GetOk("enforce_after_days")
	if ok {
		crp.EnforceAfterDays = enforceAfterDays.(int)
	}

	author, ok := d.GetOk("author")
	if ok {
		crp.Author = author.(string)
	}

	blockContainerExec, ok := d.GetOk("block_container_exec")
	if ok {
		crp.ContainerExec.Enabled = blockContainerExec.(bool)
		crp.ContainerExec.BlockContainerExec = blockContainerExec.(bool)
		allowedProcesses, ok := d.GetOk("container_exec_allowed_processes")

		if ok {
			tmpList := convertStringArr(allowedProcesses.([]interface{}))
			//tmpList = append(tmpList, "/ecs-execute-command-*/amazon-ssm-agent")
			//tmpList = append(tmpList, "/ecs-execute-command-*/ssm-session-worker")
			//tmpList = append(tmpList, "/ecs-execute-command-*/ssm-agent-worker")

			crp.ContainerExec.ContainerExecProcWhiteList = tmpList

		}
	}

	blockCryptocurrencyMining, ok := d.GetOk("block_cryptocurrency_mining")
	if ok {
		crp.EnableCryptoMiningDns = blockCryptocurrencyMining.(bool)
	}

	blockFilelessExec, ok := d.GetOk("block_fileless_exec")
	if ok {
		crp.BlockFilelessExec = blockFilelessExec.(bool)
	}

	blockNonComplaintImage, ok := d.GetOk("block_non_compliant_images")
	if ok {
		crp.BlockDisallowedImages = blockNonComplaintImage.(bool)
	}

	blockNonComplaintWorkloads, ok := d.GetOk("block_non_compliant_workloads")
	if ok {
		crp.BlockNonCompliantWorkloads = blockNonComplaintWorkloads.(bool)
	}

	blockNonK8sContainers, ok := d.GetOk("block_non_k8s_containers")
	if ok {
		crp.BlockNonK8sContainers = blockNonK8sContainers.(bool)
	}

	blockReverseShell, ok := d.GetOk("block_reverse_shell")
	if ok {
		crp.ReverseShell.BlockReverseShell = blockReverseShell.(bool)
		reverseShellAllowedProcesses, ok := d.GetOk("reverse_shell_allowed_processes")
		if ok {
			crp.ReverseShell.ReverseShellProcWhiteList = convertStringArr(reverseShellAllowedProcesses.([]interface{}))
		}
		reverseShellAllowedIps, ok := d.GetOk("reverse_shell_allowed_ips")
		if ok {
			crp.ReverseShell.ReverseShellIpWhiteList = convertStringArr(reverseShellAllowedIps.([]interface{}))
		}

	}

	blockUnregisteredImage, ok := d.GetOk("block_unregistered_images")
	if ok {
		crp.OnlyRegisteredImages = blockUnregisteredImage.(bool)
	}

	blockedCap, ok := d.GetOk("blocked_capabilities")
	if ok {
		crp.LinuxCapabilities.Enabled = true
		crp.LinuxCapabilities.RemoveLinuxCapabilities = convertStringArr(blockedCap.([]interface{}))
	}

	enableIpReputation, ok := d.GetOk("enable_ip_reputation_security")
	if ok {
		crp.EnableIPReputation = enableIpReputation.(bool)
	}

	enableDriftPrevention, ok := d.GetOk("enable_drift_prevention")
	if ok {
		crp.DriftPrevention.Enabled = enableDriftPrevention.(bool)
		crp.DriftPrevention.ExecLockdown = enableDriftPrevention.(bool)
		execLockdownWhiteList, ok := d.GetOk("exec_lockdown_white_list")
		if ok {
			crp.DriftPrevention.ExecLockdownWhiteList = convertStringArr(execLockdownWhiteList.([]interface{}))
		}
	}

	allowedExecutables, ok := d.GetOk("allowed_executables")
	if ok {
		strArr := convertStringArr(allowedExecutables.([]interface{}))
		crp.AllowedExecutables.Enabled = len(strArr) != 0
		crp.AllowedExecutables.AllowExecutables = strArr
		crp.AllowedExecutables.AllowRootExecutables = []string{}
	} else {
		crp.AllowedExecutables.Enabled = false
	}

	blockedExecutables, ok := d.GetOk("blocked_executables")
	if ok {
		strArr := convertStringArr(blockedExecutables.([]interface{}))
		crp.ExecutableBlacklist.Enabled = len(strArr) != 0
		crp.ExecutableBlacklist.Executables = strArr
	} else {
		crp.ExecutableBlacklist.Enabled = false
	}

	blockedFiles, ok := d.GetOk("blocked_files")
	if ok {
		strArr := convertStringArr(blockedFiles.([]interface{}))
		crp.FileBlock.Enabled = len(strArr) != 0
		crp.FileBlock.FilenameBlockList = strArr
	}

	crp.FileIntegrityMonitoring = client.FileIntegrityMonitoring{}
	fileIntegrityMonitoringMap, ok := d.GetOk("file_integrity_monitoring")
	if ok {
		v := fileIntegrityMonitoringMap.([]interface{})[0].(map[string]interface{})

		crp.FileIntegrityMonitoring = client.FileIntegrityMonitoring{
			Enabled:                            true,
			MonitoredFiles:                     convertStringArr(v["monitored_paths"].([]interface{})),
			ExceptionalMonitoredFiles:          convertStringArr(v["excluded_paths"].([]interface{})),
			MonitoredFilesProcesses:            convertStringArr(v["monitored_processes"].([]interface{})),
			ExceptionalMonitoredFilesProcesses: convertStringArr(v["excluded_processes"].([]interface{})),
			MonitoredFilesUsers:                convertStringArr(v["monitored_users"].([]interface{})),
			ExceptionalMonitoredFilesUsers:     convertStringArr(v["excluded_users"].([]interface{})),
			MonitoredFilesCreate:               v["monitor_create"].(bool),
			MonitoredFilesRead:                 v["monitor_read"].(bool),
			MonitoredFilesModify:               v["monitor_modify"].(bool),
			MonitoredFilesDelete:               v["monitor_delete"].(bool),
			MonitoredFilesAttributes:           v["monitor_attributes"].(bool),
		}
	}

	auditAllProcessesActivity, ok := d.GetOk("audit_all_processes_activity")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditAllProcesses = auditAllProcessesActivity.(bool)
	}

	auditFullCommandArguments, ok := d.GetOk("audit_full_command_arguments")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditProcessCmdline = auditFullCommandArguments.(bool)
	}

	auditAllNetworkActivity, ok := d.GetOk("audit_all_network_activity")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditAllNetwork = auditAllNetworkActivity.(bool)
	}

	enableForkGuard, ok := d.GetOk("enable_fork_guard")
	if ok {
		crp.EnableForkGuard = enableForkGuard.(bool)
	}

	forkGuardProcessLimit, ok := d.GetOk("fork_guard_process_limit")
	if ok {
		crp.ForkGuardProcessLimit = forkGuardProcessLimit.(int)
	}

	blockHost, ok := d.GetOk("block_access_host_network")
	if ok {
		crp.LimitContainerPrivileges.Enabled = true
		crp.LimitContainerPrivileges.Netmode = blockHost.(bool)
	}

	blockAddCapabilities, ok := d.GetOk("block_adding_capabilities")
	if ok {
		crp.LimitContainerPrivileges.Enabled = true
		crp.LimitContainerPrivileges.BlockAddCapabilities = blockAddCapabilities.(bool)
	}

	rootUser, ok := d.GetOk("block_root_user")
	if ok {
		crp.LimitContainerPrivileges.Enabled = true
		crp.LimitContainerPrivileges.PreventRootUser = rootUser.(bool)
	}

	privileged, ok := d.GetOk("block_privileged_containers")
	if ok {
		crp.LimitContainerPrivileges.Enabled = true
		crp.LimitContainerPrivileges.Privileged = privileged.(bool)
	}

	ipcMode, ok := d.GetOk("block_use_ipc_namespace")
	if ok {
		crp.LimitContainerPrivileges.Enabled = true
		crp.LimitContainerPrivileges.Ipcmode = ipcMode.(bool)
	}

	pidMode, ok := d.GetOk("block_use_pid_namespace")
	if ok {
		crp.LimitContainerPrivileges.Enabled = true
		crp.LimitContainerPrivileges.Pidmode = pidMode.(bool)
	}

	userMode, ok := d.GetOk("block_use_user_namespace")
	if ok {
		crp.LimitContainerPrivileges.Enabled = true
		crp.LimitContainerPrivileges.Usermode = userMode.(bool)
	}

	utsMode, ok := d.GetOk("block_use_uts_namespace")
	if ok {
		crp.LimitContainerPrivileges.Enabled = true
		crp.LimitContainerPrivileges.Utsmode = utsMode.(bool)
	}

	lowPort, ok := d.GetOk("block_low_port_binding")
	if ok {
		crp.LimitContainerPrivileges.Enabled = true
		crp.LimitContainerPrivileges.PreventLowPortBinding = lowPort.(bool)
	}

	limitNewPrivileges, ok := d.GetOk("limit_new_privileges")
	if ok {
		crp.NoNewPrivileges = limitNewPrivileges.(bool)
	}

	blockedPackages, ok := d.GetOk("blocked_packages")
	if ok {
		crp.PackageBlock.Enabled = true
		crp.PackageBlock.PackagesBlackList = convertStringArr(blockedPackages.([]interface{}))
	}

	blockedInboundPorts, ok := d.GetOk("blocked_inbound_ports")
	if ok {
		crp.PortBlock.Enabled = true
		crp.PortBlock.BlockInboundPorts = convertStringArr(blockedInboundPorts.([]interface{}))
	}

	blockedOutboundPorts, ok := d.GetOk("blocked_outbound_ports")
	if ok {
		crp.PortBlock.Enabled = true
		crp.PortBlock.BlockOutboundPorts = convertStringArr(blockedOutboundPorts.([]interface{}))
	}

	portScan, ok := d.GetOk("enable_port_scan_detection")
	if ok {
		crp.EnablePortScanProtection = portScan.(bool)
	}

	readOnly, ok := d.GetOk("readonly_files_and_directories")
	if ok {
		crp.ReadonlyFiles.Enabled = true
		crp.ReadonlyFiles.ReadonlyFiles = convertStringArr(readOnly.([]interface{}))
		crp.ReadonlyFiles.ExceptionalReadonlyFiles = []string{}
		expReadOnly, ok := d.GetOk("exceptional_readonly_files_and_directories")
		if ok {
			crp.ReadonlyFiles.ExceptionalReadonlyFiles = convertStringArr(expReadOnly.([]interface{}))
		}
	}

	allowedRegistries, ok := d.GetOk("allowed_registries")
	if ok {
		crp.AllowedRegistries.Enabled = true
		crp.AllowedRegistries.AllowedRegistries = convertStringArr(allowedRegistries.([]interface{}))
	}

	systemTime, ok := d.GetOk("monitor_system_time_changes")
	if ok {
		crp.SystemIntegrityProtection.Enabled = systemTime.(bool)
		crp.SystemIntegrityProtection.AuditSystemtimeChange = systemTime.(bool)
		crp.SystemIntegrityProtection.WindowsServicesMonitoring = systemTime.(bool)
		crp.SystemIntegrityProtection.MonitorAuditLogIntegrity = systemTime.(bool)
	}

	blockedVol, ok := d.GetOk("blocked_volumes")
	if ok {
		crp.RestrictedVolumes.Enabled = true
		crp.RestrictedVolumes.Volumes = convertStringArr(blockedVol.([]interface{}))
	}

	crp.MalwareScanOptions = client.MalwareScanOptions{}
	malwareScanOptionsMap, ok := d.GetOk("malware_scan_options")
	if ok {
		v := malwareScanOptionsMap.([]interface{})[0].(map[string]interface{})

		crp.MalwareScanOptions = client.MalwareScanOptions{
			Enabled:            v["enabled"].(bool),
			Action:             v["action"].(string),
			ExcludeDirectories: convertStringArr(v["exclude_directories"].([]interface{})),
			ExcludeProcesses:   convertStringArr(v["exclude_processes"].([]interface{})),
		}
	}

	return &crp
}
