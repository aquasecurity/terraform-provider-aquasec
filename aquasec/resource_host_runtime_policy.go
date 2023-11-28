package aquasec

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceHostRuntimePolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceHostRuntimePolicyCreate,
		ReadContext:   resourceHostRuntimePolicyRead,
		UpdateContext: resourceHostRuntimePolicyUpdate,
		DeleteContext: resourceHostRuntimePolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the host runtime policy",
				Required:    true,
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The description of the host runtime policy",
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
				Optional:    true,
			},
			// controls
			"block_cryptocurrency_mining": {
				Type:        schema.TypeBool,
				Description: "Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining",
				Optional:    true,
			},
			"audit_brute_force_login": {
				Type:        schema.TypeBool,
				Description: "Detects brute force login attempts",
				Optional:    true,
			},
			"enable_ip_reputation_security": {
				Type:        schema.TypeBool,
				Description: "If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.",
				Optional:    true,
			},
			"blocked_files": {
				Type:        schema.TypeList,
				Description: "List of files that are prevented from being read, modified and executed in the containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"file_integrity_monitoring": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Configuration for file integrity monitoring.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "If true, file integrity monitoring is enabled.",
							Optional:    true,
						},
						"monitored_files": {
							Type:        schema.TypeList,
							Description: "List of paths to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_monitored_files": {
							Type:        schema.TypeList,
							Description: "List of paths to be excluded from monitoring.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"monitored_files_read": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file read operations.",
							Optional:    true,
						},
						"monitored_files_modify": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file modify operations.",
							Optional:    true,
						},
						"monitored_files_attributes": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file attribute operations.",
							Optional:    true,
						},
						"monitored_files_create": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file create operations.",
							Optional:    true,
						},
						"monitored_files_delete": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file delete operations.",
							Optional:    true,
						},
						"monitored_files_processes": {
							Type:        schema.TypeList,
							Description: "List of processes associated with monitored files.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_monitored_files_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to be excluded from monitoring.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"monitored_files_users": {
							Type:        schema.TypeList,
							Description: "List of users associated with monitored files.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_monitored_files_users": {
							Type:        schema.TypeList,
							Description: "List of users to be excluded from monitoring.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
			},
			"audit_all_os_user_activity": {
				Type:        schema.TypeBool,
				Description: "If true, all process activity will be audited.",
				Optional:    true,
			},
			"audit_full_command_arguments": {
				Type:        schema.TypeBool,
				Description: "If true, full command arguments will be audited.",
				Optional:    true,
			},
			"audit_host_successful_login_events": {
				Type:        schema.TypeBool,
				Description: "If true, host successful logins will be audited.",
				Optional:    true,
			},
			"audit_host_failed_login_events": {
				Type:        schema.TypeBool,
				Description: "If true, host failed logins will be audited.",
				Optional:    true,
			},
			"audit_user_account_management": {
				Type:        schema.TypeBool,
				Description: "If true, account management will be audited.",
				Optional:    true,
			},
			"os_users_allowed": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) users that are allowed to authenticate to the host, and block authentication requests from all others.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"os_groups_allowed": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) groups that are allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"os_users_blocked": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) users that are not allowed to authenticate to the host, and block authentication requests from all others.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"os_groups_blocked": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) groups that are not allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"port_scanning_detection": {
				Type:        schema.TypeBool,
				Description: "If true, port scanning behaviors will be audited.",
				Optional:    true,
			},
			"monitor_system_time_changes": {
				Type:        schema.TypeBool,
				Description: "If true, system time changes will be monitored.",
				Optional:    true,
			},
			"monitor_windows_services": {
				Type:        schema.TypeBool,
				Description: "If true, windows service operations will be monitored.",
				Optional:    true,
			},
			"monitor_system_log_integrity": {
				Type:        schema.TypeBool,
				Description: "If true, system log will be monitored.",
				Optional:    true,
			},
			"windows_registry_monitoring": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Configuration for windows registry monitoring.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"monitor_create": {
							Type:         schema.TypeBool,
							Description:  "If true, create operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitor_read": {
							Type:         schema.TypeBool,
							Description:  "If true, read operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitor_modify": {
							Type:         schema.TypeBool,
							Description:  "If true, modification operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitor_delete": {
							Type:         schema.TypeBool,
							Description:  "If true, deletion operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitor_attributes": {
							Type:         schema.TypeBool,
							Description:  "If true, add attributes operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
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
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitored_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"excluded_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitored_users": {
							Type:        schema.TypeList,
							Description: "List of registry users to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"excluded_users": {
							Type:        schema.TypeList,
							Description: "List of registry users to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
					},
				},
				Optional: true,
			},
			"windows_registry_protection": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Configuration for windows registry protection.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"protected_paths": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"excluded_paths": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
						"protected_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
						"excluded_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
						"protected_users": {
							Type:        schema.TypeList,
							Description: "List of registry users to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
						"excluded_users": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be users from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
					},
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
						"include_directories": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be excluded from being protected.",
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
			//JSON Test
			"failed_kubernetes_checks": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"failed_checks": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"enable_port_scan_protection": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"enable_crypto_mining_dns": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"enable_ip_reputation": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"fork_guard_process_limit": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			},
			"enable_fork_guard": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"default_security_profile": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"block_non_k8s_containers": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"block_fileless_exec": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"block_container_exec": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"registry": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"reverse_shell": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"block_reverse_shell": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"reverse_shell_proc_white_list": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"reverse_shell_ip_white_list": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"container_exec": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"block_container_exec": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"container_exec_proc_white_list": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"system_integrity_protection": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"audit_systemtime_change": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"windows_services_monitoring": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"monitor_audit_log_integrity": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
					},
				},
				Optional: true,
			},
			"readonly_registry": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"readonly_registry_paths": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_readonly_registry_paths": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"readonly_registry_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_readonly_registry_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"readonly_registry_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_readonly_registry_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"registry_access_monitoring": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"monitored_registry_paths": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_monitored_registry_paths": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"monitored_registry_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_monitored_registry_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"monitored_registry_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_monitored_registry_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"monitored_registry_create": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"monitored_registry_read": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"monitored_registry_modify": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"monitored_registry_delete": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"monitored_registry_attributes": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
					},
				},
				Optional: true,
			},
			"readonly_files": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"readonly_files": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_readonly_files": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"readonly_files_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_readonly_files_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"readonly_files_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_readonly_files_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"tripwire": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"user_id": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
						"user_password": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
						"apply_on": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"serverless_app": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
					},
				},
				Optional: true,
			},
			"port_block": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"block_inbound_ports": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"block_outbound_ports": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"linux_capabilities": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"remove_linux_capabilities": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"package_block": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"packages_black_list": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_block_packages_files": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"block_packages_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"block_packages_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_block_packages_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_block_packages_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"file_block": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"filename_block_list": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_block_files": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"block_files_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"block_files_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_block_files_users": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exceptional_block_files_processes": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"whitelisted_os_users": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"user_white_list": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"group_white_list": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"blacklisted_os_users": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"group_black_list": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"user_black_list": {
							Type:        schema.TypeList,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			"auditing": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"audit_all_processes": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"audit_process_cmdline": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"audit_all_network": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"audit_os_user_activity": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"audit_success_login": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"audit_failed_login": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"audit_user_account_management": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
					},
				},
				Optional: true,
			},
			"block_non_compliant_workloads": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"block_disallowed_images": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"only_registered_images": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"scope": {
				Type:        schema.TypeList,
				Description: "Scope configuration.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"expression": {
							Type:        schema.TypeString,
							Description: "Scope expression.",
							Required:    true,
						},
						"variables": {
							Type:        schema.TypeList,
							Description: "List of variables in the scope.",
							Required:    true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"attribute": {
										Type:        schema.TypeString,
										Description: "Variable attribute.",
										Required:    true,
									},
									"value": {
										Type:        schema.TypeString,
										Description: "Variable value.",
										Required:    true,
									},
								},
							},
						},
					},
				},
			},
			"limit_container_privileges": {
				Type:        schema.TypeList,
				Description: "Container privileges configuration.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether container privilege limitations are enabled.",
							Optional:    true,
						},
						"privileged": {
							Type:        schema.TypeBool,
							Description: "Whether the container is run in privileged mode.",
							Optional:    true,
						},
						"netmode": {
							Type:        schema.TypeBool,
							Description: "Whether to limit network-related capabilities.",
							Optional:    true,
						},
						"pidmode": {
							Type:        schema.TypeBool,
							Description: "Whether to limit process-related capabilities.",
							Optional:    true,
						},
						"utsmode": {
							Type:        schema.TypeBool,
							Description: "Whether to limit UTS-related capabilities.",
							Optional:    true,
						},
						"usermode": {
							Type:        schema.TypeBool,
							Description: "Whether to limit user-related capabilities.",
							Optional:    true,
						},
						"ipcmode": {
							Type:        schema.TypeBool,
							Description: "Whether to limit IPC-related capabilities.",
							Optional:    true,
						},
						"prevent_root_user": {
							Type:        schema.TypeBool,
							Description: "Whether to prevent the use of the root user.",
							Optional:    true,
						},
						"prevent_low_port_binding": {
							Type:        schema.TypeBool,
							Description: "Whether to prevent low port binding.",
							Optional:    true,
						},
						"block_add_capabilities": {
							Type:        schema.TypeBool,
							Description: "Whether to block adding capabilities.",
							Optional:    true,
						},
						"use_host_user": {
							Type:        schema.TypeBool,
							Description: "Whether to use the host user.",
							Optional:    true,
						},
					},
				},
			},
			"bypass_scope": {
				Type:        schema.TypeList,
				Description: "Bypass scope configuration.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether bypassing the scope is enabled.",
							Optional:    true,
						},
						"scope": {
							Type:        schema.TypeList,
							Description: "Scope configuration.",
							Optional:    true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"expression": {
										Type:        schema.TypeString,
										Description: "Scope expression.",
										Optional:    true,
									},
									"variables": {
										Type:        schema.TypeList,
										Description: "List of variables in the scope.",
										Optional:    true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"attribute": {
													Type:        schema.TypeString,
													Description: "Variable attribute.",
													Optional:    true,
												},
												"value": {
													Type:        schema.TypeString,
													Description: "Variable value.",
													Optional:    true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"no_new_privileges": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"restricted_volumes": {
				Type:        schema.TypeList,
				Description: "Restricted volumes configuration.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether restricted volumes are enabled.",
							Optional:    true,
						},
						"volumes": {
							Type:        schema.TypeList,
							Description: "List of restricted volumes.",
							Optional:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"drift_prevention": {
				Type:        schema.TypeList,
				Description: "Drift prevention configuration.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether drift prevention is enabled.",
							Optional:    true,
						},
						"exec_lockdown": {
							Type:        schema.TypeBool,
							Description: "Whether to lockdown execution drift.",
							Optional:    true,
						},
						"image_lockdown": {
							Type:        schema.TypeBool,
							Description: "Whether to lockdown image drift.",
							Optional:    true,
						},
						"exec_lockdown_white_list": {
							Type:        schema.TypeList,
							Description: "List of items in the execution lockdown white list.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
			},
			"executable_blacklist": {
				Type:        schema.TypeList,
				Description: "Executable blacklist configuration.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether the executable blacklist is enabled.",
							Optional:    true,
						},
						"executables": {
							Type:        schema.TypeList,
							Description: "List of blacklisted executables.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
			},
			"allowed_registries": {
				Type:        schema.TypeList,
				Description: "Allowed registries configuration.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether allowed registries are enabled.",
							Optional:    true,
						},
						"allowed_registries": {
							Type:        schema.TypeList,
							Description: "List of allowed registries.",
							Optional:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"allowed_executables": {
				Type:        schema.TypeList,
				Description: "Allowed executables configuration.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether allowed executables configuration is enabled.",
							Optional:    true,
						},
						"allow_executables": {
							Type:        schema.TypeList,
							Description: "List of allowed executables.",
							Optional:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"separate_executables": {
							Type:        schema.TypeBool,
							Description: "Whether to treat executables separately.",
							Optional:    true,
						},
						"allow_root_executables": {
							Type:        schema.TypeList,
							Description: "List of allowed root executables.",
							Optional:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"type": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"digest": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"vpatch_version": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"resource_name": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"resource_type": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"cve": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"repo_name": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"image_name": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"exclude_application_scopes": {
				Type:        schema.TypeList,
				Description: "List of excluded application scopes.",
				Optional:    true,
				Elem: &schema.Schema{
					Type:        schema.TypeString,
					Description: "Excluded application scope.",
				},
			},
			"permission": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"is_audit_checked": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"enforce_scheduler_added_on": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			},
			"is_ootb_policy": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"is_auto_generated": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			},
			"updated": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"lastupdate": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			},
			"version": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"created": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
			"runtime_mode": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			},
			"runtime_type": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			},
		},
	}
}

func resourceHostRuntimePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	crp := expandHostRuntimePolicy(d)
	err := c.CreateRuntimePolicy(crp)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)
	return resourceHostRuntimePolicyRead(ctx, d, m)

}

func resourceHostRuntimePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	crp, err := c.GetRuntimePolicy(d.Id())

	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
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
	d.Set("block_cryptocurrency_mining", crp.EnableCryptoMiningDns)
	d.Set("audit_brute_force_login", crp.AuditBruteForceLogin)
	d.Set("enable_ip_reputation_security", crp.EnableIPReputation)
	d.Set("blocked_files", crp.FileBlock.FilenameBlockList)
	d.Set("file_integrity_monitoring", flattenFileIntegrityMonitoring(crp.FileIntegrityMonitoring))
	d.Set("audit_all_os_user_activity", crp.Auditing.AuditOsUserActivity)
	d.Set("audit_full_command_arguments", crp.Auditing.AuditProcessCmdline)
	d.Set("audit_host_successful_login_events", crp.Auditing.AuditSuccessLogin)
	d.Set("audit_host_failed_login_events", crp.Auditing.AuditFailedLogin)
	d.Set("os_users_allowed", crp.WhitelistedOsUsers.UserWhiteList)
	d.Set("os_groups_allowed", crp.WhitelistedOsUsers.GroupWhiteList)
	d.Set("os_users_blocked", crp.BlacklistedOsUsers.UserBlackList)
	d.Set("os_groups_blocked", crp.BlacklistedOsUsers.GroupBlackList)
	d.Set("malware_scan_options", flattenMalwareScanOptions(crp.MalwareScanOptions))
	d.Set("monitor_system_time_changes", crp.SystemIntegrityProtection.AuditSystemtimeChange)
	d.Set("monitor_windows_services", crp.SystemIntegrityProtection.WindowsServicesMonitoring)
	d.Set("windows_registry_monitoring", flattenWindowsRegistryMonitoring(crp.RegistryAccessMonitoring))
	d.Set("windows_registry_protection", flattenWindowsRegistryProtection(crp.ReadonlyRegistry))

	d.SetId(crp.Name)

	return nil
}

func resourceHostRuntimePolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	if d.HasChanges("description",
		"application_scopes",
		"scope_expression",
		"scope_variables",
		"enabled",
		"enforce",
		"enforce_after_days",
		"author",
		"block_cryptocurrency_mining",
		"audit_brute_force_login",
		"enable_ip_reputation_security",
		"blocked_files",
		"file_integrity_monitoring",
		"audit_all_os_user_activity",
		"audit_full_command_arguments",
		"audit_host_successful_login_events",
		"audit_host_failed_login_events",
		"audit_user_account_management",
		"os_users_allowed",
		"os_groups_allowed",
		"os_users_blocked",
		"os_groups_blocked",
		"package_block",
		"port_scanning_detection",
		"malware_scan_options",
		"monitor_system_time_changes",
		"monitor_windows_services",
		"monitor_system_log_integrity",
		"windows_registry_monitoring",
		"windows_registry_protection") {
		crp := expandHostRuntimePolicy(d)
		err := c.UpdateRuntimePolicy(crp)
		if err == nil {
			d.SetId(name)
		} else {
			return diag.FromErr(err)
		}
	}

	//d.SetId(name)

	return nil
}

func resourceHostRuntimePolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
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

func expandHostRuntimePolicy(d *schema.ResourceData) *client.RuntimePolicy {
	crp := client.RuntimePolicy{
		Name:        d.Get("name").(string),
		RuntimeType: "host",
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

	// controls

	blockCryptocurrencyMining, ok := d.GetOk("block_cryptocurrency_mining")
	if ok {
		crp.EnableCryptoMiningDns = blockCryptocurrencyMining.(bool)
	}

	auditBruteForceLogin, ok := d.GetOk("audit_brute_force_login")
	if ok {
		crp.AuditBruteForceLogin = auditBruteForceLogin.(bool)
	}

	enableIpReputation, ok := d.GetOk("enable_ip_reputation_security")
	if ok {
		crp.EnableIPReputation = enableIpReputation.(bool)
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
			Enabled:                            v["enabled"].(bool),
			MonitoredFiles:                     convertStringArrTest(v["monitored_files"].([]interface{})),
			ExceptionalMonitoredFiles:          convertStringArrTest(v["exceptional_monitored_files"].([]interface{})),
			MonitoredFilesProcesses:            convertStringArrTest(v["monitored_files_processes"].([]interface{})),
			ExceptionalMonitoredFilesProcesses: convertStringArrTest(v["exceptional_monitored_files_processes"].([]interface{})),
			MonitoredFilesUsers:                convertStringArrTest(v["monitored_files_users"].([]interface{})),
			ExceptionalMonitoredFilesUsers:     convertStringArrTest(v["exceptional_monitored_files_users"].([]interface{})),
			MonitoredFilesCreate:               v["monitored_files_create"].(bool),
			MonitoredFilesRead:                 v["monitored_files_read"].(bool),
			MonitoredFilesModify:               v["monitored_files_modify"].(bool),
			MonitoredFilesDelete:               v["monitored_files_delete"].(bool),
			MonitoredFilesAttributes:           v["monitored_files_attributes"].(bool),
		}
	}

	auditOsUserActivity, ok := d.GetOk("audit_all_os_user_activity")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditOsUserActivity = auditOsUserActivity.(bool)
	}

	auditFullCommandArguments, ok := d.GetOk("audit_full_command_arguments")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditProcessCmdline = auditFullCommandArguments.(bool)
	}

	auditHostSuccessfulLoginEvents, ok := d.GetOk("audit_host_successful_login_events")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditSuccessLogin = auditHostSuccessfulLoginEvents.(bool)
	}

	auditHostFailedLoginEvents, ok := d.GetOk("audit_host_failed_login_events")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditFailedLogin = auditHostFailedLoginEvents.(bool)
	}

	auditUserAccountManagement, ok := d.GetOk("audit_user_account_management")
	if ok {
		crp.Enabled = true
		crp.Auditing.AuditUserAccountManagement = auditUserAccountManagement.(bool)
	}

	crp.WhitelistedOsUsers.UserWhiteList = []string{}
	usersAllowed, ok := d.GetOk("os_users_allowed")
	if ok {
		strArr := convertStringArr(usersAllowed.([]interface{}))
		crp.WhitelistedOsUsers.Enabled = len(strArr) != 0
		crp.WhitelistedOsUsers.UserWhiteList = strArr
	}

	crp.WhitelistedOsUsers.GroupWhiteList = []string{}
	groupsAllowed, ok := d.GetOk("os_groups_allowed")
	if ok {
		strArr := convertStringArr(groupsAllowed.([]interface{}))
		crp.WhitelistedOsUsers.Enabled = len(strArr) != 0
		crp.WhitelistedOsUsers.GroupWhiteList = strArr
	}

	crp.BlacklistedOsUsers.UserBlackList = []string{}
	usersBlocked, ok := d.GetOk("os_users_blocked")
	if ok {
		strArr := convertStringArr(usersBlocked.([]interface{}))
		crp.BlacklistedOsUsers.Enabled = len(strArr) != 0
		crp.BlacklistedOsUsers.UserBlackList = strArr
	}

	crp.BlacklistedOsUsers.GroupBlackList = []string{}
	groupsBlocked, ok := d.GetOk("os_groups_blocked")
	if ok {
		strArr := convertStringArr(groupsBlocked.([]interface{}))
		crp.BlacklistedOsUsers.Enabled = len(strArr) != 0
		crp.BlacklistedOsUsers.GroupBlackList = strArr
	}

	crp.PackageBlock.PackagesBlackList = []string{}
	packageBlock, ok := d.GetOk("package_block")
	if ok {
		strArr := convertStringArrTest(packageBlock.([]interface{}))
		crp.PackageBlock.Enabled = len(strArr) != 0
		crp.PackageBlock.PackagesBlackList = strArr
	}

	portScanningDetection, ok := d.GetOk("port_scanning_detection")
	if ok {
		crp.EnablePortScanProtection = portScanningDetection.(bool)
	}

	systemTime, ok := d.GetOk("monitor_system_time_changes")
	if ok {
		crp.SystemIntegrityProtection.Enabled = systemTime.(bool)
		crp.SystemIntegrityProtection.AuditSystemtimeChange = systemTime.(bool)
	}

	windowsServices, ok := d.GetOk("monitor_windows_services")
	if ok {
		crp.SystemIntegrityProtection.Enabled = true
		crp.SystemIntegrityProtection.WindowsServicesMonitoring = windowsServices.(bool)
	}

	systemLogIntegrity, ok := d.GetOk("monitor_system_log_integrity")
	if ok {
		crp.SystemIntegrityProtection.Enabled = true
		crp.SystemIntegrityProtection.MonitorAuditLogIntegrity = systemLogIntegrity.(bool)
	}

	crp.RegistryAccessMonitoring = client.RegistryAccessMonitoring{}
	windowsMonitoringMap, ok := d.GetOk("windows_registry_monitoring")
	if ok {
		v := windowsMonitoringMap.([]interface{})[0].(map[string]interface{})

		crp.RegistryAccessMonitoring = client.RegistryAccessMonitoring{
			Enabled:                               true,
			MonitoredRegistryPaths:                convertStringArr(v["monitored_paths"].([]interface{})),
			ExceptionalMonitoredRegistryPaths:     convertStringArr(v["excluded_paths"].([]interface{})),
			MonitoredRegistryProcesses:            convertStringArr(v["monitored_processes"].([]interface{})),
			ExceptionalMonitoredRegistryProcesses: convertStringArr(v["excluded_processes"].([]interface{})),
			MonitoredRegistryUsers:                convertStringArr(v["monitored_users"].([]interface{})),
			ExceptionalMonitoredRegistryUsers:     convertStringArr(v["excluded_users"].([]interface{})),
			MonitoredRegistryCreate:               v["monitor_create"].(bool),
			MonitoredRegistryRead:                 v["monitor_read"].(bool),
			MonitoredRegistryModify:               v["monitor_modify"].(bool),
			MonitoredRegistryDelete:               v["monitor_delete"].(bool),
			MonitoredRegistryAttributes:           v["monitor_attributes"].(bool),
		}
	}

	crp.ReadonlyRegistry = client.ReadonlyRegistry{}
	windowsRegistryProtectionMap, ok := d.GetOk("windows_registry_protection")
	if ok {
		v := windowsRegistryProtectionMap.([]interface{})[0].(map[string]interface{})

		crp.ReadonlyRegistry = client.ReadonlyRegistry{
			Enabled:                              true,
			ReadonlyRegistryPaths:                convertStringArr(v["protected_paths"].([]interface{})),
			ExceptionalReadonlyRegistryPaths:     convertStringArr(v["excluded_paths"].([]interface{})),
			ReadonlyRegistryProcesses:            convertStringArr(v["protected_processes"].([]interface{})),
			ExceptionalReadonlyRegistryProcesses: convertStringArr(v["excluded_processes"].([]interface{})),
			ReadonlyRegistryUsers:                convertStringArr(v["protected_users"].([]interface{})),
			ExceptionalReadonlyRegistryUsers:     convertStringArr(v["excluded_users"].([]interface{})),
		}
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

func flattenFileIntegrityMonitoring(monitoring client.FileIntegrityMonitoring) []map[string]interface{} {
	if len(monitoring.MonitoredFiles) == 0 {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"monitor_create":      monitoring.MonitoredFilesCreate,
			"monitor_read":        monitoring.MonitoredFilesRead,
			"monitor_modify":      monitoring.MonitoredFilesModify,
			"monitor_delete":      monitoring.MonitoredFilesDelete,
			"monitor_attributes":  monitoring.MonitoredFilesAttributes,
			"monitored_paths":     monitoring.MonitoredFiles,
			"excluded_paths":      monitoring.ExceptionalMonitoredFiles,
			"monitored_processes": monitoring.MonitoredFilesProcesses,
			"excluded_processes":  monitoring.ExceptionalMonitoredFilesProcesses,
			"monitored_users":     monitoring.MonitoredFilesUsers,
			"excluded_users":      monitoring.ExceptionalMonitoredFilesUsers,
		},
	}
}

func flattenWindowsRegistryProtection(monitoring client.ReadonlyRegistry) []map[string]interface{} {
	if len(monitoring.ReadonlyRegistryPaths) == 0 {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"protected_paths":     monitoring.ReadonlyRegistryPaths,
			"excluded_paths":      monitoring.ExceptionalReadonlyRegistryPaths,
			"protected_processes": monitoring.ReadonlyRegistryProcesses,
			"excluded_processes":  monitoring.ExceptionalReadonlyRegistryProcesses,
			"protected_users":     monitoring.ReadonlyRegistryUsers,
			"excluded_users":      monitoring.ExceptionalReadonlyRegistryUsers,
		},
	}
}

func flattenWindowsRegistryMonitoring(monitoring client.RegistryAccessMonitoring) []map[string]interface{} {
	if len(monitoring.MonitoredRegistryPaths) == 0 {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"monitor_create":      monitoring.MonitoredRegistryCreate,
			"monitor_read":        monitoring.MonitoredRegistryRead,
			"monitor_modify":      monitoring.MonitoredRegistryModify,
			"monitor_delete":      monitoring.MonitoredRegistryDelete,
			"monitor_attributes":  monitoring.MonitoredRegistryAttributes,
			"monitored_paths":     monitoring.MonitoredRegistryPaths,
			"excluded_paths":      monitoring.ExceptionalMonitoredRegistryPaths,
			"monitored_processes": monitoring.MonitoredRegistryProcesses,
			"excluded_processes":  monitoring.ExceptionalMonitoredRegistryProcesses,
			"monitored_users":     monitoring.MonitoredRegistryUsers,
			"excluded_users":      monitoring.ExceptionalMonitoredRegistryUsers,
		},
	}
}

func flattenMalwareScanOptions(monitoring client.MalwareScanOptions) []map[string]interface{} {
	if len(monitoring.ExcludeDirectories) == 0 {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":             monitoring.Enabled,
			"action":              monitoring.Action,
			"exclude_directories": monitoring.ExcludeDirectories,
			"exclude_processes":   monitoring.ExcludeProcesses,
		},
	}
}
