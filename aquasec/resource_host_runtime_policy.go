package aquasec

import (
	"context"
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strings"
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
			}, // list
			"enable_port_scan_protection": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"enable_crypto_mining_dns": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"enable_ip_reputation": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"fork_guard_process_limit": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			}, // int
			"enable_fork_guard": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"default_security_profile": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"block_non_k8s_containers": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"block_fileless_exec": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"block_container_exec": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"registry": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
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
			}, // list
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
			}, // list
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
			}, // list
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
			}, // list
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
			}, //list
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
			}, //list
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
			}, // list
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
			}, // list
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
			}, // list
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
			}, // list
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
			}, // list
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
			}, // list
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
			}, // list
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
			}, // list
			"block_non_compliant_workloads": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"block_disallowed_images": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"only_registered_images": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
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
			}, // list
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
			}, //todo
			"no_new_privileges": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
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
			}, // list
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
			}, // list
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
			}, // list
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
			}, // list
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
			}, // list
			"type": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"digest": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"vpatch_version": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"resource_name": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"resource_type": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"cve": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"repo_name": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"image_name": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"exclude_application_scopes": {
				Type:        schema.TypeList,
				Description: "List of excluded application scopes.",
				Optional:    true,
				Elem: &schema.Schema{
					Type:        schema.TypeString,
					Description: "Excluded application scope.",
				},
			}, // list of strings
			"permission": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"is_audit_checked": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"enforce_scheduler_added_on": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			}, // int
			"is_ootb_policy": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"is_auto_generated": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"updated": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Computed:    true,
			}, // string
			"lastupdate": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			}, // string
			"version": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"created": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"runtime_mode": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			}, // int
			"runtime_type": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
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
	//JSON test
	d.Set("failed_kubernetes_checks", flattenFailedKubernetesChecks(crp.FailedKubernetesChecks))
	d.Set("enable_port_scan_protection", crp.EnablePortScanProtection)
	d.Set("enable_crypto_mining_dns", crp.EnableCryptoMiningDns)
	d.Set("enable_ip_reputation", crp.EnableIPReputation)
	d.Set("fork_guard_process_limit", crp.ForkGuardProcessLimit)
	d.Set("enable_fork_guard", crp.EnableForkGuard)
	d.Set("default_security_profile", crp.DefaultSecurityProfile)
	d.Set("block_non_k8s_containers", crp.BlockNonK8sContainers)
	d.Set("block_fileless_exec", crp.BlockFilelessExec)
	d.Set("block_container_exec", crp.BlockContainerExec)
	d.Set("registry", crp.Registry)
	d.Set("reverse_shell", flattenReverseShell(crp.ReverseShell))
	d.Set("container_exec", flattenContainerExec(crp.ContainerExec))
	d.Set("system_integrity_protection", flattenSystemIntegrityProtection(crp.SystemIntegrityProtection))
	d.Set("readonly_registry", flattenReadonlyRegistry(crp.ReadonlyRegistry))
	d.Set("registry_access_monitoring", flattenRegistryAccessMonitoring(crp.RegistryAccessMonitoring))
	d.Set("readonly_files", flattenReadonlyFiles(crp.ReadonlyFiles))
	d.Set("tripwire", flattenTripwire(crp.Tripwire))
	d.Set("port_block", flattenPortBlock(crp.PortBlock))
	d.Set("linux_capabilities", flattenLinuxCapabilities(crp.LinuxCapabilities))
	d.Set("package_block", flattenPackageBlock(crp.PackageBlock))
	d.Set("file_block", flattenFileBlock(crp.FileBlock))
	d.Set("whitelisted_os_users", flattenWhitelistedOSUsers(crp.WhitelistedOsUsers))
	d.Set("blacklisted_os_users", flattenBlacklistedOSUsers(crp.BlacklistedOsUsers))
	d.Set("auditing", flattenAuditing(crp.Auditing))
	d.Set("block_non_compliant_workloads", crp.BlockNonCompliantWorkloads)
	d.Set("block_disallowed_images", crp.BlockDisallowedImages)
	d.Set("only_registered_images", crp.OnlyRegisteredImages)
	d.Set("limit_container_privileges", flattenLimitContainerPrivileges(crp.LimitContainerPrivileges))
	d.Set("no_new_privileges", crp.NoNewPrivileges)
	d.Set("restricted_volumes", flattenRestrictedVolumes(crp.RestrictedVolumes))
	d.Set("drift_prevention", flattenDriftPrevention(crp.DriftPrevention))
	d.Set("executable_blacklist", flattenExecutableBlacklist(crp.ExecutableBlacklist))
	d.Set("allowed_registries", flattenAllowedRegistries(crp.AllowedRegistries))
	d.Set("allowed_executables", flattenAllowedExecutables(crp.AllowedExecutables))
	d.Set("type", crp.Type)
	d.Set("digest", crp.Digest)
	d.Set("vpatch_version", crp.VpatchVersion)
	d.Set("resource_name", crp.ResourceName)
	d.Set("resource_type", crp.ResourceType)
	d.Set("cve", crp.Cve)
	d.Set("repo_name", crp.RepoName)
	d.Set("image_name", crp.ImageName)
	d.Set("exclude_application_scopes", crp.ExcludeApplicationScopes)
	d.Set("permission", crp.Permission)
	d.Set("is_audit_checked", crp.IsAuditChecked)
	d.Set("enforce_scheduler_added_on", crp.EnforceSchedulerAddedOn)
	d.Set("is_ootb_policy", crp.IsOOTBPolicy)
	d.Set("is_auto_generated", crp.IsAutoGenerated)
	//d.Set("updated", (crp.Updated) // todo
	d.Set("lastupdate", crp.Lastupdate)
	d.Set("version", crp.Version)
	d.Set("created", crp.Created)
	d.Set("runtime_mode", crp.RuntimeMode)
	d.Set("runtime_type", crp.RuntimeType)
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
		"windows_registry_protection",
		//JSON test bools
		"enable_port_scan_protection",
		"enable_crypto_mining_dns",
		"enable_ip_reputation",
		"enable_fork_guard",
		"block_non_k8s_containers",
		"block_fileless_exec",
		"block_container_exec",
		"block_non_compliant_workloads",
		"block_disallowed_images",
		"only_registered_images",
		"no_new_privileges",
		"is_audit_checked",
		"is_ootb_policy",
		"is_auto_generated",
	) {
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
			MonitoredFiles:                     convertStringArrNull(v["monitored_files"].([]interface{})),
			ExceptionalMonitoredFiles:          convertStringArrNull(v["exceptional_monitored_files"].([]interface{})),
			MonitoredFilesProcesses:            convertStringArrNull(v["monitored_files_processes"].([]interface{})),
			ExceptionalMonitoredFilesProcesses: convertStringArrNull(v["exceptional_monitored_files_processes"].([]interface{})),
			MonitoredFilesUsers:                convertStringArrNull(v["monitored_files_users"].([]interface{})),
			ExceptionalMonitoredFilesUsers:     convertStringArrNull(v["exceptional_monitored_files_users"].([]interface{})),
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
			ExcludeDirectories: convertStringArrNull(v["exclude_directories"].([]interface{})),
			ExcludeProcesses:   convertStringArrNull(v["exclude_processes"].([]interface{})),
			IncludeDirectories: convertStringArrNull(v["include_directories"].([]interface{})),
		}
	}

	//JSON test bool
	enablePortScanProtection, ok := d.GetOk("enable_port_scan_protection")
	if ok {
		crp.EnablePortScanProtection = enablePortScanProtection.(bool)
	}

	enableCryptoMiningDNS, ok := d.GetOk("enable_crypto_mining_dns")
	if ok {
		crp.EnableCryptoMiningDns = enableCryptoMiningDNS.(bool)
	}

	enableIPReputation, ok := d.GetOk("enable_ip_reputation")
	if ok {
		crp.EnableIPReputation = enableIPReputation.(bool)
	}

	enableForkGuard, ok := d.GetOk("enable_fork_guard")
	if ok {
		crp.EnableForkGuard = enableForkGuard.(bool)
	}

	blockNonK8sContainers, ok := d.GetOk("block_non_k8s_containers")
	if ok {
		crp.BlockNonK8sContainers = blockNonK8sContainers.(bool)
	}

	blockFilelessExec, ok := d.GetOk("block_fileless_exec")
	if ok {
		crp.BlockFilelessExec = blockFilelessExec.(bool)
	}

	blockContainerExec, ok := d.GetOk("block_container_exec")
	if ok {
		crp.BlockContainerExec = blockContainerExec.(bool)
	}

	blockNonCompliantWorkloads, ok := d.GetOk("block_non_compliant_workloads")
	if ok {
		crp.BlockNonCompliantWorkloads = blockNonCompliantWorkloads.(bool)
	}

	blockDisallowedImages, ok := d.GetOk("block_disallowed_images")
	if ok {
		crp.BlockDisallowedImages = blockDisallowedImages.(bool)
	}

	onlyRegisteredImages, ok := d.GetOk("only_registered_images")
	if ok {
		crp.OnlyRegisteredImages = onlyRegisteredImages.(bool)
	}

	noNewPrivileges, ok := d.GetOk("no_new_privileges")
	if ok {
		crp.NoNewPrivileges = noNewPrivileges.(bool)
	}

	isAuditChecked, ok := d.GetOk("is_audit_checked")
	if ok {
		crp.IsAuditChecked = isAuditChecked.(bool)
	}

	isOOTBPolicy, ok := d.GetOk("is_ootb_policy")
	if ok {
		crp.IsOOTBPolicy = isOOTBPolicy.(bool)
	}

	isAutoGenerated, ok := d.GetOk("is_auto_generated")
	if ok {
		crp.IsAutoGenerated = isAutoGenerated.(bool)
	}

	//JSON test string int

	forkGuardProcessLimit, ok := d.GetOk("fork_guard_process_limit")
	if ok {
		crp.ForkGuardProcessLimit = forkGuardProcessLimit.(int)
	}

	defaultSecurityProfile, ok := d.GetOk("default_security_profile")
	if ok {
		crp.DefaultSecurityProfile = defaultSecurityProfile.(string)
	}

	registry, ok := d.GetOk("registry")
	if ok {
		crp.Registry = registry.(string)
	}

	Type, ok := d.GetOk("type")
	if ok {
		crp.Type = Type.(string)
	}

	digest, ok := d.GetOk("digest")
	if ok {
		crp.Digest = digest.(string)
	}

	vpatchVersion, ok := d.GetOk("vpatch_version")
	if ok {
		crp.VpatchVersion = vpatchVersion.(string)
	}

	resourceName, ok := d.GetOk("resource_name")
	if ok {
		crp.ResourceName = resourceName.(string)
	}

	resourceType, ok := d.GetOk("resource_type")
	if ok {
		crp.ResourceType = resourceType.(string)
	}

	cve, ok := d.GetOk("cve")
	if ok {
		crp.Cve = cve.(string)
	}

	repoName, ok := d.GetOk("repo_name")
	if ok {
		crp.RepoName = repoName.(string)
	}

	imageName, ok := d.GetOk("image_name")
	if ok {
		crp.ImageName = imageName.(string)
	}

	permission, ok := d.GetOk("permission")
	if ok {
		crp.Permission = permission.(string)
	}

	enforceSchedulerAddedOn, ok := d.GetOk("enforce_scheduler_added_on")
	if ok {
		crp.EnforceSchedulerAddedOn = enforceSchedulerAddedOn.(int)
	}

	//updated, ok := d.GetOk("updated")
	//if ok {
	//	crp.Updated = updated.(time.Time)
	//}

	lastupdate, ok := d.GetOk("lastupdate")
	if ok {
		crp.Lastupdate = lastupdate.(int)
	}

	version, ok := d.GetOk("version")
	if ok {
		crp.Version = version.(string)
	}

	//created, ok := d.GetOk("created")
	//if ok {
	//	crp.Created = created.(string)
	//}

	runtimeMode, ok := d.GetOk("runtime_mode")
	if ok {
		crp.RuntimeMode = runtimeMode.(int)
	}

	runtimeType, ok := d.GetOk("runtime_type")
	if ok {
		crp.RuntimeType = runtimeType.(string)
	}

	//JSON list

	excludeApplicationScopes, ok := d.GetOk("exclude_application_scopes")
	if ok {
		var scopes []string
		for _, scope := range excludeApplicationScopes.([]interface{}) {
			scopes = append(scopes, scope.(string))
		}
		crp.ExcludeApplicationScopes = scopes
	} else {
		// If "exclude_application_scopes" is not provided, set it to an empty array
		crp.ExcludeApplicationScopes = []string{}
	}

	crp.FailedKubernetesChecks = client.FailedKubernetesChecks{}
	failedKubernetesChecksMap, ok := d.GetOk("failed_kubernetes_checks")
	if ok {
		v := failedKubernetesChecksMap.([]interface{})[0].(map[string]interface{})

		crp.FailedKubernetesChecks = client.FailedKubernetesChecks{
			Enabled:      v["enabled"].(bool),
			FailedChecks: convertStringArr(v["failed_checks"].([]interface{})),
		}
	}

	crp.ReverseShell = client.ReverseShell{}
	reverseShellMap, ok := d.GetOk("reverse_shell")
	if ok {
		v := reverseShellMap.([]interface{})[0].(map[string]interface{})

		crp.ReverseShell = client.ReverseShell{
			Enabled:                   v["enabled"].(bool),
			BlockReverseShell:         v["block_reverse_shell"].(bool),
			ReverseShellProcWhiteList: convertStringArrNull(v["reverse_shell_proc_white_list"].([]interface{})),
			ReverseShellIpWhiteList:   convertStringArrNull(v["reverse_shell_ip_white_list"].([]interface{})),
		}
	}

	crp.ContainerExec = client.ContainerExec{}
	containerExecMap, ok := d.GetOk("container_exec")
	if ok {
		v := containerExecMap.([]interface{})[0].(map[string]interface{})

		crp.ContainerExec = client.ContainerExec{
			Enabled:            v["enabled"].(bool),
			BlockContainerExec: v["block_container_exec"].(bool),
		}

		// Check if "container_exec_proc_white_list" is provided and not an empty array
		if whiteList, whiteListOk := v["container_exec_proc_white_list"]; whiteListOk && len(whiteList.([]interface{})) > 0 {
			crp.ContainerExec.ContainerExecProcWhiteList = convertStringArr(whiteList.([]interface{}))
		} else {
			crp.ContainerExec.ContainerExecProcWhiteList = nil
		}
	}

	crp.SystemIntegrityProtection = client.SystemIntegrityProtection{}
	systemIntegrityProtectionMap, ok := d.GetOk("system_integrity_protection")
	if ok {
		v := systemIntegrityProtectionMap.([]interface{})[0].(map[string]interface{})

		crp.SystemIntegrityProtection = client.SystemIntegrityProtection{
			Enabled:                   v["enabled"].(bool),
			AuditSystemtimeChange:     v["audit_systemtime_change"].(bool),
			WindowsServicesMonitoring: v["windows_services_monitoring"].(bool),
			MonitorAuditLogIntegrity:  v["monitor_audit_log_integrity"].(bool),
		}
	}

	crp.ReadonlyRegistry = client.ReadonlyRegistry{}
	readonlyRegistryMap, ok := d.GetOk("readonly_registry")
	if ok {
		v := readonlyRegistryMap.([]interface{})[0].(map[string]interface{})

		crp.ReadonlyRegistry = client.ReadonlyRegistry{
			Enabled:                              v["enabled"].(bool),
			ReadonlyRegistryPaths:                convertStringArr(v["readonly_registry_paths"].([]interface{})),
			ExceptionalReadonlyRegistryPaths:     convertStringArr(v["exceptional_readonly_registry_paths"].([]interface{})),
			ReadonlyRegistryUsers:                convertStringArr(v["readonly_registry_users"].([]interface{})),
			ExceptionalReadonlyRegistryUsers:     convertStringArr(v["exceptional_readonly_registry_users"].([]interface{})),
			ReadonlyRegistryProcesses:            convertStringArr(v["readonly_registry_processes"].([]interface{})),
			ExceptionalReadonlyRegistryProcesses: convertStringArr(v["exceptional_readonly_registry_processes"].([]interface{})),
		}
	}

	crp.RegistryAccessMonitoring = client.RegistryAccessMonitoring{}
	registryAccessMonitoringMap, ok := d.GetOk("registry_access_monitoring")
	if ok {
		v := registryAccessMonitoringMap.([]interface{})[0].(map[string]interface{})

		crp.RegistryAccessMonitoring = client.RegistryAccessMonitoring{
			Enabled:                               v["enabled"].(bool),
			MonitoredRegistryPaths:                convertStringArr(v["monitored_registry_paths"].([]interface{})),
			ExceptionalMonitoredRegistryPaths:     convertStringArr(v["exceptional_monitored_registry_paths"].([]interface{})),
			MonitoredRegistryUsers:                convertStringArr(v["monitored_registry_users"].([]interface{})),
			ExceptionalMonitoredRegistryUsers:     convertStringArr(v["exceptional_monitored_registry_users"].([]interface{})),
			MonitoredRegistryProcesses:            convertStringArr(v["monitored_registry_processes"].([]interface{})),
			ExceptionalMonitoredRegistryProcesses: convertStringArr(v["exceptional_monitored_registry_processes"].([]interface{})),
			MonitoredRegistryCreate:               v["monitored_registry_create"].(bool),
			MonitoredRegistryRead:                 v["monitored_registry_read"].(bool),
			MonitoredRegistryModify:               v["monitored_registry_modify"].(bool),
			MonitoredRegistryDelete:               v["monitored_registry_delete"].(bool),
			MonitoredRegistryAttributes:           v["monitored_registry_attributes"].(bool),
		}
	}

	crp.ReadonlyFiles = client.ReadonlyFiles{}
	readonlyFilesMap, ok := d.GetOk("readonly_files")
	if ok {
		v := readonlyFilesMap.([]interface{})[0].(map[string]interface{})

		crp.ReadonlyFiles = client.ReadonlyFiles{
			Enabled:                           v["enabled"].(bool),
			ReadonlyFiles:                     convertStringArr(v["readonly_files"].([]interface{})),
			ExceptionalReadonlyFiles:          convertStringArr(v["exceptional_readonly_files"].([]interface{})),
			ReadonlyFilesProcesses:            convertStringArr(v["readonly_files_processes"].([]interface{})),
			ExceptionalReadonlyFilesProcesses: convertStringArr(v["exceptional_readonly_files_processes"].([]interface{})),
			ReadonlyFilesUsers:                convertStringArr(v["readonly_files_users"].([]interface{})),
			ExceptionalReadonlyFilesUsers:     convertStringArr(v["exceptional_readonly_files_users"].([]interface{})),
		}
	}

	crp.Tripwire = client.Tripwire{}
	tripwireMap, ok := d.GetOk("tripwire")
	if ok {
		v := tripwireMap.([]interface{})[0].(map[string]interface{})

		crp.Tripwire = client.Tripwire{
			Enabled:       v["enabled"].(bool),
			UserID:        v["user_id"].(string),
			UserPassword:  v["user_password"].(string),
			ApplyOn:       convertStringArrNull(v["apply_on"].([]interface{})),
			ServerlessApp: v["serverless_app"].(string),
		}
	}

	crp.PortBlock = client.PortBlock{}
	portBlockMap, ok := d.GetOk("port_block")
	if ok {
		v := portBlockMap.([]interface{})[0].(map[string]interface{})

		crp.PortBlock = client.PortBlock{
			Enabled:            v["enabled"].(bool),
			BlockInboundPorts:  convertStringArr(v["block_inbound_ports"].([]interface{})),
			BlockOutboundPorts: convertStringArr(v["block_outbound_ports"].([]interface{})),
		}
	}

	crp.LinuxCapabilities = client.LinuxCapabilities{}
	linuxCapabilitiesMap, ok := d.GetOk("linux_capabilities")
	if ok {
		v := linuxCapabilitiesMap.([]interface{})[0].(map[string]interface{})

		crp.LinuxCapabilities = client.LinuxCapabilities{
			Enabled:                 v["enabled"].(bool),
			RemoveLinuxCapabilities: convertStringArr(v["remove_linux_capabilities"].([]interface{})),
		}
	}

	crp.PackageBlock = client.PackageBlock{}
	packageBlockMap, ok := d.GetOk("package_block")
	if ok {
		v := packageBlockMap.([]interface{})[0].(map[string]interface{})

		crp.PackageBlock = client.PackageBlock{
			Enabled:                           v["enabled"].(bool),
			PackagesBlackList:                 convertStringArr(v["packages_black_list"].([]interface{})),
			ExceptionalBlockPackagesFiles:     convertStringArr(v["exceptional_block_packages_files"].([]interface{})),
			BlockPackagesUsers:                convertStringArr(v["block_packages_users"].([]interface{})),
			BlockPackagesProcesses:            convertStringArr(v["block_packages_processes"].([]interface{})),
			ExceptionalBlockPackagesUsers:     convertStringArr(v["exceptional_block_packages_users"].([]interface{})),
			ExceptionalBlockPackagesProcesses: convertStringArr(v["exceptional_block_packages_processes"].([]interface{})),
		}
	}

	crp.FileBlock = client.FileBlock{}
	fileBlockMap, ok := d.GetOk("file_block")
	if ok {
		v := fileBlockMap.([]interface{})[0].(map[string]interface{})

		crp.FileBlock = client.FileBlock{
			Enabled:                        v["enabled"].(bool),
			FilenameBlockList:              convertStringArr(v["filename_block_list"].([]interface{})),
			ExceptionalBlockFiles:          convertStringArr(v["exceptional_block_files"].([]interface{})),
			BlockFilesUsers:                convertStringArr(v["block_files_users"].([]interface{})),
			BlockFilesProcesses:            convertStringArr(v["block_files_processes"].([]interface{})),
			ExceptionalBlockFilesUsers:     convertStringArr(v["exceptional_block_files_users"].([]interface{})),
			ExceptionalBlockFilesProcesses: convertStringArr(v["exceptional_block_files_processes"].([]interface{})),
		}
	}

	crp.WhitelistedOsUsers = client.WhitelistedOsUsers{}
	whitelistedOSUsersMap, ok := d.GetOk("whitelisted_os_users")
	if ok {
		v := whitelistedOSUsersMap.([]interface{})[0].(map[string]interface{})

		crp.WhitelistedOsUsers = client.WhitelistedOsUsers{
			Enabled:        v["enabled"].(bool),
			UserWhiteList:  convertStringArr(v["user_white_list"].([]interface{})),
			GroupWhiteList: convertStringArr(v["group_white_list"].([]interface{})),
		}
	}

	crp.BlacklistedOsUsers = client.BlacklistedOsUsers{}
	blacklistedOSUsersMap, ok := d.GetOk("blacklisted_os_users")
	if ok {
		v := blacklistedOSUsersMap.([]interface{})[0].(map[string]interface{})

		crp.BlacklistedOsUsers = client.BlacklistedOsUsers{
			Enabled:        v["enabled"].(bool),
			GroupBlackList: convertStringArr(v["group_black_list"].([]interface{})),
			UserBlackList:  convertStringArr(v["user_black_list"].([]interface{})),
		}
	}

	crp.Auditing = client.Auditing{}
	auditingMap, ok := d.GetOk("auditing")
	if ok {
		v := auditingMap.([]interface{})[0].(map[string]interface{})

		crp.Auditing = client.Auditing{
			Enabled:                    v["enabled"].(bool),
			AuditAllProcesses:          v["audit_all_processes"].(bool),
			AuditProcessCmdline:        v["audit_process_cmdline"].(bool),
			AuditAllNetwork:            v["audit_all_network"].(bool),
			AuditOsUserActivity:        v["audit_os_user_activity"].(bool),
			AuditSuccessLogin:          v["audit_success_login"].(bool),
			AuditFailedLogin:           v["audit_failed_login"].(bool),
			AuditUserAccountManagement: v["audit_user_account_management"].(bool),
		}
	}

	crp.LimitContainerPrivileges = client.LimitContainerPrivileges{}
	limitContainerPrivilegesMap, ok := d.GetOk("limit_container_privileges")
	if ok {
		v := limitContainerPrivilegesMap.([]interface{})[0].(map[string]interface{})

		crp.LimitContainerPrivileges = client.LimitContainerPrivileges{
			Enabled:               v["enabled"].(bool),
			Privileged:            v["privileged"].(bool),
			Netmode:               v["netmode"].(bool),
			Pidmode:               v["pidmode"].(bool),
			Utsmode:               v["utsmode"].(bool),
			Usermode:              v["usermode"].(bool),
			Ipcmode:               v["ipcmode"].(bool),
			PreventRootUser:       v["prevent_root_user"].(bool),
			PreventLowPortBinding: v["prevent_low_port_binding"].(bool),
			BlockAddCapabilities:  v["block_add_capabilities"].(bool),
			UseHostUser:           v["use_host_user"].(bool),
		}
	}

	crp.RestrictedVolumes = client.RestrictedVolumes{}
	restrictedVolumesMap, ok := d.GetOk("restricted_volumes")
	if ok {
		v := restrictedVolumesMap.([]interface{})[0].(map[string]interface{})

		crp.RestrictedVolumes = client.RestrictedVolumes{
			Enabled: v["enabled"].(bool),
			Volumes: convertStringArr(v["volumes"].([]interface{})),
		}
	}

	crp.ExecutableBlacklist = client.ExecutableBlacklist{}
	executableBlacklistMap, ok := d.GetOk("executable_blacklist")
	if ok {
		v := executableBlacklistMap.([]interface{})[0].(map[string]interface{})

		crp.ExecutableBlacklist = client.ExecutableBlacklist{
			Enabled:     v["enabled"].(bool),
			Executables: convertStringArrNull(v["executables"].([]interface{})),
		}
	}

	crp.DriftPrevention = client.DriftPrevention{}
	driftPreventionMap, ok := d.GetOk("drift_prevention")
	if ok {
		v := driftPreventionMap.([]interface{})[0].(map[string]interface{})

		crp.DriftPrevention = client.DriftPrevention{
			Enabled:               v["enabled"].(bool),
			ExecLockdown:          v["exec_lockdown"].(bool),
			ImageLockdown:         v["image_lockdown"].(bool),
			ExecLockdownWhiteList: convertStringArrNull(v["exec_lockdown_white_list"].([]interface{})),
		}
	}

	crp.AllowedRegistries = client.AllowedRegistries{}
	allowedRegistriesMap, ok := d.GetOk("allowed_registries")
	if ok {
		v := allowedRegistriesMap.([]interface{})[0].(map[string]interface{})

		crp.AllowedRegistries = client.AllowedRegistries{
			Enabled:           v["enabled"].(bool),
			AllowedRegistries: convertStringArr(v["allowed_registries"].([]interface{})),
		}
	}

	crp.AllowedExecutables = client.AllowedExecutables{}
	allowedExecutablesMap, ok := d.GetOk("allowed_executables")
	if ok {
		v := allowedExecutablesMap.([]interface{})[0].(map[string]interface{})

		crp.AllowedExecutables = client.AllowedExecutables{
			Enabled:              v["enabled"].(bool),
			AllowExecutables:     convertStringArrNull(v["allow_executables"].([]interface{})),
			SeparateExecutables:  v["separate_executables"].(bool),
			AllowRootExecutables: convertStringArrNull(v["allow_root_executables"].([]interface{})),
		}
	}

	crp.Scope = client.Scope{}
	scopeMap, ok := d.GetOk("scope")
	if ok {
		v := scopeMap.([]interface{})[0].(map[string]interface{})

		crp.Scope = client.Scope{
			Expression: v["expression"].(string),
			Variables:  flattenVariables(v["variables"].([]interface{})),
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
			"enabled":                               monitoring.Enabled,
			"monitored_files_create":                monitoring.MonitoredFilesCreate,
			"monitored_files_read":                  monitoring.MonitoredFilesRead,
			"monitored_files_modify":                monitoring.MonitoredFilesModify,
			"monitored_files_delete":                monitoring.MonitoredFilesDelete,
			"monitored_files_attributes":            monitoring.MonitoredFilesAttributes,
			"monitored_files":                       monitoring.MonitoredFiles,
			"exceptional_monitored_files":           monitoring.ExceptionalMonitoredFiles,
			"monitored_files_processes":             monitoring.MonitoredFilesProcesses,
			"exceptional_monitored_files_processes": monitoring.ExceptionalMonitoredFilesProcesses,
			"monitored_files_users":                 monitoring.MonitoredFilesUsers,
			"exceptional_monitored_files_users":     monitoring.ExceptionalMonitoredFilesUsers,
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
			"include_directories": monitoring.IncludeDirectories,
		},
	}
}

// JSON test

func flattenFailedKubernetesChecks(checks client.FailedKubernetesChecks) []map[string]interface{} {
	if !checks.Enabled || len(checks.FailedChecks) == 0 {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":       checks.Enabled,
			"failed_checks": checks.FailedChecks,
		},
	}
}

func flattenReverseShell(shell client.ReverseShell) []map[string]interface{} {
	if !shell.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                       shell.Enabled,
			"block_reverse_shell":           shell.BlockReverseShell,
			"reverse_shell_proc_white_list": shell.ReverseShellProcWhiteList,
			"reverse_shell_ip_white_list":   shell.ReverseShellIpWhiteList,
		},
	}
}

func flattenContainerExec(exec client.ContainerExec) []map[string]interface{} {
	if !exec.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                        exec.Enabled,
			"block_container_exec":           exec.BlockContainerExec,
			"container_exec_proc_white_list": exec.ContainerExecProcWhiteList,
		},
	}
}

func flattenSystemIntegrityProtection(protection client.SystemIntegrityProtection) []map[string]interface{} {
	if !protection.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                     protection.Enabled,
			"audit_systemtime_change":     protection.AuditSystemtimeChange,
			"windows_services_monitoring": protection.WindowsServicesMonitoring,
			"monitor_audit_log_integrity": protection.MonitorAuditLogIntegrity,
		},
	}
}

func flattenReadonlyRegistry(registry client.ReadonlyRegistry) []map[string]interface{} {
	if !registry.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                                 registry.Enabled,
			"readonly_registry_paths":                 registry.ReadonlyRegistryPaths,
			"exceptional_readonly_registry_paths":     registry.ExceptionalReadonlyRegistryPaths,
			"readonly_registry_users":                 registry.ReadonlyRegistryUsers,
			"exceptional_readonly_registry_users":     registry.ExceptionalReadonlyRegistryUsers,
			"readonly_registry_processes":             registry.ReadonlyRegistryProcesses,
			"exceptional_readonly_registry_processes": registry.ExceptionalReadonlyRegistryProcesses,
		},
	}
}

func flattenRegistryAccessMonitoring(monitoring client.RegistryAccessMonitoring) []map[string]interface{} {
	if !monitoring.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                                  monitoring.Enabled,
			"monitored_registry_paths":                 monitoring.MonitoredRegistryPaths,
			"exceptional_monitored_registry_paths":     monitoring.ExceptionalMonitoredRegistryPaths,
			"monitored_registry_users":                 monitoring.MonitoredRegistryUsers,
			"exceptional_monitored_registry_users":     monitoring.ExceptionalMonitoredRegistryUsers,
			"monitored_registry_processes":             monitoring.MonitoredRegistryProcesses,
			"exceptional_monitored_registry_processes": monitoring.ExceptionalMonitoredRegistryProcesses,
			"monitored_registry_create":                monitoring.MonitoredRegistryCreate,
			"monitored_registry_read":                  monitoring.MonitoredRegistryRead,
			"monitored_registry_modify":                monitoring.MonitoredRegistryModify,
			"monitored_registry_delete":                monitoring.MonitoredRegistryDelete,
			"monitored_registry_attributes":            monitoring.MonitoredRegistryAttributes,
		},
	}
}

func flattenReadonlyFiles(files client.ReadonlyFiles) []map[string]interface{} {
	if !files.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                              files.Enabled,
			"readonly_files":                       files.ReadonlyFiles,
			"exceptional_readonly_files":           files.ExceptionalReadonlyFiles,
			"readonly_files_processes":             files.ReadonlyFilesProcesses,
			"exceptional_readonly_files_processes": files.ExceptionalReadonlyFilesProcesses,
			"readonly_files_users":                 files.ReadonlyFilesUsers,
			"exceptional_readonly_files_users":     files.ExceptionalReadonlyFilesUsers,
		},
	}
}

func flattenTripwire(tripwire client.Tripwire) []map[string]interface{} {
	if !tripwire.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":        tripwire.Enabled,
			"user_id":        tripwire.UserID,
			"user_password":  tripwire.UserPassword,
			"apply_on":       tripwire.ApplyOn,
			"serverless_app": tripwire.ServerlessApp,
		},
	}
}

func flattenPortBlock(portBlock client.PortBlock) []map[string]interface{} {
	if !portBlock.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":              portBlock.Enabled,
			"block_inbound_ports":  portBlock.BlockInboundPorts,
			"block_outbound_ports": portBlock.BlockOutboundPorts,
		},
	}
}

func flattenLinuxCapabilities(linuxCapabilities client.LinuxCapabilities) []map[string]interface{} {
	if !linuxCapabilities.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                   linuxCapabilities.Enabled,
			"remove_linux_capabilities": linuxCapabilities.RemoveLinuxCapabilities,
		},
	}
}

func flattenPackageBlock(packageBlock client.PackageBlock) []map[string]interface{} {
	if !packageBlock.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                              packageBlock.Enabled,
			"packages_black_list":                  packageBlock.PackagesBlackList,
			"exceptional_block_packages_files":     packageBlock.ExceptionalBlockPackagesFiles,
			"block_packages_users":                 packageBlock.BlockPackagesUsers,
			"block_packages_processes":             packageBlock.BlockPackagesProcesses,
			"exceptional_block_packages_users":     packageBlock.ExceptionalBlockPackagesUsers,
			"exceptional_block_packages_processes": packageBlock.ExceptionalBlockPackagesProcesses,
		},
	}
}

func flattenFileBlock(fileBlock client.FileBlock) []map[string]interface{} {
	if !fileBlock.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                           fileBlock.Enabled,
			"filename_block_list":               fileBlock.FilenameBlockList,
			"exceptional_block_files":           fileBlock.ExceptionalBlockFiles,
			"block_files_users":                 fileBlock.BlockFilesUsers,
			"block_files_processes":             fileBlock.BlockFilesProcesses,
			"exceptional_block_files_users":     fileBlock.ExceptionalBlockFilesUsers,
			"exceptional_block_files_processes": fileBlock.ExceptionalBlockFilesProcesses,
		},
	}
}

func flattenWhitelistedOSUsers(whitelistedOsUsers client.WhitelistedOsUsers) []map[string]interface{} {
	if !whitelistedOsUsers.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":          whitelistedOsUsers.Enabled,
			"user_white_list":  whitelistedOsUsers.UserWhiteList,
			"group_white_list": whitelistedOsUsers.GroupWhiteList,
		},
	}
}

func flattenBlacklistedOSUsers(blacklistedOsUsers client.BlacklistedOsUsers) []map[string]interface{} {
	if !blacklistedOsUsers.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":          blacklistedOsUsers.Enabled,
			"group_black_list": blacklistedOsUsers.GroupBlackList,
			"user_black_list":  blacklistedOsUsers.UserBlackList,
		},
	}
}

func flattenAuditing(auditing client.Auditing) []map[string]interface{} {
	if !auditing.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                       auditing.Enabled,
			"audit_all_processes":           auditing.AuditAllProcesses,
			"audit_process_cmdline":         auditing.AuditProcessCmdline,
			"audit_all_network":             auditing.AuditAllNetwork,
			"audit_os_user_activity":        auditing.AuditOsUserActivity,
			"audit_success_login":           auditing.AuditSuccessLogin,
			"audit_failed_login":            auditing.AuditFailedLogin,
			"audit_user_account_management": auditing.AuditUserAccountManagement,
		},
	}
}

func flattenLimitContainerPrivileges(limitContainerPrivileges client.LimitContainerPrivileges) []map[string]interface{} {
	if !limitContainerPrivileges.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                  limitContainerPrivileges.Enabled,
			"privileged":               limitContainerPrivileges.Privileged,
			"netmode":                  limitContainerPrivileges.Netmode,
			"pidmode":                  limitContainerPrivileges.Pidmode,
			"utsmode":                  limitContainerPrivileges.Utsmode,
			"usermode":                 limitContainerPrivileges.Usermode,
			"ipcmode":                  limitContainerPrivileges.Ipcmode,
			"prevent_root_user":        limitContainerPrivileges.PreventRootUser,
			"prevent_low_port_binding": limitContainerPrivileges.PreventLowPortBinding,
			"block_add_capabilities":   limitContainerPrivileges.BlockAddCapabilities,
			"use_host_user":            limitContainerPrivileges.UseHostUser,
		},
	}
}

func flattenRestrictedVolumes(restrictedVolumes client.RestrictedVolumes) []map[string]interface{} {
	if !restrictedVolumes.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled": restrictedVolumes.Enabled,
			"volumes": restrictedVolumes.Volumes,
		},
	}
}

func flattenDriftPrevention(driftPrevention client.DriftPrevention) []map[string]interface{} {
	if !driftPrevention.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                  driftPrevention.Enabled,
			"exec_lockdown":            driftPrevention.ExecLockdown,
			"image_lockdown":           driftPrevention.ImageLockdown,
			"exec_lockdown_white_list": driftPrevention.ExecLockdownWhiteList,
		},
	}
}

func flattenExecutableBlacklist(executableBlacklist client.ExecutableBlacklist) []map[string]interface{} {
	if !executableBlacklist.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":     executableBlacklist.Enabled,
			"executables": executableBlacklist.Executables,
		},
	}
}

func flattenAllowedRegistries(allowedRegistries client.AllowedRegistries) []map[string]interface{} {
	if !allowedRegistries.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":            allowedRegistries.Enabled,
			"allowed_registries": allowedRegistries.AllowedRegistries,
		},
	}
}

func flattenAllowedExecutables(allowedExecutables client.AllowedExecutables) []map[string]interface{} {
	if !allowedExecutables.Enabled {
		return []map[string]interface{}{}
	}
	return []map[string]interface{}{
		{
			"enabled":                allowedExecutables.Enabled,
			"allow_executables":      allowedExecutables.AllowExecutables,
			"separate_executables":   allowedExecutables.SeparateExecutables,
			"allow_root_executables": allowedExecutables.AllowRootExecutables,
		},
	}
}

func flattenVariables(variables []interface{}) []client.Variable {
	var result []client.Variable
	for _, v := range variables {
		val := v.(map[string]interface{})
		result = append(result, client.Variable{
			Attribute: val["attribute"].(string),
			Value:     val["value"].(string),
		})
	}
	return result
}
