package aquasec

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceFunctionRuntimePolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceFunctionRuntimePolicyCreate,
		ReadContext:   resourceFunctionRuntimePolicyRead,
		UpdateContext: resourceFunctionRuntimePolicyUpdate,
		DeleteContext: resourceFunctionRuntimePolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the function runtime policy",
				Required:    true,
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The description of the function runtime policy",
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
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the service.",
				Computed:    true,
				Optional:    true,
			},
			"block_malicious_executables": {
				Type:        schema.TypeBool,
				Description: "If true, prevent creation of malicious executables in functions during their runtime post invocation.",
				Default:     false,
				Optional:    true,
			},
			"block_running_executables_in_tmp_folder": {
				Type:         schema.TypeBool,
				Description:  "If true, prevent running of executables in functions locate in /tmp folder during their runtime post invocation.",
				RequiredWith: []string{"block_malicious_executables"},
				Default:      false,
				Optional:     true,
			},
			"block_malicious_executables_allowed_processes": {
				Type:         schema.TypeList,
				Description:  "List of processes that will be allowed",
				RequiredWith: []string{"block_malicious_executables"},
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
			"honeypot_access_key": {
				Type:        schema.TypeString,
				Description: "Honeypot User ID (Access Key)",
				Optional:    true,
			},
			"honeypot_secret_key": {
				Type:        schema.TypeString,
				Description: "Honeypot User Password (Secret Key)",
				Optional:    true,
				Sensitive:   true,
			},
			"honeypot_apply_on": {
				Type:        schema.TypeList,
				Description: "List of options to apply the honeypot on (Environment Vairable, Layer, File)",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"honeypot_serverless_app_name": {
				Type:        schema.TypeString,
				Description: "Serverless application name",
				Optional:    true,
			},
			//JSON
			"runtime_type": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Default:     "function",
			}, // string
			"runtime_mode": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			}, // int
			"created": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Computed:    true,
			}, // string
			"version": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Default:     "1.0",
			}, // string
			"updated": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Computed:    true,
			}, // string
			"is_auto_generated": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"is_ootb_policy": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"enforce_scheduler_added_on": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			}, // int
			"is_audit_checked": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"image_name": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"repo_name": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"cve": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"resource_type": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"resource_name": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"vpatch_version": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"digest": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"type": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Default:     "runtime.policy",
			}, // string
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
			"only_registered_images": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"block_non_compliant_workloads": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
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
			"lastupdate": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
				Computed:    true,
			}, // string
			"enforce_after_days": {
				Type:        schema.TypeInt,
				Description: "Indicates the number of days after which the runtime policy will be changed to enforce mode.",
				Optional:    true,
			},
			"permission": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Default:     "Write",
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
			"block_disallowed_images": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
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
			"registry": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"block_container_exec": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"block_fileless_exec": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"block_non_k8s_containers": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"audit_brute_force_login": {
				Type:        schema.TypeBool,
				Description: "Detects brute force login attempts",
				Optional:    true,
			},
			"default_security_profile": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
			}, // string
			"enable_fork_guard": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"fork_guard_process_limit": {
				Type:        schema.TypeInt,
				Description: "",
				Optional:    true,
			}, // int
			"enable_ip_reputation": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"enable_crypto_mining_dns": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"enable_port_scan_protection": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
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

		},
	}
}

func resourceFunctionRuntimePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	crp := expandFunctionRuntimePolicy(d)
	err := c.CreateRuntimePolicy(crp)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)

	return resourceFunctionRuntimePolicyRead(ctx, d, m)

}

func resourceFunctionRuntimePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
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
	d.Set("author", crp.Author)
	d.Set("application_scopes", crp.ApplicationScopes)
	d.Set("scope_variables", flattenScopeVariables(crp.Scope.Variables))
	d.Set("scope_expression", crp.Scope.Expression)
	d.Set("enabled", crp.Enabled)
	d.Set("enforce", crp.Enforce)
	d.Set("block_malicious_executables", crp.DriftPrevention.Enabled)
	d.Set("block_running_executables_in_tmp_folder", crp.DriftPrevention.ExecLockdown)
	d.Set("block_malicious_executables_allowed_processes", crp.DriftPrevention.ExecLockdownWhiteList)
	d.Set("blocked_executables", crp.ExecutableBlacklist.Executables)
	d.Set("honeypot_access_key", crp.Tripwire.UserID)
	d.Set("honeypot_secret_key", crp.Tripwire.UserPassword)
	d.Set("honeypot_apply_on", crp.Tripwire.ApplyOn)
	d.Set("honeypot_serverless_app_name", crp.Tripwire.ServerlessApp)
	//JSON
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
	//d.Set("lastupdate", crp.Lastupdate)
	d.Set("version", crp.Version)
	d.Set("created", crp.Created)
	d.Set("runtime_mode", crp.RuntimeMode)
	d.Set("runtime_type", crp.RuntimeType)
	d.SetId(crp.Name)

	return nil
}

func resourceFunctionRuntimePolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)
	if d.HasChanges("description",
		"author",
		"application_scopes",
		"scope_variables",
		"scope_expression",
		"enabled",
		"enforce",
		"block_malicious_executables",
		"block_running_executables_in_tmp_folder",
		"block_malicious_executables_allowed_processes",
		"blocked_executables",
		"honeypot_access_key",
		"honeypot_secret_key",
		"honeypot_apply_on",
		"honeypot_serverless_app_name",
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
		// JSON
		"fork_guard_process_limit",
		"default_security_profile",
		"registry",
		"type",
		"digest",
		"vpatch_version",
		"resource_name",
		"resource_type",
		"cve",
		"repo_name",
		"image_name",
		"permission",
		"updated",
		"lastupdate",
		"version",
		"created",
		"runtime_type",
		"runtime_mode",
		"enforce_scheduler_added_on",
		"exclude_application_scopes",
		"allowed_executables",
		"allowed_registries",
		"executable_blacklist",
		"drift_prevention",
		"restricted_volumes",
		"limit_container_privileges",
		"auditing",
		"blacklisted_os_users",
		"whitelisted_os_users",
		"file_block",
		"package_block",
		"linux_capabilities",
		"port_block",
		"tripwire",
		"readonly_files",
		"registry_access_monitoring",
		"readonly_registry",
		"system_integrity_protection",
		"container_exec",
		"reverse_shell",
		"failed_kubernetes_checks",
	) {

		crp := expandFunctionRuntimePolicy(d)
		err := c.UpdateRuntimePolicy(crp)
		if err == nil {
			d.SetId(name)
		} else {
			return diag.FromErr(err)
		}
	}

	return nil
}

func resourceFunctionRuntimePolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
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

func expandFunctionRuntimePolicy(d *schema.ResourceData) *client.RuntimePolicy {
	crp := client.RuntimePolicy{
		Name:        d.Get("name").(string),
		RuntimeType: "function",
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

	author, ok := d.GetOk("author")
	if ok {
		crp.Author = author.(string)
	}

	blockMalicious, ok := d.GetOk("block_malicious_executables")
	if ok {
		crp.DriftPrevention.Enabled = blockMalicious.(bool)
		blockRunningExecutablesInTmpFolder, ok := d.GetOk("block_running_executables_in_tmp_folder")
		if ok {
			crp.DriftPrevention.ExecLockdown = blockRunningExecutablesInTmpFolder.(bool)
		}
		blockMaliciousExecutablesAllowedProcesses, ok := d.GetOk("block_malicious_executables_allowed_processes")
		if ok {
			crp.DriftPrevention.ExecLockdownWhiteList = convertStringArr(blockMaliciousExecutablesAllowedProcesses.([]interface{}))
		}
	}

	blockedExecutables, ok := d.GetOk("blocked_executables")
	if ok {
		strArr := convertStringArr(blockedExecutables.([]interface{}))
		crp.ExecutableBlacklist.Enabled = len(strArr) != 0
		crp.ExecutableBlacklist.Executables = strArr
	} else {
		crp.ExecutableBlacklist.Enabled = false
	}

	accessKey, ok := d.GetOk("honeypot_access_key")
	if ok {
		crp.Tripwire.Enabled = true
		crp.Tripwire.UserID = accessKey.(string)
	}

	secretKey, ok := d.GetOk("honeypot_secret_key")
	if ok {
		crp.Tripwire.Enabled = true
		crp.Tripwire.UserPassword = secretKey.(string)
	}

	applyOn, ok := d.GetOk("honeypot_apply_on")
	if ok {
		crp.Tripwire.Enabled = true
		crp.Tripwire.ApplyOn = convertStringArr(applyOn.([]interface{}))
	}

	appName, ok := d.GetOk("honeypot_serverless_app_name")
	if ok {
		crp.Tripwire.Enabled = true
		crp.Tripwire.ServerlessApp = appName.(string)
	}

	//JSON
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
		crp.Lastupdate = lastupdate.(int64)
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
