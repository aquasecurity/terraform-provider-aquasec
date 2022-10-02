package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataHostRuntimePolicy() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataHostRuntimePolicyRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the host runtime policy",
				Required:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The description of the host runtime policy",
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
						"name": {
							Type:        schema.TypeString,
							Description: "Name assigned to the attribute.",
							Optional:    true,
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
			// controls
			"block_cryptocurrency_mining": {
				Type:        schema.TypeBool,
				Description: "Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining",
				Computed:    true,
			},
			"audit_brute_force_login": {
				Type:        schema.TypeBool,
				Description: "Detects brute force login attempts",
				Computed:    true,
			},
			"enable_ip_reputation_security": {
				Type:        schema.TypeBool,
				Description: "If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.",
				Computed:    true,
			},
			"blocked_files": {
				Type:        schema.TypeList,
				Description: "List of files that are prevented from being read, modified and executed in the containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
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
			"audit_all_os_user_activity": {
				Type:        schema.TypeBool,
				Description: "If true, all process activity will be audited.",
				Computed:    true,
			},
			"audit_full_command_arguments": {
				Type:        schema.TypeBool,
				Description: "If true, full command arguments will be audited.",
				Computed:    true,
			},
			"audit_host_successful_login_events": {
				Type:        schema.TypeBool,
				Description: "If true, host successful logins will be audited.",
				Computed:    true,
			},
			"audit_host_failed_login_events": {
				Type:        schema.TypeBool,
				Description: "If true, host failed logins will be audited.",
				Computed:    true,
			},
			"audit_user_account_management": {
				Type:        schema.TypeBool,
				Description: "If true, account management will be audited.",
				Computed:    true,
			},
			"os_users_allowed": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) users that are allowed to authenticate to the host, and block authentication requests from all others.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"os_groups_allowed": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) groups that are allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"os_users_blocked": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) users that are not allowed to authenticate to the host, and block authentication requests from all others.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"os_groups_blocked": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) groups that are not allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"package_block": {
				Type:        schema.TypeList,
				Description: "List of packages that are not allowed read, write or execute all files that under the packages.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"port_scanning_detection": {
				Type:        schema.TypeBool,
				Description: "If true, port scanning behaviors will be audited.",
				Computed:    true,
			},
			"monitor_system_time_changes": {
				Type:        schema.TypeBool,
				Description: "If true, system time changes will be monitored.",
				Computed:    true,
			},
			"monitor_windows_services": {
				Type:        schema.TypeBool,
				Description: "If true, windows service operations will be monitored.",
				Computed:    true,
			},
			"monitor_system_log_integrity": {
				Type:        schema.TypeBool,
				Description: "If true, system log will be monitored.",
				Computed:    true,
			},
			"windows_registry_monitoring": {
				Type:        schema.TypeList,
				Description: "Configuration for windows registry monitoring.",
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
							Description: "List of registry processes to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"excluded_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"monitored_users": {
							Type:        schema.TypeList,
							Description: "List of registry users to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"excluded_users": {
							Type:        schema.TypeList,
							Description: "List of registry users to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
					},
				},
				Computed: true,
			},
			"windows_registry_protection": {
				Type:        schema.TypeList,
				Description: "Configuration for windows registry protection.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"protected_paths": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"excluded_paths": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"protected_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"excluded_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"protected_users": {
							Type:        schema.TypeList,
							Description: "List of registry users to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"excluded_users": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be users from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
					},
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
						"exclude_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"include_directories": {
							Type:        schema.TypeList,
							Description: "List of directories to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
		},
	}
}

func dataHostRuntimePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
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
		// controls
		d.Set("block_cryptocurrency_mining", crp.EnableCryptoMiningDns)
		d.Set("audit_brute_force_login", crp.AuditBruteForceLogin)
		d.Set("enable_ip_reputation_security", crp.EnableIPReputation)
		d.Set("blocked_files", crp.FileBlock.FilenameBlockList)
		d.Set("file_integrity_monitoring", flattenFileIntegrityMonitoring(crp.FileIntegrityMonitoring))
		d.Set("audit_all_os_user_activity", crp.Auditing.AuditOsUserActivity)
		d.Set("audit_full_command_arguments", crp.Auditing.AuditProcessCmdline)
		d.Set("audit_host_successful_login_events", crp.Auditing.AuditSuccessLogin)
		d.Set("audit_host_failed_login_events", crp.Auditing.AuditFailedLogin)
		d.Set("audit_user_account_management", crp.Auditing.AuditUserAccountManagement)
		d.Set("os_users_allowed", crp.WhitelistedOsUsers.UserWhiteList)
		d.Set("os_groups_allowed", crp.WhitelistedOsUsers.GroupWhiteList)
		d.Set("os_users_blocked", crp.BlacklistedOsUsers.UserBlackList)
		d.Set("os_groups_blocked", crp.BlacklistedOsUsers.GroupBlackList)
		d.Set("package_block", crp.PackageBlock.PackagesBlackList)
		d.Set("port_scanning_detection", crp.EnablePortScanProtection)
		d.Set("malware_scan_options", flattenMalwareScanOptions(crp.MalwareScanOptions))
		d.Set("monitor_system_time_changes", crp.SystemIntegrityProtection.AuditSystemtimeChange)
		d.Set("monitor_windows_services", crp.SystemIntegrityProtection.WindowsServicesMonitoring)
		d.Set("monitor_system_log_integrity", crp.SystemIntegrityProtection.Enabled)
		d.Set("windows_registry_monitoring", flattenWindowsRegistryMonitoring(crp.RegistryAccessMonitoring))
		d.Set("windows_registry_protection", flattenWindowsRegistryProtection(crp.ReadonlyRegistry))

		d.SetId(name)
	} else {
		return diag.FromErr(err)
	}

	return nil
}
