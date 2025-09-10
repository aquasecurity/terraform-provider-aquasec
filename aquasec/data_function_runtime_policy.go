package aquasec

import (
	"context"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataFunctionRuntimePolicy() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataFunctionRuntimePolicyRead,
		Schema: map[string]*schema.Schema{
			// Basic information fields
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the function runtime policy",
				Required:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The description of the function runtime policy",
				Computed:    true,
			},
			"version": {
				Type:        schema.TypeString,
				Description: "Version of the function runtime policy",
				Computed:    true,
			},

			// Policy control fields
			"enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if the runtime policy is enabled or not.",
				Computed:    true,
			},
			"enforce": {
				Type:        schema.TypeBool,
				Description: "Indicates that policy should effect function execution (not just for audit).",
				Computed:    true,
			},
			"enforce_after_days": {
				Type:        schema.TypeInt,
				Description: "Indicates the number of days after which the runtime policy will be changed to enforce mode.",
				Computed:    true,
			},

			// Application scope fields
			"application_scopes": {
				Type:        schema.TypeList,
				Description: "Indicates the application scope of the service.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"exclude_application_scopes": {
				Type:        schema.TypeList,
				Description: "List of excluded application scopes.",
				Computed:    true,
				Elem: &schema.Schema{
					Type:        schema.TypeString,
					Description: "Excluded application scope.",
				},
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

			// Function security controls
			"drift_prevention": {
				Type:        schema.TypeList,
				Description: "Drift prevention configuration for functions.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether drift prevention is enabled.",
							Computed:    true,
						},
						"exec_lockdown": {
							Type:        schema.TypeBool,
							Description: "Whether to lockdown execution drift.",
							Computed:    true,
						},
						"image_lockdown": {
							Type:        schema.TypeBool,
							Description: "Whether to lockdown image drift.",
							Computed:    true,
						},
						"exec_lockdown_white_list": {
							Type:        schema.TypeList,
							Description: "List of items in the execution lockdown white list.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
					},
				},
			},
			"executable_blacklist": {
				Type:        schema.TypeList,
				Description: "Executable blacklist configuration.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether the executable blacklist is enabled.",
							Computed:    true,
						},
						"executables": {
							Type:        schema.TypeList,
							Description: "List of blacklisted executables.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
					},
				},
			},
			"allowed_executables": {
				Type:        schema.TypeList,
				Description: "Allowed executables configuration.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether allowed executables configuration is enabled.",
							Computed:    true,
						},
						"allow_executables": {
							Type:        schema.TypeList,
							Description: "List of allowed executables.",
							Computed:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"separate_executables": {
							Type:        schema.TypeBool,
							Description: "Whether to treat executables separately.",
							Computed:    true,
						},
						"allow_root_executables": {
							Type:        schema.TypeList,
							Description: "List of allowed root executables.",
							Computed:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"block_fileless_exec": {
				Type:        schema.TypeBool,
				Description: "Block fileless execution attempts.",
				Computed:    true,
			},
			"block_non_compliant_workloads": {
				Type:        schema.TypeBool,
				Description: "Block non-compliant serverless functions.",
				Computed:    true,
			},
			"block_disallowed_images": {
				Type:        schema.TypeBool,
				Description: "Block deployment from disallowed images.",
				Computed:    true,
			},

			// File monitoring and integrity
			"file_integrity_monitoring": {
				Type:        schema.TypeList,
				Description: "Configuration for file integrity monitoring.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "If true, file integrity monitoring is enabled.",
							Computed:    true,
						},
						"monitored_files": {
							Type:        schema.TypeList,
							Description: "List of paths to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"exceptional_monitored_files": {
							Type:        schema.TypeList,
							Description: "List of paths to be excluded from monitoring.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"monitored_files_read": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file read operations.",
							Computed:    true,
						},
						"monitored_files_modify": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file modify operations.",
							Computed:    true,
						},
						"monitored_files_attributes": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file attribute operations.",
							Computed:    true,
						},
						"monitored_files_create": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file create operations.",
							Computed:    true,
						},
						"monitored_files_delete": {
							Type:        schema.TypeBool,
							Description: "Whether to monitor file delete operations.",
							Computed:    true,
						},
						"monitored_files_processes": {
							Type:        schema.TypeList,
							Description: "List of processes associated with monitored files.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"exceptional_monitored_files_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to be excluded from monitoring.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"monitored_files_users": {
							Type:        schema.TypeList,
							Description: "List of users associated with monitored files.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"exceptional_monitored_files_users": {
							Type:        schema.TypeList,
							Description: "List of users to be excluded from monitoring.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
					},
				},
			},

			// Malware protection
			"malware_scan_options": {
				Type:        schema.TypeList,
				Description: "Configuration for Real-Time Malware Protection.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Defines if malware scanning is enabled or not",
							Computed:    true,
						},
						"action": {
							Type:        schema.TypeString,
							Description: "Set Action, Defaults to 'Alert' when empty",
							Computed:    true,
						},
						"include_directories": {
							Type:        schema.TypeList,
							Description: "List of directories to include in scanning.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"exclude_directories": {
							Type:        schema.TypeList,
							Description: "List of directories to exclude from scanning.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"exclude_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to exclude from scanning.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"file_forensic_collection": {
							Type:        schema.TypeBool,
							Description: "Whether to enable file forensic collection.",
							Computed:    true,
						},
					},
				},
			},

			// Honeypot/tripwire - renamed for consistency with resource
			"tripwire": {
				Type:        schema.TypeList,
				Description: "Honeypot/tripwire configuration for detecting unauthorized access.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether the honeypot is enabled.",
							Computed:    true,
						},
						"user_id": {
							Type:        schema.TypeString,
							Description: "Honeypot User ID (Access Key)",
							Computed:    true,
						},
						"user_password": {
							Type:        schema.TypeString,
							Description: "Honeypot User Password (Secret Key)",
							Computed:    true,
							Sensitive:   true,
						},
						"apply_on": {
							Type:        schema.TypeList,
							Description: "List of options to apply the honeypot on (Environment Variable, Layer, File)",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"serverless_app": {
							Type:        schema.TypeString,
							Description: "Serverless application name",
							Computed:    true,
						},
					},
				},
			},

			// Network security
			"enable_crypto_mining_dns": {
				Type:        schema.TypeBool,
				Description: "Enable detection of crypto mining via DNS monitoring",
				Computed:    true,
			},

			// Required internal fields
			"runtime_type": {
				Type:        schema.TypeString,
				Description: "Type of runtime policy",
				Computed:    true,
			},
			"type": {
				Type:        schema.TypeString,
				Description: "Policy type identifier",
				Computed:    true,
			},

			// Administrative fields
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the policy",
				Computed:    true,
			},
			"is_auto_generated": {
				Type:        schema.TypeBool,
				Description: "Indicates if the policy was auto-generated",
				Computed:    true,
			},
			"is_ootb_policy": {
				Type:        schema.TypeBool,
				Description: "Indicates if this is an out-of-the-box policy",
				Computed:    true,
			},
			"is_audit_checked": {
				Type:        schema.TypeBool,
				Description: "Indicates if audit check is enabled",
				Computed:    true,
			},

			// Internal tracking fields
			"created": {
				Type:        schema.TypeString,
				Description: "Creation timestamp",
				Computed:    true,
			},
			"updated": {
				Type:        schema.TypeString,
				Description: "Last update timestamp",
				Computed:    true,
			},
			"lastupdate": {
				Type:        schema.TypeInt,
				Description: "Internal last update tracker",
				Computed:    true,
			},
		},
	}
}

func dataFunctionRuntimePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	crp, err := c.GetRuntimePolicy(name)
	if err != nil {
		return diag.FromErr(err)
	}

	// Basic information
	d.Set("name", crp.Name)
	d.Set("description", crp.Description)
	d.Set("version", crp.Version)

	// Policy control fields
	d.Set("enabled", crp.Enabled)
	d.Set("enforce", crp.Enforce)
	d.Set("enforce_after_days", crp.EnforceAfterDays)

	// Application scope fields
	d.Set("application_scopes", crp.ApplicationScopes)
	d.Set("exclude_application_scopes", crp.ExcludeApplicationScopes)
	d.Set("scope_expression", crp.Scope.Expression)
	d.Set("scope_variables", flattenScopeVariables(crp.Scope.Variables))

	// Function security controls
	d.Set("drift_prevention", flattenDriftPrevention(crp.DriftPrevention))
	d.Set("executable_blacklist", flattenExecutableBlacklist(crp.ExecutableBlacklist))
	d.Set("allowed_executables", flattenAllowedExecutables(crp.AllowedExecutables))
	d.Set("block_fileless_exec", crp.BlockFilelessExec)
	d.Set("block_non_compliant_workloads", crp.BlockNonCompliantWorkloads)
	d.Set("block_disallowed_images", crp.BlockDisallowedImages)

	// File integrity monitoring
	// Since we can't compare with an empty struct due to slice fields,
	// check a key field to determine if we should set it
	if len(crp.FileIntegrityMonitoring.MonitoredFiles) > 0 || crp.FileIntegrityMonitoring.Enabled {
		d.Set("file_integrity_monitoring", flattenFileIntegrityMonitoring(crp.FileIntegrityMonitoring))
	}

	// Malware scan options
	// Since we can't compare with an empty struct due to slice fields,
	// check a key field to determine if we should set it
	if len(crp.MalwareScanOptions.ExcludeDirectories) > 0 ||
		len(crp.MalwareScanOptions.IncludeDirectories) > 0 ||
		crp.MalwareScanOptions.Enabled {
		d.Set("malware_scan_options", flattenMalwareScanOptions(crp.MalwareScanOptions))
	}

	// Honeypot/tripwire
	d.Set("tripwire", flattenTripwire(crp.Tripwire))

	// Network security
	d.Set("enable_crypto_mining_dns", crp.EnableCryptoMiningDns)

	// Required internal fields
	d.Set("runtime_type", crp.RuntimeType)
	d.Set("type", crp.Type)

	// Administrative fields
	d.Set("author", crp.Author)
	d.Set("is_auto_generated", crp.IsAutoGenerated)
	d.Set("is_ootb_policy", crp.IsOOTBPolicy)
	d.Set("is_audit_checked", crp.IsAuditChecked)

	// Internal tracking fields - with special handling for time.Time
	d.Set("created", crp.Created)

	// Fix for time.Time field
	if !crp.Updated.IsZero() {
		d.Set("updated", crp.Updated.Format(time.RFC3339))
	} else {
		d.Set("updated", "")
	}

	d.Set("lastupdate", crp.Lastupdate)

	d.SetId(name)

	return nil
}
