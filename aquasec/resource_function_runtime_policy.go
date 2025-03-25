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
			// Basic information fields
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
			
			// Policy control fields
			"enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if the runtime policy is enabled or not.",
				Default:     true,
				Optional:    true,
			},
			"enforce": {
				Type:        schema.TypeBool,
				Description: "Indicates that policy should effect function execution (not just for audit).",
				Default:     false,
				Optional:    true,
			},
			"enforce_after_days": {
				Type:        schema.TypeInt,
				Description: "Indicates the number of days after which the runtime policy will be changed to enforce mode.",
				Optional:    true,
			},
			
			// Application scope fields
			"application_scopes": {
				Type:        schema.TypeList,
				Description: "Indicates the application scope of the service.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
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
									"name": {
										Type:     schema.TypeString,
										Optional: true,
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
			
			// Function security controls
			"drift_prevention": {
				Type:        schema.TypeList,
				Description: "Drift prevention configuration for functions.",
				Optional:    true,
				Computed:    true,
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
				Computed:    true,
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
			"allowed_executables": {
				Type:        schema.TypeList,
				Description: "Allowed executables configuration.",
				Optional:    true,
				Computed:    true,
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
			"block_fileless_exec": {
				Type:        schema.TypeBool,
				Description: "Block fileless execution attempts.",
				Optional:    true,
			},
			"block_non_compliant_workloads": {
				Type:        schema.TypeBool,
				Description: "Block non-compliant serverless functions.",
				Optional:    true,
			},
			"block_disallowed_images": {
				Type:        schema.TypeBool,
				Description: "Block deployment from disallowed images.",
				Optional:    true,
			},
			
			// File monitoring and integrity
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
			
			// Malware protection
			"malware_scan_options": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Configuration for Real-Time Malware Protection.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Defines if malware scanning is enabled or not",
							Optional:    true,
						},
						"action": {
							Type:        schema.TypeString,
							Description: "Set Action, Defaults to 'Alert' when empty",
							Optional:    true,
						},
						"include_directories": {
							Type:        schema.TypeList,
							Description: "List of directories to include in scanning.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exclude_directories": {
							Type:        schema.TypeList,
							Description: "List of directories to exclude from scanning.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exclude_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to exclude from scanning.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			
			// Honeypot/tripwire
			"tripwire": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Honeypot/tripwire configuration for detecting unauthorized access.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Whether the honeypot is enabled.",
							Optional:    true,
							Default:     false,
						},
						"user_id": {
							Type:        schema.TypeString,
							Description: "Honeypot User ID (Access Key)",
							Optional:    true,
						},
						"user_password": {
							Type:        schema.TypeString,
							Description: "Honeypot User Password (Secret Key)",
							Optional:    true,
							Sensitive:   true,
						},
						"apply_on": {
							Type:        schema.TypeList,
							Description: "List of options to apply the honeypot on (Environment Variable, Layer, File)",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"serverless_app": {
							Type:        schema.TypeString,
							Description: "Serverless application name",
							Optional:    true,
						},
					},
				},
				Optional: true,
				Computed: true, 
			},
			
			// Network security
			"enable_crypto_mining_dns": {
				Type:        schema.TypeBool,
				Description: "Enable detection of crypto mining via DNS monitoring",
				Optional:    true,
			},
			
			// Other relevant settings
			"version": {
				Type:        schema.TypeString,
				Description: "Version of the function runtime policy",
				Optional:    true,
				Default:     "1.0",
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the policy",
				Computed:    true,
			},
			
			// Required internal fields (needed by the API)
			"runtime_type": {
				Type:        schema.TypeString,
				Description: "Type of runtime policy",
				Optional:    true,
				Default:     "function",
			},
			"type": {
				Type:        schema.TypeString,
				Description: "Policy type identifier",
				Optional:    true,
				Default:     "runtime.policy",
			},
			
			// Administrative fields
			"is_auto_generated": {
				Type:        schema.TypeBool,
				Description: "Indicates if the policy was auto-generated",
				Optional:    true,
			},
			"is_ootb_policy": {
				Type:        schema.TypeBool,
				Description: "Indicates if this is an out-of-the-box policy",
				Optional:    true,
			},
			"is_audit_checked": {
				Type:        schema.TypeBool,
				Description: "Indicates if audit check is enabled",
				Optional:    true,
			},
			
			// Internal tracking fields (computed)
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

	// Basic information
	d.Set("name", crp.Name)
	d.Set("description", crp.Description)
	d.Set("author", crp.Author)
	d.Set("version", crp.Version)
	
	// Policy control fields
	d.Set("enabled", crp.Enabled)
	d.Set("enforce", crp.Enforce)
	
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
	
	// Honeypot/tripwire
	d.Set("tripwire", flattenTripwire(crp.Tripwire))
	
	// Network security
	d.Set("enable_crypto_mining_dns", crp.EnableCryptoMiningDns)
	
	// Administrative fields
	d.Set("is_auto_generated", crp.IsAutoGenerated)
	d.Set("is_ootb_policy", crp.IsOOTBPolicy)
	d.Set("is_audit_checked", crp.IsAuditChecked)
	
	// Required internal fields
	d.Set("runtime_type", crp.RuntimeType)
	d.Set("type", crp.Type)
	
	// Maintain the resource ID
	d.SetId(crp.Name)

	return nil
}

func resourceFunctionRuntimePolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)
	
	// Check for changes in any fields
	if d.HasChanges(
		"description",
		"enabled",
		"enforce",
		"enforce_after_days",
		"application_scopes",
		"exclude_application_scopes",
		"scope",
		"scope_expression",
		"scope_variables",
		"drift_prevention",
		"executable_blacklist",
		"allowed_executables",
		"block_fileless_exec",
		"block_non_compliant_workloads",
		"block_disallowed_images",
		"file_integrity_monitoring",
		"malware_scan_options",
		"tripwire",
		"enable_crypto_mining_dns",
		"version",
		"is_auto_generated",
		"is_ootb_policy",
		"is_audit_checked",
	) {
		crp := expandFunctionRuntimePolicy(d)
		err := c.UpdateRuntimePolicy(crp)
		if err == nil {
			d.SetId(name)
		} else {
			return diag.FromErr(err)
		}
	}

	return resourceFunctionRuntimePolicyRead(ctx, d, m)
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

	return nil
}

func expandFunctionRuntimePolicy(d *schema.ResourceData) *client.RuntimePolicy {
	crp := client.RuntimePolicy{
		Name:        d.Get("name").(string),
		RuntimeType: "function",
	}

	// Basic information
	if v, ok := d.GetOk("description"); ok {
		crp.Description = v.(string)
	}
	
	if v, ok := d.GetOk("version"); ok {
		crp.Version = v.(string)
	}
	
	if v, ok := d.GetOk("author"); ok {
		crp.Author = v.(string)
	}
	
	// Policy control fields
	if v, ok := d.GetOk("enabled"); ok {
		crp.Enabled = v.(bool)
	}
	
	if v, ok := d.GetOk("enforce"); ok {
		crp.Enforce = v.(bool)
	}
	
	if v, ok := d.GetOk("enforce_after_days"); ok {
		crp.EnforceAfterDays = v.(int)
	}
	
	// Application scope fields
	if v, ok := d.GetOk("application_scopes"); ok {
		crp.ApplicationScopes = convertStringArr(v.([]interface{}))
	}
	
	if v, ok := d.GetOk("exclude_application_scopes"); ok {
		crp.ExcludeApplicationScopes = convertStringArr(v.([]interface{}))
	} else {
		// If not provided, set to empty array
		crp.ExcludeApplicationScopes = []string{}
	}
	
	// Handle scope definitions - two ways to define scopes
	// Method 1: Using scope block
	if scopeMap, ok := d.GetOk("scope"); ok {
		v := scopeMap.([]interface{})[0].(map[string]interface{})
		crp.Scope = client.Scope{
			Expression: v["expression"].(string),
			Variables:  flattenVariables(v["variables"].([]interface{})),
		}
	} else {
		// Method 2: Using separate fields
		crp.Scope.Expression = d.Get("scope_expression").(string)
		
		variables := make([]client.Variable, 0)
		if variableMap, ok := d.GetOk("scope_variables"); ok {
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
	}
	
	// Function security controls
	if v, ok := d.GetOk("drift_prevention"); ok {
		driftMap := v.([]interface{})[0].(map[string]interface{})
		crp.DriftPrevention = client.DriftPrevention{
			Enabled:               driftMap["enabled"].(bool),
			ExecLockdown:          driftMap["exec_lockdown"].(bool),
			ImageLockdown:         driftMap["image_lockdown"].(bool),
			ExecLockdownWhiteList: convertStringArrNull(driftMap["exec_lockdown_white_list"].([]interface{})),
		}
	}
	
	if v, ok := d.GetOk("executable_blacklist"); ok {
		blacklistMap := v.([]interface{})[0].(map[string]interface{})
		crp.ExecutableBlacklist = client.ExecutableBlacklist{
			Enabled:     blacklistMap["enabled"].(bool),
			Executables: convertStringArrNull(blacklistMap["executables"].([]interface{})),
		}
	}
	
	if v, ok := d.GetOk("allowed_executables"); ok {
		allowedMap := v.([]interface{})[0].(map[string]interface{})
		crp.AllowedExecutables = client.AllowedExecutables{
			Enabled:              allowedMap["enabled"].(bool),
			AllowExecutables:     convertStringArrNull(allowedMap["allow_executables"].([]interface{})),
			SeparateExecutables:  allowedMap["separate_executables"].(bool),
			AllowRootExecutables: convertStringArrNull(allowedMap["allow_root_executables"].([]interface{})),
		}
	}
	
	if v, ok := d.GetOk("block_fileless_exec"); ok {
		crp.BlockFilelessExec = v.(bool)
	}
	
	if v, ok := d.GetOk("block_non_compliant_workloads"); ok {
		crp.BlockNonCompliantWorkloads = v.(bool)
	}
	
	if v, ok := d.GetOk("block_disallowed_images"); ok {
		crp.BlockDisallowedImages = v.(bool)
	}
	
	// Honeypot/tripwire
	if v, ok := d.GetOk("tripwire"); ok {
		tripwireMap := v.([]interface{})[0].(map[string]interface{})
		crp.Tripwire = client.Tripwire{
			Enabled:       tripwireMap["enabled"].(bool),
			UserID:        tripwireMap["user_id"].(string),
			UserPassword:  tripwireMap["user_password"].(string),
			ApplyOn:       convertStringArrNull(tripwireMap["apply_on"].([]interface{})),
			ServerlessApp: tripwireMap["serverless_app"].(string),
		}
	}
	
	// Network security
	
	if v, ok := d.GetOk("enable_crypto_mining_dns"); ok {
		crp.EnableCryptoMiningDns = v.(bool)
	}
	
	// Administrative fields
	if v, ok := d.GetOk("is_auto_generated"); ok {
		crp.IsAutoGenerated = v.(bool)
	}
	
	if v, ok := d.GetOk("is_ootb_policy"); ok {
		crp.IsOOTBPolicy = v.(bool)
	}
	
	if v, ok := d.GetOk("is_audit_checked"); ok {
		crp.IsAuditChecked = v.(bool)
	}
	
	// Type field
	if v, ok := d.GetOk("type"); ok {
		crp.Type = v.(string)
	}
	
	return &crp
}