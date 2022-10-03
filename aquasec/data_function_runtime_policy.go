package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataFunctionRuntimePolicy() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataFunctionRuntimePolicyRead,
		Schema: map[string]*schema.Schema{
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
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the service.",
				Computed:    true,
			},
			"block_malicious_executables": {
				Type:        schema.TypeBool,
				Description: "If true, prevent creation of malicious executables in functions during their runtime post invocation.",
				Computed:    true,
			},
			"block_running_executables_in_tmp_folder": {
				Type:        schema.TypeBool,
				Description: "If true, prevent running of executables in functions locate in /tmp folder during their runtime post invocation.",
				Computed:    true,
			},
			"block_malicious_executables_allowed_processes": {
				Type:        schema.TypeList,
				Description: "List of processes that will be allowed",
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
			"honeypot_access_key": {
				Type:        schema.TypeString,
				Description: "Honeypot User ID (Access Key)",
				Computed:    true,
			},
			"honeypot_secret_key": {
				Type:        schema.TypeString,
				Description: "Honeypot User Password (Secret Key)",
				Computed:    true,
				Sensitive:   true,
			},
			"honeypot_apply_on": {
				Type:        schema.TypeList,
				Description: "List of options to apply the honeypot on (Environment Vairable, Layer, File)",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"honeypot_serverless_app_name": {
				Type:        schema.TypeString,
				Description: "Serverless application name",
				Computed:    true,
			},
		},
	}
}

func dataFunctionRuntimePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	crp, err := c.GetRuntimePolicy(name)
	if err == nil {
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

		d.SetId(name)
	} else {
		return diag.FromErr(err)
	}

	return nil
}
