package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceService() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataServiceRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the service. It is recommended not to use whitespace characters in the name.",
				Required:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "A textual description of the service record; maximum 500 characters.",
				Computed:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the service.",
				Computed:    true,
			},
			"containers_count": {
				Type:        schema.TypeInt,
				Description: "The number of containers associated with the service.",
				Computed:    true,
			},
			"monitoring": {
				Type:        schema.TypeBool,
				Description: "Indicates if monitoring is enabled or not",
				Computed:    true,
			},
			"enforce": {
				Type:        schema.TypeBool,
				Description: "Enforcement status of the service.",
				Computed:    true,
			},
			"application_scopes": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Indicates the application scope of the service.",
				Computed:    true,
			},
			"priority": {
				Type:        schema.TypeInt,
				Description: "Rules priority, must be between 1-100.",
				Computed:    true,
			},
			"target": {
				Type:        schema.TypeString,
				Description: "Type of the workload. container or host.",
				Computed:    true,
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
			"policies": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "The service's policies; an array of container firewall policy names.",
				Computed:    true,
			},
			"evaluated": {
				Type:        schema.TypeBool,
				Description: "Whether the service has been evaluated for security vulnerabilities.",
				Computed:    true,
			},
			"lastupdate": {
				Type:        schema.TypeInt,
				Description: "Timestamp of the last update in Unix time format.",
				Computed:    true,
			},
			"vulnerabilities_total": {
				Type:        schema.TypeInt,
				Description: "Total number of vulnerabilities.",
				Computed:    true,
			},
			"vulnerabilities_high": {
				Type:        schema.TypeInt,
				Description: "Number of high severity vulnerabilities.",
				Computed:    true,
			},
			"vulnerabilities_medium": {
				Type:        schema.TypeInt,
				Description: "Number of medium severity vulnerabilities.",
				Computed:    true,
			},
			"vulnerabilities_low": {
				Type:        schema.TypeInt,
				Description: "Number of low severity vulnerabilities.",
				Computed:    true,
			},
			"vulnerabilities_sensitive": {
				Type:        schema.TypeInt,
				Description: "Number of sensitive vulnerabilities.",
				Computed:    true,
			},
			"vulnerabilities_malware": {
				Type:        schema.TypeInt,
				Description: "Number of malware.",
				Computed:    true,
			},
			"vulnerabilities_negligible": {
				Type:        schema.TypeInt,
				Description: "Number of negligible vulnerabilities.",
				Computed:    true,
			},
			"vulnerabilities_score_average": {
				Type:        schema.TypeInt,
				Description: "The CVSS average vulnerabilities score.",
				Computed:    true,
			},
			"not_evaluated_count": {
				Type:        schema.TypeInt,
				Description: "The number of container that are not evaluated.",
				Computed:    true,
			},
			"unregistered_count": {
				Type:        schema.TypeInt,
				Description: "The number of containers allocated to the service that are not registered.",
				Computed:    true,
			},
			"is_registered": {
				Type:        schema.TypeBool,
				Description: "Indicates if registered or not.",
				Computed:    true,
			},
		},
	}
}

func dataServiceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	service, err := c.GetService(name)
	if err == nil {
		d.Set("description", service.Description)
		d.Set("author", service.Author)
		d.Set("containers_count", service.ContainersCount)
		d.Set("monitoring", service.Monitoring)
		d.Set("evaluated", service.Evaluated)
		d.Set("policies", service.Policies)
		d.Set("lastupdate", service.Lastupdate)
		d.Set("vulnerabilities_total", service.Vulnerabilities.Total)
		d.Set("vulnerabilities_high", service.Vulnerabilities.High)
		d.Set("vulnerabilities_medium", service.Vulnerabilities.Medium)
		d.Set("vulnerabilities_low", service.Vulnerabilities.Low)
		d.Set("vulnerabilities_sensitive", service.Vulnerabilities.Sensitive)
		d.Set("vulnerabilities_malware", service.Vulnerabilities.Malware)
		d.Set("vulnerabilities_negligible", service.Vulnerabilities.Negligible)
		d.Set("vulnerabilities_score_average", service.Vulnerabilities.ScoreAverage)
		d.Set("enforce", service.Enforce)
		d.Set("priority", service.MembershipRules.Priority)
		d.Set("target", service.MembershipRules.Target)
		d.Set("scope_expression", service.MembershipRules.Scope.Expression)
		d.Set("scope_variables", flattenScopeVariables(service.MembershipRules.Scope.Variables))
		d.Set("not_evaluated_count", service.NotEvaluatedCount)
		d.Set("unregistered_count", service.UnregisteredCount)
		d.Set("is_registered", service.IsRegistered)
		d.Set("application_scopes", service.ApplicationScopes)

		d.SetId(name)
	} else {
		return diag.FromErr(err)
	}

	return nil
}
