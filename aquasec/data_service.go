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
			"policies": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "The service's policies; an array of container firewall policy names.",
				Required:    true,
			},
			"local_policies": {
				Type:        schema.TypeList,
				Description: "A list of local policies for the service, including inbound and outbound network rules.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Description: "The name of the local policy.",
							Required:    true,
						},
						"type": {
							Type:        schema.TypeString,
							Description: "The type of the local policy, e.g., access.control.",
							Required:    true,
						},
						"description": {
							Type:        schema.TypeString,
							Description: "A description of the local policy.",
							Optional:    true,
						},
						"inbound_networks": {
							Type:        schema.TypeList,
							Description: "Inbound network rules for the local policy.",
							Optional:    true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"port_range": {
										Type:        schema.TypeString,
										Description: "The port range for the inbound network rule.",
										Required:    true,
									},
									"resource_type": {
										Type:        schema.TypeString,
										Description: "The resource type for the inbound network rule (e.g., anywhere).",
										Required:    true,
									},
									"resource": {
										Type:        schema.TypeString,
										Description: "Custom ip for the inbound network rule (e.g., 190.1.2.3/12).",
										Optional:    true,
									},
									"allow": {
										Type:        schema.TypeBool,
										Description: "Whether the inbound network rule is allowed.",
										Required:    true,
									},
								},
							},
						},
						"outbound_networks": {
							Type:        schema.TypeList,
							Description: "Outbound network rules for the local policy.",
							Optional:    true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"port_range": {
										Type:        schema.TypeString,
										Description: "The port range for the outbound network rule.",
										Required:    true,
									},
									"resource_type": {
										Type:        schema.TypeString,
										Description: "The resource type for the outbound network rule (e.g., anywhere).",
										Required:    true,
									},
									"resource": {
										Type:        schema.TypeString,
										Description: "Custom ip for the outbound network rule (e.g., 190.1.2.3/12).",
										Optional:    true,
									},
									"allow": {
										Type:        schema.TypeBool,
										Description: "Whether the outbound network rule is allowed.",
										Required:    true,
									},
								},
							},
						},
						"block_metadata_service": {
							Type:        schema.TypeBool,
							Description: "Whether to block access to the metadata service.",
							Optional:    true,
						},
					},
				},
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
		if err := d.Set("local_policies", flattenLocalPolicies(service.LocalPolicies)); err != nil {
			return diag.FromErr(err)
		}
		d.SetId(name)
	} else {
		return diag.FromErr(err)
	}

	return nil
}
func flattenLocalPolicies(policies []client.LocalPolicy) []map[string]interface{} {
	if policies == nil {
		return []map[string]interface{}{}
	}

	var result []map[string]interface{}
	for _, policy := range policies {
		p := map[string]interface{}{
			"name":                   policy.Name,
			"type":                   policy.Type,
			"description":            policy.Description,
			"block_metadata_service": policy.BlockMetadataService,
		}

		// Flatten inbound_networks
		var inboundNetworks []map[string]interface{}
		for _, inbound := range policy.InboundNetworks {
			inboundNetworks = append(inboundNetworks, map[string]interface{}{
				"port_range":    inbound.PortRange,
				"resource_type": inbound.ResourceType,
				"resource":      inbound.Resource,
				"allow":         inbound.Allow,
			})
		}
		p["inbound_networks"] = inboundNetworks

		// Flatten outbound_networks
		var outboundNetworks []map[string]interface{}
		for _, outbound := range policy.OutboundNetworks {
			outboundNetworks = append(outboundNetworks, map[string]interface{}{
				"port_range":    outbound.PortRange,
				"resource_type": outbound.ResourceType,
				"resource":      outbound.Resource,
				"allow":         outbound.Allow,
			})
		}
		p["outbound_networks"] = outboundNetworks

		result = append(result, p)
	}

	return result
}
