package aquasec

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceService() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceServiceCreate,
		ReadContext:   resourceServiceRead,
		UpdateContext: resourceServiceUpdate,
		DeleteContext: resourceServiceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the service. It is recommended not to use whitespace characters in the name.",
				Required:    true,
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "A textual description of the service record; maximum 500 characters.",
				Optional:    true,
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
				Default:     false,
				Optional:    true,
			},
			"enforce": {
				Type:        schema.TypeBool,
				Description: "Enforcement status of the service.",
				Default:     false,
				Optional:    true,
			},
			"application_scopes": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Indicates the application scope of the service.",
				Required:    true,
			},
			"priority": {
				Type:        schema.TypeInt,
				Description: "Rules priority, must be between 1-100.",
				Default:     100,
				Optional:    true,
			},
			"target": {
				Type:        schema.TypeString,
				Description: "Type of the workload. container or host.",
				Required:    true,
			},
			"scope_expression": {
				Type:        schema.TypeString,
				Description: "Logical expression of how to compute the dependency of the scope variables.",
				Optional:    true,
			},
			"scope_variables": {
				Type:        schema.TypeList,
				Description: "List of scope attributes.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attribute": {
							Type:        schema.TypeString,
							Description: "Class of supported scope.",
							Optional:    true,
						},
						"name": {
							Type:        schema.TypeString,
							Description: "Name assigned to the attribute.",
							Optional:    true,
						},
						"value": {
							Type:        schema.TypeString,
							Description: "Value assigned to the attribute.",
							Optional:    true,
						},
					},
				},
				Optional: true,
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

func resourceServiceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	service := expandService(d)
	err := c.CreateService(service)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)
	return resourceServiceRead(ctx, d, m)

}

func resourceServiceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	service, err := c.GetService(d.Id())

	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.Set("name", service.Name)
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
	localPolicies := make([]map[string]interface{}, 0)
	for _, policy := range service.LocalPolicies {
		localPolicies = append(localPolicies, map[string]interface{}{
			"name":                   policy.Name,
			"type":                   policy.Type,
			"description":            policy.Description,
			"inbound_networks":       convertNetworkRulesToNetworks(policy.InboundNetworks),
			"outbound_networks":      convertNetworkRulesToNetworks(policy.OutboundNetworks),
			"block_metadata_service": policy.BlockMetadataService,
		})
	}
	d.Set("local_policies", localPolicies)

	d.SetId(service.Name)

	return nil
}

func convertNetworkRulesToNetworks(networkRules []client.NetworkRule) []map[string]interface{} {
	networkMaps := make([]map[string]interface{}, 0)
	for _, networkRule := range networkRules {
		networkMaps = append(networkMaps, map[string]interface{}{
			"allow":         networkRule.Allow,
			"port_range":    networkRule.PortRange,
			"resource_type": networkRule.ResourceType,
			"resource":      networkRule.Resource,
		})
	}
	return networkMaps
}

func resourceServiceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	if d.HasChanges("description", "monitoring", "policies", "enforce", "application_scopes", "target", "priority", "scope_expression", "scope_variables", "local_policies") {
		service := expandService(d)
		err := c.UpdateService(service)
		if err == nil {
			d.SetId(name)
		} else {
			return diag.FromErr(err)
		}
	}

	//d.SetId(name)

	return nil
}

func resourceServiceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	err := c.DeleteService(name)
	if err == nil {
		d.SetId("")
	} else {
		return diag.FromErr(err)
	}

	//d.SetId("")

	return nil
}

func expandService(d *schema.ResourceData) *client.Service {
	service := client.Service{
		Name: d.Get("name").(string),
	}

	description, ok := d.GetOk("description")
	if ok {
		service.Description = description.(string)
	}

	author, ok := d.GetOk("author")
	if ok {
		service.Author = author.(string)
	}

	containers, ok := d.GetOk("containers")
	if ok {
		service.Containers = containers.([]string)
	}

	containersCount, ok := d.GetOk("container_counts")
	if ok {
		service.ContainersCount = containersCount.(int)
	}

	evaluated, ok := d.GetOk("evaluated")
	if ok {
		service.Evaluated = evaluated.(bool)
	}

	monitoring, ok := d.GetOk("monitoring")
	if ok {
		service.Monitoring = monitoring.(bool)
	}

	policies, ok := d.GetOk("policies")
	if ok {
		service.Policies = convertStringArr(policies.([]interface{}))
	}

	lastupdate, ok := d.GetOk("lastupdate")
	if ok {
		service.Lastupdate = lastupdate.(int)
	}

	highVulnerabilities, ok := d.GetOk("vulnerabilities_high")
	if ok {
		service.Vulnerabilities.High = highVulnerabilities.(int)
	}

	mediumVulnerabilities, ok := d.GetOk("vulnerabilities_medium")
	if ok {
		service.Vulnerabilities.Medium = mediumVulnerabilities.(int)
	}

	lowVulnerabilities, ok := d.GetOk("vulnerabilities_low")
	if ok {
		service.Vulnerabilities.Low = lowVulnerabilities.(int)
	}

	sensitiveVulnerabilities, ok := d.GetOk("vulnerabilities_sensitive")
	if ok {
		service.Vulnerabilities.Sensitive = sensitiveVulnerabilities.(int)
	}

	malwareVulnerabilities, ok := d.GetOk("vulnerabilities_malware")
	if ok {
		service.Vulnerabilities.Malware = malwareVulnerabilities.(int)
	}

	negligibleVulnerabilities, ok := d.GetOk("vulnerabilities_negligible")
	if ok {
		service.Vulnerabilities.Negligible = negligibleVulnerabilities.(int)
	}

	scoreAverageVulnerabilities, ok := d.GetOk("vulnerabilities_score_average")
	if ok {
		service.Vulnerabilities.ScoreAverage = scoreAverageVulnerabilities.(float64)
	}

	enforce, ok := d.GetOk("enforce")
	if ok {
		service.Enforce = enforce.(bool)
	}

	membershipRules := client.MembershipRules{}

	priority, ok := d.GetOk("priority")
	if ok {
		membershipRules.Priority = priority.(int)
	}

	target, ok := d.GetOk("target")
	if ok {
		membershipRules.Target = target.(string)
	}

	scope := client.Scope{}
	expression, ok := d.GetOk("scope_expression")
	if ok {
		scope.Expression = expression.(string)
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
	scope.Variables = variables
	membershipRules.Scope = scope
	service.MembershipRules = membershipRules

	notEvaluatedCount, ok := d.GetOk("not_evaluated_count")
	if ok {
		service.NotEvaluatedCount = notEvaluatedCount.(int)
	}

	unregisteredCount, ok := d.GetOk("unregistered_count")
	if ok {
		service.UnregisteredCount = unregisteredCount.(int)
	}

	isRegistered, ok := d.GetOk("is_registered")
	if ok {
		service.IsRegistered = isRegistered.(bool)
	}

	applicationScope, ok := d.GetOk("application_scopes")
	if ok {
		service.ApplicationScopes = convertStringArr(applicationScope.([]interface{}))
	}
	localPolicies, ok := d.GetOk("local_policies")
	if ok {
		localPoliciesList := make([]client.LocalPolicy, 0)
		for _, v := range localPolicies.([]interface{}) {
			policy := v.(map[string]interface{})

			localPoliciesList = append(localPoliciesList, client.LocalPolicy{
				Name:                 policy["name"].(string),
				Type:                 policy["type"].(string),
				Description:          policy["description"].(string),
				InboundNetworks:      expandNetworks(policy["inbound_networks"].([]interface{})),
				OutboundNetworks:     expandNetworks(policy["outbound_networks"].([]interface{})),
				BlockMetadataService: policy["block_metadata_service"].(bool),
			})
		}
		service.LocalPolicies = localPoliciesList
	}

	return &service
}

func expandNetworks(networks []interface{}) []client.NetworkRule {
	networkRules := make([]client.NetworkRule, 0)
	for _, n := range networks {
		rule := n.(map[string]interface{})
		networkRules = append(networkRules, client.NetworkRule{
			PortRange:    rule["port_range"].(string),
			ResourceType: rule["resource_type"].(string),
			Resource:     rule["resource"].(string),
			Allow:        rule["allow"].(bool),
		})
	}
	return networkRules
}

func flattenScopeVariables(variables []client.Variable) []map[string]interface{} {
	specs := make([]map[string]interface{}, len(variables))
	for i := range variables {
		specs[i] = map[string]interface{}{
			"attribute": variables[i].Attribute,
			"name":      variables[i].Name,
			"value":     variables[i].Value,
		}
	}

	return specs
}
