package aquasec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceSuppressionRule() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSuppressionRuleCreate,
		ReadContext:   resourceSuppressionRuleRead,
		UpdateContext: resourceSuppressionRuleUpdate,
		DeleteContext: resourceSuppressionRuleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"policy_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"enable": {
				Type:     schema.TypeBool,
				Required: true,
			},
			"created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"updated": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"created_by": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"updated_by": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"enforce": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"fail_build": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"fail_pr": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"enforcement_schedule": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"clear_schedule": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"policy_type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"controls": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Optional: true,
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice([]string{
									"vulnerabilitySeverity", "cveByIds", "vulnerabilityWithVendorFix",
									"misconfigurations", "misconfigurationsBySeverity", "misconfigurationsByService",
									"secretSeverity", "secretByPatterns", "secretByIds",
									"sastSeverity", "sastAiSeverity", "sastByIds",
									"pipelineMisconfigurations", "pipelineMisconfigurationsBySeverity",
									"dependencyByName", "dependencyByVersion", "dependencyByLicense",
									"manifestSecurityScanChecks", "manifestSourceCodeProtection",
									"imageName", "detectionIds", "detectionsBySeverity",
									"fsPath", "networkUrl", "portRange",
								}, false),
							),
						},
						"scan_type": {
							Type:     schema.TypeString,
							Optional: true,
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice([]string{
									"misconfiguration", "vulnerability", "secret", "pipeline",
									"sast", "dependency", "profile", "manifest",
								}, false),
							),
						},
						"provider": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"service": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"dependency_name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"version": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"dependency_source": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"operator": {
							Type:     schema.TypeString,
							Optional: true,
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice([]string{
									"greater_than", "less_than", "equals_to",
									"greater_than_or_equal_to", "less_than_or_equal_to", "all_versions",
								}, false),
							),
						},
						"severity": {
							Type:     schema.TypeString,
							Optional: true,
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice([]string{"critical", "high", "medium", "low", "unknown"}, false),
							),
						},
						"vendorfix": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"direct_only": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"reachable_only": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"cve_ids": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"avd_ids": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"dependency_ids": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"ids": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"checks": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"provider_name": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateDiagFunc: validation.ToDiagFunc(
											validation.StringLenBetween(0, 255),
										),
									},
									"service_name": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateDiagFunc: validation.ToDiagFunc(
											validation.StringLenBetween(0, 255),
										),
									},
									"check_id": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateDiagFunc: validation.ToDiagFunc(
											validation.StringLenBetween(0, 255),
										),
									},
									"check_name": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateDiagFunc: validation.ToDiagFunc(
											validation.StringLenBetween(0, 255),
										),
									},
									"scan_type": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateDiagFunc: validation.ToDiagFunc(
											validation.StringInSlice([]string{
												"misconfiguration", "vulnerability", "secret", "pipeline", "sast", "dependency", "profile", "manifest",
											}, false)),
									},
								},
							},
						},
						"patterns": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"ports": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeInt},
						},
						"file_changes": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"pattern": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateDiagFunc: validation.ToDiagFunc(
											validation.StringLenBetween(0, 255),
										),
									},
									"changes": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"target_file": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"target_line": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"fingerprint": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"file_globs": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"published_date_filter": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"days": {
										Type:     schema.TypeInt,
										Optional: true,
										Default:  30,
										ValidateDiagFunc: validation.ToDiagFunc(
											validation.IntBetween(1, 999),
										),
									},
									"enabled": {
										Type:     schema.TypeBool,
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"scope": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"expression": {
							Type:     schema.TypeString,
							Optional: true,
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringLenBetween(0, 255),
							),
						},
						"variables": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"attribute": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateDiagFunc: validation.ToDiagFunc(
											validation.StringInSlice([]string{
												"repository.id", "repository.name", "repository.branch", "repository.topic",
												"repository.label", "repository.organization", "repository.provider",
											}, false),
										),
									},
									"value": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"application_scopes": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceSuppressionRuleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	rule, _ := expandSuppressionRule(d)

	created, err := ac.CreateSuppressionRule(rule)
	if err != nil {
		return diag.FromErr(err)
	}
	if created.PolicyID == "" {
		return diag.Errorf("API did not return a policy_id for created suppression rule")
	}
	d.SetId(created.PolicyID)

	if created.Name != "" {
		_ = d.Set("name", created.Name)
	} else if rule.Name != "" {
		_ = d.Set("name", rule.Name)
	} else if v, ok := d.GetOk("name"); ok {
		_ = d.Set("name", v.(string))
	}

	if created.Description != "" {
		_ = d.Set("description", created.Description)
	} else if rule.Description != "" {
		_ = d.Set("description", rule.Description)
	}

	_ = d.Set("enable", created.Enable || rule.Enable)

	_ = d.Set("clear_schedule", created.ClearSchedule || rule.ClearSchedule)

	if len(created.ApplicationScopes) > 0 {
		_ = d.Set("application_scopes", created.ApplicationScopes)
	} else if len(rule.ApplicationScopes) > 0 {
		_ = d.Set("application_scopes", rule.ApplicationScopes)
	} else if v, ok := d.GetOk("application_scopes"); ok {
		_ = d.Set("application_scopes", v)
	}

	if created.Controls != nil && len(created.Controls) > 0 {
		_ = d.Set("controls", flattenSuppresionRuleControl(created.Controls))
	} else if v, ok := d.GetOk("controls"); ok {
		_ = d.Set("controls", v)
	}

	if created.Scope.Expression != "" || len(created.Scope.Variables) > 0 {
		_ = d.Set("scope", flattenSuppresstionRuleScope(created.Scope))
	} else if v, ok := d.GetOk("scope"); ok {
		_ = d.Set("scope", v)
	}

	return resourceSuppressionRuleRead(ctx, d, m)
}

func resourceSuppressionRuleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	id := d.Id()

	rule, err := ac.GetSuppressionRule(id)
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	if rule == nil {
		d.SetId("")
		return nil
	}

	if rule.Name != "" {
		_ = d.Set("name", rule.Name)
	} else if v, ok := d.GetOk("name"); ok {
		_ = d.Set("name", v.(string))
	}

	_ = d.Set("policy_id", rule.PolicyID)

	if rule.Description != "" {
		_ = d.Set("description", rule.Description)
	} else if v, ok := d.GetOk("description"); ok {
		_ = d.Set("description", v.(string))
	}

	_ = d.Set("enable", rule.Enable || d.Get("enable").(bool))

	_ = d.Set("created", rule.Created)
	_ = d.Set("updated", rule.Updated)
	_ = d.Set("created_by", rule.CreatedBy)
	_ = d.Set("updated_by", rule.UpdatedBy)
	_ = d.Set("enforce", rule.Enforce)
	_ = d.Set("fail_build", rule.FailBuild)
	_ = d.Set("fail_pr", rule.FailPR)
	_ = d.Set("enforcement_schedule", rule.EnforcementSchedule)
	_ = d.Set("clear_schedule", rule.ClearSchedule)
	_ = d.Set("policy_type", rule.PolicyType)

	if rule.Controls != nil && len(rule.Controls) > 0 {
		_ = d.Set("controls", flattenSuppresionRuleControl(rule.Controls))
	} else if v, ok := d.GetOk("controls"); ok {
		_ = d.Set("controls", v)
	}

	if createdScope := rule.Scope; createdScope.Expression != "" || len(createdScope.Variables) > 0 {
		_ = d.Set("scope", flattenSuppresstionRuleScope(createdScope))
	} else if v, ok := d.GetOk("scope"); ok {
		_ = d.Set("scope", v)
	}

	if len(rule.ApplicationScopes) > 0 {
		_ = d.Set("application_scopes", rule.ApplicationScopes)
	} else if v, ok := d.GetOk("application_scopes"); ok {
		_ = d.Set("application_scopes", v)
	}

	return nil
}

func resourceSuppressionRuleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	id := d.Id()

	if d.HasChanges("name", "description", "enable", "enforce", "fail_build", "fail_pr", "clear_schedule", "policy_type", "controls", "scope", "application_scopes") {
		rule, _ := expandSuppressionRule(d)
		err := ac.UpdateSuppressionRule(id, rule)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	return resourceSuppressionRuleRead(ctx, d, m)
}

func resourceSuppressionRuleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	id := d.Id()

	err := ac.DeleteSuppressionRule(id)
	if err == nil {
		d.SetId("")
	} else {
		return diag.FromErr(err)
	}
	return nil
}

func expandSuppressionRule(d *schema.ResourceData) (*client.SuppressionRule, string) {
	sr := client.SuppressionRule{}

	if name, ok := d.GetOk("name"); ok {
		sr.Name = name.(string)
	}
	if description, ok := d.GetOk("description"); ok {
		sr.Description = description.(string)
	}
	if policy_id, ok := d.GetOk("policy_id"); ok {
		sr.PolicyID = policy_id.(string)
	}
	sr.Enable = d.Get("enable").(bool)
	if created, ok := d.GetOk("created"); ok {
		if s, ok := created.(string); ok && s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				sr.Created = &t
			}
		}
	}
	if updated, ok := d.GetOk("updated"); ok {
		if s, ok := updated.(string); ok && s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				sr.Updated = &t
			}
		}
	}
	if createdBy, ok := d.GetOk("created_by"); ok {
		sr.CreatedBy = createdBy.(string)
	}
	if updatedBy, ok := d.GetOk("updated_by"); ok {
		sr.UpdatedBy = updatedBy.(string)
	}
	if enforce, ok := d.GetOk("enforce"); ok {
		sr.Enforce = enforce.(bool)
	}
	if fail_build, ok := d.GetOk("fail_build"); ok {
		sr.FailBuild = fail_build.(bool)
	}
	if fail_pr, ok := d.GetOk("fail_pr"); ok {
		sr.FailPR = fail_pr.(bool)
	}
	if enforcement_schedule, ok := d.GetOk("enforcement_schedule"); ok {
		sr.EnforcementSchedule = enforcement_schedule.(string)
	}
	if clear_schedule, ok := d.GetOk("clear_schedule"); ok {
		sr.ClearSchedule = clear_schedule.(bool)
	}
	if policy_type, ok := d.GetOk("policy_type"); ok {
		if s, ok := policy_type.(string); ok && s != "" {
			sr.PolicyType = client.PolicyType(s)
		}
	}
	if v, ok := d.GetOk("controls"); ok {
		rawControls := v.([]interface{})
		var controls []client.BuildSecuritypolicyControl
		for _, rc := range rawControls {
			if rc == nil {
				continue
			}
			m, ok := rc.(map[string]interface{})
			if !ok {
				continue
			}

			c := client.BuildSecuritypolicyControl{}

			if ctype, ok := m["type"].(string); ok {
				c.Type = client.PolicyControlType(ctype)
			}
			if scan_type, ok := m["scan_type"].(string); ok {
				c.ScanType = client.ScanType(scan_type)
			}
			if provider, ok := m["provider"].(string); ok {
				c.Provider = provider
			}
			if service, ok := m["service"].(string); ok {
				c.Service = service
			}
			if dependency_name, ok := m["dependency_name"].(string); ok {
				c.DependencyName = dependency_name
			}
			if version, ok := m["version"].(string); ok {
				c.Version = version
			}
			if dependency_source, ok := m["dependency_source"].(string); ok {
				c.DependencySource = dependency_source
			}
			if operator, ok := m["operator"].(string); ok {
				c.Operator = client.Operator(operator)
			}
			if severity, ok := m["severity"].(string); ok {
				c.Severity = client.Severity(severity)
			}
			if vendorFix, ok := m["vendorfix"].(bool); ok {
				c.VendorFix = vendorFix
			}
			if direct_only, ok := m["direct_only"].(bool); ok {
				c.DirectOnly = direct_only
			}
			if reachable_only, ok := m["reachable_only"].(bool); ok {
				c.ReachableOnly = reachable_only
			}
			if cve_ids, ok := m["cve_ids"].([]interface{}); ok {
				c.CveIDs = convertStringArr(cve_ids)
			}
			if avd_ids, ok := m["avd_ids"].([]interface{}); ok {
				c.AvdIDs = convertStringArr(avd_ids)
			}
			if dependency_ids, ok := m["dependency_ids"].([]interface{}); ok {
				c.DependencyIDs = convertStringArr(dependency_ids)
			}
			if ids, ok := m["ids"].([]interface{}); ok {
				c.IDs = convertStringArr(ids)
			}
			if vv, ok := m["checks"].([]interface{}); ok && len(vv) > 0 {
				var checks []client.Check
				for _, vi := range vv {
					if vi == nil {
						continue
					}
					if cm, ok := vi.(map[string]interface{}); ok {
						chk := client.Check{}
						if provider_name, ok := cm["provider_name"].(string); ok {
							chk.ProviderName = provider_name
						}
						if service_name, ok := cm["service_name"].(string); ok {
							chk.ServiceName = service_name
						}
						if check_id, ok := cm["check_id"].(string); ok {
							chk.CheckID = check_id
						}
						if check_name, ok := cm["check_name"].(string); ok {
							chk.CheckName = check_name
						}
						if scan_type, ok := cm["scan_type"].(string); ok {
							chk.ScanType = client.ScanType(scan_type)
						}
						checks = append(checks, chk)
					}
				}
				c.Checks = checks
			}
			if patterns, ok := m["patterns"].([]interface{}); ok {
				c.Patterns = convertStringArr(patterns)
			}
			if ports, ok := m["ports"].([]interface{}); ok {
				c.Ports = convertIntArr(ports)
			}
			if file_changes, ok := m["file_changes"].([]interface{}); ok && len(file_changes) > 0 {
				if fcMap, ok := file_changes[0].(map[string]interface{}); ok {
					fc := client.FileChanges{}
					if pattern, ok := fcMap["pattern"].(string); ok {
						fc.Pattern = pattern
					}
					if changes, ok := fcMap["changes"].([]interface{}); ok {
						fc.Changes = convertStringArr(changes)
					}
					c.FileChanges = fc
				}
			}
			if target_file, ok := m["target_file"].(string); ok {
				c.TargetFile = target_file
			}
			if target_line, ok := m["target_line"].(int); ok {
				c.TargetLine = target_line
			}
			if fingerprint, ok := m["fingerprint"].(string); ok {
				c.Fingerprint = fingerprint
			}
			if file_globs, ok := m["file_globs"].([]interface{}); ok {
				c.FileGlobs = convertStringArr(file_globs)
			}
			if published_date_filter, ok := m["published_date_filter"].([]interface{}); ok && len(published_date_filter) > 0 {
				if pfMap, ok := published_date_filter[0].(map[string]interface{}); ok {
					pf := client.PublishedDateFilter{}
					if days, ok := pfMap["days"].(int); ok {
						pf.Days = days
					}
					if enabled, ok := pfMap["enabled"].(bool); ok {
						pf.Enabled = enabled
					}
					c.PublishedDateFilter = pf
				}
			}
			controls = append(controls, c)
		}
		if len(controls) > 0 {
			sr.Controls = controls
		}
	}
	if scope, ok := d.GetOk("scope"); ok {
		rawScope := scope.([]interface{})
		if len(rawScope) > 0 && rawScope[0] != nil {
			m := rawScope[0].(map[string]interface{})
			s := client.BuildSecurityPolicyScope{}
			if expression, ok := m["expression"].(string); ok {
				s.Expression = expression
			}
			if variable, ok := m["variables"].([]interface{}); ok && len(variable) > 0 {
				var vars []client.BuildSecurityScopeVariable
				for _, vi := range variable {
					if vi == nil {
						continue
					}
					if vmap, ok := vi.(map[string]interface{}); ok {
						variableObj := client.BuildSecurityScopeVariable{}
						if attr, ok := vmap["attribute"].(string); ok && attr != "" {
							variableObj.Attribute = client.Attribute(attr)
						}
						if val, ok := vmap["value"].(string); ok {
							variableObj.Value = val
						}
						vars = append(vars, variableObj)
					}
				}
				s.Variables = vars
			}
			sr.Scope = s
		}
	}
	if application_scopes, ok := d.GetOk("application_scopes"); ok {
		if application_scope, ok := application_scopes.([]interface{}); ok {
			sr.ApplicationScopes = convertStringArr(application_scope)
		}
	}
	return &sr, ""
}
