package aquasec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceSuppressionRule() *schema.Resource {
	return &schema.Resource{
		Description: "",
		ReadContext: dataSourceSuppressionRuleRead,
		Schema: map[string]*schema.Schema{
			"order_by": {
				Type: schema.TypeString,
				Description: "Specify the parameter by which to sort the results" +
					"Available values : name, -name, created, -created, updated, -updated, enforce, -enforce," +
					"description, -description, created_by, -created_by, enforce_date, -enforce_date, enable, -enable," +
					"updated_by, -updated_by, policy_type, -policy_type, scope, -scope, application_scopes, -application_scopes",
				Optional: true,
				Default:  "name",
			},
			"page": {
				Type:        schema.TypeInt,
				Description: "Specify the starting page for the results",
				Optional:    true,
				Default:     1,
			},
			"page_size": {
				Type:        schema.TypeInt,
				Description: "Specify the number of results per page",
				Optional:    true,
				Default:     20,
			},
			"current_page": {
				Type:        schema.TypeInt,
				Description: "The current page number (starting from 1)",
				Computed:    true,
			},
			"next_page": {
				Type:        schema.TypeInt,
				Description: "The next page number (or zero if not relevant)",
				Computed:    true,
			},
			"returned_count": {
				Type:        schema.TypeInt,
				Description: "The number of records returned on the current page",
				Computed:    true,
			},
			"total_count": {
				Type:        schema.TypeInt,
				Description: "The total number of records across all pages",
				Computed:    true,
			},
			"selection_scopes": {
				Type:        schema.TypeList,
				Description: "The selection scopes applicable to the suppression rules",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"data": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"policy_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"enable": {
							Type:     schema.TypeBool,
							Computed: true,
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
							Computed: true,
						},
						"policy_type": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"controls": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"type": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"scan_type": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"provider": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"service": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"dependency_name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"version": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"dependency_source": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"operator": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"severity": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"vendorfix": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"direct_only": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"reachable_only": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"cve_ids": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"avd_ids": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"dependency_ids": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"ids": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"checks": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"provider_name": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"service_name": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"scan_type": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"check_id": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"check_name": {
													Type:     schema.TypeString,
													Computed: true,
												},
											},
										},
									},
									"patterns": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"ports": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Schema{
											Type: schema.TypeInt,
										},
									},
									"file_changes": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"pattern": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"changes": {
													Type:     schema.TypeList,
													Computed: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
											},
										},
									},
									"target_file": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"target_line": {
										Type:     schema.TypeInt,
										Computed: true,
									},
									"fingerprint": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"file_globs": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"published_date_filter": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"days": {
													Type:     schema.TypeInt,
													Computed: true,
												},
												"enabled": {
													Type:     schema.TypeBool,
													Computed: true,
												},
											},
										},
									},
								},
							},
						},
						"scope": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"expression": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"variables": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"attribute": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"value": {
													Type:     schema.TypeString,
													Computed: true,
												},
											},
										},
									},
								},
							},
						},
						"application_scopes": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func dataSourceSuppressionRuleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	query := client.SuppressionRuleQuery{
		OrderBy:  d.Get("order_by").(string),
		Page:     d.Get("page").(int),
		PageSize: d.Get("page_size").(int),
	}

	wrapper, err := ac.GetSuppressionRules(query)
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "not found") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	var srList []client.SuppressionRule
	for _, respItem := range wrapper.Data {
		b, merr := json.Marshal(respItem)
		if merr != nil {
			continue
		}
		var sr client.SuppressionRule
		if uerr := json.Unmarshal(b, &sr); uerr != nil {
			continue
		}
		srList = append(srList, sr)
	}

	rules, id := flattenSuppressionRules(&srList)

	if id == "" {
		if len(srList) > 0 && srList[0].PolicyID != "" {
			id = srList[0].PolicyID
		} else {
			id = fmt.Sprintf("suppression-rules-page-%d", query.Page)
		}
	}
	d.SetId(id)

	_ = d.Set("current_page", wrapper.CurrentPage)
	_ = d.Set("returned_count", wrapper.ReturnedCount)
	_ = d.Set("next_page", wrapper.NextPage)
	_ = d.Set("total_count", wrapper.TotalCount)
	if wrapper.SelectionScopes != nil {
		_ = d.Set("selection_scopes", wrapper.SelectionScopes)
	}

	if err := d.Set("data", rules); err != nil {
		return diag.FromErr(err)
	}

	return nil
}
