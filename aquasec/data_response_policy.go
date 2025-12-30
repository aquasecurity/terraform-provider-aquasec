package aquasec

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataResponsePolicy() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataResponsePolicyRead,
		Schema: map[string]*schema.Schema{
			"page": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  1,
			},
			"page_size": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  10,
			},
			"scope": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"title": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"pagination_data": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"data": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"title": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"application_scopes": {
							Type: schema.TypeSet,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"last_updated_by": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"last_update": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"created_at": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"trigger": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"predefined": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"input": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"name": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"attributes": {
													Type:     schema.TypeList,
													Computed: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"name": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"operation": {
																Type:     schema.TypeString,
																Computed: true,
															},
														},
													},
												},
											},
										},
									},
									"custom": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"rego": {
													Type:     schema.TypeString,
													Computed: true,
												},
											},
										},
									},
								},
							},
						},
						"outputs": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"type": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func dataResponsePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	policyResp := client.ResponsePolicyResp{
		Page:     d.Get("page").(int),
		PageSize: d.Get("page_size").(int),
		Scope:    d.Get("scope").(string),
		Title:    d.Get("title").(string),
	}

	respPol, err := ac.GetResponsePolicies(policyResp)
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "not found") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	if respPol == nil {
		if err := d.Set("data", []interface{}{}); err != nil {
			return diag.FromErr(err)
		}
		d.SetId("all")
		return nil
	}

	polList := make([]client.ResponsePolicy, 0, len(respPol.Data))
	for _, polItem := range respPol.Data {
		polList = append(polList, polItem)
	}
	policy, _ := flattenResponsePolicies(&polList)

	if err := d.Set("data", policy); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("all")
	return nil
}

func dataResponsePolicyConfig() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataResponsePolicyConfigRead,
		Schema: map[string]*schema.Schema{
			"triggers": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"input": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"asset_types": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"display_name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"field": {
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
						"attributes": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"type": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"input_type": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"asset_types": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Computed: true,
									},
									"display_name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"enabled": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"options": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"display_name": {
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
						"operations": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"type": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"display_name": {
										Type:     schema.TypeString,
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
		},
	}
}

func dataResponsePolicyConfigRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	respPolConfig, err := ac.GetResponsePolicyConfig()
	if err != nil {
		return diag.FromErr(err)
	}
	if respPolConfig == nil {
		d.SetId("config")
		return nil
	}
	if err := d.Set("triggers", flattenResponsePolicyTriggerConfigs(respPolConfig.Triggers)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("input", flattenResponsePolicyInputsConfig(respPolConfig.Input)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("config")
	return nil
}
