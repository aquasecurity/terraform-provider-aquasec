package aquasec

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceResponsePolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceResponsePolicyCreate,
		ReadContext:   resourceResponsePolicyRead,
		UpdateContext: resourceResponsePolicyUpdate,
		DeleteContext: resourceResponsePolicyDelete,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"title": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"application_scopes": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			"last_updated_by": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"created_at": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"last_update": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"trigger": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"predefined": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringIsNotEmpty,
						},
						"input": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"attributes": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"name": {
													Type:     schema.TypeString,
													Required: true,
												},
												"operation": {
													Type:     schema.TypeString,
													Required: true,
												},
												"value": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
								},
							},
						},
						"custom": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"rego": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"outputs": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"type": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
		},
	}
}

func resourceResponsePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	var appScopes []string
	if v, ok := d.GetOk("application_scopes"); ok {
		appScopes = convertStringArr(v.(*schema.Set).List())
	}

	policy := &client.ResponsePolicy{
		Title:            d.Get("title").(string),
		Description:      d.Get("description").(string),
		Enabled:          d.Get("enabled").(bool),
		ApplicationScope: appScopes,
	}

	if v, ok := d.GetOk("trigger"); ok {
		triggerList := v.([]interface{})
		if expanded := expandResponsePolicyTrigger(triggerList); expanded != nil {
			policy.Trigger = expanded
		}
	}

	if v, ok := d.GetOk("outputs"); ok {
		outputsList := v.([]interface{})
		policy.Outputs = expandResponsePolicyOutputs(outputsList)
	}
	if err := ac.CreateResponsePolicy(policy); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(fmt.Sprintf("%d", policy.Id))
	return resourceResponsePolicyRead(ctx, d, m)
}

func resourceResponsePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	policy, err := ac.GetResponsePolicy(d.Id())
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") || strings.Contains(fmt.Sprintf("%s", err), "no content") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	if policy == nil {
		d.SetId("")
		return nil
	}

	_ = d.Set("title", policy.Title)
	_ = d.Set("description", policy.Description)
	_ = d.Set("enabled", policy.Enabled)
	_ = d.Set("application_scopes", policy.ApplicationScope)
	_ = d.Set("trigger", flattenResponsePolicyTrigger(policy.Trigger))
	_ = d.Set("outputs", flattenResponsePolicyOutputs(policy.Outputs))
	_ = d.Set("last_updated_by", policy.LastUpdatedBy)
	_ = d.Set("created_at", policy.CreatedAt)
	_ = d.Set("last_update", policy.LastUpdate)
	_ = d.Set("id", fmt.Sprintf("%d", policy.Id))
	return nil
}

func resourceResponsePolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	id := d.Id()

	if !d.HasChanges(
		"title",
		"description",
		"enabled",
		"application_scopes",
		"trigger",
		"outputs",
	) {
		return resourceResponsePolicyRead(ctx, d, m)
	}

	var appScopes []string
	if v, ok := d.GetOk("application_scopes"); ok {
		appScopes = convertStringArr(v.(*schema.Set).List())
	}

	policy := &client.ResponsePolicy{
		Title:            d.Get("title").(string),
		Description:      d.Get("description").(string),
		Enabled:          d.Get("enabled").(bool),
		ApplicationScope: appScopes,
	}

	if v, ok := d.GetOk("trigger"); ok {
		policy.Trigger = expandResponsePolicyTrigger(v.([]interface{}))
	} else {
		policy.Trigger = nil
	}

	if v, ok := d.GetOk("outputs"); ok {
		policy.Outputs = expandResponsePolicyOutputs(v.([]interface{}))
	} else {
		policy.Outputs = []client.ResponsePolicyOutput{}
	}

	if _, err := ac.UpdateResponsePolicy(id, policy); err != nil {
		return diag.FromErr(err)
	}

	return resourceResponsePolicyRead(ctx, d, m)
}

func resourceResponsePolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	id := d.Id()
	err := ac.DeleteResponsePolicy(id)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
