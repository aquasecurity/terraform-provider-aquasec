package aquasec

import (
	"context"
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceUsersSaas() *schema.Resource {
	return &schema.Resource{
		Description: "The data source `aquasec_users_saas` provides a method to query all saas users within the Aqua " +
			"users management. The fields returned from this query are detailed in the Schema section below.",
		ReadContext: resourceReadSaas,
		Schema: map[string]*schema.Schema{
			"users": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"dashboard": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"csp_roles": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"user_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"email": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"confirmed": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"password_reset": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"send_announcements": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"send_scan_results": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"send_new_plugins": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"send_new_risks": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"account_admin": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"mfa_enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"provider": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"multiaccount": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"groups": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"id": {
										Type:     schema.TypeInt,
										Computed: true,
									},
									"name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"created": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
						"logins": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"id": {
										Type:     schema.TypeInt,
										Computed: true,
									},
									"ip_address": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"created": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"user_id": {
										Type:     schema.TypeInt,
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

func resourceReadSaas(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	log.Println("[DEBUG]  inside dataUser")
	c := m.(*client.Client)
	result, err := c.GetUsers()
	if err == nil {
		users, id := flattenUsersSaasData(&result)
		d.SetId(id)
		if err := d.Set("users", users); err != nil {
			return diag.FromErr(err)
		}
	} else {
		return diag.FromErr(err)
	}

	return nil
}
