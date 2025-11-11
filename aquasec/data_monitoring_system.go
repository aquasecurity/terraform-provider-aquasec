package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceMonitoringSystem() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMonitoringSystemRead,
		Schema: map[string]*schema.Schema{
			"monitors": {
				Type:        schema.TypeList,
				Description: "List of existing monitoring systems.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Description: "",
							Computed:    true,
						},
						"token": {
							Type:        schema.TypeString,
							Description: "",
							Computed:    true,
							Sensitive:   true,
						},
						"type": {
							Type:        schema.TypeString,
							Description: "",
							Computed:    true,
						},
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Computed:    true,
						},
						"interval": {
							Type:        schema.TypeInt,
							Description: "",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func dataSourceMonitoringSystemRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	result, err := ac.GetMonitoringSystems()
	if err != nil {
		return diag.FromErr(err)
	}
	monitors := flattenMonitoringSystem(&result)
	if err := d.Set("monitors", monitors); err != nil {
		return diag.FromErr(err)
	}

	if len(result) == 0 {
		d.SetId("")
		return nil
	}
	d.SetId(result[0].Name)
	return nil
}
