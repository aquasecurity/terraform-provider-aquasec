package aquasec

import (
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGateways() *schema.Resource {
	return &schema.Resource{
		Description: "The data source `aquasec_gateways` provides a method to query all gateways within the Aqua ",
		Read:        dataGatewayRead,
		Schema: map[string]*schema.Schema{
			"gateways": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"logicalname": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"version": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"hostname": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"public_address": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"grpc_address": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"status": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func dataGatewayRead(d *schema.ResourceData, m interface{}) error {
	log.Println("[DEBUG]  inside dataGateway")
	c := m.(*client.Client)
	result, err := c.GetGateways()
	if err == nil {
		gateways, id := flattenGatewaysData(&result)
		d.SetId(id)
		if err := d.Set("gateways", gateways); err != nil {
			return err
		}
	} else {
		return err
	}

	return nil
}
