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
				Description: "A list of existing gateways' parameters.",
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeString,
							Description: "The ID of the gateway (for example: 8522744b25e2_gateway)",
							Computed: true,
						},
						"logicalname": {
							Type:     schema.TypeString,
							Description: "The logical name of the gateway (for example: 8522744b25e2)",
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Description: "The description of the gateway.",
							Computed: true,
						},
						"version": {
							Type:     schema.TypeString,
							Description: "The version of the gateway.",
							Computed: true,
						},
						"hostname": {
							Type:     schema.TypeString,
							Description: "The name of the gateway's host.",
							Computed: true,
						},
						"public_address": {
							Type:     schema.TypeString,
							Description: "The public IP address of the gateway.",
							Computed: true,
						},
						"grpc_address": {
							Type:     schema.TypeString,
							Description: "The GRPC address of the gateway.",
							Computed: true,
						},
						"status": {
							Type:     schema.TypeString,
							Description: "The status of the gateway.",
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
