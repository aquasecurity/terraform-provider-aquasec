package aquasec

import (
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGroups() *schema.Resource {
	return &schema.Resource{
		Description: "The data source `aquasec_groups` provides a method to query all groups within the Aqua CSPM" +
			"group database. The fields returned from this query are detailed in the Schema section below.",
		Read: dataGroupRead,
		Schema: map[string]*schema.Schema{
			"groups": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"group_id": {
							Type:     schema.TypeString,
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
		},
	}
}

func dataGroupRead(d *schema.ResourceData, m interface{}) error {
	log.Println("[DEBUG]  inside dataGroup")
	c := m.(*client.Client)
	result, err := c.GetGroups()
	if err == nil {
		groups, id := flattenGroupsData(&result)
		d.SetId(id)
		if err := d.Set("groups", groups); err != nil {
			return err
		}
	} else {
		return err
	}

	return nil
}
