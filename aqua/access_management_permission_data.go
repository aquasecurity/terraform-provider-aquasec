package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func dataSourcePermissionSet() *schema.Resource {
	return &schema.Resource{
		Read: dataPermissionsRead,
		Schema: map[string]*schema.Schema{
			"description": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"author": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"is_super": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"ui_access": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"actions": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataPermissionsRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(client.Client)
	id := d.Get("name").(string)
	ps, err := ac.GetPermissionSet(id)
	if err != nil {
		return err
	}
	actions := d.Get("actions").([]interface{})

	d.Set("description", ps.Description)
	d.Set("author", ps.Author)
	d.Set("name", ps.Name)
	d.Set("ui_access", ps.UIAccess)
	d.Set("is_super", ps.IsSuper)
	d.Set("actions", convertStringArr(actions))

	log.Println("[DEBUG]  setting id: ", id)
	d.SetId(id)

	return nil
}
