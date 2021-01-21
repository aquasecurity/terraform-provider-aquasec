package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func dataSourceRole() *schema.Resource {
	return &schema.Resource{
		Read: dataRoleRead,
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
			"permission": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"scopes": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"groups": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"users": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataRoleRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(client.Client)
	id := d.Get("name").(string)
	ps, err := ac.GetRole(id)
	if err != nil {
		return err
	}
	scopes := d.Get("scopes").([]interface{})
	groups := d.Get("groups").([]interface{})
	users := d.Get("scopes").([]interface{})

	d.Set("description", ps.Description)
	d.Set("author", ps.Author)
	d.Set("name", ps.Name)
	d.Set("ui_access", ps.Permission)
	d.Set("scopes", convertStringArr(scopes))
	d.Set("groups", convertStringArr(groups))
	d.Set("users", convertStringArr(users))

	log.Println("[DEBUG]  setting id: ", id)
	d.SetId(id)

	return nil
}
