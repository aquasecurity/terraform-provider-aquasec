package aquasec

import (
	"context"
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourcePermissionsSets() *schema.Resource {
	return &schema.Resource{
		Description: "The data source `aquasec_permissions_sets` provides a method to query all permissions within the Aqua CSPM" +
			"The fields returned from this query are detailed in the Schema section below.",
		ReadContext: dataPermissionsSetRead,
		Schema: map[string]*schema.Schema{
			"permissions_sets": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"author": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"updated_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ui_access": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"is_super": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"actions": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
		},
	}
}

func dataPermissionsSetRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	log.Println("[DEBUG]  inside dataUser")
	c := m.(*client.Client)
	permissionsSets, err := c.GetPermissionsSets()

	if err != nil {
		return diag.FromErr(err)
	}

	id := ""
	ps := make([]interface{}, len(permissionsSets), len(permissionsSets))

	for i, permissionsSet := range permissionsSets {
		id = id + permissionsSet.Name
		p := make(map[string]interface{})
		p["name"] = permissionsSet.Name
		p["description"] = permissionsSet.Description
		p["actions"] = permissionsSet.Actions
		p["author"] = permissionsSet.Author
		p["ui_access"] = permissionsSet.UiAccess
		p["is_super"] = permissionsSet.IsSuper
		p["updated_at"] = permissionsSet.UpdatedAt
		ps[i] = p
	}

	d.SetId(id)
	if err := d.Set("permissions_sets", ps); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

// func dataPermissionsSetRead(d *schema.ResourceData, m interface{}) error {
// 	log.Println("[DEBUG]  inside dataPermissionsSet")
// 	c := m.(*client.Client)
// 	result, err := c.GetPermissionsSets()
// 	if err == nil {
// 		permissionsSets, id := flattenPermissionsSetsData(&result)
// 		d.SetId(id)
// 		if err := d.Set("permissions_sets", permissionsSets); err != nil {
// 			return err
// 		}
// 	} else {
// 		return err
// 	}

// 	return nil
// }

// func flattenPermissionsSetsData(permissionsSets *[]client.PermissionsSet) ([]interface{}, string) {
// 	id := ""
// 	if permissionsSets != nil {
// 		us := make([]interface{}, len(*permissionsSets), len(*permissionsSets))

// 		for i, permissionsSet := range *permissionsSets {
// 			id = id + permissionsSet.ID
// 			u := make(map[string]interface{})
// 			u["id"] = permissionsSet.ID
// 			u["name"] = permissionsSet.Name
// 			u["description"] = permissionsSet.Description
// 			u["actions"] = permissionsSet.Actions
// 			u["author"] = permissionsSet.Author
// 			u["ui_access"] = permissionsSet.UiAccess
// 			u["is_super"] = permissionsSet.IsSuper
// 			u["updated_at"] = permissionsSet.UpdatedAt

// 			us[i] = u
// 		}

// 		return us, id
// 	}

// 	return make([]interface{}, 0), ""
// }
