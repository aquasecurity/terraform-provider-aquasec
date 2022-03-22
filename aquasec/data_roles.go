package aquasec

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceRoles() *schema.Resource {
	return &schema.Resource{
		Description: "The data source `aquasec_roles` provides a method to query all roles within the Aqua account management" +
			"role database. The fields returned from this query are detailed in the Schema section below.",
		ReadContext: dataRolesRead,
		Schema: map[string]*schema.Schema{
			"roles": {
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
						"updated_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"permission": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"scopes": {
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

func dataRolesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	log.Println("[DEBUG]  inside dataGroup")
	c := m.(*client.Client)
	roles, err := c.GetRoles()

	if err != nil {
		return diag.FromErr(err)
	}

	id := ""
	dataRoles := make([]interface{}, len(roles), len(roles))

	for i, role := range roles {
		id = id + role.Name
		r := make(map[string]interface{})
		r["name"] = role.Name
		r["description"] = role.Description
		r["updated_at"] = role.UpdatedAt
		r["permission"] = role.Permission
		r["scopes"] = role.Scopes
		dataRoles[i] = r
	}

	d.SetId(id)
	if err := d.Set("roles", dataRoles); err != nil {
		return diag.FromErr(err)
	}
	return nil
}
