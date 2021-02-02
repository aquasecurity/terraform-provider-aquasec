package aquasec

import (
	"context"
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceUsers() *schema.Resource {
	return &schema.Resource{
		ReadContext: resourceRead,
		Schema: map[string]*schema.Schema{
			"users": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"user_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"email": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"first_time": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"roles": {
							Type:     schema.TypeSet,
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

func flattenUsersData(users *[]client.User) ([]interface{}, string) {
	id := ""
	if users != nil {
		us := make([]interface{}, len(*users), len(*users))

		for i, user := range *users {
			id = id + user.ID
			u := make(map[string]interface{})

			u["user_id"] = user.ID
			u["name"] = user.Name
			u["email"] = user.Email
			u["roles"] = user.Roles
			// oi["coffee_price"] = user.
			// oi["coffee_image"] = user.Coffee.Image
			// oi["quantity"] = user.Quantity

			us[i] = u
		}

		return us, id
	}

	return make([]interface{}, 0), ""
}

func resourceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	log.Println("[DEBUG]  inside dataUser")
	c := m.(*client.Client)
	result, err := c.GetUsers()
	if err != nil {
		return diag.FromErr(err)
	}
	users, id := flattenUsersData(&result)
	d.SetId(id)
	if err := d.Set("users", users); err != nil {
		return diag.FromErr(err)
	}

	return nil
}
