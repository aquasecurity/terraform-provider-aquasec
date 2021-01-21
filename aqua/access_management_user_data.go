package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func dataSourceUser() *schema.Resource {
	return &schema.Resource{
		Read: dataUserRead,
		Schema: map[string]*schema.Schema{
			"user_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"password": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"password_confirm": {
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
	}
}

func dataUserRead(d *schema.ResourceData, m interface{}) error {
	log.Println("[DEBUG]  inside dataUser")
	c := m.(client.Client)
	id := d.Get("user_id").(string)
	user, err := c.GetUser(id)
	if err != nil {
		return err
	}
	roles := d.Get("roles").([]interface{})

	d.Set("user_id", user.ID)
	d.Set("password", user.Password)
	d.Set("name", user.Name)
	d.Set("email", user.Email)
	d.Set("roles", convertStringArr(roles))

	log.Println("[DEBUG]  setting id: ", id)
	d.SetId(id)

	return nil
}
