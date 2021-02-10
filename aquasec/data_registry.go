package aquasec

import (
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceRegistry() *schema.Resource {
	return &schema.Resource{
		Read: dataRegistryRead,
		Schema: map[string]*schema.Schema{
			"username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"password": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"auto_pull": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"auto_pull_max": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"auto_pull_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"prefixes": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataRegistryRead(d *schema.ResourceData, m interface{}) error {
	log.Println("[DEBUG]  inside dataRegistryRead")
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	reg, err := ac.GetRegistry(name)
	if err != nil {
		return err
	}
	#prefixes := d.Get("prefixes").([]interface{})

	d.Set("username", reg.Username)
	d.Set("password", reg.Password)
	d.Set("name", reg.Name)
	d.Set("type", reg.Type)
	d.Set("url", reg.URL)
	d.Set("auto_pull", reg.AutoPull)
	d.Set("auto_pull_max", reg.AutoPullMax)
	d.Set("auto_pull_time", reg.AutoPullTime)
	d.Set("prefixes", convertStringArr(prefixes))

	log.Println("[DEBUG]  setting id: ", name)
	d.SetId(name)

	return nil
}
