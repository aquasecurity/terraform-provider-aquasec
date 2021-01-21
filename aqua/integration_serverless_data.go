package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func dataSourceServerless() *schema.Resource {
	return &schema.Resource{
		Read: dataServerlessRead,
		Schema: map[string]*schema.Schema{
			"username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"password": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"region": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"subscription_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tenant_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
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
			"sqs_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"compute_provider": {
				Type:     schema.TypeInt,
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
			"include_tags": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"exclude_tags": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataServerlessRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(client.Client)
	name := d.Get("name").(string)
	reg, err := ac.GetServerlessProject(name)
	if err != nil {
		return err
	}
	include := d.Get("include_tags").([]interface{})
	exclude := d.Get("exclude_tags").([]interface{})

	d.Set("username", reg.Username)
	d.Set("password", reg.Password)
	d.Set("name", reg.Name)
	d.Set("region", reg.Region)
	d.Set("subscription_id", reg.SubscriptionID)
	d.Set("tenant_id", reg.TenantID)
	d.Set("compute_provider", reg.ComputeProvider)
	d.Set("auto_pull", reg.AutoPull)
	d.Set("auto_pull_time", reg.AutoPullTime)
	d.Set("include", convertStringArr(include))
	d.Set("exclude", convertStringArr(exclude))

	log.Println("[DEBUG]  setting id: ", name)
	d.SetId(name)

	return nil
}
