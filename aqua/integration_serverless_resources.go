package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"time"
)

func resourceServerless() *schema.Resource {
	return &schema.Resource{
		Create: resourceServerlessCreate,
		Read:   resourceServerlessRead,
		Update: resourceServerlessUpdate,
		Delete: resourceServerlessDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"last_updated": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"author": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"region": {
				Type:     schema.TypeString,
				Required: true,
			},
			"subscription_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"tenant_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"password": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"username": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"compute_provider": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"auto_pull": {
				Type:     schema.TypeBool,
				Required: true,
			},
			"auto_pull_time": {
				Type:     schema.TypeString,
				Required: true,
			},
			"include_tags": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"exclude_tags": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

// resourceServerlessCreate will create a serverless project integration
func resourceServerlessCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	include := d.Get("include_tags").([]interface{})
	exclude := d.Get("exclude_tags").([]interface{})
	proj := client.ServerlessProject{
		Username:        d.Get("username").(string),
		Password:        d.Get("password").(string),
		Name:            d.Get("name").(string),
		Description:     d.Get("description").(string),
		Region:          d.Get("region").(string),
		TenantID:        d.Get("tenant_id").(string),
		SubscriptionID:  d.Get("subscription_id").(string),
		ComputeProvider: d.Get("compute_provider").(int),
		AutoPull:        d.Get("auto_pull").(bool),
		AutoPullTime:    d.Get("auto_pull_time").(string),
		IncludeTags:     convertStringArr(include),
		ExcludeTags:     convertStringArr(exclude),
	}

	err := ac.CreateServerlessProject(proj)
	if err != nil {
		return err
	}

	d.SetId(d.Get("name").(string))

	err = resourceServerlessRead(d, m)

	return err
}

func resourceServerlessRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	id := d.Id()
	r, err := ac.GetServerlessProject(id)
	if err != nil {
		log.Println("[DEBUG]  error calling ac.GetServerless: ", r)
		return err
	}
	return nil
}

func resourceServerlessUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)

	if d.HasChanges("username", "password", "description", "region", "compute_provider", "auto_pull",
		"auto_pull_time", "include_tags", "exclude_tags", "subscription_id", "tenant_id") {
		include := d.Get("include_tags").([]interface{})
		exclude := d.Get("exclude_tags").([]interface{})
		proj := client.ServerlessProject{
			Name:            d.Get("name").(string),
			Region:          d.Get("region").(string),
			TenantID:        d.Get("tenant_id").(string),
			SubscriptionID:  d.Get("subscription_id").(string),
			Description:     d.Get("description").(string),
			Username:        d.Get("username").(string),
			Password:        d.Get("password").(string),
			ComputeProvider: d.Get("compute_provider").(int),
			AutoPull:        d.Get("auto_pull").(bool),
			AutoPullTime:    d.Get("auto_pull_time").(string),
			IncludeTags:     convertStringArr(include),
			ExcludeTags:     convertStringArr(exclude),
		}

		err := c.UpdateServerlessProject(proj)
		if err != nil {
			log.Println("[DEBUG]  error while updating serverless: ", err)
			return err
		}
		_ = d.Set("last_updated", time.Now().Format(time.RFC850))
	}

	return nil
}

func resourceServerlessDelete(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	id := d.Id()
	err := c.DeleteServerlessProject(id)
	log.Println(err)
	if err != nil {
		log.Println("[DEBUG]  error deleting registry: ", err)
		return err
	}
	d.SetId("")

	return err
}
