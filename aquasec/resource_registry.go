package aquasec

import (
	"log"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRegistry() *schema.Resource {
	return &schema.Resource{
		Create: resourceRegistryCreate,
		Read:   resourceRegistryRead,
		Update: resourceRegistryUpdate,
		Delete: resourceRegistryDelete,
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
			"password": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
			},
			"username": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"auto_pull": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_pull_max": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"auto_pull_time": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"prefixes": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceRegistryCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	// Get and Convert Roles
	prefixes := d.Get("prefixes").([]interface{})
	registry := client.Registry{
		Username:     d.Get("username").(string),
		Password:     d.Get("password").(string),
		Name:         d.Get("name").(string),
		Type:         d.Get("type").(string),
		URL:          d.Get("url").(string),
		AutoPull:     d.Get("auto_pull").(bool),
		AutoPullMax:  d.Get("auto_pull_max").(int),
		AutoPullTime: d.Get("auto_pull_time").(string),
		Prefixes:     convertStringArr(prefixes),
	}

	err := ac.CreateRegistry(registry)
	if err != nil {
		return err
	}
	//d.SetId(d.Get("name").(string))

	err = resourceRegistryRead(d, m)
	if err == nil {
		d.SetId(d.Get("name").(string))
	} else {
		return err
	}

	return nil
}

func resourceRegistryRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	//id := d.Id()
	id := d.Get("name").(string)
	r, err := ac.GetRegistry(id)
	if err != nil {
		log.Println("[DEBUG]  error calling ac.GetRegistry: ", r)
		return err
	}
	return nil
}

func resourceRegistryUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)

	if d.HasChanges("name", "username", "password", "url", "type", "auto_pull", "auto_pull_max", "auto_pull_time", "prefixes") {
		prefixes := d.Get("prefixes").([]interface{})
		registry := client.Registry{
			Name:         d.Get("name").(string),
			Type:         d.Get("type").(string),
			Username:     d.Get("username").(string),
			Password:     d.Get("password").(string),
			URL:          d.Get("url").(string),
			AutoPull:     d.Get("auto_pull").(bool),
			AutoPullMax:  d.Get("auto_pull_max").(int),
			AutoPullTime: d.Get("auto_pull_time").(string),
			Prefixes:     convertStringArr(prefixes),
		}

		err := c.UpdateRegistry(registry)
		if err == nil {
			_ = d.Set("last_updated", time.Now().Format(time.RFC850))
		} else {
			log.Println("[DEBUG]  error while updating registry: ", err)
			return err
		}
		//_ = d.Set("last_updated", time.Now().Format(time.RFC850))
	}

	return nil
}

func resourceRegistryDelete(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	id := d.Id()
	err := c.DeleteRegistry(id)

	if err == nil {
		d.SetId("")
	} else {
		log.Println("[DEBUG]  error deleting registry: ", err)
		return err
	}
	//d.SetId("")

	return err
}
