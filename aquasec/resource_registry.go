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
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"last_updated": {
				Type:        schema.TypeString,
				Description: "The last time the registry was modified in UNIX time",
				Optional:    true,
				Computed:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "The username of the user who created or last modified the registry",
				Optional:    true,
				Computed:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the registry; string, required - this will be treated as the registry's ID, so choose a simple alphanumerical name without special signs and spaces",
				Required:    true,
				ForceNew:    true,
			},
			"password": {
				Type:        schema.TypeString,
				Description: "The password for registry authentication",
				Optional:    true,
			},
			"type": {
				Type:        schema.TypeString,
				Description: "Registry type (HUB / V1 / V2 / ENGINE / AWS / GCR).",
				Required:    true,
			},
			"username": {
				Type:        schema.TypeString,
				Description: "The username for registry authentication.",
				Optional:    true,
			},
			"url": {
				Type:        schema.TypeString,
				Description: "The URL, address or region of the registry",
				Optional:    true,
				Computed:    true,
			},
			"auto_pull": {
				Type:        schema.TypeBool,
				Description: "Whether to automatically pull images from the registry on creation and daily",
				Optional:    true,
			},
			"auto_pull_max": {
				Type:        schema.TypeInt,
				Description: "Maximum number of repositories to pull every day, defaults to 100",
				Optional:    true,
			},
			"auto_pull_time": {
				Type:        schema.TypeString,
				Description: "The time of day to start pulling new images from the registry, in the format HH:MM (24-hour clock), defaults to 03:00",
				Optional:    true,
			},
			"scanner_type": {
				Type:        schema.TypeString,
				Description: "The Scanner type",
				Optional:    true,
			},
			"prefixes": {
				Type:        schema.TypeList,
				Description: "List of possible prefixes to image names pulled from the registry",
				Required:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceRegistryCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "" {
		scannerType = "any"
	}
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
		ScannerType:  scannerType,
		Prefixes:     convertStringArr(prefixes),
	}

	err := ac.CreateRegistry(registry)
	if err != nil {
		return err
	}
	d.SetId(d.Get("name").(string))

	return resourceRegistryRead(d, m)

}

func resourceRegistryRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	r, err := ac.GetRegistry(d.Id())
	if err != nil {
		log.Println("[DEBUG]  error calling ac.GetRegistry: ", r)
		return err
	}
	if err = d.Set("auto_pull", r.AutoPull); err != nil {
		return err
	}
	if err = d.Set("name", r.Name); err != nil {
		return err
	}
	if err = d.Set("author", r.Author); err != nil {
		return err
	}
	if err = d.Set("password", r.Password); err != nil {
		return err
	}
	if err = d.Set("scanner_type", r.ScannerType); err != nil {
		return err
	}
	if err = d.Set("type", r.Type); err != nil {
		return err
	}
	if err = d.Set("url", r.URL); err != nil {
		return err
	}
	if err = d.Set("username", r.Username); err != nil {
		return err
	}
	return nil
}

func resourceRegistryUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "" {
		scannerType = "any"
	}
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
			ScannerType:  scannerType,
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
