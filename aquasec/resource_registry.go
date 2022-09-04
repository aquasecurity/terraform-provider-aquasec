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
			"auto_pull_rescan": {
				Type:        schema.TypeBool,
				Description: "Whether to automatically pull and rescan images from the registry on creation and daily",
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
			"auto_pull_interval": {
				Type:        schema.TypeInt,
				Description: "The interval in days to start pulling new images from the registry, Defaults to 1",
				Optional:    true,
			},
			"image_creation_date_condition": {
				Type:        schema.TypeString,
				Description: "Additional condition for pulling and rescanning images, Defaults to 'none'",
				Optional:    true,
				Computed:    true,
			},
			"pull_image_age": {
				Type:        schema.TypeString,
				Description: "When auto pull image enabled, sets maximum age of auto pulled images (for example for 5 Days the value should be: 5D), Requires image_creation_date_condition = \"image_age\" ",
				Optional:    true,
				Computed:    true,
			},
			"pull_image_count": {
				Type:        schema.TypeInt,
				Description: "When auto pull image enabled, sets maximum age of auto pulled images tags from each repository (based on image creation date) Requires image_creation_date_condition = \"image_count\"",
				Optional:    true,
				Computed:    true,
			},
			"scanner_type": {
				Type:        schema.TypeString,
				Description: "The Scanner type",
				Optional:    true,
				Computed:    true,
			},
			"scanner_name": {
				Type:        schema.TypeList,
				Description: "List of scanner names",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"prefixes": {
				Type:        schema.TypeList,
				Description: "List of possible prefixes to image names pulled from the registry",
				Optional:    true,
				Computed:    true,
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

	autoPull := d.Get("auto_pull").(bool)
	autoPullRescan := d.Get("auto_pull_rescan").(bool)
	autoPullInterval := d.Get("auto_pull_interval").(int)
	if (autoPull || autoPullRescan) && (autoPullInterval < 1) {
		autoPullInterval = 1
	}

	// Get and Convert Roles
	prefixes := d.Get("prefixes").([]interface{})
	scanner_name := d.Get("scanner_name").([]interface{})

	old, new := d.GetChange("scanner_name")

	existsing_scanners := old.([]interface{})

	scanner_name_added, scanner_name_removed := scannerNamesListCreate(old.([]interface{}), new.([]interface{}))

	registry := client.Registry{
		Username:                   d.Get("username").(string),
		Password:                   d.Get("password").(string),
		Name:                       d.Get("name").(string),
		Type:                       d.Get("type").(string),
		URL:                        d.Get("url").(string),
		AutoPull:                   d.Get("auto_pull").(bool),
		AutoPullRescan:             d.Get("auto_pull_rescan").(bool),
		AutoPullMax:                d.Get("auto_pull_max").(int),
		AutoPullTime:               d.Get("auto_pull_time").(string),
		ImageCreationDateCondition: d.Get("image_creation_date_condition").(string),
		PullImageAge:               d.Get("pull_image_age").(string),
		PullImageCount:             d.Get("pull_image_count").(int),
		AutoPullInterval:           autoPullInterval,
		ScannerType:                scannerType,
		ScannerName:                convertStringArr(scanner_name),
		ScannerNameAdded:           convertStringArr(scanner_name_added),
		ScannerNameRemoved:         convertStringArr(scanner_name_removed),
		ExistingScanners:           convertStringArr(existsing_scanners),
		Prefixes:                   convertStringArr(prefixes),
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
	if err = d.Set("auto_pull_rescan", r.AutoPullRescan); err != nil {
		return err
	}
	if err = d.Set("auto_pull_interval", r.AutoPullInterval); err != nil {
		return err
	}
	if err = d.Set("image_creation_date_condition", r.ImageCreationDateCondition); err != nil {
		return err
	}
	if err = d.Set("pull_image_age", r.PullImageAge); err != nil {
		return err
	}
	if err = d.Set("pull_image_count", r.PullImageCount); err != nil {
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
	if err = d.Set("prefixes", r.Prefixes); err != nil {
		return err
	}
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "specific" {
		if err = d.Set("scanner_name", r.ScannerName); err != nil {
			return err
		}
	}
	return nil
}

func resourceRegistryUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "" {
		scannerType = "any"
	}
	autoPull := d.Get("auto_pull").(bool)
	autoPullRescan := d.Get("auto_pull_rescan").(bool)
	autoPullInterval := d.Get("auto_pull_interval").(int)
	if (autoPull || autoPullRescan) && (autoPullInterval < 1) {
		autoPullInterval = 1
	}

	if d.HasChanges("name", "username", "password", "url", "type", "auto_pull", "auto_pull_rescan", "auto_pull_max", "auto_pull_time", "auto_pull_interval", "image_creation_date_condition", "scanner_name", "prefixes", "pull_image_count", "pull_image_age") {

		prefixes := d.Get("prefixes").([]interface{})
		scanner_name := d.Get("scanner_name").([]interface{})

		old, new := d.GetChange("scanner_name")

		existsing_scanners := old.([]interface{})

		scanner_name_added, scanner_name_removed := scannerNamesListCreate(old.([]interface{}), new.([]interface{}))

		registry := client.Registry{
			Name:                       d.Get("name").(string),
			Type:                       d.Get("type").(string),
			Username:                   d.Get("username").(string),
			Password:                   d.Get("password").(string),
			URL:                        d.Get("url").(string),
			AutoPull:                   d.Get("auto_pull").(bool),
			AutoPullRescan:             d.Get("auto_pull_rescan").(bool),
			AutoPullMax:                d.Get("auto_pull_max").(int),
			AutoPullTime:               d.Get("auto_pull_time").(string),
			AutoPullInterval:           autoPullInterval,
			ImageCreationDateCondition: d.Get("image_creation_date_condition").(string),
			PullImageAge:               d.Get("pull_image_age").(string),
			PullImageCount:             d.Get("pull_image_count").(int),
			ScannerType:                scannerType,
			ScannerName:                convertStringArr(scanner_name),
			ScannerNameAdded:           convertStringArr(scanner_name_added),
			ScannerNameRemoved:         convertStringArr(scanner_name_removed),
			ExistingScanners:           convertStringArr(existsing_scanners),
			Prefixes:                   convertStringArr(prefixes),
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

func scannerNamesListCreate(a, b []interface{}) (d, e []interface{}) {
	m1 := make(map[interface{}]bool)
	m2 := make(map[interface{}]bool)

	for _, item := range a {
		m1[item] = true
	}
	for _, item := range b {
		m2[item] = true
	}

	for _, item := range b {
		if _, ok := m1[item]; ok {
			continue
		} else {
			d = append(d, item)
		}
	}
	for _, item := range a {
		if _, ok := m2[item]; ok {
			continue
		} else {
			e = append(e, item)
		}
	}
	return
}
