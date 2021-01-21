package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"time"
)

func resourceAccessManagementPermission() *schema.Resource {
	return &schema.Resource{
		Create: resourcePermissionCreate,
		Read:   resourcePermissionRead,
		Update: resourcePermissionUpdate,
		Delete: resourcePermissionDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"last_updated": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"author": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"ui_access": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"is_super": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"actions": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourcePermissionCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	// Get and Convert Actions
	actions := d.Get("actions").([]interface{})
	ps := client.PermissionSet{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Author:      d.Get("author").(string),
		UIAccess:    d.Get("ui_access").(bool),
		IsSuper:     d.Get("is_super").(bool),
		Actions:     convertStringArr(actions),
	}

	err := ac.CreatePermissionSet(ps)
	if err != nil {
		return err
	}

	d.SetId(d.Get("name").(string))

	err = resourcePermissionRead(d, m)

	return err
}

func resourcePermissionRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	id := d.Id()
	r, err := ac.GetPermissionSet(id)
	if err != nil {
		log.Println("[DEBUG]  error calling ac.GetPermissionSet: ", r)
		return err
	}
	return nil
}

func resourcePermissionUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	if d.HasChanges("description", "ui_access", "is_super", "actions") {
		actions := d.Get("actions").([]interface{})
		ps := client.PermissionSet{
			Description: d.Get("description").(string),
			Name:        d.Get("name").(string),
			Author:      d.Get("author").(string),
			UIAccess:    d.Get("ui_access").(bool),
			IsSuper:     d.Get("is_super").(bool),
			Actions:     convertStringArr(actions),
		}

		err := ac.UpdatePermissionSet(ps)
		if err != nil {
			log.Println("[DEBUG]  error while updating permission set: ", err)
			return err
		}
		_ = d.Set("last_updated", time.Now().Format(time.RFC850))
	}

	return nil
}

func resourcePermissionDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	id := d.Id()

	err := ac.DeletePermissionSet(id)
	if err != nil {
		return err
	}

	return err
}
