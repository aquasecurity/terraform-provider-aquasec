package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"time"
)

func resourceAccessManagementRole() *schema.Resource {
	return &schema.Resource{
		Create: resourceRoleCreate,
		Read:   resourceRoleRead,
		Update: resourceRoleUpdate,
		Delete: resourceRoleDelete,
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
			"permission": {
				Type:     schema.TypeString,
				Required: true,
			},
			"scopes": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"groups": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"users": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceRoleCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	scopes := d.Get("scopes").([]interface{})
	groups := d.Get("groups").([]interface{})
	users := d.Get("users").([]interface{})
	role := client.Role{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Author:      d.Get("author").(string),
		Permission:  d.Get("permission").(string),
		Scopes:      convertStringArr(scopes),
		Groups:      convertStringArr(groups),
		Users:       convertStringArr(users),
	}

	err := ac.CreateRole(role)
	if err != nil {
		return err
	}

	d.SetId(d.Get("name").(string))

	err = resourceRoleRead(d, m)

	return err
}

func resourceRoleRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	id := d.Id()
	r, err := ac.GetRole(id)
	if err != nil {
		log.Println("[DEBUG]  error calling ac.GetRole: ", r)
		return err
	}
	return nil
}

func resourceRoleUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	if d.HasChanges("description", "permission", "is_super", "scopes", "users", "groups") {
		scopes := d.Get("scopes").([]interface{})
		groups := d.Get("groups").([]interface{})
		users := d.Get("users").([]interface{})
		ps := client.Role{
			Description: d.Get("description").(string),
			Name:        d.Get("name").(string),
			Author:      d.Get("author").(string),
			Permission:  d.Get("permission").(string),
			Scopes:      convertStringArr(scopes),
			Groups:      convertStringArr(groups),
			Users:       convertStringArr(users),
		}

		err := ac.UpdateRole(ps)
		if err != nil {
			log.Println("[DEBUG]  error while updating role: ", err)
			return err
		}
		_ = d.Set("last_updated", time.Now().Format(time.RFC850))
	}

	return nil
}

func resourceRoleDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	id := d.Id()

	err := ac.DeleteRole(id)
	if err != nil {
		return err
	}

	return err
}
