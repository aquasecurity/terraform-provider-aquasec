package aquasec

import (
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"time"
)

func resourceRole() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_role` resource manages your roles within Aqua.\n\n" +
			"The roles created must have permission set and at least one Role Application Scope that is already " +
			"present within Aqua.",
		Create: resourceRoleCreate,
		Read:   resourceRoleRead,
		Update: resourceRoleUpdate,
		Delete: resourceRoleDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"author": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"updated_at": {
				Type:     schema.TypeString,
				Computed: true,
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
		},
	}
}

func resourceRoleCreate(d *schema.ResourceData, m interface{}) error {

	ac := m.(*client.Client)
	role := expandRole(d)
	err := ac.CreateRole(role)
	if err != nil {
		return err
	}

	err = resourceRoleRead(d, m)
	if err == nil {
		d.SetId(role.Name)
	} else {
		return err
	}
	return nil
}

func resourceRoleRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	id := d.Get("role_name").(string)
	r, err := ac.GetRole(id)
	if err == nil {
		d.Set("updated_at", r.UpdatedAt)
		d.Set("author", r.Author)
	} else {
		log.Println("[DEBUG]  error calling ac.ReadRole: ", r)
		return err
	}
	return err
}

func resourceRoleUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)

	if d.HasChanges("description", "permission", "scopes") {

		role := expandRole(d)
		updateTime := time.Now().Format(time.RFC3339Nano)
		role.UpdatedAt = updateTime

		err := c.UpdateRole(role)
		if err != nil {
			log.Println("[DEBUG]  error while updating user: ", err)
			return err
		}
		_ = d.Set("updated_at", updateTime)
	}

	return nil
}

func resourceRoleDelete(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	name := d.Get("role_name").(string)
	err := c.DeleteRole(name)
	log.Println(err)
	if err == nil {
		d.SetId("")
	} else {
		log.Println("[DEBUG]  error deleting user: ", err)
		return err
	}

	return err
}

func expandRole(d *schema.ResourceData) *client.Role {

	role := client.Role{
		Name: d.Get("role_name").(string),
	}

	description, ok := d.GetOk("description")
	if ok {
		role.Description = description.(string)
	}

	permission, ok := d.GetOk("permission")
	if ok {
		role.Permission = permission.(string)
	}

	scopes, ok := d.GetOk("scopes")
	if ok {
		role.Scopes = convertStringArr(scopes.([]interface{}))
	}

	return &role
}
