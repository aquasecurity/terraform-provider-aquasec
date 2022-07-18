package aquasec

import (
	"log"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
				Type:        schema.TypeString,
				Description: "The name of the role, comprised of alphanumeric characters and '-', '_', ' ', ':', '.', '@', '!', '^'.",
				Required:    true,
				ForceNew:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "The name of the user who created the role. Only returned from the API for existing permissions, not part of the permission creation/modification structure.",
				Computed:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "Free text description for the role.",
				Optional:    true,
			},
			"updated_at": {
				Type:        schema.TypeString,
				Description: "The date of the last modification of the role.",
				Computed:    true,
				Optional:    true,
			},
			"permission": {
				Type:        schema.TypeString,
				Description: "The name of the Permission Set that will affect the users assigned to this specific Role.",
				Required:    true,
			},
			"scopes": {
				Type:        schema.TypeList,
				Description: "List of Application Scopes that will affect the users assigned to this specific Role.",
				Required:    true,
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
