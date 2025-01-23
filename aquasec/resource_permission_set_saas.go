package aquasec

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePermissionSetSaas() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_permission_set_saas` resource manages your Permission Set within Aqua SaaS environment.",
		Create:      resourcePermissionSetSaasCreate,
		Read:        resourcePermissionSetSaasRead,
		Update:      resourcePermissionSetSaasUpdate,
		Delete:      resourcePermissionSetSaasDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the permission set",
				Required:    true,
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "Description of the permission set",
				Optional:    true,
			},
			"actions": {
				Type:        schema.TypeList,
				Description: "List of allowed actions for the permission set",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourcePermissionSetSaasCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	permSet := expandPermissionSetSaas(d)
	err := ac.CreatePermissionSetSaas(permSet)
	if err != nil {
		return err
	}

	d.SetId(name)
	return resourcePermissionSetSaasRead(d, m)
}

func resourcePermissionSetSaasUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	if d.HasChanges("description", "actions") {
		permSet := expandPermissionSetSaas(d)
		err := ac.UpdatePermissionSetSaas(permSet)
		if err != nil {
			return err
		}
	}

	return resourcePermissionSetSaasRead(d, m)
}

func resourcePermissionSetSaasRead(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)

	permSet, err := c.GetPermissionSetSaas(d.Id())
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return err
	}

	d.Set("name", permSet.Name)
	d.Set("description", permSet.Description)
	d.Set("actions", permSet.Actions)

	return nil
}

func resourcePermissionSetSaasDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	err := ac.DeletePermissionSetSaas(name)
	if err != nil {
		return err
	}

	d.SetId("")
	return nil
}

func expandPermissionSetSaas(d *schema.ResourceData) *client.PermissionSetSaas {
	permSet := client.PermissionSetSaas{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
	}

	if v, ok := d.GetOk("actions"); ok {
		rawActions := v.([]interface{})
		actions := make([]string, len(rawActions))
		for i, action := range rawActions {
			actions[i] = action.(string)
		}
		permSet.Actions = actions
	}

	return &permSet
}