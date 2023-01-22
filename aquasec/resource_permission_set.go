package aquasec

import (
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strings"
)

func resourcePermissionSet() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_permissions_sets` resource manages your Permission Set within Aqua.",
		Create:      resourcePermissionSetCreate,
		Read:        resourcePermissionSetRead,
		Update:      resourcePermissionSetUpdate,
		Delete:      resourcePermissionSetDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Description: "The ID of this resource.",
				Optional:    true,
				Computed:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the Permission Set, comprised of alphanumeric characters and '-', '_', ' ', ':', '.', '@', '!', '^'.",
				Required:    true,
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "Free text description for the Permission Set.",
				Optional:    true,
			},
			"updated_at": {
				Type:        schema.TypeString,
				Description: "The date of the last modification of the Role.",
				Computed:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "The name of the user who created the Permission Set.",
				Optional:    true,
			},
			"ui_access": {
				Type:        schema.TypeBool,
				Description: "Whether to allow UI access for users with this Permission Set.",
				Required:    true,
			},
			"is_super": {
				Type:        schema.TypeBool,
				Description: "Give the Permission Set full access, meaning all actions are allowed without restriction.",
				Optional:    true,
			},
			"actions": {
				Type:        schema.TypeList,
				Description: "List of allowed actions for the Permission Set (not relevant if 'is_super' is true).",
				Required:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourcePermissionSetCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	iap := expandPermissionSet(d)
	err := ac.CreatePermissionsSet(iap)

	if err != nil {
		return err
	}
	d.SetId(name)
	return resourcePermissionSetRead(d, m)
}

func resourcePermissionSetUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	if d.HasChanges("description", "author", "ui_access", "is_super", "actions") {
		iap := expandPermissionSet(d)
		err := ac.UpdatePermissionsSet(iap)
		if err == nil {
			err1 := resourcePermissionSetRead(d, m)
			if err1 == nil {
				d.SetId(name)
			} else {
				return err1
			}
		} else {
			return err
		}
	}
	return nil
}

func resourcePermissionSetRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	iap, err := ac.GetPermissionsSet(d.Id())

	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404 Not Found") {
			d.SetId("")
			return nil
		}
		return err
	}

	d.Set("name", iap.Name)
	d.Set("description", iap.Description)
	d.Set("author", iap.Author)
	d.Set("ui_access", iap.UiAccess)
	d.Set("is_super", iap.IsSuper)
	d.Set("actions", iap.Actions)

	return nil
}

func resourcePermissionSetDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	err := ac.DeletePermissionsSet(name)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}

func expandPermissionSet(d *schema.ResourceData) *client.PermissionsSet {
	actions := d.Get("actions").([]interface{})
	iap := client.PermissionsSet{
		Description: d.Get("description").(string),
		Author:      d.Get("author").(string),
		UiAccess:    d.Get("ui_access").(bool),
		IsSuper:     d.Get("is_super").(bool),
		Name:        d.Get("name").(string),
		Actions:     convertStringArr(actions),
	}

	description, ok := d.GetOk("description")
	if ok {
		iap.Description = description.(string)
	}

	author, ok := d.GetOk("author")
	if ok {
		iap.Author = author.(string)
	}

	ui_access, ok := d.GetOk("ui_access")
	if ok {
		iap.UiAccess = ui_access.(bool)
	}

	is_super, ok := d.GetOk("is_super")
	if ok {
		iap.IsSuper = is_super.(bool)
	}

	return &iap
}
