package aquasec

import (
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePermissionSet() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_permissions_sets` resource manages your Permission Set within Aqua.",
		Create:      resourcePermissionSetCreate,
		Read:        resourcePermissionSetRead,
		Update:      resourcePermissionSetUpdate,
		Delete:      resourcePermissionSetDelete,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the Permission Set, comprised of alphanumeric characters and '-', '_', ' ', ':', '.', '@', '!', '^'",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Free text description for the Permission Set",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The date of the last modification of the Role.",
			},
			"author": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the user who created the Permission Set",
			},
			"ui_access": {
				Type:        schema.TypeBool,
				Required:    true,
				Description: "Whether to allow UI access for users with this Permission Set",
			},
			"is_super": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Give the Permission Set full access, meaning all actions are allowed without restriction",
			},
			"actions": {
				Description: "List of allowed actions for the Permission Set (not relevant if 'is_super' is true)",
				Type:        schema.TypeList,
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

	return nil
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
	name := d.Get("name").(string)

	iap, err := ac.GetPermissionsSet(name)
	if err == nil {
		d.Set("description", iap.Description)
		d.Set("author", iap.Author)
		d.Set("ui_access", iap.UiAccess)
		d.Set("is_super", iap.IsSuper)
		d.Set("actions", iap.Actions)
	} else {
		return err
	}
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
