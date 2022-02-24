package aquasec

import (
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePermissionSet() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_permission_set` resource manages your Permission Set within Aqua.",
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
				Type:     schema.TypeString,
				Required: true,
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
				Required: true,
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

func resourcePermissionSetCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	iap := expandPermissionSet(d)
	err := ac.CreatePermissionSet(iap)

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
		err := ac.UpdatePermissionSet(iap)
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

	iap, err := ac.GetPermissionSet(name)
	if err == nil {
		d.Set("description", iap.Description)
		d.Set("author", iap.Author)
		d.Set("ui_access", iap.UI_access)
		d.Set("is_super", iap.Is_super)
		d.Set("actions", iap.Actions)
	} else {
		return err
	}
	return nil
}

func resourcePermissionSetDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	err := ac.DeletePermissionSet(name)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}

func expandPermissionSet(d *schema.ResourceData) *client.PermissionSet {
	actions := d.Get("actions").([]interface{})
	iap := client.PermissionSet{
		Description: d.Get("description").(string),
		Author:      d.Get("author").(string),
		UI_access:   d.Get("ui_access").(bool),
		Is_super:    d.Get("is_super").(bool),
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
		iap.UI_access = ui_access.(bool)
	}

	is_super, ok := d.GetOk("is_super")
	if ok {
		iap.Is_super = is_super.(bool)
	}

	return &iap
}
