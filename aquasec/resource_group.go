package aquasec

import (
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func resourceGroup() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_group` resource manages your groups within Aqua.\n\n" +
			"The Groups created must have at least one Role that is already " +
			"present within Aqua.",
		Create: resourceGroupCreate,
		Read:   resourceGroupRead,
		Update: resourceGroupUpdate,
		Delete: resourceGroupDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"group_id": {
				Type:     schema.TypeInt,
				Description: "The ID of the created group.",
				Computed: true,
			},
			"name": {
				Type:     schema.TypeString,
				Description: "The desired name of the group.",
				Required: true,
			},
			"created": {
				Type:     schema.TypeString,
				Description: "The creation date of the group.",
				Computed: true,
			},
		},
	}
}

func resourceGroupCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	group := client.Group{
		Name: d.Get("name").(string),
	}

	err := ac.CreateGroup(&group)
	if err != nil {
		return err
	}
	d.Set("group_id", group.Id)

	err = resourceGroupRead(d, m)
	if err != nil {
		i := fmt.Sprintf("%v", group.Id)
		d.SetId(i)
	} else {
		return err
	}

	return nil
}

func resourceGroupRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	id := d.Get("group_id").(int)
	r, err := ac.GetGroup(id)
	if err == nil {
		d.Set("created", r.Created)
		d.SetId(fmt.Sprintf("%v", id))

	} else {
		log.Println("[DEBUG]  error calling ac.ReadGroup: ", r)
		return err
	}
	return nil
}

func resourceGroupUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)

	if d.HasChanges("name") {

		Group := client.Group{
			Name: d.Get("name").(string),
			Id:   d.Get("group_id").(int),
		}

		err := c.UpdateGroup(&Group)
		if err != nil {
			log.Println("[DEBUG]  error while updating Group: ", err)
			return err
		}
	}
	return nil
}

func resourceGroupDelete(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	id := d.Id()
	err := c.DeleteGroup(id)
	log.Println(err)
	if err == nil {
		d.SetId("")
	} else {
		log.Println("[DEBUG]  error deleting Group: ", err)
		return err
	}
	//d.SetId("")

	return err
}
