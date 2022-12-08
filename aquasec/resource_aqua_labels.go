package aquasec

import (
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAquaLabels() *schema.Resource {
	return &schema.Resource{
		Description: "The data source `aquasec_aqua_labels` provides a method to query all aqua labels within the Aqua account management." +
			"The fields returned from this query are detailed in the Schema section below.",
		Read:   resourceAquaLabelRead,
		Create: resourceAquaLabelCreate,
		Update: resourceAquaLabelUpdate,
		Delete: resourceAquaLabelDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Aqua label name.",
				Required:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "Aqua label description.",
				Optional:    true,
			},
			"created": {
				Type:        schema.TypeString,
				Description: "The creation date of the Aqua label.",
				Computed:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "The name of the user who created the Aqua label.",
				Computed:    true,
			},
		},
	}
}

func resourceAquaLabelCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	aquaLabel := client.AquaLabel{
		Name: d.Get("name").(string),
	}

	description, ok := d.GetOk("description")
	if ok {
		aquaLabel.Description = description.(string)
	}

	err := ac.CreateAquaLabel(&aquaLabel)

	if err != nil {
		return err
	}
	d.SetId(aquaLabel.Name)
	return resourceAquaLabelRead(d, m)
}

func resourceAquaLabelRead(d *schema.ResourceData, m interface{}) error {
	log.Println("[DEBUG]  inside resourceAquaLabelRead")
	c := m.(*client.Client)
	r, err := c.GetAquaLabel(d.Id())

	if err != nil {
		return err
	}
	d.Set("name", r.Name)
	d.Set("description", r.Description)
	d.Set("created", r.Created)
	d.Set("author", r.Author)

	return nil
}

func resourceAquaLabelUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)

	if d.HasChanges("description") {
		aqua_lable := client.AquaLabel{
			Name: d.Get("name").(string),
		}

		description, ok := d.GetOk("description")
		if ok {
			aqua_lable.Description = description.(string)
		}

		err := c.UpdateAquaLabel(&aqua_lable)

		if err != nil {
			return err
		}
		d.SetId(d.Get("name").(string))
		return nil
	}
	return resourceAquaLabelRead(d, m)
}

func resourceAquaLabelDelete(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	id := d.Id()
	err := c.DeleteAquaLabel(id)
	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}
