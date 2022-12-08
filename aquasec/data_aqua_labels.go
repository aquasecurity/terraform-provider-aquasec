package aquasec

import (
	"context"
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAquaLabels() *schema.Resource {
	return &schema.Resource{
		Description: "The data source `aquasec_aqua_labels` provides a method to query all aqua labels within the Aqua account management." +
			"The fields returned from this query are detailed in the Schema section below.",
		ReadContext: aquaLabelRead,
		Schema: map[string]*schema.Schema{
			"aqua_labels": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Description: "Aqua label name.",
							Computed:    true,
						},
						"description": {
							Type:        schema.TypeString,
							Description: "Aqua label description.",
							Computed:    true,
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
				},
			},
		},
	}
}

func aquaLabelRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	log.Println("[DEBUG]  inside resourceAquaLabelRead")
	c := m.(*client.Client)
	result, err := c.GetAquaLabels()

	if err != nil {
		return diag.FromErr(err)
	}

	id := ""
	aquaLabels := make([]interface{}, len(result.AquaLabels), len(result.AquaLabels))

	for i, aquaLabel := range result.AquaLabels {
		id = id + aquaLabel.Name
		al := make(map[string]interface{})
		al["name"] = aquaLabel.Name
		al["description"] = aquaLabel.Description
		al["created"] = aquaLabel.Created
		al["author"] = aquaLabel.Author
		aquaLabels[i] = al
	}

	d.SetId(id)
	if err := d.Set("aqua_labels", aquaLabels); err != nil {
		return diag.FromErr(err)
	}
	return nil
}
