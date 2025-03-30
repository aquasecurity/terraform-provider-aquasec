package aquasec

import (
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAssuranceScript() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_assurance_custom_script` data source provides information about an existing custom compliance script within Aqua.",
		Read:        dataSourceAssuranceScriptRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the assurance script",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Description of the assurance script",
			},
			"engine": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Script engine (e.g., yaml)",
			},
			"path": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Path of the script file",
			},
			"snippet": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Content of the script",
			},
			"kind": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Kind of script (e.g., kubernetes)",
			},
			"author": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Author of the script",
			},
			"script_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the script",
			},
			"last_modified": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Last modification timestamp",
			},
		},
	}
}

func dataSourceAssuranceScriptRead(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	// Get the script by name
	script, err := c.GetAssuranceScript(name)
	if err != nil {
		return err
	}

	if script == nil {
		return NewNotFoundErrorf("Assurance script %s not found", name)
	}

	// Set both ID and script_id
	d.SetId(script.ScriptID)
	if err := d.Set("script_id", script.ScriptID); err != nil {
		return err
	}

	return setAssuranceScript(d, script)
}
