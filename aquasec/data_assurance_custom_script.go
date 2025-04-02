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
			"script_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the script",
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
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
	scriptID := d.Get("script_id").(string)

	// Get the script by ID
	script, err := c.GetAssuranceScript(scriptID)
	if err != nil {
		return err
	}

	if script == nil {
		return NewNotFoundErrorf("Assurance script with ID %s not found", scriptID)
	}

	// Set ID
	d.SetId(script.ScriptID)

	return setAssuranceScript(d, script)
}
