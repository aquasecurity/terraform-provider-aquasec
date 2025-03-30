package aquasec

import (
	"fmt"
	"log"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAssuranceScript() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_assurance_custom_script` resource manages custom compliance scripts within Aqua.",
		Create:      resourceAssuranceScriptCreate,
		Read:        resourceAssuranceScriptRead,
		Update:      resourceAssuranceScriptUpdate,
		Delete:      resourceAssuranceScriptDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the assurance script",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the assurance script",
			},
			"engine": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Script engine (e.g., yaml)",
			},
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path of the script file",
			},
			"snippet": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Content of the script",
			},
			"kind": {
				Type:        schema.TypeString,
				Required:    true,
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

func resourceAssuranceScriptCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	script := expandAssuranceScript(d)

	err := ac.CreateAssuranceScript(script)
	if err != nil {
		return err
	}

	// Set the ID to the script_id returned from the API
	if script.ScriptID != "" {
		d.SetId(script.ScriptID)
	} else {
		d.SetId(script.Name)
	}

	return resourceAssuranceScriptRead(d, m)
}

func resourceAssuranceScriptRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	script, err := ac.GetAssuranceScript(d.Id())
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return err
	}

	if script == nil {
		d.SetId("")
		return nil
	}

	return setAssuranceScript(d, script)
}

func setAssuranceScript(d *schema.ResourceData, script *client.AssuranceScript) error {
	if err := d.Set("name", script.Name); err != nil {
		return err
	}
	if err := d.Set("description", script.Description); err != nil {
		return err
	}
	if err := d.Set("engine", script.Engine); err != nil {
		return err
	}
	if err := d.Set("path", script.Path); err != nil {
		return err
	}
	if err := d.Set("snippet", script.Snippet); err != nil {
		return err
	}
	if err := d.Set("kind", script.Kind); err != nil {
		return err
	}
	if err := d.Set("author", script.Author); err != nil {
		return err
	}
	if err := d.Set("script_id", script.ScriptID); err != nil {
		return err
	}
	if err := d.Set("last_modified", script.LastModified); err != nil {
		return err
	}

	return nil
}

func resourceAssuranceScriptUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)

	if d.HasChanges("description", "engine", "path", "snippet", "kind") {
		script := expandAssuranceScript(d)
		// Ensure we use the script_id for updates
		script.ScriptID = d.Id()
		err := c.UpdateAssuranceScript(script)
		if err != nil {
			log.Println("[DEBUG] error while updating assurance script: ", err)
			return err
		}
	}

	return resourceAssuranceScriptRead(d, m)
}

func resourceAssuranceScriptDelete(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	scriptID := d.Id()
	if scriptID == "" {
		scriptID = d.Get("script_id").(string)
	}

	err := c.DeleteAssuranceScript(scriptID)
	if err == nil {
		d.SetId("")
	} else {
		log.Println("[DEBUG] error deleting assurance script: ", err)
		return err
	}

	return nil
}

func expandAssuranceScript(d *schema.ResourceData) *client.AssuranceScript {
	script := client.AssuranceScript{
		Name: d.Get("name").(string),
	}

	if v, ok := d.GetOk("script_id"); ok {
		script.ScriptID = v.(string)
	}

	if v, ok := d.GetOk("description"); ok {
		script.Description = v.(string)
	}

	if v, ok := d.GetOk("engine"); ok {
		script.Engine = v.(string)
	}

	if v, ok := d.GetOk("path"); ok {
		script.Path = v.(string)
	}

	if v, ok := d.GetOk("snippet"); ok {
		script.Snippet = v.(string)
	}

	if v, ok := d.GetOk("kind"); ok {
		script.Kind = v.(string)
	}

	return &script
}
