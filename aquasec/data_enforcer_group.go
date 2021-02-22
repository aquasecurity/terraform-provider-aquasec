package aquasec

import (
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceEnforcerGroup() *schema.Resource {
	return &schema.Resource{
		Read: dataEnforcerGroupRead,
		Schema: map[string]*schema.Schema{
			"group_id": {
				Type:     schema.TypeString,
				Required: true,
			},
			"type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"logical_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"description": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"enforce": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"gateway_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gateway_address": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"token": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gateways": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_applications": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_labels": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_registries": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"orchestrator": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"master": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"service_account": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"namespace": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"command": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"default": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"kubernetes": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"swarm": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"windows": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func dataEnforcerGroupRead(d *schema.ResourceData, m interface{}) error {
	log.Println("[DEBUG]  inside dataEnforcerGroupRead")
	ac := m.(*client.Client)
	name := d.Get("group_id").(string)
	group, err := ac.GetEnforcerGroup(name)
	log.Print(group)
	if err != nil {
		return err
	}
	//gateways := d.Get("gateways").([]interface{})

	d.Set("group_id", group.ID)
	d.Set("description", group.Description)
	d.Set("logical_name", group.Logicalname)
	d.Set("type", group.Type)
	d.Set("enforce", group.Enforce)
	//d.Set("gateways", convertStringArr(gateways))
	d.Set("gateways", group.Gateways)
	d.Set("token", group.Token)
	d.Set("orchestrator", flattenOrchestrators(group.Orchestrator))
	d.Set("command", flattenCommands(group.Command))

	log.Println("[DEBUG]  setting id: ", name)
	d.SetId(name)

	return nil
}

func flattenOrchestrators(Orchestrator client.EnforcerOrchestrator) []map[string]interface{} {
	out := make([]map[string]interface{}, 1)
	out[0] = flattenOrchestrator(Orchestrator)
	return out
}

func flattenOrchestrator(Orch client.EnforcerOrchestrator) map[string]interface{} {
	return map[string]interface{}{
		"type":            Orch.Type,
		"master":          Orch.Master,
		"service_account": Orch.ServiceAccount,
		"namespace":       Orch.Namespace,
	}
}

func flattenCommands(Command client.EnforcerCommand) []map[string]interface{} {
	comm := make([]map[string]interface{}, 1)
	comm[0] = flattenCommand(Command)
	return comm
}

func flattenCommand(Command client.EnforcerCommand) map[string]interface{} {
	return map[string]interface{}{
		"default":    Command.Default,
		"kubernetes": Command.Kubernetes,
		"swarm":      Command.Swarm,
		"windows":    Command.Windows,
	}
}
