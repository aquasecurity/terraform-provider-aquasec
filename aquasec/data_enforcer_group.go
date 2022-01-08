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
			"sync_host_images": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"risk_explorer_auto_discovery": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"syscall_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"enforcer_image": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"container_activity_protection": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"network_protection": {
				Type:     schema.TypeBool,
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
	ac := m.(*client.Client)
	name := d.Get("group_id").(string)
	group, err := ac.GetEnforcerGroup(name)
	if err == nil {
		d.Set("token", group.Token)
		d.Set("gateway_name", group.GatewayName)
		d.Set("gateway_address", group.GatewayAddress)
		d.Set("user_access_control", group.UserAccessControl)
		d.Set("image_assurance", group.ImageAssurance)
		d.Set("host_protection", group.HostProtection)
		d.Set("audit_all", group.AuditAll)
		d.Set("audit_success_login", group.AuditSuccessLogin)
		d.Set("audit_failed_login", group.AuditFailedLogin)
		d.Set("last_update", group.LastUpdate)
		d.Set("command", flattenCommands(group.Command))
		d.Set("host_os", group.HostOs)
		d.Set("install_command", group.InstallCommand)
		d.Set("allow_kube_enforcer_audit", group.AllowKubeEnforcerAudit)
		d.Set("auto_discovery_enabled", group.AutoDiscoveryEnabled)
		d.Set("auto_discover_configure_registries", group.AutoDiscoverConfigureRegistries)
		d.Set("auto_scan_discovered_images_running_containers", group.AutoScanDiscoveredImagesRunningContainers)
		d.Set("admission_control", group.AdmissionControl)
		d.Set("micro_enforce_injection", group.MicroEnforcerInjection)
		d.Set("block_admission_control", group.BlockAdmissionControl)
		d.Set("logical_name", group.Logicalname)
		d.Set("gateways", group.Gateways)
		d.Set("risk_explorer_auto_discovery", group.RiskExplorerAutoDiscovery)
		d.Set("syscall_enabled", group.SyscallEnabled)
		d.Set("sync_host_images", group.SyncHostImages) 
		d.Set("enforcer_image", group.EnforcerImageName)

		log.Println("[DEBUG]  setting id: ", name)
		d.SetId(name)
	} else {
		return err
	}
	//gateways := d.Get("gateways").([]interface{})

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
