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
			"logical_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"enforcer_image_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"description": {
				Type:     schema.TypeString,
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
			"enforce": {
				Type:     schema.TypeBool,
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
			"behavioral_engine": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"host_behavioral_engine": {
				Type:     schema.TypeBool,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"host_network_protection": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"user_access_control": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"image_assurance": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"host_protection": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"audit_all": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"last_update": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"token": {
				Type:     schema.TypeString,
				Computed: true,
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
			"host_os": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"install_command": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"hosts_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"disconnected_count": {
				Type:     schema.TypeInt,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"connected_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"high_vulns": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"med_vulns": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"low_vulns": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"neg_vulns": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"syscall_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"runtime_type": {
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
			"runtime_policy_name": {
				Type:     schema.TypeString,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"pas_deployment_link": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"aqua_version": {
				Type:     schema.TypeString,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allow_kube_enforcer_audit": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"auto_discovery_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"auto_discover_configure_registries": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"auto_scan_discovered_images_running_containers": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"admission_control": {
				Type:     schema.TypeBool,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"micro_enforcer_injection": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"permission": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"micro_enforcer_image_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"micro_enforcer_secrets_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"block_admission_control": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"auto_copy_secrets": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"micro_enforcer_certs_secrets_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"kube_bench_image_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"antivirus_protection": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"host_user_protection": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"container_antivirus_protection": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"host_assurance": {
				Type:     schema.TypeBool,
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
		},
	}
}

func dataEnforcerGroupRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("group_id").(string)
	group, err := ac.GetEnforcerGroup(name)
	if err == nil {
		d.Set("group_id", group.ID)
		d.Set("logical_name", group.LogicalName)
		d.Set("type", group.Type)
		d.Set("enforcer_image_name", group.EnforcerImageName)
		d.Set("description", group.Description)
		d.Set("gateway_name", group.GatewayName)
		d.Set("gateway_address", group.GatewayAddress)
		d.Set("enforce", group.Enforce)
		d.Set("container_activity_protection", group.ContainerAntivirusProtection)
		d.Set("network_protection", group.NetworkProtection)
		d.Set("behavioral_engine", group.BehavioralEngine)
		d.Set("host_behavioral_engine", group.BehavioralEngine)
		d.Set("host_network_protection", group.HostNetworkProtection)
		d.Set("user_access_control", group.UserAccessControl)
		d.Set("image_assurance", group.ImageAssurance)
		d.Set("host_protection", group.HostNetworkProtection)
		d.Set("audit_all", group.AuditAll)
		d.Set("last_update", group.LastUpdate)
		d.Set("token", group.Token)
		d.Set("command", flattenCommands(group.Command))
		d.Set("orchestrator", flattenOrchestrators(group.Orchestrator))
		d.Set("type", group.Type)
		d.Set("host_os", group.HostOs)
		d.Set("install_command", group.InstallCommand)
		d.Set("hosts_count", group.HostsCount)
		d.Set("disconnected_count", group.DisconnectedCount)
		d.Set("connected_count", group.ConnectedCount)
		d.Set("high_vulns", group.HighVulns)
		d.Set("med_vulns", group.MedVulns)
		d.Set("low_vulns", group.LowVulns)
		d.Set("neg_vulns", group.NegVulns)
		d.Set("syscall_enabled", group.SyscallEnabled)
		d.Set("runtime_type", group.RuntimeType)
		d.Set("sync_host_images", group.SyncHostImages)
		d.Set("risk_explorer_auto_discovery", group.RiskExplorerAutoDiscovery)
		d.Set("runtime_policy_name", group.RuntimePolicyName)
		d.Set("pas_deployment_link", group.PasDeploymentLink)
		d.Set("aqua_version", group.AquaVersion)
		d.Set("allow_kube_enforcer_audit", group.AllowKubeEnforcerAudit)
		d.Set("auto_discovery_enabled", group.AutoDiscoveryEnabled)
		d.Set("auto_discover_configure_registries", group.AllowKubeEnforcerAudit)
		d.Set("auto_scan_discovered_images_running_containers", group.AutoScanDiscoveredImagesRunningContainers)
		d.Set("admission_control", group.AdmissionControl)
		d.Set("micro_enforcer_injection", group.MicroEnforcerInjection)
		d.Set("permission", group.Permission)
		d.Set("micro_enforcer_image_name", group.MicroEnforcerImageName)
		d.Set("micro_enforcer_secrets_name", group.MicroEnforcerSecretsName)
		d.Set("block_admission_control", group.BlockAdmissionControl)
		d.Set("auto_copy_secrets", group.AutoCopySecrets)
		d.Set("micro_enforcer_certs_secrets_name", group.MicroEnforcerCertsSecretsName)
		d.Set("kube_bench_image_name", group.KubeBenchImageName)
		d.Set("antivirus_protection", group.AntivirusProtection)
		d.Set("host_user_protection", group.HostUserProtection)
		d.Set("container_antivirus_protection", group.ContainerAntivirusProtection)
		d.Set("host_assurance", group.HostAssurance)
		d.Set("gateways", group.Gateways)
		d.Set("allowed_applications", group.AllowedApplications)
		d.Set("allowed_labels", group.AllowedLabels)
		d.Set("allowed_registries", group.AllowedRegistries)

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
