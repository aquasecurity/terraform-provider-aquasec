package aquasec

import (
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceEnforcerGroup() *schema.Resource {
	return &schema.Resource{
		Description: "The data source `aquasec_enforcer_groups` provides an Enforcer group template that generates a configuration file, which is subsequently used to generate one or more Enforcers using a Docker command.",
		Read:        dataEnforcerGroupRead,
		Schema: map[string]*schema.Schema{
			"group_id": {
				Type:        schema.TypeString,
				Description: "The ID of the Enforcer group.",
				Required:    true,
			},
			"logical_name": {
				Type:        schema.TypeString,
				Description: "Name for the batch install record.",
				Computed:    true,
			},
			"type": {
				Type:        schema.TypeString,
				Description: "Enforcer Type.",
				Computed:    true,
			},
			"enforcer_image_name": {
				Type:        schema.TypeString,
				Description: "The specific Aqua Enforcer product image (with image tag) to be deployed.",
				Computed:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "A description for the Aqua Enforcer group.",
				Computed:    true,
			},
			"gateway_name": {
				Type:        schema.TypeString,
				Description: "Gateway Name",
				Computed:    true,
			},
			"gateway_address": {
				Type:        schema.TypeString,
				Description: "Gateway Address",
				Computed:    true,
			},
			"enforce": {
				Type:        schema.TypeBool,
				Description: "Whether the enforce mode is enabled on the Enforcers.",
				Computed:    true,
			},
			"container_activity_protection": {
				Type:        schema.TypeBool,
				Description: "When set to `True` applies Container Runtime Policies, Image Profiles, and Firewall Policies to containers.",
				Computed:    true,
			},
			"network_protection": {
				Type:        schema.TypeBool,
				Description: "When set to `True` applies Firewall Policies to containers, and allows recording network maps for Aqua services. The Network Firewall setting must be disabled when deploying the Aqua Enforcer on a machine running Rocky Linux. See https://docs.aquasec.com/docs/platform-support-limitations-rocky-linux for further information.",
				Computed:    true,
			},
			"behavioral_engine": {
				Type:        schema.TypeBool,
				Description: "If `Enabled`, detects suspicious activity in your containers and displays potential security threats in the Incidents and Audits pages.",
				Computed:    true,
			},
			"host_behavioral_engine": {
				Type:        schema.TypeBool,
				Description: "When set to `True` enables these Host Runtime Policy controls: `OS Users and Groups Allowed` and `OS Users and Groups Blocked`",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"forensics": {
				Type:        schema.TypeBool,
				Description: "Select Enabled to send activity logs in your containers to the Aqua Server for forensics purposes.",
				Optional:    true,
			},
			"host_forensics": {
				Type:        schema.TypeBool,
				Description: "Select Enabled to send activity logs in your host to the Aqua Server for forensics purposes.",
				Optional:    true,
			},
			"host_network_protection": {
				Type:        schema.TypeBool,
				Description: "When set to `True` applies Firewall Policies to hosts, and allows recording network maps for Aqua services. The Network Firewall setting must be disabled when deploying the Aqua Enforcer on a machine running Rocky Linux. See https://docs.aquasec.com/docs/platform-support-limitations-rocky-linux for further information",
				Computed:    true,
			},
			"user_access_control": {
				Type:        schema.TypeBool,
				Description: "When set to `True` applies User Access Control Policies to containers. Note that Aqua Enforcers must be deployed with the AQUA_RUNC_INTERCEPTION environment variable set to 0 in order to use User Access Control Policies.",
				Computed:    true,
			},
			"image_assurance": {
				Type:        schema.TypeBool,
				Description: "When Set to `True` enables selected controls: Container Runtime Policy (`Block Non-Compliant Images`, `Block Unregistered Images`, and `Registries Allowed`) and Default Image Assurance Policy (`Images Blocked`).",
				Computed:    true,
			},
			"host_protection": {
				Type:        schema.TypeBool,
				Description: "When set to `True` enables all Host Runtime Policy controls except for `OS Users and Groups Allowed` and `OS Users and Groups Blocked`.",
				Computed:    true,
			},
			"audit_all": {
				Type:        schema.TypeBool,
				Description: "Agent will send extra audit messages to the server for success operations from inside the container (runtime).",
				Computed:    true,
			},
			"last_update": {
				Type:        schema.TypeInt,
				Description: "The last date and time the batch token was updated in UNIX time.",
				Computed:    true,
			},
			"token": {
				Type:        schema.TypeString,
				Description: "The batch install token.",
				Computed:    true,
			},
			"command": {
				Type:        schema.TypeList,
				Description: "The installation command.",
				Computed:    true,
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
				Type:        schema.TypeList,
				Description: "The orchestrator for which you are creating the Enforcer group.",
				Computed:    true,
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
							Type:        schema.TypeString,
							Description: "May be specified for these orchestrators: Kubernetes, Kubernetes GKE, OpenShift, VMware Tanzu Kubernetes Grid Integrated Edition (PKS).",
							Computed:    true,
						},
						"namespace": {
							Type:        schema.TypeString,
							Description: "May be specified for these orchestrators: Kubernetes, Kubernetes GKE, VMware Tanzu Kubernetes Grid Integrated Edition (PKS).",
							Computed:    true,
						},
					},
				},
			},
			"host_os": {
				Type:        schema.TypeString,
				Description: "The OS type for the host",
				Computed:    true,
			},
			"install_command": {
				Type:        schema.TypeString,
				Description: "Enforcer install command",
				Computed:    true,
			},
			"hosts_count": {
				Type:        schema.TypeInt,
				Description: "Number of enforcers in the enforcer group.",
				Computed:    true,
			},
			"disconnected_count": {
				Type:        schema.TypeInt,
				Description: "Number of disconnected enforcers in the enforcer group.",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"connected_count": {
				Type:        schema.TypeInt,
				Description: "Number of connected enforcers in the enforcer group.",
				Computed:    true,
			},
			"high_vulns": {
				Type:        schema.TypeInt,
				Description: "Number of high vulnerabilities in the enforcers that in this enforcer group.",
				Computed:    true,
			},
			"med_vulns": {
				Type:        schema.TypeInt,
				Description: "Number of medium vulnerabilities in the enforcers that in this enforcer group.",
				Computed:    true,
			},
			"low_vulns": {
				Type:        schema.TypeInt,
				Description: "Number of low vulnerabilities in the enforcers that in this enforcer group.",
				Computed:    true,
			},
			"neg_vulns": {
				Type:        schema.TypeInt,
				Description: "Number of negligible vulnerabilities in the enforcers that in this enforcer group.",
				Computed:    true,
			},
			"syscall_enabled": {
				Type:        schema.TypeBool,
				Description: "When set to `True` allows profiling and monitoring system calls made by running containers.",
				Computed:    true,
			},
			"runtime_type": {
				Type:        schema.TypeString,
				Description: "The container runtime environment.",
				Computed:    true,
			},
			"sync_host_images": {
				Type:        schema.TypeBool,
				Description: "When set to `True` configures Enforcers to discover local host images. Discovered images will be listed under Images > Host Images, as well as under Infrastructure (in the Images tab for applicable hosts).",
				Computed:    true,
			},
			"risk_explorer_auto_discovery": {
				Type:        schema.TypeBool,
				Description: "When set to `True` allows Enforcers to be discovered in the Risk Explorer.",
				Computed:    true,
			},
			"runtime_policy_name": {
				Type:        schema.TypeString,
				Description: "Function Runtime Policy that will applay on the nano enforcer.",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"pas_deployment_link": {
				Type:        schema.TypeString,
				Description: "pas deployment link",
				Computed:    true,
			},
			"aqua_version": {
				Type:        schema.TypeString,
				Description: "Aqua server version",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allow_kube_enforcer_audit": {
				Type:        schema.TypeBool,
				Description: "Allow kube enforcer audit.",
				Computed:    true,
			},
			"auto_discovery_enabled": {
				Type:        schema.TypeBool,
				Description: "When this option is selected, the KubeEnforcer will discover workloads on its cluster.",
				Computed:    true,
			},
			"auto_discover_configure_registries": {
				Type:        schema.TypeBool,
				Description: "This option is available only if `Enable workload discovery` is selected. If selected, the KubeEnforcer will add previously unknown image registries from the cluster to Aqua.",
				Computed:    true,
			},
			"auto_scan_discovered_images_running_containers": {
				Type:        schema.TypeBool,
				Description: "This option is available only if `Enable workload discovery` is selected. If selected, the KubeEnforcer will automatically register images running as workloads (and scan the discovered images for security issues).",
				Computed:    true,
			},
			"admission_control": {
				Type: schema.TypeBool,
				Description: `Selecting this option will allow the KubeEnforcer to block the deployment of container images that have failed any of these Container Runtime Policy controls:\
				* Block Non-Compliant Images\
				* Block Non-Compliant Workloads\
				* Block Unregistered Images\
				This functionality can work only when the KubeEnforcer is deployed in Enforce mode.`,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"micro_enforcer_injection": {
				Type:        schema.TypeBool,
				Description: "This applies only if both `Enable admission control` and Enforce mode are set. This additional option must be selected for admission control to work if the KubeEnforcer is not connected to any Gateway. If this option is not selected, admission control will be disabled; this will have no effect on containers already running.",
				Computed:    true,
			},
			"permission": {
				Type:        schema.TypeString,
				Description: "Permission Action",
				Computed:    true,
			},
			"micro_enforcer_image_name": {
				Type:        schema.TypeString,
				Description: "This option is applicable only if `Enable Pod Enforcer injection` is selected. This field specifies the path and file name of the KubeEnforcer product image to be deployed; it will be filled in automatically. You can optionally enter a different value.",
				Computed:    true,
			},
			"micro_enforcer_secrets_name": {
				Type:        schema.TypeString,
				Description: "This option is applicable only if `Enable Pod Enforcer injection` is selected.",
				Computed:    true,
			},
			"block_admission_control": {
				Type:        schema.TypeBool,
				Description: "This applies only if both `Enable admission control` and Enforce mode are set. This additional option must be selected for admission control to work if the KubeEnforcer is not connected to any Gateway. If this option is not selected, admission control will be disabled; this will have no effect on containers already running.",
				Computed:    true,
			},
			"auto_copy_secrets": {
				Type:        schema.TypeBool,
				Description: "This option is applicable only if `Enable Pod Enforcer injection` is selected. Select this option if you want Aqua Enterprise to copy the secrets defined above to the Pod Enforcer namespace and container. Otherwise, you can choose to copy these secrets by other means.",
				Computed:    true,
			},
			"micro_enforcer_certs_secrets_name": {
				Type:        schema.TypeString,
				Description: "This option is applicable only if `Enable Pod Enforcer injection` is selected.",
				Computed:    true,
			},
			"kube_bench_image_name": {
				Type: schema.TypeString,
				Description: `See https://docs.aquasec.com/docs/securing-kubernetes-applications#section-configuration-hardening, The KubeEnforcer can deploy the Aqua Security kube-bench open-source product to perform Kubernetes CIS benchmark testing of nodes.
				This field specifies the path and file name of the kube-bench product image for the KubeEnforcer to deploy; it will be filled in automatically. You can optionally enter a different value.`,
				Computed: true,
			},
			"antivirus_protection": {
				Type:        schema.TypeBool,
				Description: "This setting is available only when you have license for `Advanced Malware Protection`. Send true to make use of the license and enable the `Real-time Malware Protection` control in the Host Runtime policies.",
				Computed:    true,
			},
			"host_user_protection": {
				Type:        schema.TypeBool,
				Description: " When set to `True` enables these Host Runtime Policy controls: `OS Users and Groups Allowed` and `OS Users and Groups Blocked`",
				Computed:    true,
			},
			"container_antivirus_protection": {
				Type:        schema.TypeBool,
				Description: "This setting is available only when you have license for `Advanced Malware Protection`. Send true to make use of the license and enable the `Real-time Malware Protection` control in the Container Runtime policies.",
				Computed:    true,
			},
			"host_assurance": {
				Type:        schema.TypeBool,
				Description: "When set to `True` enables host scanning and respective Host Assurance controls.",
				Computed:    true,
			},
			"gateways": {
				Type:        schema.TypeList,
				Description: "List of Aqua gateway IDs for the Enforcers.",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_applications": {
				Type:        schema.TypeSet,
				Description: "List of application names to allow on the hosts. if provided, only containers of the listed applications will be allowed to run.",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_labels": {
				Type:        schema.TypeSet,
				Description: "List of label names to allow on the hosts.",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_registries": {
				Type:        schema.TypeSet,
				Description: "List of registry names to allow on the hosts.",
				Computed:    true,
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
		d.Set("container_activity_protection", group.ContainerActivityProtection)
		d.Set("network_protection", group.NetworkProtection)
		d.Set("behavioral_engine", group.BehavioralEngine)
		d.Set("host_behavioral_engine", group.HostBehavioralEngine)
		d.Set("forensics", group.ContainerForensicsCollection)
		d.Set("host_forensics", group.HostForensicsCollection)
		d.Set("host_network_protection", group.HostNetworkProtection)
		d.Set("user_access_control", group.UserAccessControl)
		d.Set("image_assurance", group.ImageAssurance)
		d.Set("host_protection", group.HostProtection)
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
		d.Set("auto_discover_configure_registries", group.AutoDiscoverConfigureRegistries)
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
