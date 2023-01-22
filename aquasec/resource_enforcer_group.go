package aquasec

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceEnforcerGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceEnforcerGroupCreate,
		Read:   resourceEnforcerGroupRead,
		Update: resourceEnforcerGroupUpdate,
		Delete: resourceEnforcerGroupDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"admission_control": {
				Type: schema.TypeBool,
				Description: `Selecting this option will allow the KubeEnforcer to block the deployment of container images that have failed any of these Container Runtime Policy controls:\
				* Block Non-Compliant Images\
				* Block Non-Compliant Workloads\
				* Block Unregistered Images\
				This functionality can work only when the KubeEnforcer is deployed in Enforce mode.`,
				Optional: true,
			},
			"allow_kube_enforcer_audit": {
				Type:        schema.TypeBool,
				Description: "Allow kube enforcer audit.",
				Optional:    true,
			},
			"allowed_labels": {
				Type:        schema.TypeSet,
				Description: "List of label names to allow on the hosts.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_applications": {
				Type:        schema.TypeSet,
				Description: "List of application names to allow on the hosts. if provided, only containers of the listed applications will be allowed to run.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_registries": {
				Type:        schema.TypeSet,
				Description: "List of registry names to allow on the hosts.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"antivirus_protection": {
				Type:        schema.TypeBool,
				Description: "This setting is available only when you have license for `Advanced Malware Protection`. Send true to make use of the license and enable the `Real-time Malware Protection` control in the Host Runtime policies.",
				Optional:    true,
			},
			"aqua_version": {
				Type:        schema.TypeString,
				Description: "Aqua server version",
				Computed:    true,
			},
			"audit_all": {
				Type:        schema.TypeBool,
				Description: "Agent will send extra audit messages to the server for success operations from inside the container (runtime).",
				Optional:    true,
			},
			"auto_copy_secrets": {
				Type:        schema.TypeBool,
				Description: "This option is applicable only if `Enable Pod Enforcer injection` is selected. Select this option if you want Aqua Enterprise to copy the secrets defined above to the Pod Enforcer namespace and container. Otherwise, you can choose to copy these secrets by other means.",
				Optional:    true,
				Computed:    true,
			},
			"auto_discover_configure_registries": {
				Type:        schema.TypeBool,
				Description: "This option is available only if `Enable workload discovery` is selected. If selected, the KubeEnforcer will add previously unknown image registries from the cluster to Aqua.",
				Optional:    true,
			},
			"auto_discovery_enabled": {
				Type:        schema.TypeBool,
				Description: "When this option is selected, the KubeEnforcer will discover workloads on its cluster.",
				Optional:    true,
			},
			"auto_scan_discovered_images_running_containers": {
				Type:        schema.TypeBool,
				Description: "This option is available only if `Enable workload discovery` is selected. If selected, the KubeEnforcer will automatically register images running as workloads (and scan the discovered images for security issues).",
				Optional:    true,
			},
			"behavioral_engine": {
				Type:        schema.TypeBool,
				Description: "Select Enabled to detect suspicious activity in your containers and display potential security threats in the Incidents and Audit pages.",
				Optional:    true,
			},
			"forensics": {
				Type:        schema.TypeBool,
				Description: "Select Enabled to send activity logs in your containers to the Aqua Server for forensics purposes.",
				Optional:    true,
			},
			"block_admission_control": {
				Type:        schema.TypeBool,
				Description: "This applies only if both `Enable admission control` and Enforce mode are set. This additional option must be selected for admission control to work if the KubeEnforcer is not connected to any Gateway. If this option is not selected, admission control will be disabled; this will have no effect on containers already running.",
				Optional:    true,
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
			"connected_count": {
				Type:        schema.TypeInt,
				Description: "Number of connected enforcers in the enforcer group.",
				Computed:    true,
			},
			"container_activity_protection": {
				Type:        schema.TypeBool,
				Description: "Set `True` to apply Container Runtime Policies, Image Profiles, and Firewall Policies to containers.",
				Optional:    true,
			},
			"container_antivirus_protection": {
				Type:        schema.TypeBool,
				Description: "This setting is available only when you have license for `Advanced Malware Protection`. Send true to make use of the license and enable the `Real-time Malware Protection` control in the Container Runtime policies.",
				Optional:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "A description of the Aqua Enforcer group.",
				Optional:    true,
			},
			"disconnected_count": {
				Type:        schema.TypeInt,
				Description: "Number of disconnected enforcers in the enforcer group.",
				Computed:    true,
			},
			"enforce": {
				Type:        schema.TypeBool,
				Description: "Whether to enable enforce mode on the Enforcers, defaults to False.",
				Optional:    true,
			},
			"enforcer_image_name": {
				Type:        schema.TypeString,
				Description: "The specific Aqua Enforcer product image (with image tag) to be deployed.",
				Computed:    true,
			},
			"gateway_address": {
				Type:        schema.TypeString,
				Description: "Gateway Address",
				Computed:    true,
			},
			"gateway_name": {
				Type:        schema.TypeString,
				Description: "Gateway Name",
				Computed:    true,
			},
			"gateways": {
				Type:        schema.TypeList,
				Description: "List of Aqua gateway IDs for the Enforcers.",
				Optional:    true,
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"high_vulns": {
				Type:        schema.TypeInt,
				Description: "Number of high vulnerabilities in the enforcers that in this enforcer group.",
				Computed:    true,
			},
			"host_assurance": {
				Type:        schema.TypeBool,
				Description: "Set `True` to enable host scanning and respective Host Assurance controls.",
				Optional:    true,
			},
			"host_behavioral_engine": {
				Type:        schema.TypeBool,
				Description: "Set `True` to enable these Host Runtime Policy controls: `OS Users and Groups Allowed` and `OS Users and Groups Blocked`",
				Optional:    true,
			},
			"host_forensics": {
				Type:        schema.TypeBool,
				Description: "Select Enabled to send activity logs in your host to the Aqua Server for forensics purposes.",
				Optional:    true,
			},
			"host_network_protection": {
				Type:        schema.TypeBool,
				Description: "Set `True` to apply Firewall Policies to hosts, and allow recording network maps for Aqua services. The Network Firewall setting must be disabled when deploying the Aqua Enforcer on a machine running Rocky Linux. See https://docs.aquasec.com/docs/platform-support-limitations-rocky-linux for further information",
				Optional:    true,
			},
			"host_os": {
				Type:         schema.TypeString,
				Description:  "The OS type for the host",
				Computed:     true,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"Linux", "Windows"}, false),
			},
			"host_protection": {
				Type:        schema.TypeBool,
				Description: "Set `True` to enable all Host Runtime Policy controls except for `OS Users and Groups Allowed` and `OS Users and Groups Blocked`.",
				Optional:    true,
			},
			"host_user_protection": {
				Type:        schema.TypeBool,
				Description: "Set `True` to enable these Host Runtime Policy controls: `OS Users and Groups Allowed` and `OS Users and Groups Blocked`",
				Optional:    true,
			},
			"hostname": {
				Type:        schema.TypeString,
				Description: "The hostname",
				Computed:    true,
			},
			"hosts_count": {
				Type:        schema.TypeInt,
				Description: "Number of enforcers in the enforcer group.",
				Computed:    true,
			},
			"image_assurance": {
				Type:        schema.TypeBool,
				Description: "Set `True` to enable selected controls: Container Runtime Policy (`Block Non-Compliant Images`, `Block Unregistered Images`, and `Registries Allowed`) and Default Image Assurance Policy (`Images Blocked`).",
				Optional:    true,
			},
			"group_id": {
				Type:        schema.TypeString,
				Description: "The ID of the Enforcer group.",
				Required:    true,
				ForceNew:    true,
			},
			"install_command": {
				Type:        schema.TypeString,
				Description: "Enforcer install command",
				Computed:    true,
			},
			"kube_bench_image_name": {
				Type: schema.TypeString,
				Description: `See https://docs.aquasec.com/docs/securing-kubernetes-applications#section-configuration-hardening, The KubeEnforcer can deploy the Aqua Security kube-bench open-source product to perform Kubernetes CIS benchmark testing of nodes.
				This field specifies the path and file name of the kube-bench product image for the KubeEnforcer to deploy; it will be filled in automatically. You can optionally enter a different value.`,
				Optional: true,
				Computed: true,
			},
			"last_update": {
				Type:        schema.TypeInt,
				Description: "The last date and time the batch token was updated in UNIX time.",
				Computed:    true,
			},
			"logical_name": {
				Type:        schema.TypeString,
				Description: "Name for the batch install record.",
				Optional:    true,
				Computed:    true,
			},
			"low_vulns": {
				Type:        schema.TypeInt,
				Description: "Number of low vulnerabilities in the enforcers that in this enforcer group.",
				Computed:    true,
			},
			"med_vulns": {
				Type:        schema.TypeInt,
				Description: "Number of medium vulnerabilities in the enforcers that in this enforcer group.",
				Computed:    true,
			},
			"micro_enforcer_certs_secrets_name": {
				Type:        schema.TypeString,
				Description: "This option is applicable only if `Enable Pod Enforcer injection` is selected.",
				Optional:    true,
			},
			"micro_enforcer_image_name": {
				Type:        schema.TypeString,
				Description: "This option is applicable only if `Enable Pod Enforcer injection` is selected. This field specifies the path and file name of the KubeEnforcer product image to be deployed; it will be filled in automatically. You can optionally enter a different value.",
				Optional:    true,
				Computed:    true,
			},
			"micro_enforcer_injection": {
				Type:        schema.TypeBool,
				Description: "This applies only if both `Enable admission control` and Enforce mode are set. This additional option must be selected for admission control to work if the KubeEnforcer is not connected to any Gateway. If this option is not selected, admission control will be disabled; this will have no effect on containers already running.",
				Optional:    true,
			},
			"micro_enforcer_secrets_name": {
				Type:        schema.TypeString,
				Description: "You can specify the name of the secret (in the Aqua namespace) that Aqua copies into the Pod Enforcer namespace and kube-bench, allowing them access to the Pod Enforcer and kube-bench product images, respectively.",
				Optional:    true,
				Computed:    true,
			},
			"neg_vulns": {
				Type:        schema.TypeInt,
				Description: "Number of negligible vulnerabilities in the enforcers that in this enforcer group.",
				Computed:    true,
			},
			"network_protection": {
				Type:        schema.TypeBool,
				Description: "Send true to apply Firewall Policies to containers, and allow recording network maps for Aqua services. The Network Firewall setting must be disabled when deploying the Aqua Enforcer on a machine running Rocky Linux. See https://docs.aquasec.com/docs/platform-support-limitations-rocky-linux for further information.",
				Optional:    true,
			},
			"orchestrator": {
				Type:        schema.TypeSet,
				Description: "The orchestrator for which you are creating the Enforcer group.",
				Required:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"master": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"service_account": {
							Type:        schema.TypeString,
							Description: "May be specified for these orchestrators: Kubernetes, Kubernetes GKE, OpenShift, VMware Tanzu Kubernetes Grid Integrated Edition (PKS).",
							Optional:    true,
						},
						"namespace": {
							Type:        schema.TypeString,
							Description: "May be specified for these orchestrators: Kubernetes, Kubernetes GKE, VMware Tanzu Kubernetes Grid Integrated Edition (PKS).",
							Optional:    true,
						},
					},
				},
			},
			"pas_deployment_link": {
				Type:        schema.TypeString,
				Description: "pas deployment link",
				Computed:    true,
			},
			"permission": {
				Type:        schema.TypeString,
				Description: "Permission Action",
				Optional:    true,
			},
			"risk_explorer_auto_discovery": {
				Type:        schema.TypeBool,
				Description: "Set `True` to allow Enforcers to be discovered in the Risk Explorer.",
				Optional:    true,
			},
			"runtime_policy_name": {
				Type:        schema.TypeString,
				Description: "Function Runtime Policy that will applay on the nano enforcer.",
				Computed:    true,
			},
			"runtime_type": {
				Type:         schema.TypeString,
				Description:  "The container runtime environment.",
				Computed:     true,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"docker", "crio", "containerd", "garden"}, false),
			},
			"sync_host_images": {
				Type:        schema.TypeBool,
				Description: "Set `True` to configure Enforcers to discover local host images. Discovered images will be listed under Images > Host Images, as well as under Infrastructure (in the Images tab for applicable hosts).",
				Optional:    true,
			},
			"syscall_enabled": {
				Type:        schema.TypeBool,
				Description: "Set `True` will allow profiling and monitoring system calls made by running containers.",
				Optional:    true,
			},
			"token": {
				Type:        schema.TypeString,
				Description: "The batch install token.",
				Computed:    true,
			},
			"type": {
				Type:         schema.TypeString,
				Description:  "Enforcer Type.",
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"agent", "host_enforcer", "kube_enforcer", "micro_enforcer", "nano_enforcer"}, false),
			},
			"user_access_control": {
				Type:        schema.TypeBool,
				Description: "Set `True` to apply User Access Control Policies to containers. Note that Aqua Enforcers must be deployed with the AQUA_RUNC_INTERCEPTION environment variable set to 0 in order to use User Access Control Policies.",
				Optional:    true,
			},
		},
	}
}

func resourceEnforcerGroupCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	group := expandEnforcerGroup(d)
	err := ac.CreateEnforcerGroup(group)

	if err != nil {
		return err
	}

	err = resourceEnforcerGroupRead(d, m)

	if err == nil {
		d.SetId(d.Get("group_id").(string))
	} else {
		return err
	}

	return nil
}

func resourceEnforcerGroupRead(d *schema.ResourceData, m interface{}) error {
	var name string
	ac := m.(*client.Client)
	groupId, ok := d.GetOk("group_id")

	if ok {
		name = groupId.(string)
	} else {
		name = d.Id()
	}

	r, err := ac.GetEnforcerGroup(name)

	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404 Not Found") {
			d.SetId("")
			return nil
		}
		return err
	}

	d.Set("group_id", r.ID)
	if d.Get("logical_name") == "" {
		d.Set("logical_name", r.LogicalName)
	}
	d.Set("type", r.Type)
	d.Set("enforcer_image_name", r.EnforcerImageName)
	d.Set("description", r.Description)
	d.Set("gateway_name", r.GatewayName)
	d.Set("gateway_address", r.GatewayAddress)
	d.Set("enforce", r.Enforce)
	d.Set("container_activity_protection", r.ContainerActivityProtection)
	d.Set("network_protection", r.NetworkProtection)
	d.Set("behavioral_engine", r.BehavioralEngine)
	d.Set("host_behavioral_engine", r.BehavioralEngine)
	d.Set("forensics", r.ContainerForensicsCollection)
	d.Set("host_forensics", r.HostForensicsCollection)
	d.Set("host_network_protection", r.HostNetworkProtection)
	d.Set("user_access_control", r.UserAccessControl)
	d.Set("image_assurance", r.ImageAssurance)
	d.Set("host_protection", r.HostProtection)
	d.Set("audit_all", r.AuditAll)
	d.Set("last_update", r.LastUpdate)
	d.Set("token", r.Token)
	d.Set("command", flattenCommands(r.Command))
	d.Set("orchestrator", flattenOrchestrators(r.Orchestrator))
	d.Set("host_os", r.HostOs)
	d.Set("install_command", r.InstallCommand)
	d.Set("hosts_count", r.HostsCount)
	d.Set("disconnected_count", r.DisconnectedCount)
	d.Set("connected_count", r.ConnectedCount)
	d.Set("high_vulns", r.HighVulns)
	d.Set("med_vulns", r.MedVulns)
	d.Set("low_vulns", r.LowVulns)
	d.Set("neg_vulns", r.NegVulns)
	d.Set("syscall_enabled", r.SyscallEnabled)
	d.Set("runtime_type", r.RuntimeType)
	d.Set("sync_host_images", r.SyncHostImages)
	d.Set("risk_explorer_auto_discovery", r.RiskExplorerAutoDiscovery)
	d.Set("runtime_policy_name", r.RuntimePolicyName)
	d.Set("pas_deployment_link", r.PasDeploymentLink)
	d.Set("aqua_version", r.AquaVersion)
	d.Set("allow_kube_enforcer_audit", r.AllowKubeEnforcerAudit)
	d.Set("auto_discovery_enabled", r.AutoDiscoveryEnabled)
	d.Set("auto_discover_configure_registries", r.AutoDiscoverConfigureRegistries)
	d.Set("auto_scan_discovered_images_running_containers", r.AutoScanDiscoveredImagesRunningContainers)
	d.Set("admission_control", r.AdmissionControl)
	d.Set("micro_enforcer_injection", r.MicroEnforcerInjection)
	d.Set("permission", r.Permission)
	d.Set("micro_enforcer_image_name", r.MicroEnforcerImageName)
	d.Set("micro_enforcer_secrets_name", r.MicroEnforcerSecretsName)
	d.Set("block_admission_control", r.BlockAdmissionControl)
	d.Set("auto_copy_secrets", r.AutoCopySecrets)
	d.Set("micro_enforcer_certs_secrets_name", r.MicroEnforcerCertsSecretsName)
	d.Set("kube_bench_image_name", r.KubeBenchImageName)
	d.Set("antivirus_protection", r.AntivirusProtection)
	d.Set("host_user_protection", r.HostUserProtection)
	d.Set("container_antivirus_protection", r.ContainerAntivirusProtection)
	d.Set("host_assurance", r.HostAssurance)
	d.Set("gateways", r.Gateways)
	d.Set("allowed_applications", r.AllowedApplications)
	d.Set("allowed_labels", r.AllowedLabels)
	d.Set("allowed_registries", r.AllowedRegistries)

	return nil
}

func resourceEnforcerGroupUpdate(d *schema.ResourceData, m interface{}) error {

	if d.HasChanges("admission_control",
		"allow_kube_enforcer_audit",
		"allowed_applications",
		"allowed_labels",
		"allowed_registries",
		"antivirus_protection",
		"audit_all",
		"auto_copy_secrets",
		"auto_discover_configure_registries",
		"auto_discovery_enabled",
		"auto_scan_discovered_images_running_containers",
		"behavioral_engine",
		"block_admission_control",
		"container_activity_protection",
		"container_antivirus_protection",
		"description",
		"enforce",
		"gateways",
		"host_assurance",
		"host_behavioral_engine",
		"host_network_protection",
		"host_os",
		"host_protection",
		"host_user_protection",
		"image_assurance",
		"kube_bench_image_name",
		"logical_name",
		"micro_enforcer_certs_secrets_name",
		"micro_enforcer_image_name",
		"micro_enforcer_injection",
		"micro_enforcer_secrets_name",
		"network_protection",
		"permission",
		"risk_explorer_auto_discovery",
		"runtime_type",
		"sync_host_images",
		"syscall_enabled",
		"type",
		"user_access_control",
		"orchestrator",
	) {

		ac := m.(*client.Client)

		group := expandEnforcerGroup(d)
		err := ac.UpdateEnforcerGroup(group)

		if err == nil {
			_ = d.Set("last_updated", time.Now().Format(time.RFC850))
		} else {
			log.Println("[DEBUG]  error while updating enforcer r: ", err)
			return err
		}
	}
	return nil
}

func resourceEnforcerGroupDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Id()
	err := ac.DeleteEnforcerGroup(name)
	if err != nil {
		return err
	}
	return err
}

func expandEnforcerGroup(d *schema.ResourceData) client.EnforcerGroup {

	var oType, oNameSpace, oServiceAccount string
	var oMaster bool

	enforcerGroup := client.EnforcerGroup{
		ID: d.Get("group_id").(string),
	}

	enforcerType, ok := d.GetOk("type")
	if ok {
		enforcerGroup.Type = enforcerType.(string)
		if enforcerType != "agent" {
			enforcerGroup.RuntimeType = "docker"
		} else {
			runtimeType, ok := d.GetOk("runtime_type")
			if ok {
				enforcerGroup.RuntimeType = runtimeType.(string)
			} else {
				enforcerGroup.RuntimeType = "docker"
			}
		}
	}

	admissionControl, ok := d.GetOk("admission_control")
	if ok {
		enforcerGroup.AdmissionControl = admissionControl.(bool)
	}

	allowKubeEnforcerAudit, ok := d.GetOk("allow_kube_enforcer_audit")
	if ok {
		enforcerGroup.AllowKubeEnforcerAudit = allowKubeEnforcerAudit.(bool)
	}

	allowedApplications, ok := d.GetOk("allowed_applications")
	if ok {
		enforcerGroup.AllowedApplications = convertStringArr(allowedApplications.(*schema.Set).List())
	}

	allowedLabels, ok := d.GetOk("allowed_labels")
	if ok {
		enforcerGroup.AllowedLabels = convertStringArr(allowedLabels.(*schema.Set).List())
	}

	allowedRegistries, ok := d.GetOk("allowed_registries")
	if ok {
		enforcerGroup.AllowedRegistries = convertStringArr(allowedRegistries.(*schema.Set).List())
	}

	antivirusProtection, ok := d.GetOk("antivirus_protection")
	if ok {
		enforcerGroup.AntivirusProtection = antivirusProtection.(bool)
	}

	aquaVersion, ok := d.GetOk("aqua_version")
	if ok {
		enforcerGroup.AquaVersion = aquaVersion.(string)
	}

	auditAll, ok := d.GetOk("audit_all")
	if ok {
		enforcerGroup.AuditAll = auditAll.(bool)
	}

	autoCopySecrets, ok := d.GetOk("auto_copy_secrets")
	if ok {
		enforcerGroup.AutoCopySecrets = autoCopySecrets.(bool)
	}

	autoDiscoverConfigureRegistries, ok := d.GetOk("auto_discover_configure_registries")
	if ok {
		enforcerGroup.AutoDiscoverConfigureRegistries = autoDiscoverConfigureRegistries.(bool)
	}

	autoDiscoveryEnabled, ok := d.GetOk("auto_discovery_enabled")
	if ok {
		enforcerGroup.AutoDiscoveryEnabled = autoDiscoveryEnabled.(bool)
	}

	autoScanDiscoveredImagesRunningContainers, ok := d.GetOk("auto_scan_discovered_images_running_containers")
	if ok {
		enforcerGroup.AutoScanDiscoveredImagesRunningContainers = autoScanDiscoveredImagesRunningContainers.(bool)
	}

	behavioralEngine, ok := d.GetOk("behavioral_engine")
	if ok {
		enforcerGroup.BehavioralEngine = behavioralEngine.(bool)
	}

	forensics, ok := d.GetOk("forensics")
	if ok {
		enforcerGroup.ContainerForensicsCollection = forensics.(bool)
	}

	blockAdmissionControl, ok := d.GetOk("block_admission_control")
	if ok {
		enforcerGroup.BlockAdmissionControl = blockAdmissionControl.(bool)
	}

	containerActivityProtection, ok := d.GetOk("container_activity_protection")
	if ok {
		enforcerGroup.ContainerActivityProtection = containerActivityProtection.(bool)
	}

	containerAntivirusProtection, ok := d.GetOk("container_antivirus_protection")
	if ok {
		enforcerGroup.ContainerAntivirusProtection = containerAntivirusProtection.(bool)
	}

	description, ok := d.GetOk("description")
	if ok {
		enforcerGroup.Description = description.(string)
	}

	enforce, ok := d.GetOk("enforce")
	if ok {
		enforcerGroup.Enforce = enforce.(bool)
	}

	gateways, ok := d.GetOk("gateways")
	if ok {
		enforcerGroup.Gateways = convertStringArr(gateways.([]interface{}))
	}

	hostAssurance, ok := d.GetOk("host_assurance")
	if ok {
		enforcerGroup.HostAssurance = hostAssurance.(bool)
	}

	hostBehavioralEngine, ok := d.GetOk("host_behavioral_engine")
	if ok {
		enforcerGroup.HostBehavioralEngine = hostBehavioralEngine.(bool)
	}

	hostForensics, ok := d.GetOk("host_forensics")
	if ok {
		enforcerGroup.HostForensicsCollection = hostForensics.(bool)
	}

	hostNetworkProtection, ok := d.GetOk("host_network_protection")
	if ok {
		enforcerGroup.HostNetworkProtection = hostNetworkProtection.(bool)
	}

	hostOs, ok := d.GetOk("host_os")
	if ok {
		enforcerGroup.HostOs = hostOs.(string)
	}

	hostProtection, ok := d.GetOk("host_protection")
	if ok {
		enforcerGroup.HostProtection = hostProtection.(bool)
	}

	hostUserProtection, ok := d.GetOk("host_user_protection")
	if ok {
		enforcerGroup.HostUserProtection = hostUserProtection.(bool)
	}

	imageAssurance, ok := d.GetOk("image_assurance")
	if ok {
		enforcerGroup.ImageAssurance = imageAssurance.(bool)
	}

	kubeBenchImageName, ok := d.GetOk("kube_bench_image_name")
	if ok {
		enforcerGroup.KubeBenchImageName = kubeBenchImageName.(string)
	}

	logicalName, ok := d.GetOk("logical_name")
	if ok {
		enforcerGroup.LogicalName = logicalName.(string)
	}

	microEnforcerCertsSecretsName, ok := d.GetOk("micro_enforcer_certs_secrets_name")
	if ok {
		enforcerGroup.MicroEnforcerCertsSecretsName = microEnforcerCertsSecretsName.(string)
	}

	microEnforcerImageName, ok := d.GetOk("micro_enforcer_image_name")
	if ok {
		enforcerGroup.MicroEnforcerImageName = microEnforcerImageName.(string)
	}

	microEnforcerInjection, ok := d.GetOk("micro_enforcer_injection")
	if ok {
		enforcerGroup.MicroEnforcerInjection = microEnforcerInjection.(bool)
	}

	microEnforcerSecretsName, ok := d.GetOk("micro_enforcer_secrets_name")
	if ok {
		enforcerGroup.MicroEnforcerSecretsName = microEnforcerSecretsName.(string)
	}

	networkProtection, ok := d.GetOk("network_protection")
	if ok {
		enforcerGroup.NetworkProtection = networkProtection.(bool)
	}

	permission, ok := d.GetOk("permission")
	if ok {
		enforcerGroup.Permission = permission.(string)
	}

	riskExplorerAutoDiscovery, ok := d.GetOk("risk_explorer_auto_discovery")
	if ok {
		enforcerGroup.RiskExplorerAutoDiscovery = riskExplorerAutoDiscovery.(bool)
	}

	syncHostImages, ok := d.GetOk("sync_host_images")
	if ok {
		enforcerGroup.SyncHostImages = syncHostImages.(bool)
	}

	syscallEnabled, ok := d.GetOk("syscall_enabled")
	if ok {
		enforcerGroup.SyscallEnabled = syscallEnabled.(bool)
	}

	userAccessControl, ok := d.GetOk("user_access_control")
	if ok {
		enforcerGroup.UserAccessControl = userAccessControl.(bool)
	}

	token, ok := d.GetOk("token")
	if ok {
		enforcerGroup.Token = token.(string)
	}

	if c, ok := d.GetOk("orchestrator"); ok {
		cList := c.(*schema.Set).List()
		for _, cat := range cList {
			if catData, isMap := cat.(map[string]interface{}); isMap {
				oType = catData["type"].(string)
				oNameSpace = catData["namespace"].(string)
				oServiceAccount = catData["service_account"].(string)
				oMaster = catData["master"].(bool)
			}
		}
		enforcerGroup.Orchestrator = client.EnforcerOrchestrator{
			Type:           oType,
			Namespace:      oNameSpace,
			ServiceAccount: oServiceAccount,
			Master:         oMaster,
		}
	}

	return enforcerGroup
}
