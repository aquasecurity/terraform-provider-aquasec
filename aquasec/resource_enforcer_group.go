package aquasec

import (
	"log"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceEnforcerGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceEnforcerGroupCreate,
		Read:   resourceEnforcerGroupRead,
		Update: resourceEnforcerGroupUpdate,
		Delete: resourceEnforcerGroupDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"admission_control": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"allow_kube_enforcer_audit": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"allowed_labels": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_applications": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_registries": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"antivirus_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"aqua_version": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"audit_all": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_copy_secrets": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_discover_configure_registries": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_discovery_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_scan_discovered_images_running_containers": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"behavioral_engine": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"block_admission_control": {
				Type:     schema.TypeBool,
				Optional: true,
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
			"connected_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"container_activity_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"container_antivirus_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"disconnected_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"enforce": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"enforcer_image_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gateway_address": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gateway_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gateways": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"high_vulns": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"host_assurance": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"host_behavioral_engine": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"host_network_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"host_os": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"host_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"host_user_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"hostname": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"hosts_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"image_assurance": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"group_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"install_command": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"kube_bench_image_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"last_update": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"logical_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"low_vulns": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"med_vulns": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"micro_enforcer_certs_secrets_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"micro_enforcer_image_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"micro_enforcer_injection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"micro_enforcer_secrets_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"neg_vulns": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"network_activity_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"network_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"orchestrator": {
				Type:     schema.TypeSet,
				Required: true,
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
							Type:     schema.TypeString,
							Optional: true,
						},
						"namespace": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"pas_deployment_link": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"permission": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"risk_explorer_auto_discovery": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"runtime_policy_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"runtime_type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"sync_host_images": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"syscall_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"token": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
			},
			"user_access_control": {
				Type:     schema.TypeBool,
				Optional: true,
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
	if err == nil {
		d.Set("group_id", r.ID)
		d.Set("logical_name", r.LogicalName)
		d.Set("type", r.Type)
		d.Set("enforcer_image_name", r.EnforcerImageName)
		d.Set("description", r.Description)
		d.Set("gateway_name", r.GatewayName)
		d.Set("gateway_address", r.GatewayAddress)
		d.Set("enforce", r.Enforce)
		d.Set("container_activity_protection", r.ContainerAntivirusProtection)
		d.Set("network_activity_protection", r.NetworkActivityProtection)
		d.Set("network_protection", r.NetworkProtection)
		d.Set("behavioral_engine", r.BehavioralEngine)
		d.Set("host_behavioral_engine", r.BehavioralEngine)
		d.Set("host_network_protection", r.HostNetworkProtection)
		d.Set("user_access_control", r.UserAccessControl)
		d.Set("image_assurance", r.ImageAssurance)
		d.Set("host_protection", r.HostNetworkProtection)
		d.Set("audit_all", r.AuditAll)
		d.Set("last_update", r.LastUpdate)
		d.Set("token", r.Token)
		d.Set("command", flattenCommands(r.Command))
		d.Set("orchestrator", flattenOrchestrators(r.Orchestrator))
		d.Set("type", r.Type)
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
		d.Set("auto_discover_configure_registries", r.AllowKubeEnforcerAudit)
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
	} else {
		log.Print("[ERROR]  error calling ac.GetEnforcerGroup: ", r)
		return err
	}

	return nil
}

func resourceEnforcerGroupUpdate(d *schema.ResourceData, m interface{}) error {

	if d.HasChanges("admission_control",
		"allow_kube_enforcer_audit",
		"allowed_labels",
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
		"host_os",
		"host_protection",
		"host_user_protection",
		"image_assurance",
		"kube_bench_image_name",
		"logical_name",
		"micro_enforcer_injection",
		"network_protection",
		"risk_explorer_auto_discovery",
		"sync_host_images",
		"syscall_enabled",
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

	admissionControl, ok := d.GetOk("admission_control")
	if ok {
		enforcerGroup.AdmissionControl = admissionControl.(bool)
	}

	allowKubeEnforcerAudit, ok := d.GetOk("allow_kube_enforcer_audit")
	if ok {
		enforcerGroup.AllowKubeEnforcerAudit = allowKubeEnforcerAudit.(bool)
	}

	allowedLabels, ok := d.GetOk("allowed_labels")
	if ok {
		enforcerGroup.AllowedLabels = allowedLabels.([]string)
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
	if ok {
		enforcerGroup.AutoDiscoveryEnabled = autoDiscoveryEnabled.(bool)
	}

	hostAssurance, ok := d.GetOk("host_assurance")
	if ok {
		enforcerGroup.HostAssurance = hostAssurance.(bool)
	}

	hostBehavioralEngine, ok := d.GetOk("host_behavioral_engine")
	if ok {
		enforcerGroup.HostBehavioralEngine = hostBehavioralEngine.(bool)
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

	microEnforcerInjection, ok := d.GetOk("micro_enforcer_injection")
	if ok {
		enforcerGroup.MicroEnforcerInjection = microEnforcerInjection.(bool)
	}

	networkProtection, ok := d.GetOk("network_protection")
	if ok {
		enforcerGroup.NetworkProtection = networkProtection.(bool)
	}

	riskExplorerAutoDiscovery, ok := d.GetOk("risk_explorer_auto_discovery")
	if ok {
		enforcerGroup.RiskExplorerAutoDiscovery = riskExplorerAutoDiscovery.(bool)
	}

	runtimeType, ok := d.GetOk("runtime_type")
	if ok {
		enforcerGroup.RuntimeType = runtimeType.(string)
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
