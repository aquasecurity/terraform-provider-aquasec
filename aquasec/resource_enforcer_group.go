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
			"group_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"sync_host_images": {
				Type:     schema.TypeBool,
				Optional: true,
				Default: false,
			},
			"risk_explorer_auto_discovery": {
				Type:     schema.TypeBool,
				Optional: true,
				Default: false,
			},
			"syscall_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default: false,
			},
			"enforcer_image": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"last_updated": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"logical_name": {
				Type:     schema.TypeString,
				Optional: true,
				Default: "default_value",
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
			},
			"gateways": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
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
				Optional: true,
			},
			"container_activity_protection": {
				Type:     schema.TypeBool,
				Optional: true,
				Default: false,
			},
			"network_protection": {
				Type:     schema.TypeBool,
				Optional: true,
				Default: false,
			},
			"host_network_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"user_access_control": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"image_assurance": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"host_protection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"audit_all": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"audit_success_login": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"audit_failed_login": {
				Type:     schema.TypeBool,
				Optional: true,
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
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"default": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"kubernetes": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"swarm": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"windows": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
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
			"host_os": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"install_command": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"allow_kube_enforcer_audit": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_discovery_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_discover_configure_registries": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_scan_discovered_images_running_containers": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"admission_control": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"micro_enforce_injection": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"block_admission_control": {
				Type:     schema.TypeBool,
				Optional: true,
			},
		},
	}
}

func resourceEnforcerGroupCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	var oType, oNameSpace, oServiceAccount  string
	var oMaster bool

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
	}
	// Get the Orchestrator
	orch := client.EnforcerOrchestrator{
		Type: oType,
		Namespace: oNameSpace,
		ServiceAccount: oServiceAccount,
		Master: oMaster,
	}
	// Get the gateways
	g := d.Get("gateways").([]interface{})
	
	// get the required elements
	group := client.EnforcerGroup{
		ID:           d.Get("group_id").(string),
		Logicalname:  d.Get("logical_name").(string),
		Type:         d.Get("type").(string),
		Description:  d.Get("description").(string),
		ImageAssurance: d.Get("image_assurance").(bool),
		ContainerActivityProtection: d.Get("container_activity_protection").(bool),
		NetworkProtection: d.Get("network_protection").(bool),
		SyncHostImages: d.Get("sync_host_images").(bool),
		RiskExplorerAutoDiscovery: d.Get("risk_explorer_auto_discovery").(bool),
		SyscallEnabled: d.Get("syscall_enabled").(bool),
		Enforce: d.Get("enforce").(bool),
		EnforcerImageName: d.Get("enforcer_image").(string),
		Gateways:     convertStringArr(g),
		Orchestrator: orch,
	}

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
	ac := m.(*client.Client)
	name := d.Get("group_id").(string)

	r, err := ac.GetEnforcerGroup(name)
	if err == nil {
		d.Set("token", r.Token)
		d.Set("gateway_name", r.GatewayName)
		d.Set("gateway_address", r.GatewayAddress)
		d.Set("container_activity_protection", r.ContainerActivityProtection)
		d.Set("network_protection", r.NetworkProtection)
		d.Set("host_network_protection", r.HostNetworkProtection)
		d.Set("user_access_control", r.UserAccessControl)
		d.Set("image_assurance", r.ImageAssurance)
		d.Set("host_protection", r.HostProtection)
		d.Set("audit_all", r.AuditAll)
		d.Set("audit_success_login", r.AuditSuccessLogin)
		d.Set("audit_failed_login", r.AuditFailedLogin)
		d.Set("last_update", r.LastUpdate)
		d.Set("command", flattenCommands(r.Command))
		d.Set("host_os", r.HostOs)
		d.Set("install_command", r.InstallCommand)
		d.Set("allow_kube_enforcer_audit", r.AllowKubeEnforcerAudit)
		d.Set("auto_discovery_enabled", r.AutoDiscoveryEnabled)
		d.Set("auto_discover_configure_registries", r.AutoDiscoverConfigureRegistries)
		d.Set("auto_scan_discovered_images_running_containers", r.AutoScanDiscoveredImagesRunningContainers)
		d.Set("admission_control", r.AdmissionControl)
		d.Set("micro_enforce_injection", r.MicroEnforcerInjection)
		d.Set("block_admission_control", r.BlockAdmissionControl)
		d.Set("logical_name", r.Logicalname)
		d.Set("gateways", r.Gateways)
		d.Set("risk_explorer_auto_discovery", r.RiskExplorerAutoDiscovery)
		d.Set("syscall_enabled", r.SyscallEnabled)
		d.Set("sync_host_images", r.SyncHostImages) 
		d.Set("enforcer_image", r.EnforcerImageName)
	} else {
		log.Print("[ERROR]  error calling ac.GetEnforcerGroup: ", r)
		return err
	}

	return nil
}

func resourceEnforcerGroupUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	var oType, oNamespace, oServiceAccount string
	var oMaster bool

	if c, ok := d.GetOk("orchestrator"); ok {
		cList := c.(*schema.Set).List()
		for _, cat := range cList {
			if catData, isMap := cat.(map[string]interface{}); isMap {
				oType = catData["type"].(string)
				oNamespace = catData["namespace"].(string)
				oServiceAccount = catData["service_account"].(string)
				oMaster = catData["master"].(bool)
			}
		}
	}

	// if d.HasChanges("description", "gateways", "orchestrator", "logical_name") {
		// Get the Orchestrator

		orch := client.EnforcerOrchestrator{
			Type:           oType,
			Master:         oMaster,
			ServiceAccount: oServiceAccount,
			Namespace:      oNamespace,
		}
		// get the required elements

		group := client.EnforcerGroup{
			ID:           d.Get("group_id").(string),
			Logicalname:  d.Get("logical_name").(string),
			Type:         d.Get("type").(string),
			Gateways:     convertStringArr(d.Get("gateways").([]interface{})),
			Description:  d.Get("description").(string),
			ContainerActivityProtection: d.Get("container_activity_protection").(bool),
			NetworkProtection: d.Get("network_protection").(bool),
			SyncHostImages: d.Get("sync_host_images").(bool),
			RiskExplorerAutoDiscovery: d.Get("risk_explorer_auto_discovery").(bool),
			SyscallEnabled: d.Get("syscall_enabled").(bool),
			Enforce: d.Get("enforce").(bool),
			EnforcerImageName: d.Get("enforcer_image").(string),
			Orchestrator: orch,
		}

		err := ac.UpdateEnforcerGroup(group)
		if err == nil {
			_ = d.Set("last_updated", time.Now().Format(time.RFC850))
		} else {
			log.Println("[DEBUG]  error while updating enforcer group: ", err)
			return err
		}
	// }
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
