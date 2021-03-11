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
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"last_updated": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"logical_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
			},
			"gateways": {
				Type:     schema.TypeList,
				Required: true,
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
			},
			"network_protection": {
				Type:     schema.TypeBool,
				Optional: true,
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
				Optional: true,
			},
			"token": {
				Type:     schema.TypeString,
				Optional: true,
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
				Optional: true,
			},
			"install_command": {
				Type:     schema.TypeString,
				Optional: true,
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

	var oType string

	if c, ok := d.GetOk("orchestrator"); ok {
		cList := c.(*schema.Set).List()
		for _, cat := range cList {
			if catData, isMap := cat.(map[string]interface{}); isMap {
				oType = catData["type"].(string)
				//o_namespace = catData["namespace"].(string)
				//o_service_account = catData["service_account"].(string)
				//o_master = catData["master"].(bool)
			}
		}
	}
	// Get the Orchestrator
	orch := client.EnforcerOrchestrator{
		Type: oType,
	}
	// Get the gateways
	g := d.Get("gateways").([]interface{})
	// get the required elements
	group := client.EnforcerGroup{
		ID:           d.Get("group_id").(string),
		Logicalname:  d.Get("logical_name").(string),
		Type:         d.Get("type").(string),
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
	if err != nil {
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

	if d.HasChanges("description", "gateways", "orchestrator") {
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
			Orchestrator: orch,
		}

		err := ac.UpdateEnforcerGroup(group)
		if err == nil {
			_ = d.Set("last_updated", time.Now().Format(time.RFC850))

		} else {
			log.Println("[DEBUG]  error while updating enforcer group: ", err)
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
