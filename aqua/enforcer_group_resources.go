package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"time"
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

	// Get the Orchestrator
	orch := client.EnforcerOrchestrator{
		Type: d.Get("type").(string),
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
	log.Println(d)
	d.SetId(d.Get("group_id").(string))

	err = resourceEnforcerGroupRead(d, m)
	return err
}

func resourceEnforcerGroupRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("group_id").(string)
	log.Println("[DEBUG]  enforcer group name: ", name)
	r, err := ac.GetEnforcerGroup(name)
	if err != nil {
		log.Print("[ERROR]  error calling ac.GetEnforcerGroup: ", r)
		return err
	}
	log.Println("[DEBUG]  enforcer group: ", r)
	return nil
}

func resourceEnforcerGroupUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	if d.HasChanges("description", "gateways", "orchestrator") {
		// Get the Orchestrator
		orch := client.EnforcerOrchestrator{
			Type:           d.Get("type").(string),
			Master:         d.Get("master").(bool),
			ServiceAccount: d.Get("service_account").(string),
			Namespace:      d.Get("namespace").(string),
		}
		// get the required elements
		group := client.EnforcerGroup{
			ID:           d.Get("group_id").(string),
			Logicalname:  d.Get("logical_name").(string),
			Type:         d.Get("type").(string),
			Gateways:     convertStringArr(d.Get("prefixes").([]interface{})),
			Orchestrator: orch,
		}
		err := ac.UpdateEnforcerGroup(group)
		if err != nil {
			log.Println("[DEBUG]  error while updating enforcer group: ", err)
			return err
		}
		_ = d.Set("last_updated", time.Now().Format(time.RFC850))
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
