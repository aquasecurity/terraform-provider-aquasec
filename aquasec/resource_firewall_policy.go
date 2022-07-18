package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceFirewallPolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceFirewallPolicyCreate,
		ReadContext:   resourceFirewallPolicyRead,
		UpdateContext: resourceFirewallPolicyUpdate,
		DeleteContext: resourceFirewallPolicyDelete,
		Schema: map[string]*schema.Schema{
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the policy.",
				Computed:    true,
			},
			"block_icmp_ping": {
				Type:        schema.TypeBool,
				Description: "Indicates whether policy includes blocking incoming 'ping' requests.",
				Optional:    true,
			},
			"block_metadata_service": {
				Type:        schema.TypeBool,
				Description: "Indicates whether policy includes blocking metadata services of the cloud.",
				Optional:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "Description of the Firewall Policy.",
				Optional:    true,
			},
			"inbound_networks": {
				Type:        schema.TypeList,
				Description: "Information on network addresses that are allowed to pass in data or requests.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"allow": {
							Type:        schema.TypeBool,
							Description: "Indicates whether the specified resources are allowed to pass in data or requests.",
							Required:    true,
						},
						"port_range": {
							Type:        schema.TypeString,
							Description: "Range of ports affected by firewall.",
							Required:    true,
						},
						"resource": {
							Type:        schema.TypeString,
							Description: "Information of the resource.",
							Computed:    true,
							Optional:    true,
						},
						"resource_type": {
							Type:        schema.TypeString,
							Description: "Type of the resource",
							Required:    true,
						},
					},
				},
			},
			"lastupdate": {
				Type:        schema.TypeInt,
				Description: "Timestamp of the last update in Unix time format.",
				Computed:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the policy, no longer than 128 characters and no slash characters.",
				Required:    true,
				ForceNew:    true,
			},
			"outbound_networks": {
				Type:        schema.TypeList,
				Description: "Information on network addresses that are allowed to receive data or requests.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"allow": {
							Type:        schema.TypeBool,
							Required:    true,
							Description: "Indicates whether the specified resources are allowed to receive data or requests.",
						},
						"port_range": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Range of ports affected by firewall.",
						},
						"resource": {
							Type:        schema.TypeString,
							Description: "Information of the resource.",
							Optional:    true,
							Computed:    true,
						},
						"resource_type": {
							Type:        schema.TypeString,
							Description: "Type of the resource.",
							Required:    true,
						},
					},
				},
			},
			"type": {
				Type:        schema.TypeString,
				Description: "Indicates the class of protection defined by the firewall.",
				Computed:    true,
				Optional:    true,
			},
			"version": {
				Type:        schema.TypeString,
				Description: "Aqua version functionality supported",
				Computed:    true,
				Optional:    true,
			},
		},
	}
}

func resourceFirewallPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	firewallPolicy := expandFirewallPolicy(d)
	err := c.CreateFirewallPolicy(firewallPolicy)
	if err != nil {
		return diag.FromErr(err)
	}

	//d.SetId(name)
	err1 := resourceFirewallPolicyRead(ctx, d, m)
	if err1 == nil {
		d.SetId(name)
	} else {
		return err1
	}

	//return resourceFirewallPolicyRead(ctx, d, m)
	return nil
}

func resourceFirewallPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	firewallPolicy, err := c.GetFirewallPolicy(name)
	if err == nil {
		d.Set("description", firewallPolicy.Description)
		d.Set("block_icmp_ping", firewallPolicy.BlockICMPPing)
		d.Set("block_metadata_service", firewallPolicy.BlockMetadataService)
		d.Set("type", firewallPolicy.Type)
		d.Set("author", firewallPolicy.Author)
		d.Set("lastupdate", firewallPolicy.Lastupdate)
		d.Set("version", firewallPolicy.Version)
		d.Set("inbound_networks", flattenNetworks(firewallPolicy.InboundNetworks))
		d.Set("outbound_networks", flattenNetworks(firewallPolicy.OutboundNetworks))

		d.SetId(name)
	} else {
		return diag.FromErr(err)
	}

	return nil
}

func resourceFirewallPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	if d.HasChanges("description", "block_icmp_ping", "block_metadata_service", "author", "lastupdate", "version", "inbound_networks", "outbound_networks") {
		firewallPolicy := expandFirewallPolicy(d)
		err := c.UpdateFirewallPolicy(firewallPolicy)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func resourceFirewallPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	err := c.DeleteFirewallPolicy(name)
	if err == nil {
		d.SetId("")
	} else {
		return diag.FromErr(err)
	}

	//d.SetId("")

	return nil
}

func expandFirewallPolicy(d *schema.ResourceData) client.FirewallPolicy {
	firewallPolicy := client.FirewallPolicy{
		Name: d.Get("name").(string),
	}

	author, ok := d.GetOk("author")
	if ok {
		firewallPolicy.Author = author.(string)
	}

	blockPing, ok := d.GetOk("block_icmp_ping")
	if ok {
		firewallPolicy.BlockICMPPing = blockPing.(bool)
	}

	blockSvc, ok := d.GetOk("block_metadata_service")
	if ok {
		firewallPolicy.BlockMetadataService = blockSvc.(bool)
	}

	desc, ok := d.GetOk("description")
	if ok {
		firewallPolicy.Description = desc.(string)
	}

	inboundNetworks, ok := d.GetOk("inbound_networks")
	if ok {
		inboundNetworksList := inboundNetworks.([]interface{})
		networkArr := make([]client.Networks, len(inboundNetworksList))
		for i, inboundNetworkData := range inboundNetworksList {
			inboundNetwork := inboundNetworkData.(map[string]interface{})
			network := client.Networks{
				Allow:        inboundNetwork["allow"].(bool),
				PortRange:    inboundNetwork["port_range"].(string),
				ResourceType: inboundNetwork["resource_type"].(string),
			}

			res, ok := inboundNetwork["resource"]
			if ok {
				network.Resource = res.(string)
			}

			networkArr[i] = network
		}

		firewallPolicy.InboundNetworks = networkArr
	}

	lastupdate, ok := d.GetOk("lastupdate")
	if ok {
		firewallPolicy.Lastupdate = lastupdate.(int)
	}

	typ, ok := d.GetOk("type")
	if ok {
		firewallPolicy.Type = typ.(string)
	}

	version, ok := d.GetOk("version")
	if ok {
		firewallPolicy.Type = version.(string)
	}

	outboundNetworks, ok := d.GetOk("outbound_networks")
	if ok {
		outboundNetworksList := outboundNetworks.([]interface{})
		networkArr := make([]client.Networks, len(outboundNetworksList))
		for i, outboundNetworkData := range outboundNetworksList {
			outboundNetwork := outboundNetworkData.(map[string]interface{})
			network := client.Networks{
				Allow:        outboundNetwork["allow"].(bool),
				PortRange:    outboundNetwork["port_range"].(string),
				ResourceType: outboundNetwork["resource_type"].(string),
			}

			res, ok := outboundNetwork["resource"]
			if ok {
				network.Resource = res.(string)
			}

			networkArr[i] = network
		}

		firewallPolicy.OutboundNetworks = networkArr
	}

	return firewallPolicy
}

func flattenNetworks(networks []client.Networks) []map[string]interface{} {
	flattenedNetworks := make([]map[string]interface{}, len(networks))
	for i, network := range networks {
		flattenedNetworks[i] = flattenNetwork(network)
	}

	return flattenedNetworks
}

func flattenNetwork(network client.Networks) map[string]interface{} {
	return map[string]interface{}{
		"allow":         network.Allow,
		"port_range":    network.PortRange,
		"resource_type": network.ResourceType,
		"resource":      network.Resource,
	}
}
