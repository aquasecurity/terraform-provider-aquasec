package aquasec

import (
	"context"
	"fmt"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceFirewallPolicy() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataFirewallPolicyRead,
		Schema: map[string]*schema.Schema{
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the policy.",
				Computed:    true,
			},
			"block_icmp_ping": {
				Type:        schema.TypeBool,
				Description: "Indicates whether policy includes blocking incoming 'ping' requests.",
				Computed:    true,
			},
			"block_metadata_service": {
				Type:        schema.TypeBool,
				Description: "Indicates whether policy includes blocking metadata services of the cloud.",
				Computed:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "Description of the Firewall Policy.",
				Computed:    true,
			},
			"inbound_networks": {
				Type:        schema.TypeList,
				Description: "Information on network addresses that are allowed to pass in data or requests.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"allow": {
							Type:        schema.TypeBool,
							Description: "Indicates whether the specified resources are allowed to pass in data or requests.",
							Computed:    true,
						},
						"port_range": {
							Type:        schema.TypeString,
							Description: "Range of ports affected by firewall.",
							Computed:    true,
						},
						"resource": {
							Type:        schema.TypeString,
							Description: "Information of the resource.",
							Computed:    true,
						},
						"resource_type": {
							Type:        schema.TypeString,
							Description: "Type of the resource",
							Computed:    true,
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
			},
			"outbound_networks": {
				Type:        schema.TypeList,
				Description: "Information on network addresses that are allowed to receive data or requests.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"allow": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Indicates whether the specified resources are allowed to receive data or requests.",
						},
						"port_range": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Range of ports affected by firewall.",
						},
						"resource": {
							Type:        schema.TypeString,
							Description: "Information of the resource.",
							Computed:    true,
						},
						"resource_type": {
							Type:        schema.TypeString,
							Description: "Type of the resource.",
							Computed:    true,
						},
					},
				},
			},
			"type": {
				Type:        schema.TypeString,
				Description: "Indicates the class of protection defined by the firewall.",
				Computed:    true,
			},
			"version": {
				Type:        schema.TypeString,
				Description: "Aqua version functionality supported",
				Computed:    true,
			},
		},
	}
}

func dataFirewallPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	if name == "" {
		return diag.FromErr(fmt.Errorf("firewall rule name is required"))
	}

	firewallPolicy, err := c.GetFirewallPolicy(name)
	if err != nil {
		return diag.FromErr(err)
	}

	if firewallPolicy != nil {
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

		return nil
	}

	d.SetId("")

	return diag.FromErr(fmt.Errorf("firewall rule %s not found", name))
}
