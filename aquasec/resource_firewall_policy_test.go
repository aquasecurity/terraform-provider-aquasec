package aquasec

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestResourceAquasecFirewallPolicy(t *testing.T) {
	basicFirewallPolicy := client.FirewallPolicy{
		Name:        "basic-resource-firewall-policy" + randSuffix(6),
		Description: "this is a basic firewall policy",
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicFirewallPolicyResource(basicFirewallPolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceRef(basicFirewallPolicy.Name), "name", basicFirewallPolicy.Name),
					resource.TestCheckResourceAttr(resourceRef(basicFirewallPolicy.Name), "description", basicFirewallPolicy.Description),
				),
			},
		},
	})
}

func TestResourceFirewallPolicyComplex(t *testing.T) {
	complexFirewallpolicy := client.FirewallPolicy{
		Name:                 "complex-resource-firewall-policy" + randSuffix(6),
		Description:          "this is a complex firewall policy",
		BlockICMPPing:        false,
		BlockMetadataService: true,
		InboundNetworks: []client.Networks{
			{
				Allow:        true,
				PortRange:    "8080-9090",
				ResourceType: "anywhere",
			},
		},
		OutboundNetworks: []client.Networks{
			{
				Allow:        true,
				PortRange:    "6060-7777",
				ResourceType: "anywhere",
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getComplexFirewallPolicyResource(complexFirewallpolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "name", complexFirewallpolicy.Name),
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "description", complexFirewallpolicy.Description),
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "block_metadata_service", fmt.Sprintf("%v", complexFirewallpolicy.BlockMetadataService)),
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "block_icmp_ping", fmt.Sprintf("%v", complexFirewallpolicy.BlockICMPPing)),
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "outbound_networks.0.allow", fmt.Sprintf("%v", complexFirewallpolicy.OutboundNetworks[0].Allow)),
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "outbound_networks.0.port_range", complexFirewallpolicy.OutboundNetworks[0].PortRange),
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "outbound_networks.0.resource_type", complexFirewallpolicy.OutboundNetworks[0].ResourceType),
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "inbound_networks.0.allow", fmt.Sprintf("%v", complexFirewallpolicy.InboundNetworks[0].Allow)),
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "inbound_networks.0.port_range", complexFirewallpolicy.InboundNetworks[0].PortRange),
					resource.TestCheckResourceAttr(resourceRef(complexFirewallpolicy.Name), "inbound_networks.0.resource_type", complexFirewallpolicy.InboundNetworks[0].ResourceType),
				),
			},
		},
	})
}

func resourceRef(name string) string {
	return fmt.Sprintf("aquasec_firewall_policy.%s", name)
}

func getBasicFirewallPolicyResource(firewallPolicy client.FirewallPolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_firewall_policy" "%s" {
		name = "%s"
		description = "%s"
	}`, firewallPolicy.Name,
		firewallPolicy.Name,
		firewallPolicy.Description,
	)
}

func getComplexFirewallPolicyResource(firewallPolicy client.FirewallPolicy) string {
	return fmt.Sprintf(`
	resource "aquasec_firewall_policy" "%s" {
		name = "%s"
		description = "%s"
		block_icmp_ping = "%v"
		block_metadata_service = "%v"
		inbound_networks {
			allow = %v
			port_range = "%s"
			resource_type = "%s"
		}
		outbound_networks {
			allow = %v
			port_range = "%s"
			resource_type = "%s"
		}
	  }`, firewallPolicy.Name,
		firewallPolicy.Name,
		firewallPolicy.Description,
		firewallPolicy.BlockICMPPing,
		firewallPolicy.BlockMetadataService,
		firewallPolicy.InboundNetworks[0].Allow,
		firewallPolicy.InboundNetworks[0].PortRange,
		firewallPolicy.InboundNetworks[0].ResourceType,
		firewallPolicy.OutboundNetworks[0].Allow,
		firewallPolicy.OutboundNetworks[0].PortRange,
		firewallPolicy.OutboundNetworks[0].ResourceType,
	)
}
