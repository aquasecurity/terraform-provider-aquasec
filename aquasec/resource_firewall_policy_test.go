package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestResourceAquasecFirewallPolicy(t *testing.T) {
	t.Parallel()
	basicFirewallPolicy := client.FirewallPolicy{
		Name:        acctest.RandomWithPrefix("basic-resource-firewall-policy"),
		Description: "this is a basic firewall policy",
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy(fmt.Sprintf("aquasec_firewall_policy.%v", basicFirewallPolicy.Name)),
		Steps: []resource.TestStep{
			{
				Config: getBasicFirewallPolicyResource(basicFirewallPolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(basicFirewallPolicy.Name), "name", basicFirewallPolicy.Name),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(basicFirewallPolicy.Name), "description", basicFirewallPolicy.Description),
				),
			},
			{
				ResourceName:      fmt.Sprintf("aquasec_firewall_policy.%s", basicFirewallPolicy.Name),
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestResourceFirewallPolicyComplex(t *testing.T) {
	t.Parallel()
	complexFirewallpolicy := client.FirewallPolicy{
		Name:                 acctest.RandomWithPrefix("complex-resource-firewall-policy"),
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

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy(fmt.Sprintf("aquasec_firewall_policy.%v", complexFirewallpolicy.Name)),
		Steps: []resource.TestStep{
			{
				Config: getComplexFirewallPolicyResource(complexFirewallpolicy),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "name", complexFirewallpolicy.Name),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "description", complexFirewallpolicy.Description),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "block_metadata_service", fmt.Sprintf("%v", complexFirewallpolicy.BlockMetadataService)),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "block_icmp_ping", fmt.Sprintf("%v", complexFirewallpolicy.BlockICMPPing)),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "outbound_networks.0.allow", fmt.Sprintf("%v", complexFirewallpolicy.OutboundNetworks[0].Allow)),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "outbound_networks.0.port_range", complexFirewallpolicy.OutboundNetworks[0].PortRange),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "outbound_networks.0.resource_type", complexFirewallpolicy.OutboundNetworks[0].ResourceType),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "inbound_networks.0.allow", fmt.Sprintf("%v", complexFirewallpolicy.InboundNetworks[0].Allow)),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "inbound_networks.0.port_range", complexFirewallpolicy.InboundNetworks[0].PortRange),
					resource.TestCheckResourceAttr(firewallPolicyResourceRef(complexFirewallpolicy.Name), "inbound_networks.0.resource_type", complexFirewallpolicy.InboundNetworks[0].ResourceType),
				),
			},
		},
	})
}

func firewallPolicyResourceRef(name string) string {
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
