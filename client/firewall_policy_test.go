package client

import (
	"fmt"
	"testing"
)

func TestName(t *testing.T) {
	aquaClient := NewClient("https://demox.aquasec.com", "mohammad", "mohammad123")

	con := aquaClient.GetAuthToken()
	if con {
		fmt.Println("connected")
	} else {
		fmt.Println("not connected")
		return
	}
	err := aquaClient.CreateFirewallPolicy(FirewallPolicy{
		Description: "this is test firewall policy created from the go client",
		InboundNetworks: []Networks{
			{
				Allow:        true,
				PortRange:    "0-6565",
				ResourceType: "anywhere",
			},
		},
		Name: "go-client-test",
		OutboundNetworks: []Networks{
			{
				Allow:        true,
				PortRange:    "90-9090",
				ResourceType: "anywhere",
			},
			{
				Allow:        true,
				PortRange:    "9091-99199",
				ResourceType: "anywhere",
			},
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	firewallPolicies, err := aquaClient.GetFirewallPolicies()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("getall firewall resources:", firewallPolicies)

	firewallPolicy, err := aquaClient.GetFirewallPolicy("go-client-test")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("get single firewall resources:", firewallPolicy)

	err = aquaClient.UpdateFirewallPolicy(FirewallPolicy{
		Description: "this is updated from go client",
		Name:        "go-client-test",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("updated firewall policy successfully")

	firewallPolicies, err = aquaClient.GetFirewallPolicies()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(firewallPolicies)

	err = aquaClient.DeleteFirewallPolicy("go-client-test")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("deleted firewall policy successfully")
}
