package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/pkg/errors"
)

// FirewallPolicy represents a local Aqua Firewall Policy
type FirewallPolicy struct {
	Author               string     `json:"author"`
	BlockICMPPing        bool       `json:"block_icmp_ping"`
	BlockMetadataService bool       `json:"block_metadata_service"`
	Description          string     `json:"description"`
	InboundNetworks      []Networks `json:"inbound_networks"`
	Lastupdate           int        `json:"lastupdate"`
	Name                 string     `json:"name"`
	OutboundNetworks     []Networks `json:"outbound_networks"`
	Type                 string     `json:"type"`
	Version              string     `json:"version"`
}

type Networks struct {
	Allow        bool   `json:"allow"`
	PortRange    string `json:"port_range"`
	Resource     string `json:"resource"`
	ResourceType string `json:"resource_type"`
}

// FirewallPolicyList represents a local Aqua Firewall Policy List
type FirewallPolicyList struct {
	Count    int              `json:"count"`
	Page     int              `json:"page"`
	Pagesize int              `json:"pagesize"`
	Result   []FirewallPolicy `json:"result"`
}

// GetFirewallPolicies - returns all Firewall Policies
func (cli *Client) GetFirewallPolicies() (*FirewallPolicyList, error) {
	var err error
	var response FirewallPolicyList
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/firewall_policies")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting all firewall policy")
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetFirewallPolicies from %s%s, %v ", cli.url, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal firewall_policy response")
		}
	}
	return &response, err
}

// GetFirewallPolicy - returns single Firewall Policy
func (cli *Client) GetFirewallPolicy(name string) (*FirewallPolicy, error) {
	var err error
	var response FirewallPolicy
	apiPath := fmt.Sprintf("/api/v2/firewall_policies/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := cli.gorequest.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting firewall policy")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetFirewallPolicy from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return nil, err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return nil, err
		}
		return nil, fmt.Errorf("failed getting firewall policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	if response.Name == "" {
		return nil, fmt.Errorf("firewall policy not found: %s", name)
	}
	return &response, err
}

// CreateFirewallPolicy - creates single Aqua Firewall Policy
func (cli *Client) CreateFirewallPolicy(firewallPolicy FirewallPolicy) error {
	payload, err := json.Marshal(firewallPolicy)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := "/api/v2/firewall_policies"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating firewall policy.")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed creating firewall policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// UpdateFirewallPolicy updates an existing firewall policy
func (cli *Client) UpdateFirewallPolicy(firewallPolicy FirewallPolicy) error {
	payload, err := json.Marshal(firewallPolicy)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/firewall_policies/%s", firewallPolicy.Name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying firewall policy")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed modifying firewall policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeleteFirewallPolicy removes a Firewall Policy
func (cli *Client) DeleteFirewallPolicy(name string) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/firewall_policies/%s", name)
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting firewall policy")
	}
	if resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed deleting firewall policy, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
