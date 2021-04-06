package client

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

//EnforcerOrchestrator represents a single Orchestrator
type EnforcerOrchestrator struct {
	Type           string `json:"type"`
	Master         bool   `json:"master"`
	ServiceAccount string `json:"service_account,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
}

//EnforcerCommand represents a single Commands
type EnforcerCommand struct {
	Default    string `json:"default"`
	Kubernetes string `json:"kubernetes"`
	Swarm      string `json:"swarm"`
	Windows    string `json:"windows"`
}

// EnforcerGroup is the request and response format for an Enforcer Group (hostbatch)
type EnforcerGroup struct {
	ID                                        string               `json:"id"`
	Logicalname                               string               `json:"logicalname"`
	Type                                      string               `json:"type"`
	EnforcerImageName                         string               `json:"enforcer_image_name"`
	Description                               string               `json:"description"`
	Gateways                                  []string             `json:"gateways"`
	GatewayName                               string               `json:"gateway_name"`
	GatewayAddress                            string               `json:"gateway_address"`
	Enforce                                   bool                 `json:"enforce"`
	ContainerActivityProtection               bool                 `json:"container_activity_protection"`
	NetworkProtection                         bool                 `json:"network_protection"`
	HostNetworkProtection                     bool                 `json:"host_network_protection"`
	UserAccessControl                         bool                 `json:"user_access_control"`
	ImageAssurance                            bool                 `json:"image_assurance"`
	HostProtection                            bool                 `json:"host_protection"`
	AuditAll                                  bool                 `json:"audit_all"`
	AuditSuccessLogin                         bool                 `json:"audit_success_login"`
	AuditFailedLogin                          bool                 `json:"audit_failed_login"`
	LastUpdate                                int                  `json:"last_update"`
	Token                                     string               `json:"token"`
	Command                                   EnforcerCommand      `json:"command"`
	Orchestrator                              EnforcerOrchestrator `json:"orchestrator"`
	HostOs                                    string               `json:"host_os"`
	InstallCommand                            string               `json:"install_command"`
	HostsCount                                int                  `json:"hosts_count"`
	DisconnectedCount                         int                  `json:"disconnected_count"`
	ConnectedCount                            int                  `json:"connected_count"`
	HighVulns                                 int                  `json:"high_vulns"`
	MedVulns                                  int                  `json:"med_vulns"`
	LowVulns                                  int                  `json:"low_vulns"`
	NegVulns                                  int                  `json:"neg_vulns"`
	SyscallEnabled                            bool                 `json:"syscall_enabled"`
	RuntimeType                               string               `json:"runtime_type"`
	SyncHostImages                            bool                 `json:"sync_host_images"`
	RiskExplorerAutoDiscovery                 bool                 `json:"risk_explorer_auto_discovery"`
	RuntimePolicyName                         string               `json:"runtime_policy_name"`
	PasDeploymentLink                         string               `json:"pas_deployment_link"`
	AquaVersion                               string               `json:"aqua_version"`
	AllowKubeEnforcerAudit                    bool                 `json:"allow_kube_enforcer_audit"`
	AutoDiscoveryEnabled                      bool                 `json:"auto_discovery_enabled"`
	AutoDiscoverConfigureRegistries           bool                 `json:"auto_discover_configure_registries"`
	AutoScanDiscoveredImagesRunningContainers bool                 `json:"auto_scan_discovered_images_running_containers"`
	AdmissionControl                          bool                 `json:"admission_control"`
	MicroEnforcerInjection                    bool                 `json:"micro_enforcer_injection"`
	Permission                                string               `json:"permission"`
	MicroEnforcerImageName                    string               `json:"micro_enforcer_image_name"`
	MicroEnforcerSecretsName                  string               `json:"micro_enforcer_secrets_name"`
	BlockAdmissionControl                     bool                 `json:"block_admission_control"`
}

// GetEnforcerGroup - returns single Enforcer group
// hard-coded page size of 100 for now
func (cli *Client) GetEnforcerGroup(name string) (*EnforcerGroup, error) {
	var err error
	var response EnforcerGroup
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/hostsbatch/%s", name)
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetEnforcerGroup from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	if response.ID == "" {
		err = fmt.Errorf("enforcer group not found: %s", name)
		return nil, err
	}
	return &response, err
}

// GetEnforcerGroups - returns all Enforcer groups
func (cli *Client) GetEnforcerGroups() ([]EnforcerGroup, error) {
	var err error
	var response []EnforcerGroup
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/hostsbatch")
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetEnforcerGroups from %s%s, %v ", cli.url, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal []EnforcerGroup response")
		}
	}
	return response, err
}

// CreateEnforcerGroup - creates single Aqua enforcer group
func (cli *Client) CreateEnforcerGroup(group EnforcerGroup) error {
	payload, err := json.Marshal(group)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/hostsbatch")
	resp, _, errs := request.Clone().Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed creating enforcer group")
	}
	if resp.StatusCode != 201 || resp.StatusCode != 204 {
		return err
	}
	return nil
}

// UpdateEnforcerGroup updates an existing enforcer group
// hardcoded update_enforcers parameter to true (for now)
func (cli *Client) UpdateEnforcerGroup(group EnforcerGroup) error {
	payload, err := json.Marshal(group)

	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := "/api/v1/hostsbatch"
	resp, _, errs := request.Clone().Put(cli.url+apiPath).Send(string(payload)).Param("update_enforcers", "true").End()
	//resp, _, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()

	if errs != nil {
		return errors.Wrap(err, "failed modifying enforcer group")
	}
	if resp.StatusCode != 201 || resp.StatusCode != 204 {
		return err
	}
	return nil
}

// DeleteEnforcerGroup removes an enforcer group
func (cli *Client) DeleteEnforcerGroup(name string) error {
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/hostsbatch/%s", name)
	events, _, errs := request.Clone().Delete(cli.url + apiPath).End()
	if errs != nil {
		return fmt.Errorf("error while calling DELETE on /api/v1/hostsbatch/%s: %v", name, events.StatusCode)
	}
	if events.StatusCode != 204 {
		return fmt.Errorf("failed deleting enforcer group, status code: %v", events.StatusCode)
	}
	return nil
}
