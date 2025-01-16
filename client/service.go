package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/pkg/errors"
)

// Service represents a local Aqua Service
type Service struct {
	Name              string               `json:"name"`
	Description       string               `json:"description"`
	Author            string               `json:"author"`
	Containers        []string             `json:"containers"`
	ContainersCount   int                  `json:"containers_count"`
	Evaluated         bool                 `json:"evaluated"`
	Monitoring        bool                 `json:"monitoring"`
	Policies          []string             `json:"policies"`
	LocalPolicies     []LocalPolicy        `json:"local_policies,omitempty"`
	Lastupdate        int                  `json:"lastupdate"`
	Vulnerabilities   VulnerabilitiesTypes `json:"vulnerabilities"`
	Enforce           bool                 `json:"enforce"`
	MembershipRules   MembershipRules      `json:"membership_rules"`
	NotEvaluatedCount int                  `json:"not_evaluated_count"`
	UnregisteredCount int                  `json:"unregistered_count"`
	IsRegistered      bool                 `json:"is_registered"`
	ApplicationScopes []string             `json:"application_scopes"`
}

type LocalPolicy struct {
	Name                 string        `json:"name"`
	Type                 string        `json:"type"`
	Description          string        `json:"description,omitempty"`
	InboundNetworks      []NetworkRule `json:"inbound_networks,omitempty"`
	OutboundNetworks     []NetworkRule `json:"outbound_networks,omitempty"`
	BlockMetadataService bool          `json:"block_metadata_service"`
}
type NetworkRule struct {
	PortRange    string `json:"port_range"`
	ResourceType string `json:"resource_type"`
	Resource     string `json:"resource"`
	Allow        bool   `json:"allow"`
}
type VulnerabilitiesTypes struct {
	Total        int     `json:"total"`
	High         int     `json:"high"`
	Medium       int     `json:"medium"`
	Low          int     `json:"low"`
	Sensitive    int     `json:"sensitive"`
	Malware      int     `json:"malware"`
	Negligible   int     `json:"negligible"`
	ScoreAverage float64 `json:"score_average"`
}

type MembershipRules struct {
	Priority int    `json:"priority"`
	Scope    Scope  `json:"scope"`
	Target   string `json:"target"`
}

type Scope struct {
	Expression string     `json:"expression"`
	Variables  []Variable `json:"variables"`
}

type Variable struct {
	Attribute string `json:"attribute"`
	Name      string `json:"name,omitempty"`
	Value     string `json:"value"`
}

type ServiceList struct {
	Count    int       `json:"count"`
	Page     int       `json:"page"`
	Pagesize int       `json:"pagesize"`
	Result   []Service `json:"result"`
}

// GetServices gets all the available services
func (cli *Client) GetServices() (*ServiceList, error) {
	var err error
	var response ServiceList
	request := cli.gorequest
	apiPath := "/api/v1/applications"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting list of Service")
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error unmarshalling response as Service list")
			return nil, errors.Wrap(err, fmt.Sprintf("couldn't unmarshal list service response. Body: %v", body))
		}
	} else {
		var errorResponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Error unmarshalling error response")
			return nil, fmt.Errorf("failed getting service list. Status: %v, Response: %v", events.StatusCode, body)
		}
		return nil, fmt.Errorf("failed to list Services. Status: %v. error message: %v", events.StatusCode, errorResponse.Message)
	}
	return &response, nil
}

// GetService gets an Aqua service by name
func (cli *Client) GetService(name string) (*Service, error) {
	var err error
	var response Service
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/applications/%v", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting service with name "+name)
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error unmarshaling response body")
			return nil, errors.Wrap(err, fmt.Sprintf("couldn't unmarshal get service response. Body: %v", body))
		}
	} else {
		var errorReponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorReponse)
		if err != nil {
			log.Println("failed to unmarshal error response")
			return nil, fmt.Errorf("failed getting service with name %v. Status: %v, Response: %v", name, events.StatusCode, body)
		}

		return nil, fmt.Errorf("failed getting service with name %v. Status: %v, error message: %v", name, events.StatusCode, errorReponse.Message)
	}

	return &response, nil
}

// CreateService creates an Aqua Service
func (cli *Client) CreateService(service *Service) error {
	payload, err := json.Marshal(service)
	if err != nil {
		return err
	}

	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/applications")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating service.")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v", body)
			return fmt.Errorf("failed creating service with name %v. Status: %v, Response: %v", service.Name, resp.StatusCode, body)
		}
		return fmt.Errorf("failed creating service. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// UpdateService updates an existing service policy
func (cli *Client) UpdateService(service *Service) error {
	payload, err := json.Marshal(service)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/applications/%s", service.Name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying service")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := io.ReadAll(resp.Body)
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
		return fmt.Errorf("failed modifying service policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeleteService removes a Aqua Service
func (cli *Client) DeleteService(name string) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/applications/%s", name)
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting service")
	}
	if resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		err := json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v.", body)
			return err
		}
		return fmt.Errorf("failed deleting service, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
