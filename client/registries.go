package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

// Registry defines a registry
type Registry struct {
	Name                       string    `json:"name"`
	Type                       string    `json:"type"` // [HUB, V1/V2, ENGINE, AWS, GCR]
	Description                string    `json:"description"`
	Author                     string    `json:"author"`
	Lastupdate                 int       `json:"lastupdate"`
	URL                        string    `json:"url"`
	Username                   string    `json:"username"`
	Password                   string    `json:"password"`
	ImageCreationDateCondition string    `json:"image_creation_date_condition"`
	AdvancedSettingsCleanup    bool      `json:"advanced_settings_cleanup"`
	AutoPull                   bool      `json:"auto_pull"`
	AutoPullTime               string    `json:"auto_pull_time"`
	AutoPullMax                int       `json:"auto_pull_max"`
	RegistryScanTimeout        int       `json:"registry_scan_timeout"`
	AutoPullInterval           int       `json:"auto_pull_interval"`
	AutoCleanUp                bool      `json:"auto_cleanup"`
	AlwaysPullPatterns         []string  `json:"always_pull_patterns"`
	PullRepoPatternsExcluded   []string  `json:"pull_repo_patterns_excluded"`
	AutoPullRescan             bool      `json:"auto_pull_rescan"`
	Prefixes                   []string  `json:"prefixes"`
	Webhook                    Webhook   `json:"webhook"`
	PullImageAge               string    `json:"pull_image_age"`
	PullImageCount             int       `json:"pull_image_count"`
	PullImageTagPattern        []string  `json:"pull_image_tag_pattern"`
	ScannerType                string    `json:"scanner_type"`
	ScannerName                []string  `json:"scanner_name,omitempty"`
	ScannerNameAdded           []string  `json:"scanner_name_added,omitempty"`
	ScannerNameRemoved         []string  `json:"scanner_name_removed,omitempty"`
	ExistingScanners           []string  `json:"existsing_scanners,omitempty"`
	Options                    []Options `json:"options"`
	//Architecture               string        `json:"architecture"`
	//ICRAccountId               string        `json:"icr_account_id"`
	//ACRConnectionType          string        `json:"acr_connection_type"`
	//SubscriptionId             string        `json:"subscription_id"`
	//TenantId                   string        `json:"tenant_id"`
}
type Webhook struct {
	Enabled      bool   `json:"enabled,omitempty"`
	URL          string `json:"url"`
	AuthToken    string `json:"auth_token"`
	UnQuarantine bool   `json:"un_quarantine,omitempty"`
}

type Options struct {
	Option string `json:"option"`
	Value  string `json:"value"`
}

func (cli *Client) GetRegistry(name string) (*Registry, error) {
	var err error
	var response Registry
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/registries/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		log.Println(events.StatusCode)
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetRegistry from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	if response.Name == "" {
		err = fmt.Errorf("registry: %s not found 404", name)
		return nil, err
	}
	return &response, err
}

// GetRegistries - retrieves all configured registry integrations
func (cli *Client) GetRegistries() (*[]Registry, error) {
	var err error
	var response []Registry
	request := cli.gorequest
	apiPath := "/api/v1/registries"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		log.Println(events.StatusCode)
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetRegistries from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	return &response, nil
}

// CreateRegistry - creates single Aqua registry
func (cli *Client) CreateRegistry(reg Registry) error {

	payload, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/registries")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed creating registry")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

// UpdateRegistry updates an existing registry
func (cli *Client) UpdateRegistry(reg Registry) error {
	payload, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/registries/%s", reg.Name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed modifying registry")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

// DeleteRegistry removes a registry
func (cli *Client) DeleteRegistry(name string) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/registries/%s", name)
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return fmt.Errorf("error while calling DELETE on /api/v1/users/%s: %v", name, events.StatusCode)
	}
	if events.StatusCode != 204 {
		return fmt.Errorf("failed deleting registry, status code: %v", events.StatusCode)
	}
	return nil
}
