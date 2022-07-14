package client

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

// Registry defines a registry
type Registry struct {
	Name                     string      `json:"name"`
	Type                     string      `json:"type"` // [HUB, V1/V2, ENGINE, AWS, GCR]
	DetectedType             int         `json:"detected_type"`
	Description              string      `json:"description"`
	Author                   string      `json:"author"`
	Lastupdate               int         `json:"lastupdate"`
	URL                      string      `json:"url"`
	Username                 string      `json:"username"`
	Password                 string      `json:"password"`
	AutoPull                 bool        `json:"auto_pull"`
	AutoPullTime             string      `json:"auto_pull_time"`
	AutoPullMax              int         `json:"auto_pull_max"`
	PullRepoPatterns         interface{} `json:"pull_repo_patterns"`
	PullRepoPatternsExcluded interface{} `json:"pull_repo_patterns_excluded"`
	PullTagPatterns          interface{} `json:"pull_tag_patterns"`
	PullMaxTags              int         `json:"pull_max_tags"`
	AutoPullRescan           bool        `json:"auto_pull_rescan"`
	Prefixes                 interface{} `json:"prefixes"`
	Webhook                  struct {
		Enabled      bool   `json:"enabled"`
		URL          string `json:"url"`
		AuthToken    string `json:"auth_token"`
		UnQuarantine bool   `json:"un_quarantine"`
	} `json:"webhook"`
	RegistryScanTimeout int           `json:"registry_scan_timeout"`
	PullImageAge        string        `json:"pull_image_age"`
	PullImageTagPattern []interface{} `json:"pull_image_tag_pattern"`
	AlwaysPullPatterns  []interface{} `json:"always_pull_patterns"`
	ScannerType         string        `json:"scanner_type"`
}

func (cli *Client) GetRegistry(name string) (*Registry, error) {
	var err error
	var response Registry
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/registries/%s", name)
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()
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
		err = fmt.Errorf("registry not found: %s", name)
		return nil, err
	}
	return &response, err
}

// GetRegistries - retrieves all configured registry integrations
func (cli *Client) GetRegistries() (*[]Registry, error) {
	var err error
	var response []Registry
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := "/api/v1/registries"
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()
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
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/registries")
	resp, data, errs := request.Clone().Post(cli.url + apiPath).Send(string(payload)).End()
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
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/registries/%s", reg.Name)
	resp, data, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
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
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/registries/%s", name)
	events, _, errs := request.Clone().Delete(cli.url + apiPath).End()
	if errs != nil {
		return fmt.Errorf("error while calling DELETE on /api/v1/users/%s: %v", name, events.StatusCode)
	}
	if events.StatusCode != 204 {
		return fmt.Errorf("failed deleting registry, status code: %v", events.StatusCode)
	}
	return nil
}
