package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

type ServerlessApplication struct {
	Username                string   `json:"username"`
	Password                string   `json:"password"`
	SubscriptionId          string   `json:"subscription_id"`
	TenantId                string   `json:"tenant_id"`
	CloudProject            string   `json:"cloud_project"`
	ExternalId              string   `json:"external_id"`
	Name                    string   `json:"name"`
	Region                  string   `json:"region"`
	ComputeProviderType     int      `json:"compute_provider"`
	Author                  string   `json:"author"`
	LastUpdate              int      `json:"lastupdate"`
	PullTagsPattern         []string `json:"pull_tags_pattern"`
	PullTagsPatternExcluded []string `json:"pull_tags_pattern_excluded"`
	AutoPull                bool     `json:"auto_pull"`
	AutoPullTime            string   `json:"auto_pull_time"`
	AutoPullMax             int      `json:"auto_pull_max"`
	AutoPullPattern         string   `json:"auto_pull_pattern"`
	SqsUrl                  string   `json:"sqs_url"`
	Description             string   `json:"description"`
	ExcludeTags             []string `json:"exclude_tags"`
	IncludeTags             []string `json:"include_tags"`
	ExistsingScanners       []string `json:"existsing_scanners"`
	RoleARN                 string   `json:"role_arn"`
	ScannerGroupName        string   `json:"scanner_group_name"`
	ScannerName             []string `json:"scanner_name"`
	ScannerNameAdded        []string `json:"scanner_name_added"`
	ScannerNameRemoved      []string `json:"scanner_name_removed"`
	ScannerType             string   `json:"scanner_type"`
}

type ServerlessApplicationsResponse struct {
	Project []ServerlessApplication `json:"project"`
}

func (cli *Client) GetServerlessApplications() (*ServerlessApplicationsResponse, error) {
	var err error
	var response ServerlessApplicationsResponse

	request := cli.gorequest
	apiPath := "/api/v2/serverless/projects"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if resp.StatusCode != 200 {
		err = json.Unmarshal([]byte(data), &response)
		if err != nil {
			log.Printf("Error calling func GetServerlessApplications from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	return &response, nil
}

func (cli *Client) GetServerlessApplication(name string) (*ServerlessApplication, error) {
	var err error
	var response ServerlessApplication

	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/serverless/projects/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(data), &response)
		if err != nil {
			log.Printf("Error calling func GetServerlessApplication from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	if response.Name == "" {
		err = fmt.Errorf("serverless application: %s not found 404", name)
		return nil, err
	}
	return &response, nil
}

func (cli *Client) CreateServerlessApplication(app ServerlessApplication) error {
	payload, err := json.Marshal(app)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := "/api/v2/serverless/projects"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed creating serverless application")
	}

	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data, string(payload))
	}
	return nil
}

func (cli *Client) UpdateServerlessApplication(app ServerlessApplication) error {
	payload, err := json.Marshal(app)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/serverless/projects/%s", app.Name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed updating serverless application")
	}

	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data, string(payload))
	}
	return nil
}

func (cli *Client) DeleteServerlessApplication(name string) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/serverless/projects/%s", name)
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(err, "failed deleting serverless application")
	}

	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}
