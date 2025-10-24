package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
)

type LogService struct {
	AuditFilter               string `json:"audit_filter,omitempty"`
	Audit                     string `json:"audit,omitempty"`
	ClientID                  string `json:"client_id,omitempty"`
	ClientSecret              string `json:"client_secret,omitempty"`
	Cloud                     string `json:"cloud,omitempty"`
	DisplayName               string `json:"displayname,omitempty"`
	Enable                    bool   `json:"enable,omitempty"`
	EnableAlphanumericSorting bool   `json:"enable_alphanumeric_sorting,omitempty"`
	ExternalID                string `json:"external_id,omitempty"`
	HasNewLabel               bool   `json:"hasnewlabel,omitempty"`
	Index                     string `json:"index,omitempty"`
	Key                       string `json:"key,omitempty"`
	KeyID                     string `json:"keyid,omitempty"`
	LearnMore                 string `json:"learnmore,omitempty"`
	LogGroup                  string `json:"loggroup,omitempty"`
	LogName                   string `json:"logname,omitempty"`
	Logo                      string `json:"logo,omitempty"`
	LogoFull                  string `json:"logofull,omitempty"`
	Name                      string `json:"name,omitempty"`
	Network                   string `json:"network,omitempty"`
	Password                  string `json:"password,omitempty"`
	ProjectID                 string `json:"projectid,omitempty"`
	Region                    string `json:"region,omitempty"`
	RoleArn                   string `json:"role_arn,omitempty"`
	Rule                      string `json:"rule,omitempty"`
	Source                    string `json:"source,omitempty"`
	SourceType                string `json:"sourcetype,omitempty"`
	StreamName                string `json:"stream_name,omitempty"`
	TenantID                  string `json:"tenant_id,omitempty"`
	Token                     string `json:"token,omitempty"`
	URL                       string `json:"url,omitempty"`
	User                      string `json:"user,omitempty"`
	Workspace                 string `json:"workspace,omitempty"`
	CACert                    string `json:"ca_cert,omitempty"`
	VerifyCert                bool   `json:"verify_cert,omitempty"`
	AuthenticationOption      string `json:"authentication_option,omitempty"`
	CredentialsJSON           string `json:"credentials_json,omitempty"`
}

type LogManagement struct {
	Services []LogService `json:"services"`
}

func (cli *Client) GetLogManagement(name string) (*LogService, error) {
	var err error
	var response LogService
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/settings/log_services/%s", name)
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
			log.Printf("Error calling func GetLogManagement from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	if events.StatusCode != 201 && events.StatusCode != 200 && events.StatusCode != 204 {
		err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
		return nil, err
	}
	return &response, nil
}

func (cli *Client) GetLogManagements() (*map[string]LogService, error) {
	var err error
	var response map[string]LogService
	request := cli.gorequest
	apiPath := "/api/v1/settings/log_services"
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
			log.Printf("Error calling func GetLogManagements from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	if events.StatusCode != 201 && events.StatusCode != 200 && events.StatusCode != 204 {
		err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
		return nil, err
	}
	return &response, nil
}

func (cli *Client) CreateLogManagement(logService LogService) error {
	var err error
	request := cli.gorequest
	name := logService.Name
	apiPath := fmt.Sprintf("/api/v1/settings/log_services/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(logService).End()
	if errs != nil {
		log.Println(events.StatusCode)
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}
	if events.StatusCode != 200 && events.StatusCode != 201 {
		err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
		return err
	}
	return nil
}

func (cli *Client) UpdateLogManagement(name string, logMgmt LogService) error {
	var err error
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/settings/log_services/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(logMgmt).End()
	if errs != nil {
		log.Println(events.StatusCode)
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}
	if events.StatusCode != 200 {
		err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
		return err
	}
	return nil
}

func (cli *Client) DeleteLogManagement(name string) error {
	var err error
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/settings/log_services/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).End()
	if errs != nil {
		log.Println(events.StatusCode)
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}
	if events.StatusCode != 200 && events.StatusCode != 204 {
		err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
		return err
	}
	return nil
}
