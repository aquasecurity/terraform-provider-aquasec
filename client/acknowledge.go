package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/pkg/errors"
)

// Acknowledge defines a security issue acknowledge
type Acknowledge struct {
	IssueType              string    `json:"issue_type"`
	ResourceType           string    `json:"resource_type"`
	ImageName              string    `json:"image_name"`
	RegistryName           string    `json:"registry_name"`
	ResourceName           string    `json:"resource_name"`
	ResourceVersion        string    `json:"resource_version"`
	ResourceFormat         string    `json:"resource_format"`
	ResourceCpe            string    `json:"resource_cpe"`
	ResourcePath           string    `json:"resource_path"`
	ResourceHash           string    `json:"resource_hash"`
	IssueName              string    `json:"issue_name"`
	Comment                string    `json:"comment"`
	Author                 string    `json:"author"`
	Date                   time.Time `json:"date"`
	FixVersion             string    `json:"fix_version"`
	ExpirationDays         int       `json:"expiration_days"`
	ExpirationConfiguredAt time.Time `json:"expiration_configured_at"`
	ExpirationConfiguredBy string    `json:"expiration_configured_by"`
	Permission             string    `json:"permission"`
	Os                     string    `json:"os"`
	OsVersion              string    `json:"os_version"`
	DockerId               string    `json:"docker_id"`
	RepositoryName         string    `json:"repository_name"`
	Repository             string    `json:"repository"`
}

type AcknowledgeList struct {
	Result []Acknowledge `json:"result"`
}

type AcknowledgePost struct {
	Comment string        `json:"comment"`
	Issues  []Acknowledge `json:"issues"`
}

// AcknowledgeCreate create security acknowledge
func (cli *Client) AcknowledgeCreate(acknowledgePost AcknowledgePost) error {
	payload, err := json.Marshal(acknowledgePost)

	if err != nil {
		return err
	}

	request := cli.gorequest
	apiPath := "/api/v2/risks/acknowledge"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed creating security acknowledges")
	}

	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data, string(payload))
	}
	return nil
}

// AcknowledgeRead reads all security acknowledges
func (cli *Client) AcknowledgeRead() (*AcknowledgeList, error) {
	var err error
	var response AcknowledgeList

	request := cli.gorequest

	apiPath := fmt.Sprintf("/api/v2/risks/acknowledge?order_by=date")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetAcknowledge from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	return &response, nil
}

// AcknowledgeDelete delete security acknowledge
func (cli *Client) AcknowledgeDelete(acknowledgePost AcknowledgePost) error {
	payload, err := json.Marshal(acknowledgePost)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := "/api/v2/risks/acknowledge/multiple"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed deleting security acknowledges")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}
