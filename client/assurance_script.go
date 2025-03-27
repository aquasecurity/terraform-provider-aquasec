package client

import (
	"encoding/json"
	"fmt"
	"io"
)

type AssuranceScript struct {
	ScriptID     string `json:"script_id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Engine       string `json:"engine"`
	Path         string `json:"path"`
	Snippet      string `json:"snippet"`
	Kind         string `json:"kind"`
	Author       string `json:"author"`
	LastModified int    `json:"last_modified"`
}

func (cli *Client) GetAssuranceScript(name string) (*AssuranceScript, error) {
	apiPath := fmt.Sprintf("/api/v2/image_assurance/user_scripts/%s", name)
	resp, body, errs := cli.gorequest.Clone().
		Set("Authorization", "Bearer "+cli.token).
		Get(cli.url + apiPath).
		End()

	if errs != nil {
		return nil, fmt.Errorf("failed getting Assurance Script: %v", errs)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed getting Assurance Script, status: %v", resp.Status)
	}

	var script AssuranceScript
	err := json.Unmarshal([]byte(body), &script)
	if err != nil {
		return nil, err
	}

	return &script, nil
}

func (cli *Client) CreateAssuranceScript(script *AssuranceScript) error {
	payload := []AssuranceScript{*script}
	apiPath := "/api/v2/image_assurance/user_scripts"

	resp, _, errs := cli.gorequest.Clone().
		Set("Authorization", "Bearer "+cli.token).
		Post(cli.url + apiPath).
		Send(payload).
		End()

	if errs != nil {
		return fmt.Errorf("failed creating Assurance Script: %v", errs)
	}

	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		return fmt.Errorf("failed creating Assurance Script, status: %v, body: %s", resp.Status, body)
	}

	return nil
}

func (cli *Client) UpdateAssuranceScript(script *AssuranceScript) error {
	apiPath := fmt.Sprintf("/api/v2/image_assurance/user_scripts/%s", script.Name)

	resp, _, errs := cli.gorequest.Clone().
		Set("Authorization", "Bearer "+cli.token).
		Put(cli.url + apiPath).
		Send(script).
		End()

	if errs != nil {
		return fmt.Errorf("failed updating Assurance Script: %v", errs)
	}

	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("failed updating Assurance Script, status: %v", resp.Status)
	}

	return nil
}

func (cli *Client) DeleteAssuranceScript(name string) error {
	apiPath := fmt.Sprintf("/api/v2/image_assurance/user_scripts/%s", name)

	resp, _, errs := cli.gorequest.Clone().
		Set("Authorization", "Bearer "+cli.token).
		Delete(cli.url + apiPath).
		End()

	if errs != nil {
		return fmt.Errorf("failed deleting Assurance Script: %v", errs)
	}

	if resp.StatusCode != 204 {
		return fmt.Errorf("failed deleting Assurance Script, status: %v", resp.Status)
	}

	return nil
}
