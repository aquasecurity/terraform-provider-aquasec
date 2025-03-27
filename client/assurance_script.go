package client

import (
	"encoding/json"
	"fmt"
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
	ReadOnly     bool   `json:"read_only"`
	Severity     string `json:"severity"`
	AvdID        string `json:"avd_id"`
	Type         string `json:"type"`
	Custom       any    `json:"custom"`
	Title        string `json:"title"`
	Overwrite    bool   `json:"overwrite"`
}

func (c *Client) CreateAssuranceScript(script *AssuranceScript) error {
	payload := []AssuranceScript{*script}
	response, body, errs := c.gorequest.Post(c.url+"/api/v2/image_assurance/user_scripts").
		Set("Authorization", "Bearer "+c.token).
		Send(payload).
		End()

	if errs != nil {
		return fmt.Errorf("failed creating Assurance Script: %v", errs)
	}

	if response.StatusCode != 200 && response.StatusCode != 201 && response.StatusCode != 204 {
		return fmt.Errorf("failed creating Assurance Script, status: %v, body: %s", response.Status, body)
	}

	// Parse the response body
	var createdScripts []AssuranceScript
	if err := json.Unmarshal([]byte(body), &createdScripts); err != nil {
		return fmt.Errorf("failed to parse response body: %v", err)
	}

	// Update the script with the returned data
	if len(createdScripts) > 0 {
		*script = createdScripts[0]
	}

	return nil
}

func (c *Client) GetAssuranceScript(scriptID string) (*AssuranceScript, error) {
	response, body, errs := c.gorequest.Get(c.url+"/api/v2/image_assurance/user_scripts/"+scriptID).
		Set("Authorization", "Bearer "+c.token).
		End()

	if errs != nil {
		return nil, fmt.Errorf("failed getting Assurance Script: %v", errs)
	}

	if response.StatusCode == 404 {
		return nil, nil
	}

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("failed getting Assurance Script, status: %v", response.Status)
	}

	var script AssuranceScript
	if err := json.Unmarshal([]byte(body), &script); err != nil {
		return nil, fmt.Errorf("failed to parse response body: %v", err)
	}

	return &script, nil
}

func (c *Client) UpdateAssuranceScript(script *AssuranceScript) error {
	response, body, errs := c.gorequest.Put(c.url+"/api/v2/image_assurance/user_scripts/"+script.ScriptID).
		Set("Authorization", "Bearer "+c.token).
		Send(script).
		End()

	if errs != nil {
		return fmt.Errorf("failed updating Assurance Script: %v", errs)
	}

	if response.StatusCode != 200 && response.StatusCode != 204 {
		return fmt.Errorf("failed updating Assurance Script, status: %v, body: %s", response.Status, body)
	}

	return nil
}

func (c *Client) DeleteAssuranceScript(scriptID string) error {
	response, body, errs := c.gorequest.Delete(c.url+"/api/v2/image_assurance/user_scripts/"+scriptID).
		Set("Authorization", "Bearer "+c.token).
		End()

	if errs != nil {
		return fmt.Errorf("failed deleting Assurance Script: %v", errs)
	}

	if response.StatusCode != 204 && response.StatusCode != 200 {
		return fmt.Errorf("failed deleting Assurance Script, status: %v, body: %s", response.Status, body)
	}

	return nil
}
