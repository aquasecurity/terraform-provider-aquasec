package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/pkg/errors"
)

type Plugin struct {
	ID                int    `json:"id,omitempty"`
	Cloud             string `json:"cloud,omitempty"`
	Title             string `json:"title"`
	Description       string `json:"description"`
	Severity          string `json:"severity,omitempty"`
	RecommendedAction string `json:"recommended_action"`
	Link              string `json:"link,omitempty"`
	MoreInfo          string `json:"more_info"`
	CategoryID        int    `json:"category_id,omitempty"`
	CustomID          string `json:"custom_id,omitempty"`

	Severities []SeverityOverride `json:"severities,omitempty"`
	ASL        *ASL               `json:"asl,omitempty"`
}

type SeverityOverride struct {
	KeyID     *int   `json:"key_id"`
	AccountID int    `json:"account_id"`
	Severity  string `json:"severity"`
}

type ASL struct {
	Version        *int            `json:"version,omitempty"`
	APIs           []string        `json:"apis"`
	TargetResource string          `json:"targetResource"`
	Conditions     json.RawMessage `json:"conditions"`
	Scope          json.RawMessage `json:"scope,omitempty"`
}

func (p *Plugin) EffectiveSeverity() string {
	for _, s := range p.Severities {
		if s.KeyID == nil {
			return s.Severity
		}
	}
	return p.Severity
}

func (cli *Client) GetPlugin(id int) (*Plugin, error) {
	var err error
	var response Plugin
	request := cli.gorequest
	apiPath := fmt.Sprintf("/v2/customplugin/%d", id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}

	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.tokenUrl + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), fmt.Sprintf("failed getting CSPM plugin with ID: %d", id))
	}
	var result struct {
		Data Plugin `json:"data"`
	}

	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &result)
		if err != nil {
			log.Printf("Error unmarshaling response body")
			return nil, errors.Wrap(err, fmt.Sprintf("couldn't unmarshal get CSPM plugin response. Body: %v", body))
		}
		response = result.Data
	} else {
		var errorResponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Println("failed to unmarshal error response")
			return nil, fmt.Errorf("failed getting CSPM plugin with ID: %d. Status: %v, Response: %v", id, events.StatusCode, body)
		}
		return nil, fmt.Errorf("failed getting CSPM plugin with ID %v. Status: %v, error message: %v", id, events.StatusCode, errorResponse.Message)
	}
	return &response, nil
}

func (cli *Client) CreatePlugin(plugin Plugin) (*Plugin, error) {
	payload, err := json.Marshal(plugin)
	if err != nil {
		return nil, err
	}

	request := cli.gorequest
	apiPath := fmt.Sprintf("/v2/customplugin")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	log.Println(string(payload))

	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.tokenUrl + apiPath).Send(string(payload)).End()

	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed creating cspm plugin.")
	}

	var result struct {
		Data Plugin `json:"data"`
	}
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		err = json.Unmarshal([]byte(body), &result)
		if err != nil {
			return nil, fmt.Errorf("Failed to unmarshal response body: %v", body)
		}
		if result.Data.ID == 0 {
			return nil, fmt.Errorf("Plugin created (HTTP %d) but no ID found in response body: %v", resp.StatusCode, body)
		}
	} else {
		var errorResponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v", body)
			return nil, fmt.Errorf("failed creating CSPM plugin with ID: %v. Status: %v, Response: %v", plugin.ID, resp.StatusCode, body)
		}
		return nil, fmt.Errorf("failed creating CSPM plugin. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	plugin.ID = result.Data.ID

	return &plugin, nil
}

func (cli *Client) UpdatePlugin(plugin *Plugin) error {
	pluginID := plugin.ID
	if pluginID == 0 {
		return fmt.Errorf("plugin ID is required for update")
	}

	// reset these fields, update api doesn't accept them as they cannot be changed
	plugin.ID = 0
	plugin.Cloud = ""

	payload, err := json.Marshal(plugin)
	if err != nil {
		return err
	}

	request := cli.gorequest
	apiPath := fmt.Sprintf("/v2/customplugin/%d", pluginID)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}

	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.tokenUrl + apiPath).Send(string(payload)).End()

	if errs != nil {
		return errors.Wrap(getMergedError(errs), fmt.Sprintf("failed modifying CSPM plugin ID: %d", pluginID))
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
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
		return fmt.Errorf("failed modifying CSPM plugin. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	return nil
}

func (cli *Client) UpdatePluginSeverity(pluginID int, severity string) error {
	data := map[string]string{"severity": severity}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	request := cli.gorequest
	apiPath := fmt.Sprintf("/v2/customplugin/%d", pluginID)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}

	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.tokenUrl + apiPath).Send(string(payload)).End()

	if errs != nil {
		return errors.Wrap(getMergedError(errs), fmt.Sprintf("failed modifying CSPM plugin ID: %d", pluginID))
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
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
		return fmt.Errorf("failed modifying CSPM plugin. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	return nil
}

func (cli *Client) DeletePlugin(pluginID int) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/v2/customplugin/%d", pluginID)
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.tokenUrl + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting CSPM plugin")
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		err := json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v.", body)
			return err
		}
		return fmt.Errorf("failed deleting CSPM plugin, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
