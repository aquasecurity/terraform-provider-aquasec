package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
)

type ResponsePolicy struct {
	Id               int                    `json:"id,omitempty"`
	Title            string                 `json:"title,omitempty"`
	Description      string                 `json:"description,omitempty"`
	Enabled          bool                   `json:"enabled"`
	Trigger          *ResponsePolicyTrigger `json:"trigger"`
	ApplicationScope []string               `json:"application_scopes"`
	Outputs          []ResponsePolicyOutput `json:"outputs"`
	LastUpdatedBy    string                 `json:"last_updated_by,omitempty"`
	CreatedAt        int64                  `json:"created_at,omitempty"`
	LastUpdate       int64                  `json:"last_update,omitempty"`
}

type ResponsePolicyTrigger struct {
	Predefined string                       `json:"predefined,omitempty"`
	Input      *ResponsePolicyInputTrigger  `json:"input,omitempty"`
	Custom     *ResponsePolicyCustomTrigger `json:"custom,omitempty"`
}

type ResponsePolicyInputTrigger struct {
	Name      string                                `json:"name,omitempty"`
	Attribute []ResponsePolicyInputTriggerAttribute `json:"attributes,omitempty"`
}

type ResponsePolicyInputTriggerAttribute struct {
	Name      string `json:"name,omitempty"`
	Operation string `json:"operation,omitempty"`
	Value     string `json:"value,omitempty"`
}

type ResponsePolicyCustomTrigger struct {
	Rego string `json:"rego,omitempty"`
}

type ResponsePolicyOutput struct {
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Template string `json:"template,omitempty"`
}

type ResponsePolicyResp struct {
	Page           int              `json:"page"`
	PageSize       int              `json:"page_size"`
	Scope          string           `json:"scope"`
	Title          string           `json:"title"`
	PaginationData bool             `json:"pagination_data"`
	Data           []ResponsePolicy `json:"data"`
}

type ResponsePolicyConfig struct {
	Triggers []TriggerConfigs `json:"triggers,omitempty"`
	Input    InputConfig      `json:"input,omitempty"`
}

type InputConfig struct {
	AssetTypes []AssetType          `json:"asset_types,omitempty"`
	Attributes []InputAttribute     `json:"attributes,omitempty"`
	Operations []AttributeOperation `json:"operations,omitempty"`
}

type AssetType struct {
	DisplayName string `json:"display_name,omitempty"`
	Field       string `json:"field,omitempty"`
	Value       string `json:"value,omitempty"`
}

type Option struct {
	DisplayName string `json:"display_name,omitempty"`
	Value       string `json:"value,omitempty"`
}

type TriggerConfigs struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

type InputAttribute struct {
	Name        string   `json:"name,omitempty"`
	Type        string   `json:"type,omitempty"`
	InputType   string   `json:"input_type,omitempty"`
	AssetTypes  []string `json:"asset_types,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Enabled     bool     `json:"enabled,omitempty"`
	Options     []Option `json:"options,omitempty"`
}

type AttributeOperation struct {
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
}

func (cli *Client) GetResponsePolicyConfig() (*ResponsePolicyConfig, error) {
	var err error
	var response ResponsePolicyConfig
	request := cli.gorequest
	apiPath := "/api/v2/response_policies/configs"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, fmt.Errorf("error calling %s", apiPath)
	}
	if events.StatusCode == 200 || events.StatusCode == 201 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetResponsePolicyConfig from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	} else if events.StatusCode == 204 {
		return nil, nil
	} else {
		err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
		return nil, err
	}
	return &response, nil
}

func (cli *Client) GetResponsePolicies(policyResp ResponsePolicyResp) (*ResponsePolicyResp, error) {
	var err error
	var response ResponsePolicyResp
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/response_policies?page=%d&page_size=%d&scope=%s&title=%s", policyResp.Page, policyResp.PageSize, url.QueryEscape(policyResp.Scope), url.QueryEscape(policyResp.Title))

	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err

	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, fmt.Errorf("error calling %s", apiPath)
	}

	if events.StatusCode != 201 && events.StatusCode != 200 && events.StatusCode != 204 {
		var errResp ErrorResponse
		if uerr := json.Unmarshal([]byte(body), &errResp); uerr == nil && errResp.Message != "" {
			return nil, fmt.Errorf("failed getting response policies: status=%s message=%s", events.Status, errResp.Message)
		}
		return nil, fmt.Errorf("failed getting response policies: status=%s body=%s", events.Status, body)
	}
	if events.StatusCode == 204 {
		return nil, nil
	}

	err = json.Unmarshal([]byte(body), &response)
	if err != nil {
		if strings.HasPrefix(strings.TrimSpace(body), "[") {
			var data []ResponsePolicy
			if uerr := json.Unmarshal([]byte(body), &data); uerr != nil {
				log.Printf("Error unmarshaling array response in GetResponsePolicies from %s%s, %v ", cli.url, apiPath, uerr)
				return nil, uerr
			}
			response.Data = data
			response.Page = policyResp.Page
			response.PageSize = policyResp.PageSize
			response.Scope = policyResp.Scope
			response.Title = policyResp.Title
		} else {
			log.Printf("Error calling func GetResponsePolicies from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	return &response, nil
}

func (cli *Client) GetResponsePolicy(id string) (*ResponsePolicy, error) {
	var err error
	var response ResponsePolicy
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/response_policies/%s", id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, fmt.Errorf("error calling %s", apiPath)
	}
	if events.StatusCode == 200 || events.StatusCode == 201 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetResponsePolicy from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
		return &response, nil
	}

	if events.StatusCode == 204 {
		return nil, nil
	}

	err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
	return nil, err
}

func (cli *Client) CreateResponsePolicy(policy *ResponsePolicy) error {
	var response ResponsePolicy
	request := cli.gorequest
	apiPath := "/api/v2/response_policies"

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}

	events, body, errs := request.Clone().
		Set("Authorization", "Bearer "+cli.token).
		Set("Content-Type", "application/json").
		Post(cli.url + apiPath).
		Send(policy).
		End()

	if errs != nil {
		return fmt.Errorf("error calling %s: %v", apiPath, errs)
	}

	if events.StatusCode == 201 || events.StatusCode == 200 {
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			return err
		}
		policy.Id = response.Id
		return nil
	}

	return fmt.Errorf("error calling %s, status %d, body %s", apiPath, events.StatusCode, body)
}

func (cli *Client) DeleteResponsePolicy(id string) error {
	var err error
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/response_policies/%s", id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return fmt.Errorf("error calling %s", apiPath)
	}
	if events.StatusCode != 201 && events.StatusCode != 200 && events.StatusCode != 204 {
		err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
		return err
	}
	return nil
}

func (cli *Client) UpdateResponsePolicy(id string, policy *ResponsePolicy) (*ResponsePolicy, error) {
	var response ResponsePolicy
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/response_policies/%s", id)

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}

	events, body, errs := request.Clone().
		Set("Authorization", "Bearer "+cli.token).
		Set("Content-Type", "application/json").
		Put(cli.url + apiPath).
		Send(policy).
		End()

	if errs != nil {
		return nil, fmt.Errorf("error calling %s: %v", apiPath, errs)
	}

	if events.StatusCode == 200 || events.StatusCode == 201 {
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			return nil, err
		}
		return &response, nil
	}

	return nil, fmt.Errorf("error calling %s, status %d, body %s", apiPath, events.StatusCode, body)
}

func (cli *Client) DeleteResponsePolicies() (*map[string]interface{}, error) {
	var err error
	var response map[string]interface{}
	request := cli.gorequest
	apiPath := "/api/v2/response_policies"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return nil, fmt.Errorf("error calling %s", apiPath)
	}
	if events.StatusCode == 200 || events.StatusCode == 201 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func DeleteResponsePolicies from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
		return &response, nil
	}

	if events.StatusCode == 204 {
		return nil, nil
	}

	err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
	return nil, err
}

func (cli *Client) UpdateResponsePolicyStatus(id int, enabled bool) (*ResponsePolicy, error) {
	var err error
	var response ResponsePolicy
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/response_policies/%d/status", id)
	statusData := map[string]bool{"enabled": enabled}
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(statusData).End()
	if errs != nil {
		return nil, fmt.Errorf("error calling %s", apiPath)
	}
	if events.StatusCode == 200 || events.StatusCode == 201 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func UpdateResponsePolicyStatus from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
		return &response, nil
	}

	if events.StatusCode == 204 {
		return nil, nil
	}

	err = fmt.Errorf("error calling %s, status code %d, body %s", apiPath, events.StatusCode, body)
	return nil, err
}
