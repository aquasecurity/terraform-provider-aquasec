package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

// APIKey represents the structure of an API key in Aqua SaaS
type APIKey struct {
	ID            int      `json:"id,omitempty"`
	Description   string   `json:"description,omitempty"`
	AccessKey     string   `json:"access_key,omitempty"`
	SecretKey     string   `json:"secret,omitempty"`
	Enabled       bool     `json:"enabled,omitempty"`
	IPAddresses   []string `json:"ip_addresses,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	CreatedAt     string   `json:"created,omitempty"`
	UpdatedAt     string   `json:"updated,omitempty"`
	Expiration    int      `json:"expiration,omitempty"`
	Whitelisted   bool     `json:"whitelisted,omitempty"`
	IacToken      bool     `json:"iac_token,omitempty"`
	AccountID     int      `json:"account_id,omitempty"`
	Owner         int      `json:"owner,omitempty"`
	SystemKey     bool     `json:"system_key,omitempty"`
	GroupID       int      `json:"group_id,omitempty"`
	PermissionIDs []int    `json:"permission_ids,omitempty"`
	Limit         int      `json:"limit,omitempty"`
	Offset        int      `json:"offset,omitempty"`
	OpenAccess    bool     `json:"open_access,omitempty"`
	ScansPerMonth int      `json:"scans_per_month,omitempty"`
}

type APIKeyResponse struct {
	Data []APIKey `json:"data"`
	Meta struct {
		Count      int  `json:"count"`
		NextOffset *int `json:"next_offset"`
	} `json:"meta"`
}

// ApiKeyList contains a list of API keys
type ApiKeyList struct {
	Items []APIKey `json:"data,omitempty"`
}

// GetApiKey fetches a single API key by its ID
func (cli *Client) GetApiKey(id int) (*APIKey, error) {
	request := cli.gorequest

	apiPath := fmt.Sprintf("/v2/apikeys/%d", id)
	baseUrl := cli.tokenUrl

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}

	events, body, errs := request.Get(baseUrl+apiPath).
		Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).
		End()

	if errs != nil {
		return nil, fmt.Errorf("error calling %s: %v", apiPath, errs[0])
	}

	if events.StatusCode != 200 {
		return nil, fmt.Errorf("GetApiKey failed with status %d: %s", events.StatusCode, body)
	}

	key, err := getApiKeyResponse(body)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GetApiKeys fetches all API keys with pagination support.
func (cli *Client) GetApiKeys(limit, offset int) ([]APIKey, error) {
	var allKeys []APIKey

	for {
		request := cli.gorequest
		qs := fmt.Sprintf("?limit=%d", limit)
		if offset > 0 {
			qs += fmt.Sprintf("&offset=%d", offset)
		}

		apiPath := "/v2/apikeys" + qs
		baseUrl := cli.tokenUrl

		if err := cli.limiter.Wait(context.Background()); err != nil {
			return nil, err
		}

		events, body, errs := request.Get(baseUrl+apiPath).
			Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).
			End()

		if errs != nil {
			return nil, fmt.Errorf("error calling %s: %v", apiPath, errs[0])
		}
		if events.StatusCode != 200 {
			return nil, fmt.Errorf("GetApiKeys: unexpected status %d: %s", events.StatusCode, body)
		}

		var apiResponse APIKeyResponse
		if err := json.Unmarshal([]byte(body), &apiResponse); err != nil {
			return nil, fmt.Errorf("error unmarshaling API keys response: %w", err)
		}

		allKeys = append(allKeys, apiResponse.Data...)

		if apiResponse.Meta.NextOffset == nil {
			break
		}
		offset = *apiResponse.Meta.NextOffset
	}

	return allKeys, nil
}

func (cli *Client) CreateApiKey(apikey *APIKey) error {
	baseUrl := ""
	apiPath := ""
	var err error

	if cli.clientType == Saas || cli.clientType == SaasDev {
		apiPath = "/v2/apikeys"
		baseUrl = cli.tokenUrl
	}

	payload := map[string]interface{}{
		"description": apikey.Description,
	}
	if apikey.ID != 0 {
		payload["source_key_id"] = apikey.ID
	}
	if len(apikey.IPAddresses) > 0 {
		payload["ip_addresses"] = apikey.IPAddresses
	}
	if apikey.Expiration != 0 {
		payload["expiration"] = apikey.Expiration
	}
	if len(apikey.Roles) > 0 {
		payload["roles"] = apikey.Roles
	}
	if apikey.Whitelisted {
		payload["whitelisted"] = apikey.Whitelisted
	}
	if apikey.IacToken {
		payload["iac_token"] = apikey.IacToken
	}

	if len(apikey.PermissionIDs) > 0 {
		payload["permission_ids"] = apikey.PermissionIDs
	}
	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}

	resp, body, errs := request.Post(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(payload).End()

	if errs != nil {
		return errors.Wrap(errs[0], "CreateApiKey request failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("CreateApiKey failed (%d): %s", resp.StatusCode, body)
	}

	result, err := getApiKeyResponse(body)
	if err != nil {
		return err
	}
	*apikey = *result

	// Verify the ID is populated
	if apikey.ID == 0 {
		return fmt.Errorf("CreateApiKey succeeded but returned empty ID")
	}
	return nil
}

// UpdateApiKey updates supported fields (PUT /v2/apikeys/{id})
func (cli *Client) UpdateApiKey(apikey *APIKey) error {
	baseUrl := ""
	apiPath := ""

	if cli.clientType == Saas || cli.clientType == SaasDev {
		apiPath = fmt.Sprintf("/v2/apikeys/%d", apikey.ID)
		baseUrl = cli.tokenUrl
	}

	payload := make(map[string]interface{})

	if apikey.Description != "" {
		payload["description"] = apikey.Description
	}

	payload["enabled"] = apikey.Enabled
	if len(apikey.IPAddresses) > 0 {
		payload["ip_addresses"] = apikey.IPAddresses
	}

	payload["roles"] = apikey.Roles
	payload["group_id"] = apikey.GroupID

	request := cli.gorequest
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}

	resp, body, errs := request.Put(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(payload).End()
	if errs != nil {
		return errors.Wrap(errs[0], "UpdateApiKey request failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("UpdateApiKey failed (%d): %s", resp.StatusCode, body)
	}
	return nil
}

func (cli *Client) DeleteApiKey(id int) error {
	resp, _, errs := cli.gorequest.
		Delete(fmt.Sprintf("%s/v2/apikeys/%d", cli.tokenUrl, id)).
		Set("Authorization", "Bearer "+cli.token).
		End()

	if errs != nil {
		return errors.Wrap(errs[0], "DeleteApiKey request failed")
	}
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("DeleteApiKey failed (%d)", resp.StatusCode)
	}
	return nil
}

func getApiKeyResponse(body string) (*APIKey, error) {
	var wrapper struct {
		Data APIKey `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &wrapper); err != nil {
		return nil, errors.Wrap(err, "unmarshal APIKey response")
	}
	return &wrapper.Data, nil
}
