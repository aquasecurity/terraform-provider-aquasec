package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

)

type RoleMappingSaas struct {
	CspRole    string   `json:"csp_role"`
	SamlGroups []string `json:"saml_groups"`
	Id         int      `json:"id"`
	Created    string   `json:"created"`
	AccountId  int      `json:"account_id"`
}

type RoleMappingSaasList struct {
	Items []RoleMappingSaas `json:"data"`
}

type RoleMappingSaasResponse struct {
	RoleMappingSaas RoleMappingSaas `json:"data"`
}

const roleMappingBasePath = "/api/cspm/v2/samlmappings"

func (cli *Client) GetRoleMappingSaas(id string) (*RoleMappingSaas, error) {
	if cli.clientType != Saas && cli.clientType != SaasDev {
		return nil, fmt.Errorf("GetRoleMappingSaas is supported only in Aqua SaaS environment")
	}

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s%s/%s", cli.saasUrl, roleMappingBasePath, id)
	resp, body, errs := cli.gorequest.Clone().Get(url).
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).End()

	if len(errs) > 0 {
		return nil, fmt.Errorf("failed GET %s: %v", url, errs)
	}
	if resp.StatusCode != statusOK {
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, body)
	}

	var result RoleMappingSaasResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal RoleMappingSaas response")
	}
	return &result.RoleMappingSaas, nil
}

func (cli *Client) GetRolesMappingSaas() (*RoleMappingSaasList, error) {
	if cli.clientType != Saas && cli.clientType != SaasDev {
		return nil, fmt.Errorf("GetRolesMappingSaas is supported only in Aqua SaaS environment")
	}

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s%s", cli.saasUrl, roleMappingBasePath)
	resp, body, errs := cli.gorequest.Clone().Get(url).
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).End()

	if len(errs) > 0 {
		return nil, fmt.Errorf("failed GET %s: %v", url, errs)
	}
	if resp.StatusCode != statusOK {
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, body)
	}

	var result RoleMappingSaasList
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal RoleMappingSaas list")
	}
	return &result, nil
}

func (cli *Client) CreateRoleMappingSaas(saas *RoleMappingSaas) error {
	if cli.clientType != Saas && cli.clientType != SaasDev {
		return fmt.Errorf("CreateRoleMappingSaas is supported only in Aqua SaaS environment")
	}

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}

	url := fmt.Sprintf("%s%s", cli.saasUrl, roleMappingBasePath)
	saasPayload := map[string]interface{}{
		"csp_role":     saas.CspRole,
		"saml_groups": saas.SamlGroups,
	}
	payload, _ := json.Marshal(saasPayload)

	resp, body, errs := cli.gorequest.Clone().Post(url).
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).
		Send(string(payload)).End()

	if len(errs) > 0 {
		return fmt.Errorf("failed POST %s: %v", url, errs)
	}
	if resp.StatusCode != statusCreated {
		return fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, body)
	}

	var response RoleMappingSaasResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		return errors.Wrap(err, "failed to unmarshal response after creation")
	}
	saas.Id = response.RoleMappingSaas.Id
	saas.Created = response.RoleMappingSaas.Created
	saas.AccountId = response.RoleMappingSaas.AccountId
	return nil
}

func (cli *Client) UpdateRoleMappingSaas(saas *RoleMappingSaas, id string) error {
	if cli.clientType != Saas && cli.clientType != SaasDev {
		return fmt.Errorf("UpdateRoleMappingSaas is supported only in Aqua SaaS environment")
	}

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}

	url := fmt.Sprintf("%s%s/%s", cli.saasUrl, roleMappingBasePath, id)
	payloadMap := map[string]interface{}{
		"saml_groups": saas.SamlGroups,
	}
	payload, _ := json.Marshal(payloadMap)

	resp, body, errs := cli.gorequest.Clone().Put(url).
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).
		Send(string(payload)).End()

	if len(errs) > 0 {
		return fmt.Errorf("failed PUT %s: %v", url, errs)
	}
	if resp.StatusCode != statusNoContent {
		return fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, body)
	}
	return nil
}

func (cli *Client) DeleteRoleMappingSaas(id string) error {
	if cli.clientType != Saas && cli.clientType != SaasDev {
		return fmt.Errorf("DeleteRoleMappingSaas is supported only in Aqua SaaS environment")
	}

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}

	url := fmt.Sprintf("%s%s/%s", cli.saasUrl, roleMappingBasePath, id)
	resp, body, errs := cli.gorequest.Clone().Delete(url).
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).End()

	if len(errs) > 0 {
		return fmt.Errorf("failed DELETE %s: %v", url, errs)
	}
	if resp.StatusCode != statusOK {
		return fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, body)
	}
	return nil
}
