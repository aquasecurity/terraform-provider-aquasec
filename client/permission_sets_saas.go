package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

const (
	apiPathPrefix    = "/api/access_mgmt/permissions"
	waitDuration     = 2 * time.Second
	statusOK         = 200
	statusCreated    = 201
	statusNoContent  = 204
	authHeaderFormat = "Bearer %s"
)

type CustomerAction struct {
	Name         string   `json:"name"`
	Dependencies []string `json:"dependencies,omitempty"`
}

type CustomerModule struct {
	Name    string           `json:"name"`
	Actions []CustomerAction `json:"actions"`
}

type CustomerModules struct {
	Modules []CustomerModule `json:"modules"`
}

type PermissionSetSaas struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Actions     []string `json:"actions,omitempty"`
}

func unmarshalResponse(body string, target interface{}) error {
	if err := json.Unmarshal([]byte(body), target); err != nil {
		return fmt.Errorf("error unmarshaling response: %v", err)
	}
	return nil
}

func (cli *Client) GetPermissionSetSaas(name string) (*PermissionSetSaas, error) {

	var response PermissionSetSaas
	fullURL := fmt.Sprintf("%s%s/%s", cli.saasUrl, apiPathPrefix, name)

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}

	resp, body, errs := cli.gorequest.Clone().
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).
		Get(fullURL).
		End()

	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting SaaS PermissionSet")
	}

	if resp.StatusCode == statusOK {
		if err := unmarshalResponse(body, &response); err != nil {
			return nil, err
		}
		return &response, nil
	}

	return nil, fmt.Errorf("failed getting SaaS PermissionSet: %s", resp.Status)
}

func (cli *Client) CreatePermissionSetSaas(permissionSet *PermissionSetSaas) error {

	payload, err := json.Marshal(permissionSet)
	if err != nil {
		return err
	}

	fullURL := cli.saasUrl + apiPathPrefix

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}

	resp, body, errs := cli.gorequest.Clone().
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).
		Post(fullURL).
		Send(string(payload)).
		End()

	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating SaaS PermissionSet")
	}

	if resp.StatusCode != statusCreated && resp.StatusCode != statusNoContent {
		return fmt.Errorf("failed creating SaaS PermissionSet: %s", body)
	}

	time.Sleep(waitDuration)
	return nil
}

func (cli *Client) UpdatePermissionSetSaas(permissionSet *PermissionSetSaas) error {

	payload, err := json.Marshal(permissionSet)
	if err != nil {
		return err
	}

	fullURL := cli.saasUrl + apiPathPrefix

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}

	resp, body, errs := cli.gorequest.Clone().
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).
		Put(fullURL).
		Send(string(payload)).
		End()

	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed updating SaaS PermissionSet")
	}

	if resp.StatusCode != statusNoContent {
		return fmt.Errorf("failed updating SaaS PermissionSet: %s", body)
	}

	return nil
}

func (cli *Client) DeletePermissionSetSaas(name string) error {

	fullURL := fmt.Sprintf("%s%s/%s", cli.saasUrl, apiPathPrefix, name)

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}

	resp, body, errs := cli.gorequest.Clone().
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).
		Delete(fullURL).
		End()

	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting SaaS PermissionSet")
	}

	if resp.StatusCode != statusNoContent {
		return fmt.Errorf("failed deleting SaaS PermissionSet: %s", body)
	}

	return nil
}

func (cli *Client) GetPermissionSetActions() (*CustomerModules, error) {
	var response CustomerModules
	fullURL := cli.url + apiPathPrefix + "/actions"

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}

	resp, body, errs := cli.gorequest.Clone().
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).
		Get(fullURL).
		End()

	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting permission actions")
	}

	if resp.StatusCode == statusOK {
		if err := unmarshalResponse(body, &response); err != nil {
			return nil, err
		}
		return &response, nil
	}

	return nil, fmt.Errorf("failed getting permission actions: %s", resp.Status)
}

func (cli *Client) GetPermissionSetsSaas() ([]PermissionSetSaas, error) {

	fullURL := cli.saasUrl + apiPathPrefix

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}

	resp, body, errs := cli.gorequest.Clone().
		Set("Authorization", fmt.Sprintf(authHeaderFormat, cli.token)).
		Get(fullURL).
		End()

	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed listing SaaS PermissionSets")
	}

    if resp.StatusCode == statusOK {
        var response struct {
            Items []PermissionSetSaas `json:"permissions"`
            Page  int                 `json:"page"`
            Size  int                 `json:"size"`
            Total int                 `json:"total"`
        }
        if err := unmarshalResponse(body, &response); err != nil {
            return nil, err
        }
        return response.Items, nil
    }

    return nil, fmt.Errorf("failed listing SaaS PermissionSets: %s", resp.Status)
}
