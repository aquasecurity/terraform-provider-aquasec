package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"log"
)

// Role represents a local Aqua Role
type Role struct {
	Name        string   `json:"name,omitempty"` // Display Name
	Description string   `json:"description,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
	Author      string   `json:"author,omitempty"`
	Permission  string   `json:"permission,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

// RoleList contains a list of Role
type RoleList struct {
	Items []Role `json:"result,omitempty"`
}

// GetRole - returns single Aqua Role
func (cli *Client) GetRole(name string) (*Role, error) {
	var err error
	var response Role
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/access_management/roles/%s", name)
	baseUrl := cli.url
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}

	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func getRole from %s%s, %s ", baseUrl, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal role response")
		}
	}

	if response.Name == "" {
		err = fmt.Errorf("role not found: %s", name)
		return nil, err
	}
	return &response, err
}

// GetRoles - returns all Aqua RoleList
func (cli *Client) GetRoles() ([]Role, error) {
	var err error
	var response RoleList
	request := cli.gorequest

	apiPath := "/api/v2/access_management/roles"
	baseUrl := cli.url
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}

	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetRoles from %s%s, %v ", cli.url, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal roles response")
		}
	}
	return response.Items, err
}

// CreateRole - creates single Aqua role
func (cli *Client) CreateRole(role *Role) error {
	baseUrl := cli.url
	apiPath := "/api/v2/access_management/roles"
	var err error

	payload, err := json.Marshal(role)
	//payload :=  map[string]interface{}{
	//	"name": role.Name,
	//	"description": role.Description,
	//	"permission": role.Permission,
	//	"scopes": role.Scopes,
	//}

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Post(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(string(payload)).End()
	fmt.Sprintf(data)
	if errs != nil {
		return errors.Wrap(err, "failed creating role")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

// UpdateRole updates an existing role
func (cli *Client) UpdateRole(role *Role) error {
	apiPath := fmt.Sprintf("/api/v2/access_management/roles/%s", role.Name)
	baseUrl := cli.url
	var err error
	payload, err := json.Marshal(role)

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Put(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed modifying role")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

// DeleteRole removes a role
func (cli *Client) DeleteRole(name string) error {

	baseUrl := cli.url
	apiPath := fmt.Sprintf("/api/v2/access_management/roles/%s", name)

	request := cli.gorequest
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, _, errs := request.Delete(baseUrl+apiPath).Set("Authorization", "Bearer "+cli.token).End()
	if errs != nil {
		return fmt.Errorf("error while calling DELETE on /api/v1/roles/%s: %v", name, events.StatusCode)
	}
	if events.StatusCode != 204 && events.StatusCode != 200 {
		return fmt.Errorf("failed deleting role, status code: %v", events.StatusCode)
	}
	return nil
}
