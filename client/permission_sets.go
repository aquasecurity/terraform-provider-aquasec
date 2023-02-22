package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/pkg/errors"
)

// User represents a local Aqua user
type PermissionsSet struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"` // Display Name
	Description string   `json:"description,omitempty"`
	Actions     []string `json:"actions,omitempty"`
	Author      string   `json:"author,omitempty"`
	UiAccess    bool     `json:"ui_access,omitempty"`
	IsSuper     bool     `json:"is_super,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

type PermissionsSetList struct {
	Items []PermissionsSet `json:"result,omitempty"`
}

func (cli *Client) GetPermissionsSet(name string) (*PermissionsSet, error) {
	var err error
	var response PermissionsSet
	apiPath := fmt.Sprintf("/api/v2/access_management/permissions/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := cli.gorequest.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting PermissionSet")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetPermissionSet from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return nil, err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return nil, err
		}
		return nil, fmt.Errorf("failed getting PermissionSet. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	if response.Name == "" {
		return nil, fmt.Errorf("PermissionSet: %s not found 404", name)
	}
	return &response, err
}

// GetPermissionsSets - returns all Aqua PermissionsSetList
func (cli *Client) GetPermissionsSets() ([]PermissionsSet, error) {
	var err error
	var response PermissionsSetList
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/access_management/permissions")
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
			log.Printf("Error calling func GetPermissionsSets from %s%s, %v ", cli.url, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal permission sets response")
		}
	}
	return response.Items, err
}

func Find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// CreatePermissionSet - creates single Aqua PermissionSet Assurance Policy
func (cli *Client) CreatePermissionsSet(permissionset *PermissionsSet) error {
	payload, err := json.Marshal(permissionset)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := "/api/v2/access_management/permissions"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating PermissionSet.")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
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
		return fmt.Errorf("failed creating PermissionSet. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// UpdatePermissionSet updates an existing PermissionSet Assurance Policy
func (cli *Client) UpdatePermissionsSet(permissionset *PermissionsSet) error {
	payload, err := json.Marshal(permissionset)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/access_management/permissions/%s", permissionset.Name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying PermissionSet")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
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
		return fmt.Errorf("failed modifying PermissionSet. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeletePermissionSet removes a PermissionSet Assurance Policy
func (cli *Client) DeletePermissionsSet(name string) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/access_management/permissions/%s", name)
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting PermissionSet")
	}
	if resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
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
		return fmt.Errorf("failed deleting PermissionSet, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
