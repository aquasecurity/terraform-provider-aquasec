package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/pkg/errors"
)

type ScannerGroup struct {
	Name              string        `json:"name,omitempty"`
	Description       string        `json:"description,omitempty"`
	Status            string        `json:"status,omitempty"`
	OSType            string        `json:"os_type,omitempty"`
	Type              string        `json:"type,omitempty"`
	Author            string        `json:"author,omitempty"`
	CreatedAt         int64         `json:"created_at,omitempty"`
	UpdatedAt         int64         `json:"updated_at,omitempty"`
	Registries        []string      `json:"registries,omitempty"`
	ApplicationScopes []string      `json:"application_scopes,omitempty"`
	Scanners          []Scanners    `json:"scanners,omitempty"`
	DeployCommand     DeployCommand `json:"deploy_command,omitempty"`
	Tokens            []string      `json:"tokens,omitempty"`
}

type Scanners struct {
	LastHeartBeat  string `json:"last_heartbeat,omitempty"`
	ScannerName    string `json:"scanner_name,omitempty"`
	ScannerVersion string `json:"scanner_version,omitempty"`
	OsVersion      string `json:"os_version,omitempty"`
	Token          string `json:"token,omitempty"`
	RegisteredOn   string `json:"registered_on,omitempty"`
}

type DeployCommand struct {
	AdditionalProp1 string `json:"additional_prop1,omitempty"`
	AdditionalProp2 string `json:"additional_prop2,omitempty"`
	AdditionalProp3 string `json:"additional_prop3,omitempty"`
}

type ScannerGroupList struct {
	Items            []ScannerGroup `json:"result,omitempty"`
	Count            int            `json:"count,omitempty"`
	Page             int            `json:"page,omitempty"`
	PageSize         int            `json:"page_size,omitempty"`
	MoreDataAllPages int            `json:"more_data_all_pages,omitempty"`
	IsEstimatedCount bool           `json:"is_estimated_count,omitempty"`
	IsPartialData    bool           `json:"is_partial_data,omitempty"`
}

// GetScannerGroup retrieve a scanner group by its name
func (cli *Client) GetScannerGroup(name string) (*ScannerGroup, error) {
	var err error
	var response ScannerGroup
	baseUrl := cli.url
	apiPath := fmt.Sprintf("/api/v2/scanner_groups/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := cli.gorequest.Get(baseUrl+apiPath).Set("Authorization", "Bearer "+cli.token).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting ScannerGroup")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetScannerGroup from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	} else {
		body, err := io.ReadAll(resp.Body)
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
		return nil, fmt.Errorf("failed getting ScannerGroup. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	if response.Name == "" {
		return nil, fmt.Errorf("ScannerGroup: %s not found 404", name)
	}
	return &response, err
}

// GetScannerGroups retrieve list of scanner groups
func (cli *Client) GetScannerGroups() ([]ScannerGroup, error) {
	var err error
	var response ScannerGroupList
	request := cli.gorequest
	baseUrl := cli.url
	apiPath := "/api/v2/scanner_groups"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", "Bearer "+cli.token).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetScannerGroups from %s%s, %v ", cli.url, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal scanner groups response")
		}
	}
	return response.Items, err
}

// CreateScannerGroup creates a scanner group
func (cli *Client) CreateScannerGroup(scannerGroup *ScannerGroup) error {
	payload, err := json.Marshal(scannerGroup)
	if err != nil {
		return err
	}
	request := cli.gorequest
	baseUrl := cli.url
	apiPath := "/api/v2/scanner_groups"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Post(baseUrl+apiPath).Set("Authorization", "Bearer "+cli.token).Send(string(payload)).End()

	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating scannerGroup.")
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		var errorResponse ErrorResponse
		if err := json.Unmarshal([]byte(body), &errorResponse); err != nil {
			log.Printf("Failed to Unmarshal response body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed creating scannerGroup. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// UpdateScannerGroup updates a scanner group
func (cli *Client) UpdateScannerGroup(scannerGroup *ScannerGroup) error {
	var apiPath string
	payload, err := json.Marshal(scannerGroup)
	if err != nil {
		return err
	}
	baseUrl := cli.url
	request := cli.gorequest
	if scannerGroup.Type == "legacy" {
		apiPath = "/api/v2/migrate_scanner_groups"
	} else {
		apiPath = fmt.Sprintf("/api/v2/scanner_groups/%s", scannerGroup.Name)
	}
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Put(baseUrl+apiPath).Set("Authorization", "Bearer "+cli.token).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying ScannerGroup")
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		if err := json.Unmarshal([]byte(body), &errorResponse); err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed modifying ScannerGroup. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeleteScannerGroup removes a Scanner Group
func (cli *Client) DeleteScannerGroup(name string) error {
	request := cli.gorequest
	apiPath := "/api/v2/scanner_groups"
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	body := []string{name}
	events, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).Send(body).End()
	if errs != nil {
		return fmt.Errorf("error while calling DELETE on /api/v2/scanner_groups/%s: %v", name, events.StatusCode)
	}
	if events.StatusCode == 404 {
		return nil
	}
	if events.StatusCode != 204 && events.StatusCode != 200 {
		return fmt.Errorf("failed deleting scanner group, status code: %v", events.StatusCode)
	}
	return nil

}
