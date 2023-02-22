package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/pkg/errors"
)

type AquaLabel struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     string `json:"created"`
	Author      string `json:"author"`
}

type AquaLabels struct {
	AquaLabels []AquaLabel `json:"result"`
}

// GetAquaLabel - get a single Aqua label
func (cli *Client) GetAquaLabel(name string) (*AquaLabel, error) {
	var err error
	var response AquaLabel
	apiPath := fmt.Sprintf("/api/v1/settings/labels/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := cli.gorequest.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting Aqua label")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetLabel from %s%s, %v ", cli.url, apiPath, err)
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
		return nil, fmt.Errorf("failed getting Aqua label. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	if response.Name == "" {
		return nil, fmt.Errorf("aqua label: %s not found 404", name)
	}
	return &response, err
}

// GetAquaLabels - get a list of aqua labels
func (cli *Client) GetAquaLabels() (*AquaLabels, error) {
	var err error
	var response AquaLabels
	apiPath := fmt.Sprintf("/api/v2/settings/labels")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := cli.gorequest.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting Aqua labels")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetAquaLabels from %s%s, %v ", cli.url, apiPath, err)
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
		return nil, fmt.Errorf("failed getting Aqua labels. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	return &response, err

}

// CreateAquaLabel - creates single Aqua Aqua label
func (cli *Client) CreateAquaLabel(aquaLabel *AquaLabel) error {
	payload, err := json.Marshal(aquaLabel)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/settings/labels")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating Aqua label.")
	}
	if resp.StatusCode != 200 {
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
		return fmt.Errorf("failed creating Aqua label. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// UpdateAquaLabel updates an existing Aqua label
func (cli *Client) UpdateAquaLabel(aquaLabel *AquaLabel) error {
	payload, err := json.Marshal(aquaLabel)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/settings/labels/%s", aquaLabel.Name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying Aqua label")
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
		return fmt.Errorf("failed modifying Aqua label. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeleteAquaLabel removes a Aqua label
func (cli *Client) DeleteAquaLabel(name string) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/settings/labels/%s", name)
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting Aqua label")
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
		return fmt.Errorf("failed deleting Aqua label, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
