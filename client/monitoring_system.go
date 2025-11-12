package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

type MonitoringSystem struct {
	Name     string  `json:"name"`
	Enabled  bool    `json:"enabled"`
	Interval int     `json:"interval"`
	Token    *string `json:"token,omitempty"`
	Type     string  `json:"type"`
}

func (cli *Client) GetMonitoringSystems() ([]MonitoringSystem, error) {
	var err error
	var response []MonitoringSystem
	request := cli.gorequest
	apiPath := "/api/v1/settings/monitoring"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("no response from %s", apiPath)
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetMonitoringSystem from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
		return response, nil
	}

	if resp.StatusCode == 404 {
		return nil, nil
	} else {
		return nil, fmt.Errorf("GetMonitoringSystem: unexpected status %d from %s: %s", resp.StatusCode, apiPath, body)
	}
}

func (cli *Client) GetMonitoringSystem(name string) (*MonitoringSystem, error) {
	var err error
	var response MonitoringSystem

	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/settings/monitoring/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("no response from %s", apiPath)
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(data), &response)
		if err != nil {
			log.Printf("Error calling func GetMonitoringSystem from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
		return &response, nil
	}

	if resp.StatusCode == 404 {
		return nil, nil
	} else {
		return nil, fmt.Errorf("GetMonitoringSystem: unexpected status %d from %s: %s", resp.StatusCode, apiPath, data)
	}
}

func (cli *Client) CreateMonitoringSystem(monitoringSystem MonitoringSystem) error {
	payload, err := json.Marshal(monitoringSystem)
	if err != nil {
		return err
	}
	request := cli.gorequest
	name := monitoringSystem.Name
	apiPath := fmt.Sprintf("/api/v1/settings/monitoring/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Errorf("error calling %s", apiPath)
	}
	if resp == nil {
		return fmt.Errorf("update monitoring system: no HTTP response (nil)")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(body)
	}
	return nil
}

func (cli *Client) UpdateMonitoringSystem(monitoringSystem MonitoringSystem) error {
	payload, err := json.Marshal(monitoringSystem)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/settings/monitoring/%s", monitoringSystem.Name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Errorf("update monitoring system: request failed: %s", errs)
	}
	if resp == nil {
		return fmt.Errorf("update monitoring system: no HTTP response (nil)")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

func (cli *Client) DeleteMonitoringSystem(monitoringSystem MonitoringSystem) error {
	payload, err := json.Marshal(monitoringSystem)
	if err != nil {
		return err
	}
	request := cli.gorequest
	name := monitoringSystem.Name
	apiPath := fmt.Sprintf("/api/v1/settings/monitoring/%s", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Errorf("delete monitoring system: request failed: %s", errs)
	}

	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}
