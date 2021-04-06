package client

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

//Notification defines a Notification
type Notification struct {
	Enabled    bool   `json:"enabled"`
	Channel    string `json:"channel"`
	WebhookURL string `json:"webhook_url"`
	UserName   string `json:"user_name"`
	MainText   string `json:"main_text"`
	Icon       string `json:"icon"`
	ServiceKey string `json:"service_key"`
	Type       string `json:"type"`
	Name       string `json:"name"`
}

//SlackNotificationCreate enables a Slack Notification
func (cli *Client) SlackNotificationCreate(notf Notification) error {
	payload, err := json.Marshal(notf)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/settings/notifiers/Slack")
	resp, _, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed creating Slack notification")
	}

	if resp.StatusCode != 201 || resp.StatusCode != 204 {
		return err
	}
	return nil
}

//SlackNotificationUpdate enables/disables a Slack Notification
func (cli *Client) SlackNotificationUpdate(notf Notification) error {
	payload, err := json.Marshal(notf)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/settings/notifiers/Slack")

	resp, _, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed creating Slack notification")
	}
	if resp.StatusCode != 201 || resp.StatusCode != 204 {
		return err
	}
	return nil
}

//SlackNotificationRead reads the given slack configurations
func (cli *Client) SlackNotificationRead() (*Notification, error) {
	var err error
	var response Notification

	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/settings/notifiers/Slack")
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetSlackNotification from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	return &response, nil
}

//SlackNotificationDelete enables/disables a Slack Notification
//Since there is no DELETE method implementation of the API, we are basically setting the values as spaces
//and setting the enabled indicator as false
func (cli *Client) SlackNotificationDelete(notf Notification) error {
	payload, err := json.Marshal(notf)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/settings/notifiers/Slack")
	resp, _, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed deleting Slack notification")
	}
	if resp.StatusCode != 201 || resp.StatusCode != 204 {
		return err
	}
	return nil
}
