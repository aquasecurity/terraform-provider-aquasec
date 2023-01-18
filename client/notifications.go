package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/pkg/errors"
)

//NotificationOld defines a NotificationOld
type NotificationOld struct {
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

type Notification struct {
	Id          int                    `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Author      string                 `json:"author"`
	LastUpdated int64                  `json:"last_updated"`
	Template    map[string]string      `json:"template"`
	Properties  map[string]interface{} `json:"properties"`
}

type Notifications struct {
	Slack      []Notification `json:"slack"`
	Jira       []Notification `json:"jira"`
	Email      []Notification `json:"email"`
	Teams      []Notification `json:"teams"`
	Webhook    []Notification `json:"webhook"`
	Splunk     []Notification `json:"splunk"`
	ServiceNow []Notification `json:"serviceNow"`
}

func (cli *Client) GetNotifications() (*Notifications, error) {

	var err error
	var response Notifications

	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := "/api/v2/notification/outputs?groupBy=type"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetNotifications from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	return &response, nil

}

func (cli *Client) GetNotification(id string) (*Notification, error) {

	var err error
	var response Notification

	request := cli.gorequest
	//request.Set(")
	apiPath := fmt.Sprintf("/api/v2/notification/outputs/%s", id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetNotification from %s%s, %v ", cli.url, apiPath, err)
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
		return nil, fmt.Errorf("failed getting Notification status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return &response, nil
}

func (cli *Client) CreateNotification(notification *Notification) error {
	payload, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := "/api/v2/notification/outputs"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	response, data, errs := request.Clone().Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, fmt.Sprintf("failed creating %s notification", notification.Type))
	}

	if response.StatusCode != 201 {
		return errors.Errorf(data)
	}
	//not := Notification{}
	err = json.Unmarshal([]byte(data), notification)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal create notification response")
	}

	return nil
}

func (cli *Client) UpdateNotification(notification *Notification) error {
	payload, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/notification/outputs/%v", notification.Id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	response, data, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, fmt.Sprintf("failed updating %s notification", notification.Type))
	}

	if response.StatusCode != 200 {
		return errors.Errorf(data)
	}

	err = json.Unmarshal([]byte(data), &notification)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal update notification response")
	}

	return nil
}

func (cli *Client) DeleteNotification(id string) error {
	var err error

	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/notification/outputs/%s", id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Delete(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return err
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
		return fmt.Errorf("failed deleting Notification, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// todo: Old Notification, should be removed after next release
//SlackNotificationCreate enables a Slack NotificationOld
func (cli *Client) SlackNotificationCreate(notification NotificationOld) error {
	payload, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v1/settings/notifiers/Slack")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed creating Slack notification")
	}

	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

//SlackNotificationUpdate enables/disables a Slack NotificationOld
func (cli *Client) SlackNotificationUpdate(notification NotificationOld) error {
	payload, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := "/api/v1/settings/notifiers/Slack"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed creating Slack notification")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

//SlackNotificationRead reads the given slack configurations
func (cli *Client) SlackNotificationRead() (*NotificationOld, error) {
	var err error
	var response NotificationOld

	request := cli.gorequest
	apiPath := "/api/v1/settings/notifiers/Slack"
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
			log.Printf("Error calling func GetSlackNotification from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	return &response, nil
}

//SlackNotificationDelete enables/disables a Slack NotificationOld
//Since there is no DELETE method implementation of the API, we are basically setting the values as spaces
//and setting the enabled indicator as false
func (cli *Client) SlackNotificationDelete(notification NotificationOld) error {
	payload, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := "/api/v1/settings/notifiers/Slack"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed deleting Slack notification")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}
