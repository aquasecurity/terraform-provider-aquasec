package client

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

// User represents a local Aqua user
type User struct {
	ID              string   `json:"id"` // Username
	Password        string   `json:"password,omitempty"`
	PasswordConfirm string   `json:"passwordConfirm,omitempty"`
	Roles           []string `json:"roles,omitempty"`
	Name            string   `json:"name,omitempty"` // Display Name
	Email           string   `json:"email,omitempty"`
	FirstTime       bool     `json:"first_time,omitempty"`
}

// NewPassword represents a password change
type NewPassword struct {
	Name     string `json:"name"`
	Password string `json:"new_password"`
}

// GetUser - returns single Aqua user
func (cli *Client) GetUser(name string) (*User, error) {
	var err error
	var response User
	cli.gorequest.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/users/%s", name)
	events, body, errs := cli.gorequest.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		log.Println(events.StatusCode)
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetUser from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	}
	if response.Name == "" {
		err = fmt.Errorf("user not found: %s", name)
		return nil, err
	}
	return &response, err
}

// GetUsers - returns all Aqua users
func (cli *Client) GetUsers() ([]User, error) {
	var err error
	var response []User
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/users")
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetUser from %s%s, %v ", cli.url, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal users response")
		}
	}
	return response, err
}

// CreateUser - creates single Aqua user
func (cli *Client) CreateUser(user User) error {
	payload, err := json.Marshal(user)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/users")
	resp, _, errs := request.Clone().Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed creating user")
	}
	if resp.StatusCode != 201 || resp.StatusCode != 204 {
		return err
	}
	return nil
}

// UpdateUser updates an existing user
func (cli *Client) UpdateUser(user User) error {
	payload, err := json.Marshal(user)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/users/%s", user.ID)
	resp, _, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed modifying user")
	}
	if resp.StatusCode != 201 || resp.StatusCode != 204 {
		return err
	}
	return nil
}

// DeleteUser removes a user
func (cli *Client) DeleteUser(name string) error {
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/users/%s", name)
	events, _, errs := request.Clone().Delete(cli.url + apiPath).End()
	if errs != nil {
		return fmt.Errorf("error while calling DELETE on /api/v1/users/%s: %v", name, events.StatusCode)
	}
	if events.StatusCode != 204 {
		return fmt.Errorf("failed deleting user, status code: %v", events.StatusCode)
	}
	return nil
}

// ChangePassword modifies the user's password
func (cli *Client) ChangePassword(password NewPassword) error {
	payload, err := json.Marshal(password)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/users/%s/password", password.Name)
	resp, _, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return fmt.Errorf("error while calling PUT on /api/v1/users/%s/password: %v", password.Name, resp.StatusCode)
	}
	if resp.StatusCode != 204 {
		return fmt.Errorf("failed changing user password , status code: %v", resp.StatusCode)
	}
	return nil
}
