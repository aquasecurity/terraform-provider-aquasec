package client

import (
	"crypto/tls"
	"encoding/json"
	"log"

	"github.com/parnurzeal/gorequest"
)

// Client - API client
type Client struct {
	url       string
	user      string
	password  string
	token     string
	name      string
	gorequest *gorequest.SuperAgent
}

// NewClient - initialize and return the Client
func NewClient(url string, user string, password string) *Client {
	c := &Client{
		url:       url,
		user:      user,
		password:  password,
		gorequest: gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true}),
	}
	return c
}

// GetAuthToken - Connect to Aqua and return a JWT bearerToken (string)
// Return: bool - successfully connected?
func (cli *Client) GetAuthToken() bool {
	var connected bool
	resp, body, err := cli.gorequest.Post(cli.url+"/api/v1/login").Param("abilities", "1").
		Send(`{"id":"` + cli.user + `", "password":"` + cli.password + `"}`).End()
	if err != nil {
		connected = false
		return connected
	}

	if resp.StatusCode == 200 {
		var raw map[string]interface{}
		_ = json.Unmarshal([]byte(body), &raw)
		cli.token = raw["token"].(string)
		connected = true
	} else {
		log.Printf("Failed with status: %s", resp.Status)
		connected = false
	}
	return connected
}
