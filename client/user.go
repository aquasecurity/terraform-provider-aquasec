package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

type BasicId struct {
	Id string `json:"id"`
}

type FullUser struct {
	BasicId
	BasicUser
}

type Login struct {
	Id        int    `json:"id"`
	IpAddress string `json:"ip_address"`
	Created   string `json:"created"`
	UserId    int    `json:"user_id"`
}

type UserGroups struct {
	Name       string `json:"name,omitempty"`
	GroupAdmin bool   `json:"group_admin,omitempty"`
}

type BasicUser struct {
	Password        string `json:"password,omitempty"`
	PasswordConfirm string `json:"passwordConfirm,omitempty"`
	Name            string `json:"name,omitempty"` // Display Name
	Email           string `json:"email,omitempty"`
	FirstTime       bool   `json:"first_time,omitempty"`
	IsSuper         bool   `json:"is_super,omitempty"`
	UiAccess        bool   `json:"ui_access,omitempty"`
	//Actions
	//Scopes
	Role  string   `json:"role,omitempty"`
	Roles []string `json:"roles,omitempty"`
	Type  string   `json:"type,omitempty"`
	Plan  string   `json:"plan,omitempty"`

	//SAAS vars:
	//Dashboard
	CspRoles          []string     `json:"csp_roles,omitempty"`
	Confirmed         bool         `json:"confirmed,omitempty"`
	PasswordReset     bool         `json:"password_reset,omitempty"`
	SendAnnouncements bool         `json:"send_announcements,omitempty"`
	SendScanResults   bool         `json:"send_scan_results,omitempty"`
	SendNewPlugin     bool         `json:"send_new_plugin,omitempty"`
	SendNewRisks      bool         `json:"send_new_risks,omitempty"`
	AccountAdmin      bool         `json:"account_admin,omitempty"`
	Created           string       `json:"created,omitempty"`
	Updated           string       `json:"updated,omitempty"`
	Provider          string       `json:"provider,omitempty"`
	Multiaccount      bool         `json:"multiaccount,omitempty"`
	Groups            []Group      `json:"groups,omitempty"`
	Logins            []Login      `json:"logins"`
	UserGroups        []UserGroups `json:"user_groups,omitempty"`
}

// UserList contains a list of UserSaas
type UserList struct {
	Items []interface{} `json:"data,omitempty"`
}

// NewPassword represents a password change
type NewPassword struct {
	Name     string `json:"name"`
	Password string `json:"new_password"`
}

//GetUser - returns single Aqua user
func (cli *Client) GetUser(name string) (*FullUser, error) {
	var err error
	var response FullUser
	baseUrl := cli.url
	apiPath := fmt.Sprintf("/api/v1/users/%s", name)
	if cli.clientType == Saas || cli.clientType == SaasDev {
		baseUrl = cli.tokenUrl
		apiPath = fmt.Sprintf("/v2/users/%s/?expand=csproles,group", name)
	}

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		log.Println(events.StatusCode)
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}

	if events.StatusCode == 200 {

		response, err = getUserResponse(cli, body, "GetUser", baseUrl, apiPath)

		if err != nil {
			return nil, err
		}
	}

	if response.Name == "" {
		if response.Email == "" {
			err = fmt.Errorf("user not found: %s", name)
			return nil, err
		}
	}
	return &response, err
}

//GetUsers - returns all Aqua users
func (cli *Client) GetUsers() ([]FullUser, error) {
	var err error
	var response []FullUser

	baseUrl := cli.url
	apiPath := "/api/v1/users"
	if cli.clientType == Saas || cli.clientType == SaasDev {
		baseUrl = cli.tokenUrl
		apiPath = "/v2/users?expand=login,csproles,group"
	}

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", baseUrl+apiPath)
		return nil, err
	}

	if events.StatusCode == 200 {
		if cli.clientType == Saas || cli.clientType == SaasDev {
			var saasResponse UserList

			err = json.Unmarshal([]byte(body), &saasResponse)

			if err != nil {
				log.Printf("Error calling func GetUser from %s%s, %v ", cli.url, apiPath, err)
				return nil, errors.Wrap(err, "could not unmarshal users response")
			}

			for _, item := range saasResponse.Items {
				//var fullUser FullUser
				fullUser, err := BuildFullUser(item)
				if err != nil {
					log.Printf("Error calling func GetUser from %s%s, %v ", cli.url, apiPath, err)
					return nil, errors.Wrap(err, "could not unmarshal users response")
				}

				response = append(response, fullUser)
			}
		} else {

			var cspResponse []interface{}

			err = json.Unmarshal([]byte(body), &cspResponse)

			if err != nil {
				log.Printf("Error calling func GetUser from %s%s, %v ", cli.url, apiPath, err)
				return nil, errors.Wrap(err, "could not unmarshal users response")
			}

			for _, item := range cspResponse {
				//var fullUser FullUser
				fullUser, err := BuildFullUser(item)
				if err != nil {
					log.Printf("Error calling func GetUser from %s%s, %v ", cli.url, apiPath, err)
					return nil, errors.Wrap(err, "could not unmarshal users response")
				}

				response = append(response, fullUser)
			}

		}
		if err != nil {
			log.Printf("Error calling func GetUser from %s%s, %v ", cli.url, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal users response")
		}
	}

	return response, err
}

// CreateUser - creates single Aqua user
func (cli *Client) CreateUser(user *FullUser) error {
	saas := false
	baseUrl := cli.url
	apiPath := "/api/v1/users"
	if cli.clientType == Saas || cli.clientType == SaasDev {
		saas = true
		baseUrl = cli.tokenUrl
		apiPath = "/v2/users"
	}

	payload, err := json.Marshal(UpdatePayload(saas, false, user))

	if err != nil {
		return err
	}

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Post(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(string(payload)).End()
	fmt.Sprintf(data)
	if errs != nil {
		return errors.Wrap(err, "failed creating user")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	if saas {
		dataUser, err := getUserResponse(cli, data, "CreateUser", baseUrl, apiPath)

		if err != nil {
			return err
		}
		user.BasicId.Id = dataUser.BasicId.Id
	}
	return nil
}

// UpdateUser updates an existing user
func (cli *Client) UpdateUser(user *FullUser) error {
	saas := false
	baseUrl := cli.url
	apiPath := fmt.Sprintf("/api/v1/users/%s", user.Id)

	if cli.clientType == Saas || cli.clientType == SaasDev {
		saas = true
		baseUrl = cli.tokenUrl
		apiPath = fmt.Sprintf("/v2/users/%s", user.Id)
	}

	payload, err := json.Marshal(UpdatePayload(saas, true, user))

	if err != nil {
		return err
	}

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Put(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(err, "failed modifying user")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

// DeleteUser removes a user
func (cli *Client) DeleteUser(name string) error {

	baseUrl := cli.url
	apiPath := fmt.Sprintf("/api/v1/users/%s", name)

	if cli.clientType == Saas || cli.clientType == SaasDev {
		baseUrl = cli.tokenUrl
		apiPath = fmt.Sprintf("/v2/users/%s", name)
	}

	request := cli.gorequest
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, _, errs := request.Delete(baseUrl+apiPath).Set("Authorization", "Bearer "+cli.token).End()
	if errs != nil {
		return fmt.Errorf("error while calling DELETE on /api/v1/users/%s: %v", name, events.StatusCode)
	}
	if events.StatusCode != 204 && events.StatusCode != 200 {
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
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return fmt.Errorf("error while calling PUT on /api/v1/users/%s/password: %v", password.Name, resp.StatusCode)
	}
	if resp.StatusCode != 204 {
		return fmt.Errorf("failed changing user password , status code: %v", resp.StatusCode)
	}
	return nil
}

func (id *BasicId) UnmarshalJSON(data []byte) error {
	type intType struct {
		ID int `json:"id"`
	}

	type stringType struct {
		ID string `json:"id"`
	}

	var i intType
	err := json.Unmarshal(data, &i)
	if err != nil {
		var s stringType
		err := json.Unmarshal(data, &s)
		if err != nil {
			return err
		}
		id.Id = s.ID
		return nil
	}
	id.Id = fmt.Sprintf("%v", i.ID)

	return nil
}

func BuildFullUser(i interface{}) (FullUser, error) {
	var id BasicId
	var user BasicUser
	var err error
	var fullUser FullUser

	z, _ := json.Marshal(i)

	err = json.Unmarshal(z, &id)

	if err != nil {
		return fullUser, err
	}

	err = json.Unmarshal(z, &user)

	if err != nil {
		return fullUser, err
	}

	fullUser.BasicId = id
	fullUser.BasicUser = user

	//u := FullUser{
	//	id,
	//	user,
	//}

	return fullUser, err

}

func UpdatePayload(saas, update bool, user *FullUser) interface{} {
	i := make(map[string]interface{})
	//u, _ := json.Marshal(user)
	//json.Unmarshal(u, i)
	if saas {
		i["account_admin"] = user.BasicUser.AccountAdmin
		if user.BasicUser.CspRoles == nil {
			i["csp_roles"] = []string{}
		} else {
			i["csp_roles"] = user.BasicUser.CspRoles
		}
		if !update {
			i["email"] = user.BasicUser.Email
		}
	} else {
		i["email"] = user.BasicUser.Email
		i["first_time"] = user.BasicUser.FirstTime
		i["id"] = user.BasicId.Id
		i["name"] = user.BasicUser.Name
		i["password"] = user.BasicUser.Password
		i["passwordConfirm"] = user.BasicUser.PasswordConfirm
		i["roles"] = user.BasicUser.Roles
		i["email"] = user.BasicUser.Email
	}
	return i
}

func getUserResponse(cli *Client, body string, operation, baseUrl, apiPath string) (FullUser, error) {
	var err error
	var response FullUser

	if cli.clientType == Saas || cli.clientType == SaasDev {
		var saasResponse map[string]interface{}

		err = json.Unmarshal([]byte(body), &saasResponse)

		if err != nil {
			log.Printf("Error calling func %s from %s%s, %v ", operation, baseUrl, apiPath, err)
			return response, errors.Wrap(err, "could not unmarshal users response")
		}

		fullUser, err := BuildFullUser(saasResponse["data"])

		if err != nil {
			log.Printf("Error calling func %s from %s%s, %v ", operation, baseUrl, apiPath, err)
			return response, errors.Wrap(err, "could not unmarshal users response")
		}

		response = fullUser

	} else {

		var cspResponse interface{}

		err = json.Unmarshal([]byte(body), &cspResponse)

		if err != nil {
			log.Printf("Error calling func GetUser from %s%s, %v ", cli.url, apiPath, err)
			return response, errors.Wrap(err, "could not unmarshal users response")
		}

		fullUser, err := BuildFullUser(cspResponse)
		if err != nil {
			log.Printf("Error calling func GetUser from %s%s, %v ", cli.url, apiPath, err)
			return response, errors.Wrap(err, "could not unmarshal users response")
		}
		response = fullUser
	}
	return response, nil
}
