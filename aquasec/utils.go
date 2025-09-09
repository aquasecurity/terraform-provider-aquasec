package aquasec

import (
	"encoding/json"
	"fmt"
	os "os"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func convertStringArr(ifaceArr []interface{}) []string {
	return convertAndMapStringArr(ifaceArr, func(s string) string { return s })
}

func convertStringArrNull(ifaceArr []interface{}) []string {
	return convertAndMapStringArrNull(ifaceArr, func(s string) string { return s })

}

func convertIntArr(ifaceArr []interface{}) []int {
	return convertAndMapIntArr(ifaceArr, func(i int) int { return i })
}

func convertAndMapIntArr(ifaceArr []interface{}, mapper func(int) int) []int {
	intArr := make([]int, len(ifaceArr))
	for i, val := range ifaceArr {
		intArr[i] = mapper(val.(int))
	}
	return intArr
}

func convertAndMapStringArrNull(ifaceArr []interface{}, f func(string) string) []string {
	var arr = make([]string, 0)
	for _, v := range ifaceArr {
		if v == nil {
			continue
		}
		arr = append(arr, f(v.(string)))
	}
	return arr
}

func convertStringArrTest(ifaceArr []interface{}) []string {
	var result []string
	for _, iface := range ifaceArr {
		if s, ok := iface.(string); ok {
			result = append(result, s)
		} else {
			// Handle the case where iface is not a string.
			// You may choose to log an error or take other appropriate action.
			// For now, let's add an empty string to the result.
			result = append(result, "")
		}
	}
	return result
}

func convertAndMapStringArr(ifaceArr []interface{}, f func(string) string) []string {
	var arr []string
	for _, v := range ifaceArr {
		if v == nil {
			continue
		}
		arr = append(arr, f(v.(string)))
	}
	return arr
}

func convertToGroupsStruct(i []interface{}) []client.Group {
	var m []client.Group
	b, _ := json.Marshal(i)
	json.Unmarshal(b, &m)
	return m
}

func convertToLoginStruct(i []interface{}) []client.Login {
	var m []client.Login
	b, _ := json.Marshal(i)
	json.Unmarshal(b, &m)
	return m
}

func flattenUsersData(users *[]client.FullUser) ([]interface{}, string) {
	id := ""
	if users != nil {
		us := make([]interface{}, len(*users), len(*users))

		for i, user := range *users {
			id = id + user.Id
			u := make(map[string]interface{})
			u["user_id"] = user.BasicId.Id
			u["name"] = user.BasicUser.Name
			u["email"] = user.BasicUser.Email
			u["first_time"] = user.BasicUser.FirstTime
			u["is_super"] = user.BasicUser.IsSuper
			u["ui_access"] = user.BasicUser.UiAccess
			u["role"] = user.BasicUser.Role
			u["roles"] = user.BasicUser.Roles
			u["type"] = user.BasicUser.Type
			u["plan"] = user.BasicUser.Plan
			us[i] = u
		}

		return us, id
	}

	return make([]interface{}, 0), ""
}

func flattenUsersSaasData(users *[]client.FullUser) ([]interface{}, string) {
	var (
		us     []interface{}
		idList []string
	)
	if users != nil {
		us = make([]interface{}, len(*users))

		for i, user := range *users {
			idList = append(idList, user.Id)
			u := make(map[string]interface{})
			groups := make([]interface{}, len(user.Groups))
			logins := make([]interface{}, len(user.Logins))

			//u["dashboard"] 	 	= user.BasicUser.
			u["csp_roles"] = user.BasicUser.CspRoles
			u["id"] = user.BasicId.Id
			u["email"] = user.BasicUser.Email
			u["mfa_enabled"] = user.BasicUser.MfaEnabled
			u["confirmed"] = user.BasicUser.Confirmed
			u["password_reset"] = user.BasicUser.PasswordReset
			u["send_announcements"] = user.BasicUser.SendAnnouncements
			u["send_scan_results"] = user.BasicUser.SendScanResults
			u["send_new_plugins"] = user.BasicUser.SendNewPlugin
			u["send_new_risks"] = user.BasicUser.SendNewRisks
			u["account_admin"] = user.BasicUser.AccountAdmin
			u["created"] = user.BasicUser.Created
			//u["provider"] = user.BasicUser.Provider
			u["multiaccount"] = user.BasicUser.Multiaccount
			u["count_failed_signin"] = user.BasicUser.CountFailedSignin
			u["last_signin_attempt"] = user.BasicUser.LastSigninAttempt

			// Adding Groups
			for j, group := range user.BasicUser.Groups {
				g := make(map[string]interface{})
				g["id"] = group.Id
				g["name"] = group.Name
				g["created"] = group.Created
				groups[j] = g
			}
			u["groups"] = groups

			// Adding Logins
			for j, login := range user.BasicUser.Logins {
				l := make(map[string]interface{})
				l["id"] = login.Id
				l["ip_address"] = login.IpAddress
				l["created"] = login.Created
				l["csp_roles"] = login.CspRoles
				l["cspm_groups"] = login.CspmGroups
				l["groups"] = login.Groups
				logins[j] = l
			}
			u["logins"] = logins

			us[i] = u
		}
	}

	var id string
	if len(idList) > 0 {
		id = strings.Join(idList, ",")
	} else {
		id = "no_users"
	}

	return us, id
}

func flattenGroupsData(groups *[]client.Group) ([]interface{}, string) {
	id := ""
	if groups != nil {
		gr := make([]interface{}, len(*groups), len(*groups))
		for i, group := range *groups {
			//users := make([]interface{}, len(group.Users), len(group.Users))

			id = id + fmt.Sprintf("%v", group.Id)
			g := make(map[string]interface{})

			g["group_id"] = fmt.Sprintf("%v", group.Id)
			g["name"] = group.Name
			g["created"] = group.Created
			gr[i] = g
		}
		return gr, id
	}
	return make([]interface{}, 0), ""
}

func flattenGatewaysData(gateways *[]client.Gateway) ([]interface{}, string) {
	id := ""
	if gateways != nil {
		us := make([]interface{}, len(*gateways), len(*gateways))

		for i, gateway := range *gateways {
			id = id + gateway.ID
			u := make(map[string]interface{})
			u["id"] = gateway.ID
			u["logicalname"] = gateway.Logical_Name
			u["description"] = gateway.Description
			u["version"] = gateway.Version
			u["hostname"] = gateway.Host_Name
			u["public_address"] = gateway.SSH_Address
			u["grpc_address"] = gateway.GRPC_Address
			u["status"] = gateway.Status
			u["project_id"] = gateway.ProjectID
			u["type"] = gateway.Type
			u["address"] = gateway.Address
			u["last_update"] = gateway.LastUpdate
			u["server_id"] = gateway.ServerID
			u["server_name"] = gateway.ServerName
			u["docker_version"] = gateway.DockerVersion
			u["host_os"] = gateway.HostOS

			us[i] = u
		}

		return us, id
	}

	return make([]interface{}, 0), ""
}

func isSaasEnv() bool {
	url := os.Getenv("AQUA_URL")

	switch url {
	case consts.SaasUrl:
		return true
	case consts.SaasDevUrl:
		return true
	case consts.SaasEu1Url:
		return true
	case consts.SaasAsia1Url:
		return true
	case consts.SaasAsia2Url:
		return true
	case consts.SaaSAu2Url:
		return true
	default:
		return false
	}
}

func isResourceExist(response string) bool {
	if strings.Contains(response, "404") {
		return false
	} else {
		return true
	}
}

func validateSaasResourceWarning(legacyResource, newResource string) schema.SchemaValidateFunc {
	return func(val interface{}, key string) ([]string, []error) {
		if isSaasEnv() {
			return []string{
				fmt.Sprintf(
					"You are using %s with an Aqua SaaS instance. Please migrate to %s, designed specifically for Aqua SaaS customers and supporting the entire SaaS platform beyond workload protection.",
					legacyResource, newResource,
				),
			}, nil
		}
		return nil, nil
	}
}
