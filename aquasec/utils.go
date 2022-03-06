package aquasec

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
)

func convertStringArr(ifaceArr []interface{}) []string {
	return convertAndMapStringArr(ifaceArr, func(s string) string { return s })
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
	id := ""
	if users != nil {
		us := make([]interface{}, len(*users), len(*users))

		for i, user := range *users {
			id = id + user.Id
			u := make(map[string]interface{})
			groups := make([]interface{}, len(user.Groups), len(user.Groups))
			logins := make([]interface{}, len(user.Logins), len(user.Logins))

			//u["dashboard"] 	 	= user.BasicUser.
			u["csp_roles"] = user.BasicUser.CspRoles
			u["user_id"] = user.BasicId.Id
			u["email"] = user.BasicUser.Email

			u["confirmed"] = user.BasicUser.Confirmed
			u["password_reset"] = user.BasicUser.PasswordReset
			u["send_announcements"] = user.BasicUser.SendAnnouncements
			u["send_scan_results"] = user.BasicUser.SendScanResults
			u["send_new_plugins"] = user.BasicUser.SendNewPlugin
			u["send_new_risks"] = user.BasicUser.SendNewRisks
			u["account_admin"] = user.BasicUser.AccountAdmin
			u["created"] = user.BasicUser.Created
			//u["provider"] 	 	= user.BasicUser.Provider
			u["multiaccount"] = user.BasicUser.Multiaccount

			//adding Groups
			for i, group := range user.BasicUser.Groups {
				g := make(map[string]interface{})
				g["id"] = group.Id
				g["name"] = group.Name
				g["created"] = group.Created
				//g["users"]	= group.Users
				groups[i] = g
			}
			u["groups"] = groups

			//Adding logins
			for i, login := range user.BasicUser.Logins {
				l := make(map[string]interface{})
				l["id"] = login.Id
				l["ip_address"] = login.IpAddress
				l["created"] = login.Created
				l["user_id"] = login.UserId
				logins[i] = l
			}
			u["logins"] = logins

			us[i] = u
		}

		return us, id
	}

	return make([]interface{}, 0), ""
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
