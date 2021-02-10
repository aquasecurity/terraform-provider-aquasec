package aquasec

import (
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

func flattenUsersData(users *[]client.User) ([]interface{}, string) {
	id := ""
	if users != nil {
		us := make([]interface{}, len(*users), len(*users))

		for i, user := range *users {
			id = id + user.ID
			u := make(map[string]interface{})

			u["user_id"] = user.ID
			u["name"] = user.Name
			u["email"] = user.Email
			u["roles"] = user.Roles

			us[i] = u
		}

		return us, id
	}

	return make([]interface{}, 0), ""
}
