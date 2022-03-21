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

			us[i] = u
		}

		return us, id
	}

	return make([]interface{}, 0), ""
}
