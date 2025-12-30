package aquasec

import (
	"encoding/json"
	"fmt"
	os "os"
	"strings"
	"time"

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

func flattenMonitoringSystem(monitors *[]client.MonitoringSystem) []interface{} {
	if monitors == nil {
		return []interface{}{}
	}
	ms := make([]interface{}, len(*monitors))
	for i, monitor := range *monitors {
		m := map[string]interface{}{
			"name":     monitor.Name,
			"enabled":  monitor.Enabled,
			"type":     monitor.Type,
			"interval": monitor.Interval,
		}
		if monitor.Token != nil {
			m["token"] = *monitor.Token
		} else {
			m["token"] = ""
		}
		ms[i] = m
	}
	return ms
}

func flattenSuppressionRules(rules *[]client.SuppressionRule) ([]interface{}, string) {
	id := ""
	if rules != nil {
		sr := make([]interface{}, len(*rules), len(*rules))
		for i, rule := range *rules {
			id = id + fmt.Sprintf("%v", rule.PolicyID)
			r := make(map[string]interface{})

			r["policy_id"] = rule.PolicyID
			r["name"] = rule.Name
			r["description"] = rule.Description
			r["enable"] = rule.Enable
			if rule.Created != nil {
				r["created"] = rule.Created.Format(time.RFC3339)
			} else {
				r["created"] = ""
			}
			if rule.Updated != nil {
				r["updated"] = rule.Updated.Format(time.RFC3339)
			} else {
				r["updated"] = ""
			}
			r["created_by"] = rule.CreatedBy
			r["updated_by"] = rule.UpdatedBy
			r["enforce"] = rule.Enforce
			r["fail_build"] = rule.FailBuild
			r["fail_pr"] = rule.FailPR
			r["enforcement_schedule"] = rule.EnforcementSchedule
			r["clear_schedule"] = rule.ClearSchedule
			r["policy_type"] = []string{string(rule.PolicyType)}
			r["controls"] = flattenSuppresionRuleControl(rule.Controls)
			r["scope"] = flattenSuppresstionRuleScope(rule.Scope)
			r["application_scopes"] = rule.ApplicationScopes
			sr[i] = r
		}
		return sr, id
	}
	return make([]interface{}, 0), ""
}

func flattenSuppresstionRuleScope(scope1 client.BuildSecurityPolicyScope) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"expression": scope1.Expression,
			"variables":  flattenSuppressionRuleScopeVariables(scope1.Variables),
		},
	}
}

func flattenSuppressionRuleScopeVariables(sVar []client.BuildSecurityScopeVariable) []interface{} {
	check := make([]interface{}, len(sVar))
	for i := range sVar {
		check[i] = map[string]interface{}{
			"attribute": sVar[i].Attribute,
			"value":     sVar[i].Value,
		}
	}

	return check
}

func flattenSuppresionRuleControl(controls []client.BuildSecuritypolicyControl) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(controls))

	for _, c := range controls {
		item := map[string]interface{}{
			"type":                  c.Type,
			"scan_type":             c.ScanType,
			"provider":              c.Provider,
			"service":               c.Service,
			"dependency_name":       c.DependencyName,
			"version":               c.Version,
			"dependency_source":     c.DependencySource,
			"operator":              c.Operator,
			"severity":              c.Severity,
			"vendorfix":             c.VendorFix,
			"direct_only":           c.DirectOnly,
			"reachable_only":        c.ReachableOnly,
			"cve_ids":               c.CveIDs,
			"avd_ids":               c.AvdIDs,
			"dependency_ids":        c.DependencyIDs,
			"ids":                   c.IDs,
			"checks":                flattenSuppressionRuleCheck(c.Checks),
			"patterns":              c.Patterns,
			"ports":                 c.Ports,
			"file_changes":          flattenSuppressionRuleFileChange(c.FileChanges),
			"target_file":           c.TargetFile,
			"target_line":           c.TargetLine,
			"fingerprint":           c.Fingerprint,
			"file_globs":            c.FileGlobs,
			"published_date_filter": flattenSuppresionRulePublishedDateFilter(c.PublishedDateFilter),
		}
		result = append(result, item)
	}
	return result
}

func flattenSuppressionRuleCheck(checks []client.Check) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(checks))

	for _, chk := range checks {
		result = append(result, map[string]interface{}{
			"provider_name": chk.ProviderName,
			"service_name":  chk.ServiceName,
			"check_id":      chk.CheckID,
			"check_name":    chk.CheckName,
			"scan_type":     chk.ScanType,
		})
	}

	return result
}

func flattenSuppressionRuleFileChange(file client.FileChanges) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"pattern": file.Pattern,
			"changes": file.Changes,
		},
	}
}

func flattenSuppresionRulePublishedDateFilter(date client.PublishedDateFilter) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"days":    date.Days,
			"enabled": date.Enabled,
		},
	}
}

func flattenResponsePolicies(policies *[]client.ResponsePolicy) ([]interface{}, string) {
	id := ""
	if policies == nil {
		return []interface{}{}, ""
	}

	pols := make([]interface{}, len(*policies))
	for i, policy := range *policies {
		id = id + fmt.Sprintf("%v", policy.Id)
		p := map[string]interface{}{
			"id":              policy.Id,
			"title":           policy.Title,
			"description":     policy.Description,
			"enabled":         policy.Enabled,
			"last_updated_by": policy.LastUpdatedBy,
			"last_update":     policy.LastUpdate,
			"created_at":      policy.CreatedAt,
			"application_scopes": func() []interface{} {
				if policy.ApplicationScope == nil {
					return []interface{}{}
				}
				as := make([]interface{}, len(policy.ApplicationScope))
				for i, v := range policy.ApplicationScope {
					as[i] = v
				}
				return as
			}(),
			"trigger": flattenResponsePolicyTrigger(policy.Trigger),
			"outputs": flattenResponsePolicyOutputs(policy.Outputs),
		}
		pols[i] = p
	}
	return pols, id
}

func flattenResponsePolicyTrigger(trigger *client.ResponsePolicyTrigger) []interface{} {
	if trigger == nil {
		return []interface{}{}
	}

	block := map[string]interface{}{
		"predefined": trigger.Predefined,
		"input":      flattenResponsePolicyTriggerInput(trigger.Input),
	}

	// Only include "custom" if non-empty
	if trigger.Custom != nil && trigger.Custom.Rego != "" {
		block["custom"] = []interface{}{
			map[string]interface{}{
				"rego": trigger.Custom.Rego,
			},
		}
	}

	return []interface{}{block}
}

func flattenResponsePolicyTriggerInput(inputs *client.ResponsePolicyInputTrigger) []interface{} {
	if inputs == nil {
		return []interface{}{}
	}
	inps := make([]interface{}, 1)
	in := map[string]interface{}{
		"name":       inputs.Name,
		"attributes": flattenResponsePolicyTriggerInputAttributes(inputs.Attribute),
	}
	inps[0] = in
	return inps
}

func flattenResponsePolicyTriggerInputAttributes(attrs []client.ResponsePolicyInputTriggerAttribute) []interface{} {
	if len(attrs) == 0 {
		return []interface{}{}
	}
	out := make([]interface{}, len(attrs))
	for i, a := range attrs {
		out[i] = map[string]interface{}{
			"name":      a.Name,
			"operation": a.Operation,
			"value":     a.Value,
		}
	}
	return out
}

func flattenResponsePolicyTriggerCustom(custom *client.ResponsePolicyCustomTrigger) []interface{} {
	if custom == nil {
		return []interface{}{}
	}
	cust := make([]interface{}, 1)
	c := map[string]interface{}{
		"rego": custom.Rego,
	}
	cust[0] = c
	return cust
}

func flattenResponsePolicyOutputs(outputs []client.ResponsePolicyOutput) []interface{} {
	if len(outputs) == 0 {
		return []interface{}{}
	}
	result := make([]interface{}, len(outputs))
	for i, o := range outputs {
		result[i] = map[string]interface{}{
			"name": o.Name,
			"type": o.Type,
		}
	}
	return result
}

func flattenResponsePolicyTriggerConfigs(triggers []client.TriggerConfigs) []interface{} {
	if triggers == nil {
		return []interface{}{}
	}
	trs := make([]interface{}, len(triggers))
	for i, trigger := range triggers {
		t := map[string]interface{}{
			"name": trigger.Name,
			"type": trigger.Type,
		}
		trs[i] = t
	}
	return trs
}

func flattenResponsePolicyInputsConfig(input client.InputConfig) []interface{} {
	in := map[string]interface{}{
		"asset_types": flattenResponsePolicyAssetTypesConfig(input.AssetTypes),
		"attributes":  flattenResponsePolicyTriggerInputAttributesConfig(input.Attributes),
		"operations":  flattenResponsePolicyTriggerInputOperationsConfig(input.Operations),
	}
	return []interface{}{in}
}

func flattenResponsePolicyTriggerInputAttributesConfig(attrs []client.InputAttribute) []interface{} {
	if attrs == nil {
		return []interface{}{}
	}
	atrs := make([]interface{}, len(attrs))
	for i, attr := range attrs {
		a := map[string]interface{}{
			"name":         attr.Name,
			"type":         attr.Type,
			"input_type":   attr.InputType,
			"asset_types":  attr.AssetTypes,
			"display_name": attr.DisplayName,
			"enabled":      attr.Enabled,
			"options":      flattenResponsePolicyOptionsConfig(attr.Options),
		}
		atrs[i] = a
	}
	return atrs
}

func flattenResponsePolicyTriggerInputOperationsConfig(ops []client.AttributeOperation) []interface{} {
	if ops == nil {
		return []interface{}{}
	}
	operations := make([]interface{}, len(ops))
	for i, op := range ops {
		o := map[string]interface{}{
			"name":         op.Name,
			"type":         op.Type,
			"display_name": op.DisplayName,
			"enabled":      op.Enabled,
		}
		operations[i] = o
	}
	return operations
}

func flattenResponsePolicyAssetTypesConfig(assetTypes []client.AssetType) []interface{} {
	if assetTypes == nil {
		return []interface{}{}
	}
	ats := make([]interface{}, len(assetTypes))
	for i, at := range assetTypes {
		a := map[string]interface{}{
			"display_name": at.DisplayName,
			"field":        at.Field,
			"value":        at.Value,
		}
		ats[i] = a
	}
	return ats
}

func flattenResponsePolicyOptionsConfig(options []client.Option) []interface{} {
	if options == nil {
		return []interface{}{}
	}
	opts := make([]interface{}, len(options))
	for i, opt := range options {
		o := map[string]interface{}{
			"display_name": opt.DisplayName,
			"value":        opt.Value,
		}
		opts[i] = o
	}
	return opts
}

func expandResponsePolicyTrigger(list []interface{}) *client.ResponsePolicyTrigger {
	if len(list) == 0 {
		return nil
	}
	item, ok := list[0].(map[string]interface{})
	if !ok {
		return nil
	}

	trigger := &client.ResponsePolicyTrigger{
		Predefined: item["predefined"].(string),
	}

	if inList, ok := item["input"].([]interface{}); ok && len(inList) > 0 {
		inMap, _ := inList[0].(map[string]interface{})
		if inMap != nil {
			trigger.Input = &client.ResponsePolicyInputTrigger{
				Name: inMap["name"].(string),
			}
			// Process attributes if they exist
			if attrs, ok := inMap["attributes"].([]interface{}); ok && len(attrs) > 0 {
				trigger.Input.Attribute = expandResponsePolicyTriggerInputAttributes(attrs)
			}
		}
	}

	if customList, ok := item["custom"].([]interface{}); ok && len(customList) > 0 {
		if cm, ok := customList[0].(map[string]interface{}); ok {
			if rego, _ := cm["rego"].(string); rego != "" {
				trigger.Custom = &client.ResponsePolicyCustomTrigger{Rego: rego}
			}
		}
	}

	return trigger
}

func expandResponsePolicyTriggerInputs(inputs []interface{}) []client.ResponsePolicyInputTrigger {
	var rpit []client.ResponsePolicyInputTrigger
	for _, in := range inputs {
		inputMap, ok := in.(map[string]interface{})
		if !ok {
			continue
		}
		// attributes is defined as a TypeList in the schema, so expect []interface{}
		var attrs []interface{}
		if a, ok := inputMap["attributes"].([]interface{}); ok {
			attrs = a
		} else {
			attrs = []interface{}{}
		}
		name, _ := inputMap["name"].(string)
		rpit = append(rpit, client.ResponsePolicyInputTrigger{
			Name:      name,
			Attribute: expandResponsePolicyTriggerInputAttributes(attrs),
		})
	}
	return rpit
}

func expandResponsePolicyTriggerInputAttributes(attrs []interface{}) []client.ResponsePolicyInputTriggerAttribute {
	var rpita []client.ResponsePolicyInputTriggerAttribute
	for _, a := range attrs {
		attrMap := a.(map[string]interface{})
		rpita = append(rpita, client.ResponsePolicyInputTriggerAttribute{
			Name:      attrMap["name"].(string),
			Operation: attrMap["operation"].(string),
			Value:     attrMap["value"].(string),
		})
	}
	return rpita
}

func expandResponsePolicyTriggerCustom(custom []interface{}) []client.ResponsePolicyCustomTrigger {
	var rpct []client.ResponsePolicyCustomTrigger
	for _, c := range custom {
		customMap := c.(map[string]interface{})
		rpct = append(rpct, client.ResponsePolicyCustomTrigger{
			Rego: customMap["rego"].(string),
		})
	}
	return rpct
}

func expandResponsePolicyOutputs(list []interface{}) []client.ResponsePolicyOutput {
	outs := []client.ResponsePolicyOutput{}
	for _, o := range list {
		if outMap, ok := o.(map[string]interface{}); ok {
			name, _ := outMap["name"].(string)
			typ, _ := outMap["type"].(string)
			// Preserve user-provided outputs even if name or type are empty strings.
			// Filtering them out here caused asymmetric behavior with flattenResponsePolicyOutputs
			// leading to state drift. Let API validation handle empty fields if necessary.
			outs = append(outs, client.ResponsePolicyOutput{
				Name: name,
				Type: typ,
			})
		}
	}
	return outs
}
