package aquasec

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceUserSaas() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_user_saas` resource manages your saas users within Aqua.\n\n" +
			"The users created must have at least one Csp Role that is already " +
			"present within Aqua.",
		Create: resourceUserSaasCreate,
		Read:   resourceUserSaasRead,
		Update: resourceUserSaasUpdate,
		Delete: resourceUserSaasDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			//"dashboard": {
			//	Type:     schema.TypeBool,
			//	Computed: true,
			//},
			"csp_roles": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"id": {
				Type:     schema.TypeString,
				Computed: true,
				ForceNew: true,
			},
			"email": {
				Type:     schema.TypeString,
				Required: true,
			},
			"mfa_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"confirmed": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"password_reset": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"send_announcements": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"send_scan_results": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"send_new_plugins": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"send_new_risks": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"account_admin": {
				Type:     schema.TypeBool,
				Required: true,
			},
			"created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			//"provider": {
			//	Type:     schema.TypeString,
			//	Computed: true,
			//},
			"multiaccount": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"groups": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"created": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"logins": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"ip_address": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"csp_roles": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"cspm_roles": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"groups": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"count_failed_signin": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"last_signin_attempt": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceUserSaasCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	basicId := client.BasicId{Id: d.Get("id").(string)}

	var basicUser client.BasicUser

	cspRoles, ok := d.GetOk("csp_roles")
	if ok {
		basicUser.CspRoles = convertStringArr(cspRoles.([]interface{}))
	}

	email, ok := d.GetOk("email")
	if ok {
		basicUser.Email = email.(string)
	}

	accountAdmin, ok := d.GetOk("account_admin")
	if ok {
		basicUser.AccountAdmin = accountAdmin.(bool)
	}

	mfaEnabled, ok := d.GetOk("mfa_enabled")
	if ok {
		basicUser.MfaEnabled = mfaEnabled.(bool)
	}

	userGroups, ok := d.GetOk("groups")
	if ok {
		j, err := json.Marshal(userGroups)
		if err != nil {
			return fmt.Errorf("resourceUserSaasCreate: Failed to get userGroups, %v", err)
		}

		var dataGroups []client.UserGroups
		err = json.Unmarshal(j, &dataGroups)
		if err != nil {
			return fmt.Errorf("resourceUserSaasCreate: Failed to get userGroups, %v", err)
		}
		//for _, group := range userGroups.([]interface{}) {
		//	var g client.UserGroups
		//	g.Name = group.(client.UserGroups).Name
		//	g.GroupAdmin = group.(client.UserGroups).GroupAdmin
		//	dataGroups = append(dataGroups, g)
		//}
		basicUser.UserGroups = dataGroups
	}

	user := client.FullUser{
		BasicId:   basicId,
		BasicUser: basicUser,
	}

	err := ac.CreateUser(&user)
	if err != nil {
		return err
	}
	d.Set("id", user.BasicId.Id)

	//adding user to user selected client.BasicUser{}.Groups
	if user.BasicUser.UserGroups != nil {
		intId, _ := strconv.Atoi(user.BasicId.Id)
		err = manageUserSaasGroups(intId, "add", user.BasicUser.UserGroups, m)
		if err != nil {
			return err
		}
		groups := make([]interface{}, len(user.BasicUser.UserGroups), len(user.BasicUser.UserGroups))
		for i, group := range user.BasicUser.UserGroups {
			g := make(map[string]interface{})
			g["name"] = group.Name
			groups[i] = g
		}

		d.Set("groups", groups)
	}
	d.SetId(user.BasicId.Id)
	return resourceUserSaasRead(d, m)

}

func resourceUserSaasRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	r, err := ac.GetUser(d.Id())
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return err
	}
	logins := make([]interface{}, len(r.BasicUser.Logins))

	d.Set("confirmed", r.Confirmed)
	d.Set("password_reset", r.PasswordReset)
	d.Set("send_announcements", r.SendAnnouncements)
	d.Set("send_scan_results", r.SendScanResults)
	d.Set("send_new_plugins", r.SendNewPlugin)
	d.Set("send_new_risks", r.SendNewRisks)
	d.Set("created", r.Created)
	//d.Set("provider", r.Provider)
	d.Set("multiaccount", r.Multiaccount)
	d.Set("account_admin", r.AccountAdmin)
	d.Set("email", r.Email)
	d.Set("mfa_enabled", r.MfaEnabled)
	d.Set("id", r.BasicId.Id)
	d.Set("count_failed_signin", r.CountFailedSignin)
	d.Set("last_signin_attempt", r.LastSigninAttempt)

	for i, login := range r.BasicUser.Logins {
		l := make(map[string]interface{})
		l["id"] = login.Id
		l["ip_address"] = login.IpAddress
		l["created"] = login.Created
		l["csp_roles"] = login.CspRoles
		l["cspm_groups"] = login.CspmGroups
		l["groups"] = login.Groups
		logins[i] = l
	}

	d.Set("logins", logins)
	d.SetId(r.BasicId.Id)

	return nil
}

func resourceUserSaasUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	//id := d.Id()
	if d.HasChanges("email") {
		return fmt.Errorf("user email cannot be changed")
	}
	if d.HasChange("mfa_enabled") {
		err := d.Set("mfa_enabled", d.Get("mfa_enabled").(bool))
		if err != nil {
			return fmt.Errorf("error setting mfa_enabled state: %v", err)
		}
	}
	if d.HasChanges("csp_roles", "account_admin", "groups") {
		var err error
		groupsState, groupDiff := d.GetChange("groups")

		//getting current groups
		userGroups := d.Get("groups")

		j, err := json.Marshal(userGroups)
		if err != nil {
			return fmt.Errorf("resourceUserSaasCreate: Failed to get userGroups, %v", err)
		}

		var dataGroups []client.UserGroups
		err = json.Unmarshal(j, &dataGroups)
		if err != nil {
			return fmt.Errorf("resourceUserSaasCreate: Failed to get userGroups, %v", err)
		}

		cspRoles := d.Get("csp_roles").([]interface{})
		basicId := client.BasicId{Id: d.Get("id").(string)}
		basicUser := client.BasicUser{
			AccountAdmin: d.Get("account_admin").(bool),
			CspRoles:     convertStringArr(cspRoles),
			UserGroups:   dataGroups,
		}

		user := client.FullUser{
			BasicId:   basicId,
			BasicUser: basicUser,
		}

		err = c.UpdateUser(&user)
		if err != nil {
			log.Println("[DEBUG]  error while updating user: ", err)
			return err
		}

		//updating groups
		//removing old groups
		intId, _ := strconv.Atoi(user.BasicId.Id)
		err = manageUserSaasGroups(intId, "add", user.BasicUser.UserGroups, m)
		j, err = json.Marshal(groupsState)
		if err != nil {
			return fmt.Errorf("Failed to get groupsState, %v", err)
		}
		var groupsStateList []client.UserGroups
		err = json.Unmarshal(j, &groupsStateList)
		if err != nil {
			return fmt.Errorf("Failed to get groupsStateList, %v", err)
		}
		manageUserSaasGroups(intId, "remove", groupsStateList, m)

		//addingUsers
		j, err = json.Marshal(groupDiff)
		if err != nil {
			return fmt.Errorf("Failed to get groupDiff, %v", err)
		}
		var groupsDiffList []client.UserGroups
		err = json.Unmarshal(j, &groupsDiffList)
		if err != nil {
			return fmt.Errorf("Failed to get groupsDiffList, %v", err)
		}
		manageUserSaasGroups(intId, "add", groupsDiffList, m)
	}
	return nil
}

func resourceUserSaasDelete(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	id := d.Id()
	err := c.DeleteUser(id)
	log.Println(err)
	if err == nil {
		d.SetId("")
	} else {
		log.Println("[DEBUG]  error deleting user: ", err)
		return err
	}
	//d.SetId("")

	return err
}

func manageUserSaasGroups(userId int, operation string, userGroups []client.UserGroups, m interface{}) error {
	c := m.(*client.Client)
	var err error
	mappedGroups, err := getMapForGroupsByNameAndId(m)

	if err != nil {
		return fmt.Errorf("manageUserSaasGroups: Failed to get all groups, %s", err)
	}

	for _, group := range userGroups {
		if group.Name == "Default" {
			continue
		}

		err = c.ManageUserGroups(mappedGroups[group.Name], userId, group.GroupAdmin, operation)
		if err != nil {
			log.Println(fmt.Sprintf("[DEBUG]  error adding user to group: %s", group.Name), err)
			return err
		}
	}
	return nil
}

func getMapForGroupsByNameAndId(m interface{}) (map[string]int, error) {
	ac := m.(*client.Client)
	mappedGroups := make(map[string]int)
	groups, err := ac.GetGroups()

	if err != nil {
		return mappedGroups, fmt.Errorf("getMapForGroupsByNameAndId: Failed to get all groups, %s", err)
	}

	for _, group := range groups {
		mappedGroups[group.Name] = group.Id
	}
	return mappedGroups, err

}
