package aquasec

import (
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func resourceUser() *schema.Resource {
	return &schema.Resource{
		Description: "The `aquasec_user` resource manages your users within Aqua.\n\n" +
			"The users created must have at least one Role that is already " +
			"present within Aqua.",
		Create: resourceUserCreate,
		Read:   resourceUserRead,
		Update: resourceUserUpdate,
		Delete: resourceUserDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"user_id": {
				Type:     schema.TypeString,
				Description: "The user ID.",
				Required: true,
				ForceNew: true,
			},
			"password": {
				Type:     schema.TypeString,
				Description: "Login password for the user; string, required, at least 8 characters long.",
				Required: true,
			},
			"password_confirm": {
				Type:     schema.TypeString,
				Description: "Password confirmation.",
				Optional: true,
			},
			"name": {
				Type:     schema.TypeString,
				Description: "The user name.",
				Optional: true,
			},
			"email": {
				Type:     schema.TypeString,
				Description: "The user Email.",
				Optional: true,
			},
			"first_time": {
				Type:     schema.TypeBool,
				Description: "If the user must change password at next login.",
				Optional: true,
			},
			"is_super": {
				Type:     schema.TypeBool,
				Description: "Give the Permission Set full access, meaning all actions are allowed without restriction.",
				Computed: true,
			},
			"ui_access": {
				Type:     schema.TypeBool,
				Description: "Whether to allow UI access for users with this Permission Set.",
				Computed: true,
			},
			"role": {
				Type:     schema.TypeString,
				Description: "The first role that assigned to the user for backward compatibility.",
				Computed: true,
			},
			"roles": {
				Type:     schema.TypeList,
				Description: "The roles that will be assigned to the user.",
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"type": {
				Type:     schema.TypeString,
				Description: "The user type (Aqua, LDAP, SAML, OAuth2, OpenID, Tenant Manager).",
				Computed: true,
			},
			"plan": {
				Type:     schema.TypeString,
				Description: "User's Aqua plan (Developer / Team / Advanced).",
				Computed: true,
			},
		},
	}
}

func resourceUserCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	basicId := client.BasicId{Id: d.Get("user_id").(string)}
	var basicUser client.BasicUser

	password, ok := d.GetOk("password")
	if ok {
		basicUser.Password = password.(string)
	}

	passwordConfirm, ok := d.GetOk("passwordConfirm")
	if ok {
		basicUser.PasswordConfirm = passwordConfirm.(string)
	}

	name, ok := d.GetOk("name")
	if ok {
		basicUser.Name = name.(string)
	}

	email, ok := d.GetOk("email")
	if ok {
		basicUser.Email = email.(string)
	}

	roles, ok := d.GetOk("roles")
	if ok {
		basicUser.Roles = convertStringArr(roles.([]interface{}))
	}

	firstTime, ok := d.GetOk("first_time")
	if ok {
		basicUser.FirstTime = firstTime.(bool)
	}

	user := client.FullUser{
		BasicId:   basicId,
		BasicUser: basicUser,
	}

	err := ac.CreateUser(&user)
	if err != nil {
		return err
	}

	err = resourceUserRead(d, m)
	if err == nil {
		d.SetId(d.Get("user_id").(string))
	} else {
		return err
	}

	return nil
}

func resourceUserRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	id := d.Get("user_id").(string)
	r, err := ac.GetUser(id)
	if err == nil {
		d.Set("first_time", r.BasicUser.FirstTime)
		d.Set("is_super", r.BasicUser.IsSuper)
		d.Set("ui_access", r.BasicUser.UiAccess)
		d.Set("role", r.BasicUser.Role)
		d.Set("user_id", r.BasicId.Id)
		d.Set("type", r.BasicUser.Type)
	} else {
		log.Println("[DEBUG]  error calling ac.ReadUser: ", r)
		return err
	}
	return nil
}

func resourceUserUpdate(d *schema.ResourceData, m interface{}) error {
	c := m.(*client.Client)
	id := d.Id()

	// if the password has changed, call a different API method
	if d.HasChange("password") {
		password := client.NewPassword{
			Name:     id,
			Password: d.Get("password").(string),
		}
		log.Println("password: ", password)
		err := c.ChangePassword(password)
		if err != nil {
			log.Println("[DEBUG]  error while changing password: ", err)
			return err
		}
	}

	if d.HasChanges("email", "roles") {
		roles := d.Get("roles").([]interface{})
		basicId := client.BasicId{Id: d.Get("user_id").(string)}
		basicUser := client.BasicUser{
			Name:  d.Get("name").(string),
			Email: d.Get("email").(string),
			Roles: convertStringArr(roles),
		}

		user := client.FullUser{
			BasicId:   basicId,
			BasicUser: basicUser,
		}

		err := c.UpdateUser(&user)
		if err != nil {
			log.Println("[DEBUG]  error while updating user: ", err)
			return err
		}
	}

	return nil
}

func resourceUserDelete(d *schema.ResourceData, m interface{}) error {
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
