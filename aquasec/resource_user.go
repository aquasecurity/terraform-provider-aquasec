package aquasec

import (
	"log"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
			"last_updated": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"user_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"password": {
				Type:     schema.TypeString,
				Required: true,
			},
			"password_confirm": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"email": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"first_time": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"roles": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceUserCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	// Get and Convert Roles
	roles := d.Get("roles").([]interface{})
	user := client.User{
		ID:        d.Get("user_id").(string),
		Password:  d.Get("password").(string),
		Name:      d.Get("name").(string),
		Email:     d.Get("email").(string),
		FirstTime: d.Get("first_time").(bool),
		Roles:     convertStringArr(roles),
	}

	err := ac.CreateUser(user)
	if err != nil {
		return err
	}

	//d.SetId(d.Get("user_id").(string))

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

	//id := d.Id()
	id := d.Get("user_id").(string)
	r, err := ac.GetUser(id)
	if err != nil {
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
		_ = d.Set("last_updated", time.Now().Format(time.RFC850))
	}

	if d.HasChanges("email", "roles") {
		roles := d.Get("roles").([]interface{})
		user := client.User{
			ID:    d.Get("user_id").(string),
			Name:  d.Get("name").(string),
			Email: d.Get("email").(string),
			Roles: convertStringArr(roles),
		}

		err := c.UpdateUser(user)
		if err == nil {
			_ = d.Set("last_updated", time.Now().Format(time.RFC850))
		} else {
			log.Println("[DEBUG]  error while updating user: ", err)
			return err
		}
		//_ = d.Set("last_updated", time.Now().Format(time.RFC850))
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
