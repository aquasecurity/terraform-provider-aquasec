package aquasec

import (
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceNotification() *schema.Resource {
	return &schema.Resource{
		Create: resourceNotificationCreate,
		Update: resourceNotificationUpdate,
		Read:   resourceNotificationRead,
		Delete: resourceNotificationDelete,
		Schema: map[string]*schema.Schema{
			"user_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"webhook_url": {
				Type:     schema.TypeString,
				Required: true,
			},
			"channel": {
				Type:     schema.TypeString,
				Required: true,
			},
			"enabled": {
				Type:     schema.TypeBool,
				Required: true,
			},
			"main_text": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"icon": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"service_key": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}

}

func resourceNotificationCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	notification := client.Notification{
		UserName:   d.Get("user_name").(string),
		WebhookURL: d.Get("webhook_url").(string),
		Channel:    d.Get("channel").(string),
		Enabled:    d.Get("enabled").(bool),
		MainText:   d.Get("main_text").(string),
		Icon:       d.Get("icon").(string),
		ServiceKey: d.Get("service_key").(string),
		Name:       "Slack",
		Type:       d.Get("type").(string),
	}

	err := ac.SlackNotificationCreate(notification)
	if err != nil {
		return err
	}

	//d.SetId(d.Get("name").(string))

	err = resourceNotificationRead(d, m)
	if err == nil {
		d.SetId("Slack")
	} else {
		return err
	}

	return nil
}

func resourceNotificationUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	notification := client.Notification{
		UserName:   d.Get("user_name").(string),
		WebhookURL: d.Get("webhook_url").(string),
		Channel:    d.Get("channel").(string),
		Enabled:    d.Get("enabled").(bool),
		MainText:   d.Get("main_text").(string),
		Icon:       d.Get("icon").(string),
		ServiceKey: d.Get("service_key").(string),
		Name:       "Slack",
		Type:       d.Get("type").(string),
	}

	err := ac.SlackNotificationUpdate(notification)
	if err != nil {
		return err
	}

	return nil
}

func resourceNotificationRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	r, err := ac.SlackNotificationRead()
	if err != nil {
		log.Println("[DEBUG]  error calling ac.GetSlackNotification: ", r)
		return err
	}
	return nil
}

func resourceNotificationDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	notification := client.Notification{
		UserName:   "",
		WebhookURL: "",
		Channel:    "",
		Enabled:    false,
		MainText:   "",
		Icon:       "",
		ServiceKey: "",
		Name:       "Slack",
		Type:       "slack",
	}

	err := ac.SlackNotificationDelete(notification)
	if err != nil {
		return err
	}

	return err
}
