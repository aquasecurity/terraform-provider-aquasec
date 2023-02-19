package aquasec

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceNotificationOld() *schema.Resource {
	return &schema.Resource{
		Description: "Provides an Aquasec Notification Slack resource",
		Create:      resourceNotificationOldCreate,
		Update:      resourceNotificationOldUpdate,
		Read:        resourceNotificationOldRead,
		Delete:      resourceNotificationOldDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
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
				Optional: true,
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}

}

func resourceNotificationOldCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	NotificationOld := client.NotificationOld{
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

	err := ac.SlackNotificationCreate(NotificationOld)
	if err != nil {
		return err
	}

	//d.SetId(d.Get("name").(string))

	err = resourceNotificationOldRead(d, m)
	if err == nil {
		d.SetId("Slack")
	} else {
		return err
	}

	return nil
}

func resourceNotificationOldUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	NotificationOld := client.NotificationOld{
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

	err := ac.SlackNotificationUpdate(NotificationOld)
	if err != nil {
		return err
	}

	return nil
}

func resourceNotificationOldRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	r, err := ac.SlackNotificationRead()
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return err
	}
	if err = d.Set("channel", r.Channel); err != nil {
		return err
	}
	if err = d.Set("enabled", r.Enabled); err != nil {
		return err
	}
	if err = d.Set("name", r.Name); err != nil {
		return err
	}
	if err = d.Set("type", r.Type); err != nil {
		return err
	}
	if err = d.Set("user_name", r.UserName); err != nil {
		return err
	}
	if err = d.Set("webhook_url", r.WebhookURL); err != nil {
		return err
	}
	return nil
}

func resourceNotificationOldDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	NotificationOld := client.NotificationOld{
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

	err := ac.SlackNotificationDelete(NotificationOld)
	if err != nil {
		return err
	}

	return err
}
