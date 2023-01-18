package aquasec

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"strconv"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSourceNotification() *schema.Resource {
	return &schema.Resource{
		Description:   "Provides a Aquasec Notification resource. This can be used to create and manage Aquasec Notification resources.",
		CreateContext: resourceNotificationCreate,
		ReadContext:   resourceNotificationRead,
		UpdateContext: resourceNotificationUpdate,
		DeleteContext: resourceNotificationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Description: "Notification Id",
				Computed:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "Notification name",
				Required:    true,
			},
			"type": {
				Type:        schema.TypeString,
				Description: "Notifications types, allowed values: slack\\ jira\\ email\\ teams\\ webhook\\ splunk\\ serviceNow",
				Required:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "The user that created the notification",
				Computed:    true,
			},
			"last_updated": {
				Type:        schema.TypeString,
				Description: "Notification last update time",
				Computed:    true,
			},
			"template": {
				Type:        schema.TypeMap,
				Description: "Notification Template",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"properties": {
				Type:        schema.TypeMap,
				Description: "Notification properties, please check the examples for setting it",
				Elem: &schema.Schema{
					Type:     schema.TypeString,
					Optional: true,
				},
				Required: true,
			},
		},
	}
}

func resourceNotificationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	userProperties := d.Get("properties")
	notification, err := ac.GetNotification(d.Id())

	password, ok := userProperties.(map[string]interface{})["password"]

	if ok {
		_, ok := notification.Properties["password"]
		if !ok {
			notification.Properties["password"] = password
		}
	}

	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "Notification Output with id doesn't exist") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	err = d.Set("name", notification.Name)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("type", notification.Type)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("author", notification.Author)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("template", notification.Template)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("properties", convertListValueToString(notification.Properties))
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("last_updated", fmt.Sprintf("%v", notification.LastUpdated))
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(fmt.Sprintf("%v", notification.Id))

	return nil
}

func resourceNotificationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	notification := expandNotification(d)

	err := ac.CreateNotification(notification)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("author", notification.Author)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("last_updated", fmt.Sprintf("%v", notification.LastUpdated))
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("id", fmt.Sprintf("%v", notification.Id))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(fmt.Sprintf("%v", notification.Id))
	//return resourceNotificationRead(d,m)
	err = d.Set("template", notification.Template)

	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("properties", convertListValueToString(notification.Properties))

	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceNotificationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	if d.HasChange("properties") {
		notification := expandNotification(d)
		idInt, err := strconv.Atoi(d.Id())
		if err != nil {
			return diag.FromErr(err)
		}
		notification.Id = idInt
		err = ac.UpdateNotification(notification)

		if err != nil {
			return diag.FromErr(err)
		}

		err = d.Set("template", notification.Template)

		if err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func resourceNotificationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	err := ac.DeleteNotification(d.Id())

	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")

	return nil
}

func expandNotification(d *schema.ResourceData) *client.Notification {
	notification := client.Notification{}

	name, ok := d.GetOk("name")

	if ok {
		notification.Name = name.(string)
	}

	notType, ok := d.GetOk("type")

	if ok {
		notification.Type = notType.(string)
	}

	properties, ok := d.GetOk("properties")

	if ok {
		notification.Properties = convertNotificationPropertiesToMapOfInterface(properties.(map[string]interface{}))
	}

	return &notification
}

func convertNotificationPropertiesToMapOfInterface(properties map[string]interface{}) map[string]interface{} {
	propertiesMap := map[string]interface{}{}
	for k, v := range properties {
		if k == "recipients" || k == "definition_of_done" || k == "affects_versions" {
			if strings.Contains(v.(string), ",") {
				propertiesMap[k] = strings.Split(v.(string), ",")
			} else {
				propertiesMap[k] = []string{v.(string)}
			}
		} else if k == "port" {
			portInt, _ := strconv.Atoi(v.(string))
			propertiesMap[k] = portInt
		} else if k == "use_mx" {
			boolValue, _ := strconv.ParseBool(v.(string))
			propertiesMap[k] = boolValue
		} else {
			propertiesMap[k] = v.(string)
		}
	}
	return propertiesMap
}
