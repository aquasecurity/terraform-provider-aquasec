package aquasec

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAPIKey() *schema.Resource {
	return &schema.Resource{
		Create: resourceAPIKeyCreate,
		Read:   resourceAPIKeyRead,
		Update: resourceAPIKeyUpdate,
		Delete: resourceAPIKeyDelete,

		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Description: "The apikey ID",
				Computed:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The API key description.",
				Optional:    true,
			},
			"enabled": {
				Type:        schema.TypeBool,
				Description: "Whether the apikey is enabled or not.",
				Optional:    true,
				Default:     true,
			},
			"ip_addresses": {
				Type:        schema.TypeList,
				Description: "List of IP addresses the API key can be used from.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"access_key": {
				Type:        schema.TypeString,
				Description: "The API key value.",
				Computed:    true,
			},
			"secret": {
				Type:        schema.TypeString,
				Description: "The API key secret.",
				Computed:    true,
				Sensitive:   true,
				ForceNew:    true,
			},
			"roles": {
				Type:        schema.TypeList,
				Description: "The roles that will be assigned to the API key.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"created": {
				Type:        schema.TypeString,
				Description: "The date of the API key creation.",
				Computed:    true,
			},
			"updated": {
				Type:        schema.TypeString,
				Description: "The date of the API key's last update.",
				Computed:    true,
			},
			"expiration": {
				Type:        schema.TypeInt,
				Description: "The date of the API key's expiry",
				Optional:    true,
			},
			"whitelisted": {
				Type: schema.TypeBool,
				Description: "If true, the API key is whitelisted. " +
					"Whitelisted API keys can be used without IP address restrictions.",
				Optional: true,
				Default:  false,
			},
			"iac_token": {
				Type: schema.TypeBool,
				Description: "If true, the API key is an Infrastructure as Code (IaC)" +
					" token. IaC tokens are used for automated deployments and " +
					"should be kept secure.",
				Optional: true,
				Default:  false,
			},
			"account_id": {
				Type: schema.TypeInt,
				Description: "The ID of the account that owns the API key. " +
					"This is useful for multi-tenant environments where API keys " +
					"are associated with specific accounts.",
				Computed: true,
			},
			"owner": {
				Type: schema.TypeInt,
				Description: "The ID of the user who created the API key. " +
					"This can be used for auditing purposes to track who created " +
					"the API key.",
				Computed: true,
			},
			"system_key": {
				Type: schema.TypeBool,
				Description: "Indicates if the API key is a system key. " +
					"System keys are typically used for internal services and " +
					"should not be used for regular API access.",
				Computed: true,
			},
			"group_id": {
				Type:        schema.TypeInt,
				Description: "The group ID that is associated with the API key.",
				Optional:    true,
			},
			"permission_ids": {
				Type: schema.TypeList,
				Description: "List of permission IDs for the API key, if empty the API" +
					"key has global admin permissions.",
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			},
		},
	}
}

func resourceAPIKeyCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	var api client.APIKey

	// Required field
	api.Description = d.Get("description").(string)

	// Optional fields
	ipaddresses, ok := d.GetOk("ip_addresses")
	if ok {
		api.IPAddresses = convertStringArr(ipaddresses.([]interface{}))
	}

	roles, ok := d.GetOk("roles")
	if ok {
		api.Roles = convertStringArr(roles.([]interface{}))
	}

	expiration := d.Get("expiration").(int)
	log.Printf("[DEBUG] Received expiration days: %d", expiration)
	expirationDate, errs := SetExpirationDate(expiration)
	if errs != nil {
		log.Printf("[ERROR] Error setting expiration date: %s", errs)
		return fmt.Errorf("Error setting expiration date: %s", errs)
	}
	api.Expiration = int(expirationDate.Sub(time.Now()).Hours() / 24)

	api.Whitelisted = d.Get("whitelisted").(bool)
	api.IacToken = d.Get("iac_token").(bool)
	api.SystemKey = d.Get("system_key").(bool)

	permissionIds, ok := d.GetOk("permission_ids")
	if ok {
		api.PermissionIDs = convertIntArr(permissionIds.([]interface{}))
	}

	apiKey := &client.APIKey{
		ID:            api.ID,
		Description:   api.Description,
		IPAddresses:   api.IPAddresses,
		Roles:         api.Roles,
		Expiration:    api.Expiration,
		Whitelisted:   api.Whitelisted,
		IacToken:      api.IacToken,
		SystemKey:     api.SystemKey,
		GroupID:       api.GroupID,
		PermissionIDs: api.PermissionIDs,
	}
	err := ac.CreateApiKey(apiKey)
	if err != nil {
		return fmt.Errorf("CreateApiKey error: %w", err)
	}
	if apiKey.ID.String() == "" {
		return fmt.Errorf("CreateApiKey succeeded but returned empty ID")
	}
	d.SetId(apiKey.ID.String())
	d.Set("access_key", apiKey.AccessKey)
	d.Set("secret", apiKey.SecretKey)
	err = resourceAPIKeyUpdate(d, m)
	if err != nil {
		return err
	}
	return resourceAPIKeyRead(d, m)
}

func resourceAPIKeyRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	id, err := strconv.Atoi(d.Id())
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("invalid API key ID: %s", d.Id())
	}

	apikey, err := ac.GetApiKey(id)
	if err != nil {
		return err
	}

	d.Set("id", apikey.ID.String())
	d.Set("description", apikey.Description)
	d.Set("enabled", apikey.Enabled)
	d.Set("ip_addresses", apikey.IPAddresses)
	d.Set("roles", apikey.Roles)
	d.Set("expiration", apikey.Expiration)
	d.Set("created", apikey.CreatedAt)
	d.Set("updated", apikey.UpdatedAt)
	d.Set("whitelisted", apikey.Whitelisted)
	d.Set("iac_token", apikey.IacToken)
	d.Set("account_id", apikey.AccountID)
	d.Set("owner", apikey.Owner)
	d.Set("system_key", apikey.SystemKey)
	d.Set("group_id", apikey.GroupID)
	d.Set("permission_ids", apikey.PermissionIDs)

	return nil
}

func resourceAPIKeyUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	id, err := strconv.Atoi(d.Id())

	if err != nil {
		return fmt.Errorf("invalid API key ID: %d", id)
	}

	log.Printf("[DEBUG] Updating API Key for the ID: %d", id)
	if d.HasChanges("description", "ip_addresses", "enabled", "roles", "whitelisted", "iac_token", "system_key", "group_id") {
		roles := d.Get("roles").([]interface{})
		ipaddresses := d.Get("ip_addresses").([]interface{})
		id := d.Id()
		apikey := &client.APIKey{
			ID:          json.Number(id),
			Description: d.Get("description").(string),
			Enabled:     d.Get("enabled").(bool),
			IPAddresses: convertStringArr(ipaddresses),
			Roles:       convertStringArr(roles),
			Whitelisted: d.Get("whitelisted").(bool),
			IacToken:    d.Get("iac_token").(bool),
			SystemKey:   d.Get("system_key").(bool),
			GroupID:     d.Get("group_id").(int),
		}

		err := ac.UpdateApiKey(apikey)
		if err != nil {
			return fmt.Errorf("error while updating API Key: %w", err)
		}
	}
	return nil
}

func resourceAPIKeyDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	id, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("invalid API key ID: %s", d.Id())
	}

	err = ac.DeleteApiKey(id)
	if err == nil {
		d.SetId("")
	} else {
		log.Println("[DEBUG] error deleting user: ", err)
		return err
	}
	return nil
}

func SetExpirationDate(days int) (time.Time, error) {
	if days <= 0 || days > 365 {
		log.Printf("[ERROR] Invalid days value: %d; must be between 1 and 365", days)
		return time.Time{}, fmt.Errorf("invalid days value; must be between 1 and 365")
	}
	now := time.Now()
	expirationDate := now.AddDate(0, 0, days)
	if expirationDate.After(now.AddDate(1, 0, 0)) {
		log.Printf("[ERROR] Expiration date %v exceeds one year from today %v", expirationDate, now.AddDate(1, 0, 0))
		return time.Time{}, fmt.Errorf("expiration date cannot exceed one year from today")
	}
	return expirationDate, nil
}
