package aquasec

import (
	"context"
	"fmt"
	"log"
	"math"
	"strconv"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAPIKey() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAPIKeyCreate,
		ReadContext:   resourceAPIKeyRead,
		UpdateContext: resourceAPIKeyUpdate,
		DeleteContext: resourceAPIKeyDelete,

		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Description: "The apikey ID",
				Computed:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The API key description.",
				Required:    true,
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
				Default:     365,
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

func resourceAPIKeyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
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

	if v, ok := d.GetOk("expiration"); ok {
		api.Expiration = v.(int) // TTL in days
	}

	api.GroupID = d.Get("group_id").(int)
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
		GroupID:       api.GroupID,
		PermissionIDs: api.PermissionIDs,
	}
	err := ac.CreateApiKey(apiKey)
	if err != nil {
		return diag.FromErr(fmt.Errorf("CreateApiKey error: %w", err))
	}
	if apiKey.ID == 0 {
		return diag.FromErr(fmt.Errorf("CreateApiKey succeeded but returned empty ID"))
	}
	d.SetId(strconv.Itoa(apiKey.ID))
	d.Set("access_key", apiKey.AccessKey)
	d.Set("secret", apiKey.SecretKey)
	updateDiags := resourceAPIKeyUpdate(ctx, d, m)
	if updateDiags.HasError() {
		return updateDiags
	}
	return resourceAPIKeyRead(ctx, d, m)
}

func resourceAPIKeyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*client.Client)

	id, err := strconv.Atoi(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	key, err := client.GetApiKey(id)
	if err != nil {
		return diag.FromErr(err)
	}

	if key.ID == 0 {
		d.SetId("") // resource removed
		return nil
	}
	if key.Expiration > 0 {
		now := time.Now().UnixMilli()
		diffMillis := float64(int64(key.Expiration) - now)
		ttl := int(math.Round(diffMillis / (1000 * 60 * 60 * 24)))
		if ttl < 0 {
			ttl = 0
		}
		if err := d.Set("expiration", ttl); err != nil {
			return diag.Errorf("error setting TTL expiration: %v", err)
		}
	} else {
		// If expiration is zero or negative, set TTL to 0 (expired or no expiration)
		if err := d.Set("expiration", 0); err != nil {
			return diag.Errorf("error setting TTL expiration: %v", err)
		}
	}
	if key.GroupID == 0 {
		if err := d.Set("group_id", nil); err != nil {
			return diag.Errorf("error setting group_id: %v", err)
		}
	} else {
		if err := d.Set("group_id", key.GroupID); err != nil {
			return diag.Errorf("error setting group_id: %v", err)
		}
	}

	_ = d.Set("access_key", key.AccessKey)
	_ = d.Set("description", key.Description)
	_ = d.Set("account_id", key.AccountID)
	_ = d.Set("enabled", key.Enabled)
	_ = d.Set("roles", key.Roles)
	_ = d.Set("ip_addresses", key.IPAddresses)

	return nil
}

func resourceAPIKeyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	if d.HasChanges("description", "ip_addresses", "enabled", "roles", "group_id", "permission_ids") {
		var roles []string
		if v, ok := d.GetOk("roles"); ok {
			roles = convertStringArr(v.([]interface{}))
		} else {
			roles = []string{}
		}
		var ipaddresses []string
		if v, ok := d.GetOk("ip_addresses"); ok {
			ipaddresses = convertStringArr(v.([]interface{}))
		} else {
			ipaddresses = []string{}
		}
		var permissionIds []int
		if v, ok := d.GetOk("permission_ids"); ok {
			permissionIds = convertIntArr(v.([]interface{}))
		} else {
			permissionIds = []int{}
		}
		id, errs := strconv.Atoi(d.Id())
		if errs != nil {
			return diag.FromErr(fmt.Errorf("invalid API key ID: %s", d.Id()))
		}

		apikey := &client.APIKey{
			ID:            id,
			Description:   d.Get("description").(string),
			Enabled:       d.Get("enabled").(bool),
			IPAddresses:   ipaddresses,
			Roles:         roles,
			GroupID:       d.Get("group_id").(int),
			PermissionIDs: permissionIds,
		}

		err := ac.UpdateApiKey(apikey)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error while updating API Key: %w", err))
		}
	}
	return nil
}

func resourceAPIKeyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	id, err := strconv.Atoi(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("invalid API key ID: %s", d.Id()))
	}

	err = ac.DeleteApiKey(id)
	if err != nil {
		log.Println("[DEBUG] error deleting API key: ", err)
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
