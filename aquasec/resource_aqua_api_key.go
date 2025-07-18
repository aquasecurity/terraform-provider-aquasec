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
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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
				Type:         schema.TypeInt,
				Description:  "The date of the API key's expiry",
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 365),
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
		expirationDays := v.(int)
		if expirationDays > 365 {
			return diag.FromErr(fmt.Errorf("expiration cannot be more than 365 days"))
		} else if expirationDays < 1 {
			return diag.FromErr(fmt.Errorf("expiration cannot be less than 1 day"))
		}
		api.Expiration = expirationDays
	}
	api.Whitelisted = d.Get("whitelisted").(bool)
	api.IacToken = d.Get("iac_token").(bool)

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
		Whitelisted:   api.Whitelisted,
		IacToken:      api.IacToken,
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

	expirationVal := key.Expiration
	if expirationVal > 1000000000 {
		// Treat as Unix timestamp in milliseconds
		expTime := time.UnixMilli(int64(expirationVal))
		daysUntil := int(math.Round(time.Until(expTime).Hours() / 24))
		if daysUntil >= 1 && daysUntil <= 365 {
			d.Set("expiration", daysUntil)
		} else {
			// Expired or out-of-range
			log.Printf("[WARN] API returned invalid expiration value (%d days) for key ID %d", daysUntil, id)
			d.Set("expiration", nil) // or consider setting to a default?
		}
	} else {
		// Treat as days directly
		if expirationVal >= 1 && expirationVal <= 365 {
			d.Set("expiration", expirationVal)
		} else {
			log.Printf("[WARN] API returned nonstandard expiration value: %d for key ID %d", expirationVal, id)
			d.Set("expiration", nil)
		}
	}

	if key.GroupID == 0 {
		d.Set("group_id", nil)
	} else {
		d.Set("group_id", key.GroupID)
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

	if d.HasChanges("description", "ip_addresses", "enabled", "roles", "group_id") {
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
		id, errs := strconv.Atoi(d.Id())
		if errs != nil {
			return diag.FromErr(fmt.Errorf("invalid API key ID: %s", d.Id()))
		}

		apikey := &client.APIKey{
			ID:          id,
			Description: d.Get("description").(string),
			Enabled:     d.Get("enabled").(bool),
			IPAddresses: ipaddresses,
			Roles:       roles,
			GroupID:     d.Get("group_id").(int),
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
