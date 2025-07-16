package aquasec

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAPIKeys() *schema.Resource {
	return &schema.Resource{
		Description: "Data source `aquasec_aqua_api_keys` provides all API keys or a single key by ID.",
		ReadContext: dataAPIKeyRead,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:         schema.TypeString,
				Optional:     true,
				ExactlyOneOf: []string{"id", "limit"},
			},
			"limit": {
				Type:         schema.TypeInt,
				Optional:     true,
				ExactlyOneOf: []string{"id", "limit"},
			},
			"offset": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"apikeys": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"access_key": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"open_access": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"scans_per_month": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"account_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"roles": {
							Type:        schema.TypeList,
							Description: "The roles that will be assigned to the API key.",
							Optional:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"group_id": {
							Type:        schema.TypeInt,
							Description: "The group ID that is associated with the API key.",
							Optional:    true,
						},
						"expiration": {
							Type:        schema.TypeInt,
							Description: "The date of the API key's expiry",
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
						"ip_addresses": {
							Type:        schema.TypeList,
							Description: "List of IP addresses the API key can be used from.",
							Optional:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			// Flattened attributes for latest or single-key mode:
			"access_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"description": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"open_access": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"scans_per_month": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"account_id": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"roles": {
				Type:        schema.TypeList,
				Description: "The roles that will be assigned to the API key.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"group_id": {
				Type:        schema.TypeInt,
				Description: "The group ID that is associated with the API key.",
				Optional:    true,
			},
			"expiration": {
				Type:        schema.TypeInt,
				Description: "The date of the API key's expiry",
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
			"ip_addresses": {
				Type:        schema.TypeList,
				Description: "List of IP addresses the API key can be used from.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataAPIKeyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	var diags diag.Diagnostics

	// Single-key fetch by ID
	if idRaw, ok := d.GetOk("id"); ok {
		id, _ := strconv.Atoi(idRaw.(string))
		key, err := c.GetApiKey(id)
		if err != nil {
			return diag.FromErr(err)
		}

		d.SetId(strconv.Itoa(id))
		d.Set("access_key", key.AccessKey)
		d.Set("description", key.Description)
		d.Set("open_access", key.OpenAccess)
		d.Set("scans_per_month", key.ScansPerMonth)
		d.Set("account_id", key.AccountID)
		d.Set("enabled", key.Enabled)
		d.Set("roles", key.Roles)
		d.Set("permission_ids", key.PermissionIDs)
		d.Set("expiration", key.Expiration)
		d.Set("group_id", key.GroupID)
		d.Set("ip_addresses", key.IPAddresses)

		if key.CreatedAt != "" {
			t, err := parseWithFallback(key.CreatedAt, time.RFC3339, time.Time{})
			if err != nil {
				log.Printf("[WARN] could not parse created %q: %v", key.CreatedAt, err)
			}
			d.Set("created", t.Format(time.RFC3339))
		}

		// Clear list attribute
		d.Set("apikeys", nil)
		return diags
	}

	// List mode: paginated fetch
	limit := d.Get("limit").(int)
	offset := d.Get("offset").(int)
	list, err := c.GetApiKeys(limit, offset)
	if err != nil {
		return diag.FromErr(err)
	}

	var items []map[string]interface{}
	for _, k := range list {
		created := ""
		if k.CreatedAt != "" {
			if t, err := parseWithFallback(k.CreatedAt, time.RFC3339, time.Time{}); err == nil {
				created = t.Format(time.RFC3339)
			} else {
				log.Printf("[WARN] could not parse created %q: %v", k.CreatedAt, err)
			}
		}
		items = append(items, map[string]interface{}{
			"id":              k.ID,
			"access_key":      k.AccessKey,
			"description":     k.Description,
			"created":         created,
			"open_access":     k.OpenAccess,
			"scans_per_month": k.ScansPerMonth,
			"account_id":      k.AccountID,
			"enabled":         k.Enabled,
			"roles":           k.Roles,
			"permission_ids":  k.PermissionIDs,
			"expiration":      k.Expiration,
			"group_id":        k.GroupID,
			"ip_addresses":    k.IPAddresses,
		})
	}

	d.Set("apikeys", items)

	// Clear flattened fields so they don't reflect stale state
	for _, fld := range []string{
		"access_key", "description", "created",
		"open_access", "scans_per_month", "account_id", "enabled",
		"group_id", "permission_ids", "expiration", "roles",
	} {
		d.Set(fld, nil)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))
	return diags
}

func parseWithFallback(s, layout string, fallback time.Time) (time.Time, error) {
	t, err := time.Parse(layout, s)
	if err != nil {
		return fallback, err
	}
	return t, nil
}
