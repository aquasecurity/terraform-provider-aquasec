package aquasec

import (
	"context"
	"log"
	"math"
	"strconv"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAPIKeys() *schema.Resource {
	return &schema.Resource{
		Description: "Data source `aquasec_aqua_api_keys` provides all API keys by limit and offset.",
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
							Computed:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"group_id": {
							Type:        schema.TypeInt,
							Description: "The group ID that is associated with the API key.",
							Computed:    true,
						},
						"expiration": {
							Type:        schema.TypeInt,
							Description: "The date of the API key's expiry",
							Computed:    true,
						},
						"permission_ids": {
							Type: schema.TypeList,
							Description: "List of permission IDs for the API key, if empty the API" +
								"key has global admin permissions.",
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeInt,
							},
						},
						"ip_addresses": {
							Type:        schema.TypeList,
							Description: "List of IP addresses the API key can be used from.",
							Computed:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
		},
	}
}

func dataAPIKeyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	var diags diag.Diagnostics

	if idRaw, ok := d.GetOk("id"); ok {
		id, err := strconv.Atoi(idRaw.(string))
		if err != nil {
			return diag.FromErr(err)
		}
		key, err := c.GetApiKey(id)
		if err != nil {
			return diag.FromErr(err)
		}

		if key.ID == 0 {
			return diag.Errorf("API key returned with empty or zero id")
		}

		created := ""
		if key.CreatedAt != "" {
			if t, err := parseWithFallback(key.CreatedAt, time.RFC3339, time.Time{}); err == nil {
				created = t.Format(time.RFC3339)
			} else {
				log.Printf("[WARN] could not parse created %q: %v", key.CreatedAt, err)
			}
		}

		item := map[string]interface{}{
			"id":              key.ID,
			"access_key":      key.AccessKey,
			"description":     key.Description,
			"created":         created,
			"open_access":     key.OpenAccess,
			"scans_per_month": key.ScansPerMonth,
			"account_id":      key.AccountID,
			"enabled":         key.Enabled,
			"roles":           key.Roles,
			"permission_ids":  key.PermissionIDs,
			"expiration":      millisecondsToDays(int64(key.Expiration)), // raw timestamp in ms
			"group_id":        key.GroupID,
			"ip_addresses":    key.IPAddresses,
		}
		if err := d.Set("apikeys", []interface{}{item}); err != nil {
			return diag.FromErr(err)
		}
		d.SetId(strconv.Itoa(id))
		return diags
	}
	if limitRaw, ok := d.GetOk("limit"); ok {
		limit := limitRaw.(int)
		offset := d.Get("offset").(int)

		if limit == 0 {
			return diag.Errorf("`limit` must be greater than 0 when using limit/offset")
		}

		keys, err := c.GetApiKeys(limit, offset)
		if err != nil {
			return diag.FromErr(err)
		}

		var items []map[string]interface{}
		for _, k := range keys {
			if k.ID == 0 {
				log.Printf("[WARN] skipping API key with empty id")
				continue
			}

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
				"expiration":      millisecondsToDays(int64(k.Expiration)), // raw timestamp in ms
				"group_id":        k.GroupID,
				"ip_addresses":    k.IPAddresses,
			})
		}

		if err := d.Set("apikeys", items); err != nil {
			return diag.FromErr(err)
		}
		d.SetId(strconv.FormatInt(time.Now().Unix(), 10))
		return diags
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))
	return diag.Errorf("either \"id\" or \"limit\" must be set on data source")
}

func parseWithFallback(s, layout string, fallback time.Time) (time.Time, error) {
	t, err := time.Parse(layout, s)
	if err != nil {
		return fallback, err
	}
	return t, nil
}

func millisecondsToDays(ms int64) int {
	if ms == 0 {
		return 0
	}
	expirationTime := time.UnixMilli(ms)
	duration := expirationTime.Sub(time.Now())

	days := int(math.Ceil(duration.Hours() / 24))
	if days < 0 {
		return 0
	}
	return days
}
