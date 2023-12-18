package aquasec

import (
	"context"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRoleMapping() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRoleMappingCreate,
		ReadContext:   resourceRoleMappingRead,
		UpdateContext: resourceRoleMappingUpdate,
		DeleteContext: resourceRoleMappingDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"saml": {
				Type:        schema.TypeSet,
				Description: "SAML Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua. Use '|' as a separator for multiple roles.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
							ForceNew: true,
						},
					},
				},
				Optional: true,
				MaxItems: 1,
			},
			"oauth2": {
				Type:        schema.TypeSet,
				Description: "Oauth2 Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua. Use '|' as a separator for multiple roles.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
							ForceNew: true,
						},
					},
				},
				Optional: true,
				MaxItems: 1,
			},
			"openid": {
				Type:        schema.TypeSet,
				Description: "OpenId Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua. Use '|' as a separator for multiple roles.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
							ForceNew: true,
						},
					},
				},
				Optional: true,
				MaxItems: 1,
			},
			"ldap": {
				Type:        schema.TypeSet,
				Description: "LDAP Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua. Use '|' as a separator for multiple roles.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
							ForceNew: true,
						},
					},
				},
				Optional: true,
				MaxItems: 1,
			},
		},
	}
}

func resourceRoleMappingCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	sso, ldap, err := expandRoleMapping(d, c)
	if err != nil {
		return diag.FromErr(err)
	}
	err = c.CreateSSO(sso)
	if err != nil {
		return diag.FromErr(err)
	}

	err = c.CreateLdap(ldap)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId("aquasec-aquaRoleMapping")
	return resourceRoleMappingRead(ctx, d, m)
}

func resourceRoleMappingRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	sso, err := c.GetSSO()
	if err == nil {
		saml, ok := d.GetOk("saml")
		if ok {
			sso.Saml.RoleMapping = convertRoleMapping(saml.(*schema.Set).List()[0].(map[string]interface{}))
			d.Set("saml", flattenSamlRoleMapping(sso.Saml))
		}
		oAuth2, ok := d.GetOk("oauth2")
		if ok {
			sso.OAuth2.RoleMapping = convertRoleMapping(oAuth2.(*schema.Set).List()[0].(map[string]interface{}))
			d.Set("oauth2", flattenOAuth2RoleMapping(sso.OAuth2))
		}
		openId, ok := d.GetOk("openid")
		if ok {
			sso.OpenId.RoleMapping = convertRoleMapping(openId.(*schema.Set).List()[0].(map[string]interface{}))
			d.Set("openid", flattenOpenIdRoleMapping(sso.OpenId))
		}

		ldap, err := c.GetLdap()

		if err == nil {
			l, ok := d.GetOk("ldap")
			if ok {
				ldap.RoleMapping = convertRoleMapping(l.(*schema.Set).List()[0].(map[string]interface{}))
				d.Set("l", flattenLdapRoleMapping(ldap))
			}
		}

		d.SetId("aquasec-RoleMapping")
	} else {
		return diag.FromErr(err)
	}
	return nil
}

func resourceRoleMappingUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChanges("saml", "oauth2", "openid", "ldap") {
		c := m.(*client.Client)
		sso, ldap, err := expandRoleMapping(d, c)
		if err != nil {
			return diag.FromErr(err)
		}
		err = c.UpdateSSO(sso)
		if err != nil {
			return diag.FromErr(err)
		}

		err = c.UpdateLdap(ldap)
		if err != nil {
			return diag.FromErr(err)
		}

		d.SetId("aquasec-RoleMapping")
		return resourceRoleMappingRead(ctx, d, m)
	}
	return nil
}

func resourceRoleMappingDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	sso, err := c.GetSSO()

	if err != nil {
		return diag.FromErr(err)
	}
	// setting the sso to an empty map, because the api support only put operation
	saml, ok := d.GetOk("saml")
	if ok {
		sso.Saml.RoleMapping = splitRoleMapping(convertRoleMapping(saml.(*schema.Set).List()[0].(map[string]interface{})), sso.Saml.RoleMapping)
	}
	oAuth2, ok := d.GetOk("oauth2")
	if ok {
		sso.OAuth2.RoleMapping = splitRoleMapping(convertRoleMapping(oAuth2.(*schema.Set).List()[0].(map[string]interface{})), sso.OAuth2.RoleMapping)
	}
	openId, ok := d.GetOk("openid")
	if ok {
		sso.OpenId.RoleMapping = splitRoleMapping(convertRoleMapping(openId.(*schema.Set).List()[0].(map[string]interface{})), sso.OpenId.RoleMapping)
	}

	err = c.DeleteSSO(sso)

	if err != nil {
		return diag.FromErr(err)
	}

	ldap, err := c.GetLdap()

	if err != nil {
		return diag.FromErr(err)
	}

	l, ok := d.GetOk("ldap")

	if ok {
		ldap.RoleMapping = splitRoleMapping(convertRoleMapping(l.(*schema.Set).List()[0].(map[string]interface{})), ldap.RoleMapping)
	}

	err = c.DeleteLdap(ldap)

	if err != nil {
		return diag.FromErr(err)
	}

	if err == nil {
		d.SetId("")
	} else {
		return diag.FromErr(err)
	}

	return nil
}

func expandRoleMapping(d *schema.ResourceData, c *client.Client) (*client.SSO, *client.Ldap, error) {
	// for now we are allowing to set from terraform only role mapping all the other vars are getting from the console.
	sso, err := c.GetSSO()
	if err != nil {
		return nil, nil, err
	}

	saml, ok := d.GetOk("saml")
	if ok {
		sso.Saml.RoleMapping = joinRoleMapping(convertRoleMapping(saml.(*schema.Set).List()[0].(map[string]interface{})), sso.Saml.RoleMapping)
	}

	oauth2, ok := d.GetOk("oauth2")
	if ok {
		sso.OAuth2.RoleMapping = joinRoleMapping(convertRoleMapping(oauth2.(*schema.Set).List()[0].(map[string]interface{})), sso.OAuth2.RoleMapping)
	}

	openid, ok := d.GetOk("openid")
	if ok {
		sso.OpenId.RoleMapping = joinRoleMapping(convertRoleMapping(openid.(*schema.Set).List()[0].(map[string]interface{})), sso.OpenId.RoleMapping)
	}

	ldap, err := c.GetLdap()

	if err != nil {
		return nil, nil, err
	}

	l, ok := d.GetOk("ldap")
	if ok {
		ldap.RoleMapping = joinRoleMapping(convertRoleMapping(l.(*schema.Set).List()[0].(map[string]interface{})), ldap.RoleMapping)
	}

	return sso, ldap, nil
}
