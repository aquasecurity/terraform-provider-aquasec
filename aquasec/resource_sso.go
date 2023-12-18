package aquasec

import (
	"context"
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strings"
)

func resourceSSO() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSSOCreate,
		ReadContext:   resourceSSORead,
		UpdateContext: resourceSSOUpdate,
		DeleteContext: resourceSSODelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"saml": {
				Type:        schema.TypeSet,
				Description: "SAML Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"aqua_creds_enable": {
							Type:        schema.TypeBool,
							Description: "aqua_creds_enable.",
							Computed:    true,
						},
						"aqua_sso_url": {
							Type:        schema.TypeString,
							Description: "The URL for your Aqua Server. This should be in the form https://<AQUA_SERVER_NAME>/api/v1/saml_auth.",
							Computed:    true,
						},
						"auth_by_role": {
							Type:        schema.TypeBool,
							Description: "If true, authorize by role.",
							Computed:    true,
						},
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Enabled SAML Authentication.",
							Computed:    true,
						},
						"identity_provider_issuer": {
							Type:        schema.TypeString,
							Description: "Identity Provider Issuer.",
							Computed:    true,
						},
						"identity_provider_logout_url": {
							Type:        schema.TypeString,
							Description: "Identity Provider Single Sign-On logout URL.",
							Computed:    true,
						},
						"identity_provider_sso_url": {
							Type:        schema.TypeString,
							Description: "Identity Provider Single Sign-On URL.",
							Computed:    true,
						},
						"aqua_sso_logout_url": {
							Type:        schema.TypeString,
							Description: "Logout URL.",
							Computed:    true,
						},
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
						},
						"signed_request": {
							Type:        schema.TypeBool,
							Description: "signed request.",
							Computed:    true,
						},
						"slo_enabled": {
							Type:        schema.TypeBool,
							Description: "If set to true, single logout (SLO) is enabled.",
							Computed:    true,
						},
						"service_provider_issuer": {
							Type:        schema.TypeString,
							Description: "Service provider issuer, this should be aquasec.com.",
							Computed:    true,
						},
						"sso_enable": {
							Type:        schema.TypeBool,
							Description: "Show SSO button on Login.",
							Computed:    true,
						},
						"token_provided": {
							Type:        schema.TypeBool,
							Description: "token provided.",
							Computed:    true,
						},
						"user_login_id": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the user.",
							Computed:    true,
						},
						"user_role": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the role",
							Computed:    true,
						},
						"x509cert": {
							Type:        schema.TypeString,
							Description: "x509cert.",
							Computed:    true,
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
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Enabled OAuth2 Authentication.",
							Computed:    true,
						},
						"identity_provider_issuer": {
							Type:        schema.TypeString,
							Description: "Identity provider issuer.",
							Computed:    true,
						},
						"json_web_key_set_url": {
							Type:        schema.TypeString,
							Description: "Enter the JWKS_URI URL as defined in the authorization server configuration.",
							Computed:    true,
						},
						"user_role": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the role.",
							Computed:    true,
						},
						"user_login_id": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the user.",
							Computed:    true,
						},
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
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
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Enabled OpenId Authentication.",
							Computed:    true,
						},
						"provider_name": {
							Type:        schema.TypeString,
							Description: "Provider name.",
							Computed:    true,
						},
						"consumer_secret": {
							Type:        schema.TypeString,
							Description: "Enter the Client Secret from your provider as defined in your OpenID provider configuration.",
							Computed:    true,
						},
						"consumer_key": {
							Type:        schema.TypeString,
							Description: "Enter the Client ID from your provider as defined in your OpenID provider configuration.",
							Computed:    true,
						},
						"aqua_redirect_endpoint": {
							Type:        schema.TypeString,
							Description: "Enter the Redirect Endpoint, For example: https://<aqua_server_name:port>/api/v2/oidc/callback.",
							Computed:    true,
						},
						"identity_provider_issuer_url": {
							Type:        schema.TypeString,
							Description: "Enter the Issuer URI as defined in the OpenID provider configuration.",
							Computed:    true,
						},
						"scope": {
							Type:        schema.TypeList,
							Description: "Application Scopes.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"user_role": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the role.",
							Computed:    true,
						},
						"user_login_id": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the user.",
							Computed:    true,
						},
						"auth_by_role": {
							Type:        schema.TypeBool,
							Description: "If true, authorize by role",
							Computed:    true,
						},
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
						},
					},
				},
				Optional: true,
				MaxItems: 1,
			},
		},
	}
}

func resourceSSOCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	sso, err := expandSSO(d, c)
	if err != nil {
		return diag.FromErr(err)
	}
	err = c.CreateSSO(sso)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("aquasec-sso")
	//return nil
	return resourceSSORead(ctx, d, m)
}

func resourceSSORead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	sso, err := c.GetSSO()
	if err == nil {
		saml, ok := d.GetOk("saml")
		if ok {
			sso.Saml.RoleMapping = convertRoleMapping(saml.(*schema.Set).List()[0].(map[string]interface{}))
			d.Set("saml", flattenSaml(sso.Saml))
		}
		oAuth2, ok := d.GetOk("oauth2")
		if ok {
			sso.OAuth2.RoleMapping = convertRoleMapping(oAuth2.(*schema.Set).List()[0].(map[string]interface{}))
			d.Set("oauth2", flattenOAuth2(sso.OAuth2))
		}
		openId, ok := d.GetOk("openid")
		if ok {
			sso.OpenId.RoleMapping = convertRoleMapping(openId.(*schema.Set).List()[0].(map[string]interface{}))
			d.Set("openid", flattenOpenId(sso.OpenId))
		}
		d.SetId("aquasec-sso")
	} else {
		return diag.FromErr(err)
	}
	return nil
}

func resourceSSOUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChanges("saml", "oauth2", "openid") {
		c := m.(*client.Client)
		sso, err := expandSSO(d, c)
		if err != nil {
			return diag.FromErr(err)
		}
		err = c.UpdateSSO(sso)
		if err != nil {
			return diag.FromErr(err)
		}
		d.SetId("aquasec-sso")
		return resourceSSORead(ctx, d, m)
	}

	return nil
}

func resourceSSODelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	sso, err := c.GetSSO()

	if err != nil {
		return diag.FromErr(err)
	}
	// setting the roleMapping to an empty map, because the api support only put operation
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
	if err == nil {
		d.SetId("")
	} else {
		return diag.FromErr(err)
	}

	return nil
}

func expandSSO(d *schema.ResourceData, c *client.Client) (*client.SSO, error) {
	// for now we are allowing to set from terraform only role mapping all the other vars are getting from the console.
	sso, err := c.GetSSO()
	if err != nil {
		return nil, err
	}

	saml, ok := d.GetOk("saml")
	if ok {
		sso.Saml.RoleMapping = joinRoleMapping(convertRoleMapping(saml.(*schema.Set).List()[0].(map[string]interface{})), sso.Saml.RoleMapping)
	} else {
	}

	oauth2, ok := d.GetOk("oauth2")
	if ok {
		sso.OAuth2.RoleMapping = joinRoleMapping(convertRoleMapping(oauth2.(*schema.Set).List()[0].(map[string]interface{})), sso.OAuth2.RoleMapping)
	}

	openid, ok := d.GetOk("openid")
	if ok {
		sso.OpenId.RoleMapping = joinRoleMapping(convertRoleMapping(openid.(*schema.Set).List()[0].(map[string]interface{})), sso.OpenId.RoleMapping)
	}

	return sso, nil
}

func convertRoleMapping(m map[string]interface{}) map[string][]string {
	roleMapping := make(map[string][]string)

	if len(m["role_mapping"].(map[string]interface{})) > 0 {
		for key, element := range m["role_mapping"].(map[string]interface{}) {
			elementArry := strings.Split(element.(string), "|")
			roleMapping[key] = elementArry
		}
	}
	return roleMapping
}

func joinRoleMapping(m1, m2 map[string][]string) map[string][]string {
	for k, v := range m2 {
		tmpMapValues := strings.Join(m1[k], ",")
		if _, ok := m1[k]; ok {
			for _, value := range v {
				if !strings.Contains(tmpMapValues, value) {
					tmpMapValues += fmt.Sprintf(", %s", value)
				}
			}
			m1[k] = strings.Split(tmpMapValues, ",")
		} else {
			m1[k] = v
		}
	}
	return m1
}

func splitRoleMapping(m1, m2 map[string][]string) map[string][]string {
	newArr := make(map[string][]string)
	for k, v := range m2 {

		if value, ok := m1[k]; ok {
			tmpMapValues := strings.Join(m1[k], ",")
			if len(value) != len(v) {
				for i, s := range v {
					if strings.Contains(tmpMapValues, s) {
						v = append(v[:i], v[i+1:]...)
					}
				}
				newArr[k] = v
			}
		} else {
			newArr[k] = v
		}
	}
	return newArr
}
