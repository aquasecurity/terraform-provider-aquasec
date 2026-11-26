package aquasec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

var (
	titlePattern         = regexp.MustCompile(`^[ A-Za-z0-9()',&=\[\]"/-]{1,255}$`)
	freeTextPattern      = regexp.MustCompile(`^[ A-Za-z0-9._~()'!*:@,;+?#$%&=\[\]"/-]+$`)
	multilineTextPattern = regexp.MustCompile("^[ \\n\\r`A-Za-z0-9._~()'!*:@,;+?#$%&=\\[\\]\"/-]+$")
	customIDPattern      = regexp.MustCompile(`^[ A-Za-z0-9._~()'!*:@,;+?#$%&=\[\]"/-]{1,255}$`)
	severityPattern      = regexp.MustCompile(`^[a-zA-Z0-9_:,-]{1,250}$`)
	apiNamePattern       = regexp.MustCompile(`^[a-z0-9A-Z_:]{5,100}$`)
)

var validOperators = map[string]bool{
	"EQ": true, "NE": true, "GT": true, "LT": true, "GTE": true, "LTE": true,
	"IN": true, "NOT_IN": true, "MATCHES": true, "NOTMATCHES": true,
	"LIKE": true, "STARTS_WITH": true, "ENDS_WITH": true,
	"CONTAINS": true, "NOTCONTAINS": true, "EXISTS": true, "NOT_EXISTS": true,
	"ISTRUE": true, "ISFALSE": true, "ISEMPTY": true, "NOTEMPTY": true,
}

var validTransforms = map[string]bool{
	"NONE": true, "STRING": true, "INTEGER": true, "DATE": true,
	"DAYSFROM": true, "MONTHS_FROM": true, "MINUTES_FROM": true, "HOURS_FROM": true,
	"COUNT": true, "EACH": true, "TO_LOWERCASE": true, "IPRANGE": true,
}

var valuelessOps = map[string]bool{
	"EXISTS": true, "NOT_EXISTS": true, "ISTRUE": true, "ISFALSE": true,
	"ISEMPTY": true, "NOTEMPTY": true,
}
var setOps = map[string]bool{"IN": true, "NOT_IN": true}

var booleanFuncs = map[string]bool{
	"isPublic": true, "isKeyCustomerManaged": true, "isScopePublic": true,
	"isPublicCIDR": true, "isPrivateCIDR": true, "isCIDR": true,
	"isSecurityGroupReference": true, "uniqueExecutionRole": true,
	"getResources": true, "getResource": true,
	"isSecurityGroupInUse": true,
}

var numericFuncs = map[string]bool{
	"dateDifference": true, "numberOfHosts": true,
}

var validQuantifiers = map[string]bool{
	"ANY": true, "ALL": true, "NONE": true,
}

const freeTextErrMsg = `must contain only letters, digits, spaces, or one of: . _ ~ ( ) ' ! * : @ , ; + ? # $ % & = [ ] " / -`

func resourceCspmPlugin() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages an Aqua CSPM custom plugin (custom rule).",
		CreateContext: resourceCspmPluginCreate,
		ReadContext:   resourceCspmPluginRead,
		UpdateContext: resourceCspmPluginUpdate,
		DeleteContext: resourceCspmPluginDelete,

		Schema: map[string]*schema.Schema{
			"cloud": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"aws", "azure", "google", "oracle"}, false),
			},
			"title": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.All(
					validation.StringMatch(titlePattern, `must be 1-255 characters of letters, digits, spaces, or one of: ( ) ' , & = [ ] " / -`),
				),
			},
			"description": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(1, 2048),
					validation.StringMatch(multilineTextPattern, freeTextErrMsg),
				),
			},
			"more_info": {
				Type:     schema.TypeString,
				Optional: true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(1, 512),
					validation.StringMatch(multilineTextPattern, freeTextErrMsg),
				),
			},
			"recommended_action": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(1, 16383),
					validation.StringMatch(multilineTextPattern, freeTextErrMsg),
				),
			},
			"link": {
				Type:     schema.TypeString,
				Optional: true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(1, 255),
					validation.StringMatch(freeTextPattern, freeTextErrMsg),
				),
			},
			"severity": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Free-form severity string (e.g. Low, Medium, High). Note: the API normalizes this to lowercase.",
				ValidateFunc: validation.StringMatch(
					severityPattern,
					"must be 1-250 characters of letters, digits, or one of: _ : , -",
				),
			},
			"category_id": {
				Type:         schema.TypeInt,
				Required:     true,
				Description:  "Aqua CSPM category ID. Use the categories endpoint to list available IDs.",
				ValidateFunc: validation.IntBetween(1, 99999999999),
			},
			"custom_id": {
				Type:     schema.TypeString,
				Optional: true,
				ValidateFunc: validation.StringMatch(
					customIDPattern,
					`must be 1-255 characters of letters, digits, or one of: . _ ~ ( ) ' ! * : @ , ; + ? # $ % & = [ ] " / -`,
				),
			},
			"asl": {
				Type:        schema.TypeList,
				Required:    true,
				MaxItems:    1,
				Description: "Aqua Security Language — the plugin's check logic.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"version": {
							Type:         schema.TypeInt,
							Optional:     true,
							Default:      2,
							Description:  "ASL version. The v2 endpoint requires 2; defaults to 2 if omitted.",
							ValidateFunc: validation.IntInSlice([]int{2}),
						},
						"apis": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of cloud APIs to query (e.g. s3:getBucketTagging). No upper limit.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
								ValidateFunc: validation.StringMatch(
									apiNamePattern,
									"each API must be 5-100 characters of letters, digits, or colons (e.g. s3:getBucketTagging)",
								),
							},
						},
						"target_resource": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The service:api whose records the rule is applied to. Must be one of apis.",
							ValidateFunc: validation.StringMatch(
								apiNamePattern,
								"must be 5-100 characters of letters, digits, or colons (e.g. s3:listBuckets)",
							),
						},
						"conditions": {
							Type:             schema.TypeString,
							Required:         true,
							Description:      "ASL condition tree as JSON (a single node, or a flat array of condition leaves). Use jsonencode(...).",
							ValidateFunc:     validateASLNodeString,
							DiffSuppressFunc: suppressEquivalentJSON,
						},
						"scope": {
							Type:             schema.TypeString,
							Optional:         true,
							Description:      "Optional pre-filter (a single ASL node) as JSON. Use jsonencode(...).",
							ValidateFunc:     validateASLNodeString,
							DiffSuppressFunc: suppressEquivalentJSON,
						},
					},
				},
			},
		},
	}
}

func resourceCspmPluginCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	asl, err := buildASLFromData(d)
	if err != nil {
		return diag.FromErr(err)
	}

	pluginReq := client.Plugin{
		Cloud:             d.Get("cloud").(string),
		Title:             d.Get("title").(string),
		Description:       d.Get("description").(string),
		Severity:          d.Get("severity").(string),
		RecommendedAction: d.Get("recommended_action").(string),
		Link:              d.Get("link").(string),
		MoreInfo:          d.Get("more_info").(string),
		CategoryID:        d.Get("category_id").(int),
		CustomID:          d.Get("custom_id").(string),
		ASL:               asl,
	}

	created, err := c.CreatePlugin(pluginReq)
	if err != nil {
		return diag.Errorf("Failed to create plugin: %s", err)
	}

	d.SetId(strconv.Itoa(created.ID))

	return resourceCspmPluginRead(ctx, d, m)
}

func resourceCspmPluginRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	var diags diag.Diagnostics

	id, err := strconv.Atoi(d.Id())
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return diag.Errorf("Invalid plugin ID in state: %s", err)
	}

	plugin, err := c.GetPlugin(id)
	if err != nil {
		return diag.Errorf("Failed to read plugin: %s", err)
	}
	if plugin == nil {
		d.SetId("")
		return diags
	}

	d.Set("cloud", plugin.Cloud)
	d.Set("title", plugin.Title)
	d.Set("description", plugin.Description)
	d.Set("severity", strings.ToLower(plugin.EffectiveSeverity()))
	d.Set("recommended_action", plugin.RecommendedAction)
	d.Set("link", plugin.Link)
	d.Set("more_info", plugin.MoreInfo)
	d.Set("category_id", plugin.CategoryID)
	d.Set("custom_id", plugin.CustomID)

	if err := d.Set("asl", flattenASL(plugin.ASL)); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func resourceCspmPluginUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	id, err := strconv.Atoi(d.Id())
	if err != nil {
		return diag.Errorf("Invalid plugin ID in state: %s", err)
	}

	asl, err := buildASLFromData(d)
	if err != nil {
		return diag.FromErr(err)
	}

	pluginReq := &client.Plugin{
		ID:                id,
		Title:             d.Get("title").(string),
		Description:       d.Get("description").(string),
		RecommendedAction: d.Get("recommended_action").(string),
		Link:              d.Get("link").(string),
		MoreInfo:          d.Get("more_info").(string),
		CategoryID:        d.Get("category_id").(int),
		CustomID:          d.Get("custom_id").(string),
		ASL:               asl,
	}

	err = c.UpdatePlugin(pluginReq)
	if err != nil {
		return diag.Errorf("Failed to update plugin: %s", err)
	}

	err = c.UpdatePluginSeverity(id, d.Get("severity").(string))
	if err != nil {
		return diag.Errorf("Failed to update severity: %s", err)
	}

	return resourceCspmPluginRead(ctx, d, m)
}

func resourceCspmPluginDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	var diags diag.Diagnostics

	id, err := strconv.Atoi(d.Id())
	if err != nil {
		return diag.Errorf("Invalid plugin ID in state: %s", err)
	}

	err = c.DeletePlugin(id)
	if err != nil {
		return diag.Errorf("Failed to delete plugin: %s", err)
	}

	d.SetId("")
	return diags
}

// ----------------------------------------------------------------------------
// Helpers and Validators
// ----------------------------------------------------------------------------

func buildASLFromData(d *schema.ResourceData) (*client.ASL, error) {
	aslList := d.Get("asl").([]interface{})
	if len(aslList) == 0 || aslList[0] == nil {
		return nil, fmt.Errorf("an ASL block must be defined")
	}

	aslMap := aslList[0].(map[string]interface{})

	var version *int
	if v, ok := aslMap["version"].(int); ok && v > 0 {
		version = &v
	}

	var apis []string
	if apiList, ok := aslMap["apis"].([]interface{}); ok {
		for _, a := range apiList {
			apis = append(apis, a.(string))
		}
	}

	targetResource := aslMap["target_resource"].(string)
	if !containsString(apis, targetResource) {
		return nil, fmt.Errorf("ASL api not declared: targetResource references api %q which is not listed in asl.apis", targetResource)
	}

	var conditions json.RawMessage
	if cs, ok := aslMap["conditions"].(string); ok && cs != "" {
		conditions = json.RawMessage(cs)
	}

	var scope json.RawMessage
	if sc, ok := aslMap["scope"].(string); ok && sc != "" {
		scope = json.RawMessage(sc)
		// Validate APIs referenced in scope are present in the 'apis' list
		for _, ref := range collectConditionAPIs(scope) {
			if !containsString(apis, ref) {
				return nil, fmt.Errorf("ASL api not declared: scope references api %q which is not listed in asl.apis", ref)
			}
		}
	}

	// Validate APIs referenced in conditions are present in the 'apis' list
	for _, ref := range collectConditionAPIs(conditions) {
		if !containsString(apis, ref) {
			return nil, fmt.Errorf("ASL api not declared: condition references api %q which is not listed in asl.apis", ref)
		}
	}

	return &client.ASL{
		Version:        version,
		APIs:           apis,
		TargetResource: targetResource,
		Conditions:     conditions,
		Scope:          scope,
	}, nil
}

func flattenASL(asl *client.ASL) []interface{} {
	if asl == nil {
		return nil
	}

	m := make(map[string]interface{})

	if asl.Version != nil {
		m["version"] = *asl.Version
	}
	m["apis"] = asl.APIs
	m["target_resource"] = asl.TargetResource

	if len(asl.Conditions) > 0 {
		m["conditions"] = string(asl.Conditions)
	}
	if len(asl.Scope) > 0 {
		m["scope"] = string(asl.Scope)
	}

	return []interface{}{m}
}

// Equivalent to `jsontypes.NormalizedType{}` functionality to suppress whitespace/ordering Diffs
func suppressEquivalentJSON(k, old, new string, d *schema.ResourceData) bool {
	if old == new {
		return true
	}
	var o, n interface{}
	if err := json.Unmarshal([]byte(old), &o); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(new), &n); err != nil {
		return false
	}
	return reflect.DeepEqual(o, n)
}

func validateASLNodeString(val interface{}, key string) (warns []string, errs []error) {
	v, ok := val.(string)
	if !ok || v == "" {
		return warns, errs
	}
	raw := json.RawMessage(v)
	msgs := validateASLRoot(raw)
	for _, msg := range msgs {
		errs = append(errs, fmt.Errorf("Invalid ASL: %s", msg))
	}
	return warns, errs
}

// ----------------------------------------------------------------------------
// Unchanged underlying raw validation logic
// ----------------------------------------------------------------------------

func validateASLRoot(raw json.RawMessage) []string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []string{"conditions/scope must not be empty"}
	}
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return []string{fmt.Sprintf("not valid JSON array: %v", err)}
		}
		if len(arr) < 1 || len(arr) > 25 {
			return []string{fmt.Sprintf("flat conditions array must have 1..25 items, has %d", len(arr))}
		}
		var errs []string
		for i, el := range arr {
			errs = append(errs, validateASLNode(fmt.Sprintf("[%d]", i), el)...)
		}
		return errs
	}
	return validateASLNode("$", raw)
}

func validateASLNode(path string, raw json.RawMessage) []string {
	var base struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &base); err != nil {
		return []string{fmt.Sprintf("%s: not a valid JSON object: %v", path, err)}
	}

	switch base.Type {
	case "condition":
		return validateConditionNode(path, raw)
	case "tag":
		return validateTagNode(path, raw)
	case "group":
		return validateGroupNode(path, raw)
	case "function":
		return validateFunctionNode(path, raw)
	case "element":
		return validateElementNode(path, raw)
	case "":
		return []string{fmt.Sprintf("%s: missing \"type\" (must be condition, tag, group, function or element)", path)}
	default:
		return []string{fmt.Sprintf("%s: unknown type %q (must be condition, tag, group, function or element)", path, base.Type)}
	}
}

func validateConditionNode(path string, raw json.RawMessage) []string {
	var c struct {
		Property  string          `json:"property"`
		Op        string          `json:"op"`
		Transform string          `json:"transform"`
		Value     json.RawMessage `json:"value"`
	}
	_ = json.Unmarshal(raw, &c)

	var errs []string
	if c.Property == "" {
		errs = append(errs, path+": condition is missing \"property\"")
	}
	if c.Op == "" {
		errs = append(errs, path+": condition is missing \"op\"")
	} else if !validOperators[c.Op] {
		errs = append(errs, fmt.Sprintf("%s: unsupported operator %q", path, c.Op))
	}
	if c.Transform != "" && !validTransforms[c.Transform] {
		errs = append(errs, fmt.Sprintf("%s: unsupported transform %q", path, c.Transform))
	}

	if c.Op != "" && validOperators[c.Op] {
		errs = append(errs, validateValueShape(path, c.Op, c.Value)...)
	}
	return errs
}

func validateTagNode(path string, raw json.RawMessage) []string {
	var t struct {
		Operator string `json:"operator"`
		Key      *struct {
			Op string `json:"op"`
		} `json:"key"`
		Values []struct {
			Op string `json:"op"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return []string{fmt.Sprintf("%s: invalid tag node: %v", path, err)}
	}
	var errs []string
	if t.Operator != "" && t.Operator != "AND" && t.Operator != "OR" {
		errs = append(errs, fmt.Sprintf("%s: tag operator must be AND or OR, got %q", path, t.Operator))
	}
	if t.Key == nil {
		errs = append(errs, path+": tag is missing \"key\"")
	} else if t.Key.Op != "" && !validOperators[t.Key.Op] {
		errs = append(errs, fmt.Sprintf("%s.key: unsupported operator %q", path, t.Key.Op))
	}
	if len(t.Values) == 0 {
		errs = append(errs, path+": tag is missing \"values\"")
	}
	for i, val := range t.Values {
		if val.Op != "" && !validOperators[val.Op] {
			errs = append(errs, fmt.Sprintf("%s.values[%d]: unsupported operator %q", path, i, val.Op))
		}
	}
	return errs
}

func validateGroupNode(path string, raw json.RawMessage) []string {
	var g struct {
		Operator   string            `json:"operator"`
		Conditions []json.RawMessage `json:"conditions"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return []string{fmt.Sprintf("%s: invalid group node: %v", path, err)}
	}
	var errs []string
	if g.Operator != "AND" && g.Operator != "OR" {
		errs = append(errs, fmt.Sprintf("%s: group operator must be AND or OR, got %q", path, g.Operator))
	}
	if len(g.Conditions) < 1 || len(g.Conditions) > 25 {
		errs = append(errs, fmt.Sprintf("%s: group must have 1..25 conditions, has %d", path, len(g.Conditions)))
	}
	for i, child := range g.Conditions {
		errs = append(errs, validateASLNode(fmt.Sprintf("%s.conditions[%d]", path, i), child)...)
	}
	return errs
}

func validateValueShape(path, op string, value json.RawMessage) []string {
	present, isArray, isString := classifyValue(value)
	switch {
	case valuelessOps[op]:
		if present {
			return []string{fmt.Sprintf("%s: operator %s must not have a \"value\"", path, op)}
		}
	case setOps[op]:
		if !present || !isArray {
			return []string{fmt.Sprintf("%s: operator %s requires an array \"value\"", path, op)}
		}
	default:
		if present && !isString {
			return []string{fmt.Sprintf("%s: operator %s requires a single string \"value\"", path, op)}
		}
	}
	return nil
}

func validateFunctionNode(path string, raw json.RawMessage) []string {
	var f struct {
		Fn    string          `json:"fn"`
		Op    string          `json:"op"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return []string{fmt.Sprintf("%s: invalid function node: %v", path, err)}
	}
	var errs []string
	if f.Fn == "" {
		return []string{path + ": function is missing \"fn\""}
	}
	isBool := booleanFuncs[f.Fn]
	isNum := numericFuncs[f.Fn]
	if !isBool && !isNum {
		return []string{fmt.Sprintf("%s: unsupported function %q", path, f.Fn)}
	}
	present, _, _ := classifyValue(f.Value)
	if isBool {
		if f.Op != "" {
			errs = append(errs, fmt.Sprintf("%s: boolean function %s must not have an \"op\"", path, f.Fn))
		}
		if present {
			errs = append(errs, fmt.Sprintf("%s: boolean function %s must not have a \"value\"", path, f.Fn))
		}
	} else {
		if f.Op == "" {
			errs = append(errs, fmt.Sprintf("%s: numeric function %s requires an \"op\"", path, f.Fn))
		} else if !validOperators[f.Op] {
			errs = append(errs, fmt.Sprintf("%s: unsupported operator %q", path, f.Op))
		}
		if !present {
			errs = append(errs, fmt.Sprintf("%s: numeric function %s requires a numeric \"value\"", path, f.Fn))
		}
	}
	return errs
}

func validateElementNode(path string, raw json.RawMessage) []string {
	var e struct {
		Property   string          `json:"property"`
		Quantifier string          `json:"quantifier"`
		Where      json.RawMessage `json:"where"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return []string{fmt.Sprintf("%s: invalid element node: %v", path, err)}
	}
	var errs []string
	if e.Property == "" {
		errs = append(errs, path+": element is missing \"property\"")
	}
	if e.Quantifier == "" {
		errs = append(errs, path+": element is missing \"quantifier\"")
	} else if !validQuantifiers[e.Quantifier] {
		errs = append(errs, fmt.Sprintf("%s: quantifier must be ANY, ALL or NONE, got %q", path, e.Quantifier))
	}
	if len(bytes.TrimSpace(e.Where)) == 0 {
		errs = append(errs, path+": element is missing \"where\"")
	} else {
		errs = append(errs, validateASLNode(path+".where", e.Where)...)
	}
	return errs
}

func classifyValue(raw json.RawMessage) (present, isArray, isString bool) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" {
		return false, false, false
	}
	switch t[0] {
	case '[':
		return true, true, false
	case '"':
		return true, false, true
	default:
		return true, false, false
	}
}

func collectConditionAPIs(raw json.RawMessage) []string {
	var out []string
	var walk func(json.RawMessage)
	walk = func(r json.RawMessage) {
		t := bytes.TrimSpace(r)
		if len(t) == 0 {
			return
		}
		if t[0] == '[' {
			var arr []json.RawMessage
			if json.Unmarshal(r, &arr) == nil {
				for _, e := range arr {
					walk(e)
				}
			}
			return
		}
		var node struct {
			API        string            `json:"api"`
			Conditions []json.RawMessage `json:"conditions"`
		}
		if json.Unmarshal(r, &node) == nil {
			if node.API != "" {
				out = append(out, node.API)
			}
			for _, c := range node.Conditions {
				walk(c)
			}
		}
	}
	walk(raw)
	return out
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
