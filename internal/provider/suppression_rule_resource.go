package provider

import (
	"context"
	"fmt"
	"strconv"

	aquasec "github.com/aquasecurity/terraform-provider-aquasec/client"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &suppressionRuleResource{}
	_ resource.ResourceWithConfigure   = &suppressionRuleResource{}
	_ resource.ResourceWithImportState = &suppressionRuleResource{}
)

// NewSuppressionRuleResource is a helper function to simplify the provider implementation.
func NewSuppressionRuleResource() resource.Resource {
	return &suppressionRuleResource{}
}

// suppressionRuleResource is the resource implementation.
type suppressionRuleResource struct {
	client *aquasec.Client
}

// suppressionRuleResourceModel maps the resource schema data.
type suppressionRuleResourceModel struct {
	ID                types.String               `tfsdk:"id"`
	Name              types.String               `tfsdk:"name"`
	ApplicationScopes []types.String             `tfsdk:"application_scopes"`
	Scope             *suppressionRuleScopeModel `tfsdk:"scope"`
	Score             []types.Int64              `tfsdk:"score"`
	Severity          types.String               `tfsdk:"severity"`
	FixAvailable      types.String               `tfsdk:"fix_available"`
	Vulnerabilities   types.String               `tfsdk:"vulnerabilities"`
	Expiry            types.Int64                `tfsdk:"expiry"`
	Comment           types.String               `tfsdk:"comment"`
	Created           types.String               `tfsdk:"created"`
	Author            types.String               `tfsdk:"author"`
	Status            types.Bool                 `tfsdk:"status"`
}

// suppressionRuleScopeModel maps suppression rule scope data.
type suppressionRuleScopeModel struct {
	Expression types.String                   `tfsdk:"expression"`
	Variables  []suppressionRuleVariableModel `tfsdk:"variables"`
}

// suppressionRuleVariableModel maps suppression rule variable data.
type suppressionRuleVariableModel struct {
	Attribute types.String `tfsdk:"attribute"`
	Value     types.String `tfsdk:"value"`
	Name      types.String `tfsdk:"name"`
}

// Metadata returns the resource type name.
func (r *suppressionRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_suppression_rule"
}

// Schema defines the schema for the resource.
func (r *suppressionRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Numeric identifier of the suppression rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the suppression rule.",
			},
			"application_scopes": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "List of application scopes for the suppression rule.",
			},
			"scope": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"expression": schema.StringAttribute{
						Optional:    true,
						Description: "Expression of the suppression rule.",
					},
					"variables": schema.ListNestedAttribute{
						Optional: true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"attribute": schema.StringAttribute{
									Required:    true,
									Description: "Attribute of the variable.",
								},
								"value": schema.StringAttribute{
									Required:    true,
									Description: "Value of the variable.",
								},
								"name": schema.StringAttribute{
									Optional:    true,
									Description: "Name of the variable.",
								},
							},
						},
					},
				},
				Optional:    true,
				Computed:    true,
				Description: "Scope of the suppression rule.",
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplace(),
				},
				Default: objectdefault.StaticValue(types.ObjectValueMust(
					map[string]attr.Type{
						"expression": types.StringType,
						"variables": types.ListType{
							ElemType: types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"attribute": types.StringType,
									"value":     types.StringType,
									"name":      types.StringType,
								},
							},
						},
					},
					map[string]attr.Value{
						"expression": attr.Value(types.StringValue("")),
						"variables": attr.Value(types.ListNull(types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"attribute": types.StringType,
								"value":     types.StringType,
								"name":      types.StringType,
							},
						})),
					}),
				),
			},
			"score": schema.ListAttribute{
				ElementType: types.Int64Type,
				Optional:    true,
				Computed:    true,
				Description: "List of scores for the suppression rule.",
				Default:     listdefault.StaticValue(types.ListValueMust(types.Int64Type, []attr.Value{})),
			},
			"severity": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Severity of the suppression rule.",
				Default:     stringdefault.StaticString(""),
			},
			"fix_available": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Fix available for the suppression rule.",
				Default:     stringdefault.StaticString("false"),
			},
			"vulnerabilities": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Vulnerabilities for the suppression rule.",
				Default:     stringdefault.StaticString(""),
			},
			"expiry": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Expiry in days of the suppression rule.",
				Default:     int64default.StaticInt64(0),
			},
			"comment": schema.StringAttribute{
				Required:    true,
				Description: "Comment for the suppression rule.",
			},
			"created": schema.StringAttribute{
				Computed:    true,
				Description: "Creation date of the suppression rule.",
			},
			"author": schema.StringAttribute{
				Computed:    true,
				Description: "Author of the suppression rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"status": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Activation status of the suppression rule.",
				Default:     booldefault.StaticBool(true),
			},
		},
		Description: "Manages a suppression rule.",
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *suppressionRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan suppressionRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan
	suppressionRule := aquasec.SuppressionRule{
		Name:            plan.Name.ValueString(),
		Score:           []int{},
		Severity:        plan.Severity.ValueString(),
		FixAvailable:    plan.FixAvailable.ValueString(),
		Vulnerabilities: plan.Vulnerabilities.ValueString(),
		Expiry:          int(plan.Expiry.ValueInt64()),
		Comment:         plan.Comment.ValueString(),
		Created:         plan.Created.ValueString(),
		Author:          plan.Author.ValueString(),
		Status:          plan.Status.ValueBool(),
	}
	for _, applicationScope := range plan.ApplicationScopes {
		suppressionRule.ApplicationScopes = append(suppressionRule.ApplicationScopes, applicationScope.ValueString())
	}
	if plan.Scope != nil {
		suppressionRule.Scope = &aquasec.Scope{
			Expression: plan.Scope.Expression.ValueString(),
		}
		for _, variable := range plan.Scope.Variables {
			suppressionRule.Scope.Variables = append(suppressionRule.Scope.Variables, aquasec.Variable{
				Attribute: variable.Attribute.ValueString(),
				Value:     variable.Value.ValueString(),
				Name:      variable.Name.ValueString(),
			})
		}
	}
	for _, score := range plan.Score {
		suppressionRule.Score = append(suppressionRule.Score, int(score.ValueInt64()))
	}

	// Create new suppression rule
	suppressionRuleID, err := r.client.CreateSuppressionRule(suppressionRule)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating suppression rule",
			"Could not create suppression rule, unexpected error: "+err.Error(),
		)
		return
	}

	// Update suppression rule status if it is false (default is true)
	if !plan.Status.ValueBool() {
		err = r.client.DisableSuppressionRule(strconv.Itoa(suppressionRuleID))
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating suppression rule status",
				"Could not update suppression rule status, unexpected error: "+err.Error(),
			)
			return
		}
	}

	fetchedSuppressionRule, err := r.client.GetSuppressionRule(strconv.Itoa(suppressionRuleID))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error fetching suppression rule",
			"Could not fetch suppression rule, unexpected error: "+err.Error(),
		)
		return
	}

	// Map response body to schema and populate Computed attribute values
	plan.ID = types.StringValue(strconv.Itoa(fetchedSuppressionRule.ID))
	plan.ApplicationScopes = []types.String{}
	plan.Scope = &suppressionRuleScopeModel{
		Expression: types.StringValue(fetchedSuppressionRule.Scope.Expression),
		Variables:  nil,
	}
	plan.Score = []types.Int64{}
	plan.Severity = types.StringValue(fetchedSuppressionRule.Severity)
	plan.FixAvailable = types.StringValue(fetchedSuppressionRule.FixAvailable)
	plan.Vulnerabilities = types.StringValue(fetchedSuppressionRule.Vulnerabilities)
	plan.Expiry = types.Int64Value(int64(fetchedSuppressionRule.Expiry))
	plan.Comment = types.StringValue(fetchedSuppressionRule.Comment)
	plan.Created = types.StringValue(fetchedSuppressionRule.Created)
	plan.Author = types.StringValue(fetchedSuppressionRule.Author)
	plan.Status = types.BoolValue(fetchedSuppressionRule.Status)

	for _, applicationScope := range fetchedSuppressionRule.ApplicationScopes {
		plan.ApplicationScopes = append(plan.ApplicationScopes, types.StringValue(applicationScope))
	}

	for _, variable := range fetchedSuppressionRule.Scope.Variables {
		variableModel := suppressionRuleVariableModel{
			Attribute: types.StringValue(variable.Attribute),
			Value:     types.StringValue(variable.Value),
		}
		if variable.Name != "" {
			variableModel.Name = types.StringValue(variable.Name)
		}
		plan.Scope.Variables = append(plan.Scope.Variables, variableModel)
	}

	for _, score := range fetchedSuppressionRule.Score {
		plan.Score = append(plan.Score, types.Int64Value(int64(score)))
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *suppressionRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state suppressionRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get refreshed suppression rule value from AquaSec
	suppressionRule, err := r.client.GetSuppressionRule(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading AquaSec Suppression Rule",
			"Could not read AquaSec suppression rule ID "+state.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	// Overwrite suppression rule with refreshed state
	state.ID = types.StringValue(strconv.Itoa(suppressionRule.ID))
	state.Name = types.StringValue(suppressionRule.Name)
	state.ApplicationScopes = []types.String{}
	state.Scope = &suppressionRuleScopeModel{
		Expression: types.StringValue(suppressionRule.Scope.Expression),
		Variables:  nil,
	}
	state.Score = []types.Int64{}
	state.Severity = types.StringValue(suppressionRule.Severity)
	state.FixAvailable = types.StringValue(suppressionRule.FixAvailable)
	state.Vulnerabilities = types.StringValue(suppressionRule.Vulnerabilities)
	state.Expiry = types.Int64Value(int64(suppressionRule.Expiry))
	state.Comment = types.StringValue(suppressionRule.Comment)
	state.Created = types.StringValue(suppressionRule.Created)
	state.Author = types.StringValue(suppressionRule.Author)
	state.Status = types.BoolValue(suppressionRule.Status)

	for _, applicationScope := range suppressionRule.ApplicationScopes {
		state.ApplicationScopes = append(state.ApplicationScopes, types.StringValue(applicationScope))
	}

	for _, variable := range suppressionRule.Scope.Variables {
		variableModel := suppressionRuleVariableModel{
			Attribute: types.StringValue(variable.Attribute),
			Value:     types.StringValue(variable.Value),
		}
		if variable.Name != "" {
			variableModel.Name = types.StringValue(variable.Name)
		}
		state.Scope.Variables = append(state.Scope.Variables, variableModel)
	}

	for _, score := range suppressionRule.Score {
		state.Score = append(state.Score, types.Int64Value(int64(score)))
	}

	// Set refreshed state
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *suppressionRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve values from plan
	var plan, prior suppressionRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	diags = req.State.Get(ctx, &prior)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan
	id, err := strconv.Atoi(plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Converting AquaSec Suppression Rule",
			"Could not convert suppression rule id, unexpected error: "+err.Error(),
		)
		return
	}

	suppressionRule := aquasec.SuppressionRule{
		ID:              id,
		Name:            plan.Name.ValueString(),
		Score:           []int{},
		Severity:        plan.Severity.ValueString(),
		FixAvailable:    plan.FixAvailable.ValueString(),
		Vulnerabilities: plan.Vulnerabilities.ValueString(),
		Expiry:          int(plan.Expiry.ValueInt64()),
		Comment:         plan.Comment.ValueString(),
		Created:         plan.Created.ValueString(),
		Author:          plan.Author.ValueString(),
		Status:          plan.Status.ValueBool(),
	}
	for _, applicationScope := range plan.ApplicationScopes {
		suppressionRule.ApplicationScopes = append(suppressionRule.ApplicationScopes, applicationScope.ValueString())
	}
	if plan.Scope != nil {
		suppressionRule.Scope = &aquasec.Scope{
			Expression: plan.Scope.Expression.ValueString(),
		}
		for _, variable := range plan.Scope.Variables {
			suppressionRule.Scope.Variables = append(suppressionRule.Scope.Variables, aquasec.Variable{
				Attribute: variable.Attribute.ValueString(),
				Value:     variable.Value.ValueString(),
				Name:      variable.Name.ValueString(),
			})
		}
	}
	for _, score := range plan.Score {
		suppressionRule.Score = append(suppressionRule.Score, int(score.ValueInt64()))
	}

	// Update existing suppression rule
	err = r.client.UpdateSuppressionRule(suppressionRule)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating suppression rule",
			"Could not update suppression rule, unexpected error: "+err.Error(),
		)
		return
	}

	// Update suppression rule status if it has changed
	if plan.Status.ValueBool() != prior.Status.ValueBool() {
		if plan.Status.ValueBool() {
			err = r.client.ActivateSuppressionRule(plan.ID.ValueString())
		} else {
			err = r.client.DisableSuppressionRule(plan.ID.ValueString())
		}
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating suppression rule status",
				"Could not update suppression rule status, unexpected error: "+err.Error(),
			)
			return
		}
	}

	// Fetch updated items from GetSuppressionRule as UpdateSuppressionRule does not return updated data
	fetchedSuppressionRule, err := r.client.GetSuppressionRule(plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error fetching suppression rule",
			"Could not fetch suppression rule, unexpected error: "+err.Error(),
		)
		return
	}

	// Update resource state with updated suppression rule
	plan.ID = types.StringValue(strconv.Itoa(fetchedSuppressionRule.ID))
	plan.ApplicationScopes = []types.String{}
	plan.Scope = &suppressionRuleScopeModel{
		Expression: types.StringValue(fetchedSuppressionRule.Scope.Expression),
		Variables:  nil,
	}
	plan.Score = []types.Int64{}
	plan.Severity = types.StringValue(fetchedSuppressionRule.Severity)
	plan.FixAvailable = types.StringValue(fetchedSuppressionRule.FixAvailable)
	plan.Vulnerabilities = types.StringValue(fetchedSuppressionRule.Vulnerabilities)
	plan.Expiry = types.Int64Value(int64(fetchedSuppressionRule.Expiry))
	plan.Comment = types.StringValue(fetchedSuppressionRule.Comment)
	plan.Created = types.StringValue(fetchedSuppressionRule.Created)
	plan.Author = types.StringValue(fetchedSuppressionRule.Author)
	plan.Status = types.BoolValue(fetchedSuppressionRule.Status)

	for _, applicationScope := range fetchedSuppressionRule.ApplicationScopes {
		plan.ApplicationScopes = append(plan.ApplicationScopes, types.StringValue(applicationScope))
	}

	for _, variable := range fetchedSuppressionRule.Scope.Variables {
		variableModel := suppressionRuleVariableModel{
			Attribute: types.StringValue(variable.Attribute),
			Value:     types.StringValue(variable.Value),
		}
		if variable.Name != "" {
			variableModel.Name = types.StringValue(variable.Name)
		}
		plan.Scope.Variables = append(plan.Scope.Variables, variableModel)
	}

	for _, score := range fetchedSuppressionRule.Score {
		plan.Score = append(plan.Score, types.Int64Value(int64(score)))
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *suppressionRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve values from state
	var state suppressionRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing suppression rule
	err := r.client.DeleteSuppressionRule(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting suppression rule",
			"Could not delete suppression rule, unexpected error: "+err.Error(),
		)
		return
	}
}

// Configure adds the provider configured client to the resource.
func (r *suppressionRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*aquasec.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *aquasec.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

func (r *suppressionRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Retrieve import ID andn save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
