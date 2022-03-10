package aquasec

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceApplicationScope() *schema.Resource {
	return &schema.Resource{
		Create: resourceApplicationScopeCreate,
		Read:   resourceApplicationScopeRead,
		Update: resourceApplicationScopeUpdate,
		Delete: resourceApplicationScopeDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"author": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"owner_email": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"categories": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"artifacts": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"image": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"function": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"cf": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
						"entity_scope": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"expression": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"variables": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"attribute": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
												"value": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
											},
										},
									},
								},
							},
						},
						"workloads": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"kubernetes": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"os": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"cf": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
						"infrastructure": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"os": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"cf": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func resourceApplicationScopeCreate(d *schema.ResourceData, m interface{}) error {

	/*if ok && categories.(*schema.Set).Len() > 0 {

		categoryentries := categories.(map[string]interface{})
		artifactentries := categoryentries["artifacts"].([]interface{})
		workloadentries := categoryentries["workloads"].([]interface{})
		infrastructureentries := categoryentries["infrastructure"].([]interface{})
		artifactarray := make([]client.Artifact, len(artifactentries))
		for i, data := range artifactentries {
			imagelist := data.(map[string]interface{})

		}


		VariablesList := scopeentries["variables"].([]interface{})
			variablearray := make([]client.VariableI, len(VariablesList))
			for i, Data := range VariablesList {
				varLists := Data.(map[string]interface{})
				VarData := client.VariableI{
					Attribute: varLists["attribute"].(string),
					Name:      varLists["name"].(string),
					Value:     varLists["value"].(string),
				}
				variablearray[i] = VarData
			}

		categoryStruct1 := client.Category{
			Artifacts:      artifactarray,
			Workloads:      workloadarray,
			Infrastructure: infrastructurearray,
		}
		iap.Categories = categoryStruct1

	}*/

	ac := m.(*client.Client)
	name := d.Get("name").(string)
	iap, err1 := expandApplicationScope(d)
	if err1 != nil {
		return fmt.Errorf("expanding applications is failed with error: %v", err1)
	}
	err := ac.CreateApplicationScope(iap)

	if err == nil {
		err1 := resourceApplicationScopeRead(d, m)
		if err1 == nil {
			d.SetId(name)
		} else {
			return fmt.Errorf("application scope resource read is failed with error: %v", err1)
		}
	} else {
		return fmt.Errorf("application scope resource create is failed with error:  %v", err)
	}

	return nil
}

func expandApplicationScope(d *schema.ResourceData) (*client.ApplicationScope, error) {

	var err error
	iap := client.ApplicationScope{
		Name: d.Get("name").(string),
	}

	description, ok := d.GetOk("description")
	if ok {
		iap.Description = description.(string)
	}

	author, ok := d.GetOk("author")
	if ok {
		iap.Author = author.(string)
	}

	owner_email, ok := d.GetOk("owner_email")
	if ok {
		iap.OwnerEmail = owner_email.(string)
	}

	/*image, ok := d.GetOk("image")
	if ok {
		j, err := json.Marshal(image)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreate1z: Failed to get applicationScope, %v and %v", err, j)
		}
		var imageStruct client.Image
		err = json.Unmarshal(j, &imageStruct)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreatez: Failed to get applicationScope, %v and %v", err, j)
		}
		iap.Categories.Artifacts.Image = imageStruct
	}*/

	/*variables, ok := d.GetOk("variables")
	if ok {
		label := make([]map[string]interface{}, len(labels))
		for i := range variables {
			label[i] := map[string]interface{}{
			fmt.Println(label[i].Key),

			}
		}

	}*/

	image, ok := d.GetOk("category.artifact.image")
	if ok {
		j, err := json.Marshal(image)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreate1a: Failed to get applicationScope, %v and %v", err, j)
		}
		var imageStruct client.CommonStruct
		err = json.Unmarshal(j, &imageStruct)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreatea: Failed to get applicationScope, %v and %v", err, j)
		}
		iap.Categories.Artifacts.Image = imageStruct
	}

	categories, ok := d.GetOk("categories")
	if ok {
		j, err := json.Marshal(categories)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreate1z: Failed to get applicationScope, %v and %v", err, j)
		}
		var categorytruct client.Category
		err = json.Unmarshal(j, &categorytruct)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreatez: Failed to get applicationScope, %v and %v", err, j)
		}
		iap.Categories = categorytruct
	}

	/*artifacts, ok := d.GetOk("artifacts")
	if ok {
		j, err := json.Marshal(artifacts)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreate1a: Failed to get applicationScope, %v and %v", err, j)
		}
		var artifactStruct client.Artifact
		err = json.Unmarshal(j, &artifactStruct)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreatea: Failed to get applicationScope, %v and %v", err, j)
		}
		iap.Categories.Artifacts = artifactStruct
	}

	entityscope, ok := d.GetOk("entity_scope")
	if ok {
		j, err := json.Marshal(entityscope)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreate1e: Failed to get applicationScope, %v and %v", err, j)
		}
		var entityscopeStruct client.EntityScope
		err = json.Unmarshal(j, &entityscopeStruct)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreatee: Failed to get applicationScope, %v and %v", err, j)
		}
		iap.Categories.EntityScope = entityscopeStruct
	}

	workloads, ok := d.GetOk("Workloads")
	if ok {
		j, err := json.Marshal(workloads)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreate1w: Failed to get applicationScope, %v and %v", err, j)
		}
		var WorkloadStruct client.Workload
		err = json.Unmarshal(j, &WorkloadStruct)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreatew: Failed to get applicationScope, %v and %v", err, j)
		}
		iap.Categories.Workloads = WorkloadStruct
	}

	infrastructure, ok := d.GetOk("infrastructure")
	if ok {
		j, err := json.Marshal(infrastructure)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreate1i: Failed to get applicationScope, %v and %v", err, j)
		}
		var infrastructureStruct client.Artifact
		err = json.Unmarshal(j, &infrastructureStruct)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreatei: Failed to get applicationScope, %v and %v", err, j)
		}
		iap.Categories.Artifacts = infrastructureStruct
	}*/

	return &iap, err

}

func resourceApplicationScopeRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	iap, err := ac.GetApplicationScope(name)
	if err == nil {
		d.Set("name", iap.Name)
		d.Set("description", iap.Description)
		d.Set("author", iap.Author)
		d.Set("owner_email", iap.OwnerEmail)
		d.Set("categories", flattenCategories(iap.Categories))
	} else {
		return err
	}
	return nil
}

func resourceApplicationScopeUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	if d.HasChanges("description", "name", "author", "owner_email", "categories") {
		iap, err1 := expandApplicationScope(d)
		if err1 != nil {
			return err1
		}
		err := ac.UpdateApplicationScope(iap, name)
		if err == nil {
			err1 := resourceApplicationScopeRead(d, m)
			if err1 == nil {
				d.SetId(name)
			} else {
				return err1
			}
		} else {
			return err
		}
	}
	return nil
}

func resourceApplicationScopeDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	err := ac.DeleteApplicationScope(name)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}

func flattenCategories(category1 client.Category) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"artifacts":      flattenArtifacts(category1.Artifacts),
			"entity_scope":   flattenEntityScope(category1.EntityScope),
			"Workloads":      flattenWorkloads(category1.Workloads),
			"infrastructure": flattenInfrastructure(category1.Infrastructure),
		},
	}
}

func flattenArtifacts(artifact1 client.Artifact) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"image":    flattenAppScopeCommon(artifact1.Image),
			"function": flattenAppScopeCommon(artifact1.Function),
			"cf":       flattenAppScopeCommon(artifact1.CF),
		},
	}
}

func flattenWorkloads(workload1 client.Workload) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"kubernetes": flattenAppScopeCommon(workload1.Kubernetes),
			"os":         flattenAppScopeCommon(workload1.OS),
			"cf":         flattenAppScopeCommon(workload1.CF),
		},
	}
}

func flattenInfrastructure(infra1 client.Infrastructure) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"kubernetes": flattenAppScopeCommon(infra1.Kubernetes),
			"os":         flattenAppScopeCommon(infra1.OS),
		},
	}
}

func flattenAppScopeCommon(group client.CommonStruct) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"expression": group.Expression,
			"variables":  flattenAppScopeVariables(group.Variables),
		},
	}
}

func flattenEntityScope(entityscope client.EntityScope) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"expression": entityscope.Expression,
			"variables":  flattenEntityScopeVariables(entityscope.EntityVariable),
		},
	}
}

func flattenAppScopeVariables(variables []client.Variables) []interface{} {
	check := make([]interface{}, len(variables))
	for i := range variables {
		check[i] = map[string]interface{}{
			"attribute": variables[i].Attribute,
			"value":     variables[i].Value,
		}
	}

	return check
}

func flattenEntityScopeVariables(variables []client.EntityVariable) []interface{} {

	check := make([]interface{}, len(variables))
	for i := range variables {
		check[i] = map[string]interface{}{
			"attribute": variables[i].Attribute,
			"value":     variables[i].Value,
		}
	}

	return check
}

/*
func expandApplicationScope(d *schema.ResourceData) (*client.ApplicationScope, error) {
	iap := client.ApplicationScope{
		Name: d.Get("name").(string),
	}

	var err error

	description, ok := d.GetOk("description")
	if ok {
		iap.Description = description.(string)
	}

	author, ok := d.GetOk("author")
	if ok {
		iap.Author = author.(string)
	}

	owner_email, ok := d.GetOk("owner_email")
	if ok {
		iap.OwnerEmail = owner_email.(string)
	}

	categories, ok := d.GetOk("categories")
	if ok {
		j, err := json.Marshal(categories)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreate1: Failed to get applicationScope, %v", err)
		}
		var categoryStruct client.Category
		err = json.Unmarshal(j, &categoryStruct)
		if err != nil {
			return &iap, fmt.Errorf("resourceApplicationScopeCreate: Failed to get applicationScope, %v", err)
		}

		iap.Categories = categoryStruct
	}

	return &iap, err
}*/
