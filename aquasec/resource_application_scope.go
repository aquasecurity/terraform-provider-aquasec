package aquasec

import (
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
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of an application scope.",
				Required:    true,
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "Description of the application scope.",
				Optional:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the service.",
				Computed:    true,
			},
			"owner_email": {
				Type:        schema.TypeString,
				Description: "Name of an application scope.",
				Optional:    true,
			},
			"categories": {
				Type:        schema.TypeSet,
				Description: "Artifacts (of applications) / Workloads (containers) / Infrastructure (elements).",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"artifacts": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "An artifact is an application. It can be an image (for a container, not a CF application); a serverless function; or a Tanzu Application Service (TAS) droplet.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"image": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "Name of a registry as defined in Aqua",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
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
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "Function name",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
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
									"cf": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
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
								},
							},
						},
						"entity_scope": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"expression": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"variables": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"attribute": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"value": {
													Type:     schema.TypeString,
													Computed: true,
												},
											},
										},
									},
								},
							},
						},
						"workloads": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A workload is a running container. It can run in a Kubernetes cluster, on a VM (no orchestrator), or under Tanzu Application Service (TAS).",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"cf": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
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
									"kubernetes": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
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
									"os": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
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
								},
							},
						},
						"infrastructure": {
							Type:        schema.TypeSet,
							Description: "An infrastructure resource is an element of a computing environment on which a workload is orchestrated and run. It can be a host (VM) or a Kubernetes cluster.",
							Optional:    true,
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
									"os": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
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
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	iap, err1 := expandApplicationScope(d)
	if err1 != nil {
		return fmt.Errorf("expanding applications is failed with error: %v", err1)
	}
	err := ac.CreateApplicationScope(iap)

	if err == nil {
		d.SetId(name)
	} else {
		return fmt.Errorf("application scope resource create is failed with error:  %v", err)
	}

	return resourceApplicationScopeRead(d, m)
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

	categories, ok := d.GetOk("categories")

	if ok {
		categories := categories.(*schema.Set).List()[0].(map[string]interface{})
		var artifacts map[string]interface{}
		var workloads map[string]interface{}
		var infrastructure map[string]interface{}

		if len(categories["artifacts"].(*schema.Set).List()) > 0 {
			artifacts = categories["artifacts"].(*schema.Set).List()[0].(map[string]interface{})
		}

		if len(categories["workloads"].(*schema.Set).List()) > 0 {
			workloads = categories["workloads"].(*schema.Set).List()[0].(map[string]interface{})

		}
		if len(categories["infrastructure"].(*schema.Set).List()) > 0 {
			infrastructure = categories["infrastructure"].(*schema.Set).List()[0].(map[string]interface{})
		}

		categoryStruct := createCategory(artifacts, workloads, infrastructure)

		iap.Categories = categoryStruct
	}

	return &iap, err

}

func resourceApplicationScopeRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	iap, err := ac.GetApplicationScope(d.Id())
	if err == nil {

		err = d.Set("name", iap.Name)
		if err != nil {
			return err
		}
		err = d.Set("description", iap.Description)
		if err != nil {
			return err
		}
		err = d.Set("author", iap.Author)
		if err != nil {
			return err
		}
		err = d.Set("owner_email", iap.OwnerEmail)
		if err != nil {
			return err
		}

		err = d.Set("categories", flattenCategories(iap.Categories))

		if err != nil {
			return err
		}

		d.SetId(iap.Name)
	} else {
		return err
	}

	return nil
}

func resourceApplicationScopeUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	if d.HasChanges("description", "name", "author", "owner_email", "categories") {
		var err error

		iap, err1 := expandApplicationScope(d)
		if err1 != nil {
			return err1
		}
		err = ac.UpdateApplicationScope(iap, name)
		if err != nil {
			return err
		}
		return resourceApplicationScopeRead(d, m)

	}
	return nil
}

func createCategory(a map[string]interface{}, w map[string]interface{}, i map[string]interface{}) client.Category {

	//creating Artifacts
	var image client.CommonStruct
	var function client.CommonStruct
	var cf client.CommonStruct

	//creating Workloads
	var wkubernetes client.CommonStruct
	var wos client.CommonStruct
	var wcf client.CommonStruct

	//creating Infrastructure
	var ikubernetes client.CommonStruct
	var ios client.CommonStruct

	if len(a) != 0 {
		if len(a["image"].(*schema.Set).List()) != 0 {
			image = createCommonStruct(a["image"].(*schema.Set).List()[0].(map[string]interface{}))
		} else {
			image = createEmptyCommonStruct()
		}
		if len(a["function"].(*schema.Set).List()) != 0 {
			function = createCommonStruct(a["function"].(*schema.Set).List()[0].(map[string]interface{}))
		} else {
			function = createEmptyCommonStruct()
		}
		if len(a["cf"].(*schema.Set).List()) != 0 {
			cf = createCommonStruct(a["cf"].(*schema.Set).List()[0].(map[string]interface{}))
		} else {
			cf = createEmptyCommonStruct()
		}
	}

	if len(w) != 0 {
		if len(w["kubernetes"].(*schema.Set).List()) != 0 {
			wkubernetes = createCommonStruct(w["kubernetes"].(*schema.Set).List()[0].(map[string]interface{}))
		} else {
			wkubernetes = createEmptyCommonStruct()
		}
		if len(w["os"].(*schema.Set).List()) != 0 {
			wos = createCommonStruct(w["os"].(*schema.Set).List()[0].(map[string]interface{}))
		} else {
			wos = createEmptyCommonStruct()
		}
		if len(w["cf"].(*schema.Set).List()) != 0 {
			wcf = createCommonStruct(w["cf"].(*schema.Set).List()[0].(map[string]interface{}))
		} else {
			wcf = createEmptyCommonStruct()
		}
	}

	if len(i) != 0 {
		if len(i["kubernetes"].(*schema.Set).List()) != 0 {
			ikubernetes = createCommonStruct(i["kubernetes"].(*schema.Set).List()[0].(map[string]interface{}))
		} else {
			ikubernetes = createEmptyCommonStruct()
		}
		if len(i["os"].(*schema.Set).List()) > 0 {
			ios = createCommonStruct(i["os"].(*schema.Set).List()[0].(map[string]interface{}))
		} else {
			ios = createEmptyCommonStruct()
		}
	}

	return client.Category{
		Artifacts: client.Artifact{
			Image:    image,
			Function: function,
			CF:       cf,
		},
		Workloads: client.Workload{
			Kubernetes: wkubernetes,
			OS:         wos,
			WCF:        wcf,
		},
		Infrastructure: client.Infrastructure{
			IKubernetes: ikubernetes,
			IOS:         ios,
		},
	}

}

func createCommonStruct(m map[string]interface{}) client.CommonStruct {
	var commonStruct client.CommonStruct

	Expresion := m["expression"].(string)
	Vars := []client.Variables{}
	for _, variable := range m["variables"].([]interface{}) {
		v := variable.(map[string]interface{})
		Vars = append(Vars, client.Variables{
			Attribute: v["attribute"].(string),
			Value:     v["value"].(string),
		})
	}
	commonStruct.Expression = Expresion
	commonStruct.Variables = Vars

	return commonStruct
}

func createEmptyCommonStruct() client.CommonStruct {
	var commonStruct1 client.CommonStruct
	Expresion := ""
	Vars := []client.Variables{}
	commonStruct1.Expression = Expresion
	commonStruct1.Variables = Vars

	return commonStruct1
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
			"infrastructure": flattenInfrastructure(category1.Infrastructure),
			"workloads":      flattenWorkloads(category1.Workloads),
		},
	}
}

func flattenArtifacts(artifact1 client.Artifact) []map[string]interface{} {
	artifactsMap := map[string]interface{}{}

	if artifact1.Image.Expression != "" {
		artifactsMap["image"] = flattenAppScopeCommon(artifact1.Image)
	}

	if artifact1.Function.Expression != "" {
		artifactsMap["function"] = flattenAppScopeCommon(artifact1.Function)
	}

	if artifact1.CF.Expression != "" {
		artifactsMap["cf"] = flattenAppScopeCommon(artifact1.CF)
	}
	if len(artifactsMap) == 0 {
		return make([]map[string]interface{}, 0)
	} else {
		return []map[string]interface{}{artifactsMap}
	}
}

func flattenWorkloads(workload1 client.Workload) []map[string]interface{} {
	workloadMap := map[string]interface{}{}

	if workload1.WCF.Expression != "" {
		workloadMap["cf"] = flattenAppScopeCommon(workload1.WCF)
	}

	if workload1.Kubernetes.Expression != "" {
		workloadMap["kubernetes"] = flattenAppScopeCommon(workload1.Kubernetes)
	}

	if workload1.OS.Expression != "" {
		workloadMap["os"] = flattenAppScopeCommon(workload1.OS)
	}

	if len(workloadMap) == 0 {
		return make([]map[string]interface{}, 0)
	} else {
		return []map[string]interface{}{workloadMap}
	}
}

func flattenInfrastructure(infra1 client.Infrastructure) []map[string]interface{} {

	infraMap := map[string]interface{}{}

	if infra1.IKubernetes.Expression != "" {
		infraMap["kubernetes"] = flattenAppScopeCommon(infra1.IKubernetes)
	}

	if infra1.IOS.Expression != "" {
		infraMap["os"] = flattenAppScopeCommon(infra1.IOS)
	}

	if len(infraMap) == 0 {
		return make([]map[string]interface{}, 0)
	} else {
		return []map[string]interface{}{infraMap}
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

func flattenEntityScope(entityscope client.CommonStruct) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"expression": entityscope.Expression,
			"variables":  flattenAppScopeVariables(entityscope.Variables),
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
