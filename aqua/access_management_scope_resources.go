package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"time"
)

func resourceAccessManagementScope() *schema.Resource {
	return &schema.Resource{
		Create: resourceApplicationScopeCreate,
		Read:   resourceApplicationScopeRead,
		Update: resourceApplicationScopeUpdate,
		Delete: resourceApplicationScopeDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"last_updated": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"categories": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						// Artifacts
						"artifacts": {
							Type:     schema.TypeSet,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"image": {
										Type:     schema.TypeSet,
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeSet,
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
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeSet,
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
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeSet,
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
						// Workloads
						"workloads": {
							Type:     schema.TypeSet,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"kubernetes": {
										Type:     schema.TypeSet,
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeSet,
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
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeSet,
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
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeSet,
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
						// Infrastructure
						"infrastructure": {
							Type:     schema.TypeSet,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"kubernetes": {
										Type:     schema.TypeSet,
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeSet,
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
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeSet,
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

	// Need to map the incoming terraform resource to an application scope
	as := mapResourceToScope(d)

	err := ac.CreateApplicationScope(as)
	if err != nil {
		return err
	}
	d.SetId(d.Get("name").(string))
	err = resourceApplicationScopeRead(d, m)
	return err
}

func resourceApplicationScopeRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	r, err := ac.GetApplicationScope(name)
	if err != nil {
		log.Print("[ERROR]  error calling ac.GetApplicationScope: ", r)
		return err
	}

	return nil
}

func resourceApplicationScopeUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	if d.HasChanges("description", "categories") {
		as := mapResourceToScope(d)
		err := ac.UpdateApplicationScope(as)
		if err != nil {
			log.Println("[DEBUG]  error while updating application scope: ", err)
			return err
		}
		_ = d.Set("last_updated", time.Now().Format(time.RFC850))
	}
	return nil
}

func resourceApplicationScopeDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	scopeID := d.Id()

	err := ac.DeleteApplicationScope(scopeID)
	if err != nil {
		return err
	}

	return err
}

func mapResourceToScope(d *schema.ResourceData) client.ApplicationScope {
	as := client.ApplicationScope{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
	}

	if c, ok := d.GetOk("categories"); ok {
		cList := c.(*schema.Set).List()
		for _, cat := range cList {
			if catData, isMap := cat.(map[string]interface{}); isMap {
				// artifacts
				artifacts := catData["artifacts"]
				artList := artifacts.(*schema.Set).List()
				for _, art := range artList {
					if artData, isMap := art.(map[string]interface{}); isMap {
						// image
						image := artData["image"]
						imageList := image.(*schema.Set).List()
						for _, img := range imageList {
							var il []client.ASVariable
							if iData, isMap := img.(map[string]interface{}); isMap {
								as.Categories.Artifacts.Image.Expression = iData["expression"].(string)
								variables := iData["variables"]
								variablesList := variables.(*schema.Set).List()
								for _, v := range variablesList {
									if vData, isMap := v.(map[string]interface{}); isMap {
										vb := client.ASVariable{
											Attribute: vData["attribute"].(string),
											Value:     vData["value"].(string),
										}
										il = append(il, vb)
									}
								}
							}
							as.Categories.Artifacts.Image.Variables = il
						}
						// function
						function := artData["function"]
						functionList := function.(*schema.Set).List()
						for _, f := range functionList {
							var il []client.ASVariable
							if iData, isMap := f.(map[string]interface{}); isMap {
								as.Categories.Artifacts.Function.Expression = iData["expression"].(string)
								variables := iData["variables"]
								variablesList := variables.(*schema.Set).List()
								for _, v := range variablesList {
									if vData, isMap := v.(map[string]interface{}); isMap {
										vb := client.ASVariable{
											Attribute: vData["attribute"].(string),
											Value:     vData["value"].(string),
										}
										il = append(il, vb)
									}
								}
							}
							as.Categories.Artifacts.Function.Variables = il
						}
						// CF
						cf := artData["cf"]
						cfList := cf.(*schema.Set).List()
						for _, c := range cfList {
							var il []client.ASVariable
							if iData, isMap := c.(map[string]interface{}); isMap {
								as.Categories.Artifacts.Cf.Expression = iData["expression"].(string)
								variables := iData["variables"]
								variablesList := variables.(*schema.Set).List()
								for _, v := range variablesList {
									if vData, isMap := v.(map[string]interface{}); isMap {
										vb := client.ASVariable{
											Attribute: vData["attribute"].(string),
											Value:     vData["value"].(string),
										}
										il = append(il, vb)
									}
								}
							}
							as.Categories.Artifacts.Cf.Variables = il
						}
					}
				}
				// workloads
				workloads := catData["workloads"]
				workList := workloads.(*schema.Set).List()
				for _, work := range workList {
					if workData, isMap := work.(map[string]interface{}); isMap {
						// kubernetes
						kubernetes := workData["kubernetes"]
						kubeList := kubernetes.(*schema.Set).List()
						for _, img := range kubeList {
							var il []client.ASVariable
							if iData, isMap := img.(map[string]interface{}); isMap {
								as.Categories.Workloads.Kubernetes.Expression = iData["expression"].(string)
								variables := iData["variables"]
								variablesList := variables.(*schema.Set).List()
								for _, v := range variablesList {
									if vData, isMap := v.(map[string]interface{}); isMap {
										vb := client.ASVariable{
											Attribute: vData["attribute"].(string),
											Value:     vData["value"].(string),
										}
										il = append(il, vb)
									}
								}
							}
							as.Categories.Workloads.Kubernetes.Variables = il
						}
						// OS
						os := workData["os"]
						osList := os.(*schema.Set).List()
						for _, o := range osList {
							var il []client.ASVariable
							if iData, isMap := o.(map[string]interface{}); isMap {
								as.Categories.Workloads.Os.Expression = iData["expression"].(string)
								variables := iData["variables"]
								variablesList := variables.(*schema.Set).List()
								for _, v := range variablesList {
									if vData, isMap := v.(map[string]interface{}); isMap {
										vb := client.ASVariable{
											Attribute: vData["attribute"].(string),
											Value:     vData["value"].(string),
										}
										il = append(il, vb)
									}
								}
							}
							as.Categories.Workloads.Os.Variables = il
						}
						// CF
						cf := workData["cf"]
						cfList := cf.(*schema.Set).List()
						for _, c := range cfList {
							var il []client.ASVariable
							if iData, isMap := c.(map[string]interface{}); isMap {
								as.Categories.Workloads.Cf.Expression = iData["expression"].(string)
								variables := iData["variables"]
								variablesList := variables.(*schema.Set).List()
								for _, v := range variablesList {
									if vData, isMap := v.(map[string]interface{}); isMap {
										vb := client.ASVariable{
											Attribute: vData["attribute"].(string),
											Value:     vData["value"].(string),
										}
										il = append(il, vb)
									}
								}
							}
							as.Categories.Workloads.Cf.Variables = il
						}
					}
				}
				// infrastructure
				infrastructure := catData["infrastructure"]
				infraList := infrastructure.(*schema.Set).List()
				for _, infra := range infraList {
					if infraData, isMap := infra.(map[string]interface{}); isMap {
						// kubernetes
						kubernetes := infraData["kubernetes"]
						kubeList := kubernetes.(*schema.Set).List()
						for _, img := range kubeList {
							var il []client.ASVariable
							if iData, isMap := img.(map[string]interface{}); isMap {
								as.Categories.Infrastructure.Kubernetes.Expression = iData["expression"].(string)
								variables := iData["variables"]
								variablesList := variables.(*schema.Set).List()
								for _, v := range variablesList {
									if vData, isMap := v.(map[string]interface{}); isMap {
										vb := client.ASVariable{
											Attribute: vData["attribute"].(string),
											Value:     vData["value"].(string),
										}
										il = append(il, vb)
									}
								}
							}
							as.Categories.Infrastructure.Kubernetes.Variables = il
						}
						// OS
						os := infraData["os"]
						osList := os.(*schema.Set).List()
						for _, o := range osList {
							var il []client.ASVariable
							if iData, isMap := o.(map[string]interface{}); isMap {
								as.Categories.Infrastructure.Os.Expression = iData["expression"].(string)
								variables := iData["variables"]
								variablesList := variables.(*schema.Set).List()
								for _, v := range variablesList {
									if vData, isMap := v.(map[string]interface{}); isMap {
										vb := client.ASVariable{
											Attribute: vData["attribute"].(string),
											Value:     vData["value"].(string),
										}
										il = append(il, vb)
									}
								}
							}
							as.Categories.Infrastructure.Os.Variables = il
						}
					}
				}
			}
		}
	}
	return as
}
