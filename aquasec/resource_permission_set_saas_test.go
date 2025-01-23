package aquasec

import (
   "fmt"
   "regexp"
   "testing"
   
   "github.com/aquasecurity/terraform-provider-aquasec/client"
   "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
   "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
   "github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const (
   resourceName = "aquasec_permission_set_saas.new"
   maxNameLength = 20
   initialDescription = "Initial description"
)

var defaultTestActions = []string{
   "account_mgmt.groups.read",
   "cspm.cloud_accounts.read",
}

var extendedTestActions = []string{
   "account_mgmt.groups.read",
   "cspm.cloud_accounts.read", 
   "cnapp.inventory.read",
   "cnapp.insights.read",
   "cnapp.dashboards.read",
}

var invalidConfigTestCases = []struct {
   name     string
   config   string
   errorMsg string
}{
   {
       name: "missing required name",
       config: `
           resource "aquasec_permission_set_saas" "invalid" {
               description = "test"
           }`,
       errorMsg: "name",
   },
   {
       name: "invalid action",
       config: `
           resource "aquasec_permission_set_saas" "invalid" {
               name = "test"
               actions = ["invalid.action"]
           }`,
       errorMsg: "action.*not supported",
   },
}

// Helper Functions

func testAccCheckAquasecPermissionSetSaas(name, description string, actions []string) string {
   actionsStr := ""
   for _, action := range actions {
       actionsStr += fmt.Sprintf(`"%s",`, action)
   }
   if len(actionsStr) > 0 {
       actionsStr = actionsStr[:len(actionsStr)-1]
   }

   return fmt.Sprintf(`
   resource "aquasec_permission_set_saas" "new" {
       name        = "%s"
       description = "%s"
       actions     = [%s]
   }`, name, description, actionsStr)
}

func testAccCheckAquasecPermissionSetSaasExists(n string) resource.TestCheckFunc {
   return func(s *terraform.State) error {
       rs, ok := s.RootModule().Resources[n]
       if !ok {
           return NewNotFoundErrorf("%s in state", n)
       }

       if rs.Primary.ID == "" {
           return NewNotFoundErrorf("ID for %s in state", n)
       }

       c := testAccProvider.Meta().(*client.Client)
       _, err := c.GetPermissionSetSaas(rs.Primary.ID)
       if err != nil {
           return fmt.Errorf("error finding permission set %s: %s", rs.Primary.ID, err)
       }

       return nil
   }
}

func testAccPermissionSetSaasDestroy(s *terraform.State) error {
   c := testAccProvider.Meta().(*client.Client)

   for _, rs := range s.RootModule().Resources {
       if rs.Type != "aquasec_permission_set_saas.new" {
           continue
       }

       permSet, err := c.GetPermissionSetSaas(rs.Primary.ID)
       if err == nil && permSet != nil {
           return fmt.Errorf("permission set %q still exists", rs.Primary.ID)
       }
   }

   return nil
}

// Test Functions

func TestAquasecPermissionSetSaasManagement(t *testing.T) {
   if !isSaasEnv() {
       t.Skip("Skipping permission set test - not a SaaS environment")
   }

   name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]
   description := "Permission set created by Terraform acceptance test"

   resource.Test(t, resource.TestCase{
       PreCheck:     func() { testAccPreCheck(t) },
       Providers:    testAccProviders,
       CheckDestroy: testAccPermissionSetSaasDestroy,
       Steps: []resource.TestStep{
           {
               Config: testAccCheckAquasecPermissionSetSaas(name, description, extendedTestActions),
               Check: resource.ComposeTestCheckFunc(
                   testAccCheckAquasecPermissionSetSaasExists(resourceName),
               ),
           },
           {
               Config: testAccCheckAquasecPermissionSetSaas(name, "Updated "+description, extendedTestActions),
               Check: resource.ComposeTestCheckFunc(
                   testAccCheckAquasecPermissionSetSaasExists(resourceName),
                   resource.TestCheckResourceAttr(resourceName, "description", "Updated "+description),
               ),
           },
           {
               ResourceName:      resourceName,
               ImportState:       true,
               ImportStateVerify: true,
           },
       },
   })
}

func TestAquasecPermissionSetSaasInvalidConfig(t *testing.T) {
   for _, tc := range invalidConfigTestCases {
       t.Run(tc.name, func(t *testing.T) {
           resource.Test(t, resource.TestCase{
               PreCheck:     func() { testAccPreCheck(t) },
               Providers:    testAccProviders,
               CheckDestroy: testAccPermissionSetSaasDestroy,
               Steps: []resource.TestStep{
                   {
                       Config:      tc.config,
                       ExpectError: regexp.MustCompile(tc.errorMsg),
                   },
               },
           })
       })
   }
}

func TestAquasecPermissionSetSaasWithExternalChanges(t *testing.T) {
   if !isSaasEnv() {
       t.Skip("Skipping permission set test - not a SaaS environment")
   }

   name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]

   resource.Test(t, resource.TestCase{
       PreCheck:     func() { testAccPreCheck(t) },
       Providers:    testAccProviders,
       CheckDestroy: nil,
       Steps: []resource.TestStep{
           {
               Config: testAccCheckAquasecPermissionSetSaas(name, initialDescription, defaultTestActions),
               ExpectNonEmptyPlan: true,
               Check: resource.ComposeTestCheckFunc(
                   testAccCheckAquasecPermissionSetSaasExists(resourceName),
                   func(s *terraform.State) error {
                       t.Logf("[INFO] Permission Set '%s' created via Terraform with description: '%s'", name, initialDescription)
                       provider := testAccProvider.Meta().(*client.Client)
                       permSet := &client.PermissionSetSaas{
                           Name:        name,
                           Description: "Modified via API",
                           Actions:     defaultTestActions,
                       }
                       if err := provider.UpdatePermissionSetSaas(permSet); err != nil {
                           return err
                       }
                       t.Logf("[INFO] Permission Set '%s' modified externally via API to description: 'Modified via API'", name)
                       return nil
                   },
               ),
           },
           {
               Config: testAccCheckAquasecPermissionSetSaas(name, initialDescription, defaultTestActions),
               Check: resource.ComposeTestCheckFunc(
                   resource.TestCheckResourceAttr(resourceName, "description", initialDescription),
                   func(s *terraform.State) error {
                       provider := testAccProvider.Meta().(*client.Client)
                       permSet, err := provider.GetPermissionSetSaas(name)
                       if err != nil {
                           return err
                       }
                       t.Logf("[INFO] Permission Set '%s' reverted by Terraform to match state - description: '%s'", name, permSet.Description)
                       return nil
                   },
               ),
           },
           {
               Config: testAccCheckAquasecPermissionSetSaas(name, initialDescription, append(defaultTestActions, "cspm.cloud_accounts.write")),
               ExpectNonEmptyPlan: false,
               Check: resource.ComposeTestCheckFunc(
                   func(s *terraform.State) error {
                       t.Logf("[INFO] Running terraform plan to verify no changes needed for Permission Set '%s'", name)
                       t.Logf("[INFO] Terraform updating Permission Set '%s' actions via configuration", name)
                       return nil
                   },
               ),
           },
       },
   })
}

func TestAquasecPermissionSetSaasReadErrorHandling(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping permission set test - not a SaaS environment")
	}

	name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccPermissionSetSaasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecPermissionSetSaas(name, "test description", defaultTestActions),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecPermissionSetSaasExists(resourceName),
					// Delete the permission set outside of Terraform
					func(s *terraform.State) error {
						client := testAccProvider.Meta().(*client.Client)
						return client.DeletePermissionSetSaas(name)
					},
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAquasecPermissionSetSaasUpdateErrorHandling(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping permission set test - not a SaaS environment")
	}

	name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccPermissionSetSaasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecPermissionSetSaas(name, "initial", defaultTestActions),
			},
			{
				Config: testAccCheckAquasecPermissionSetSaas(name, "updated", append(defaultTestActions, "invalid.action")),
				ExpectError: regexp.MustCompile("Error: failed updating SaaS PermissionSet"),
			},
		},
	})
}


func TestAquasecPermissionSetSaasValues(t *testing.T) {
    if !isSaasEnv() {
        t.Skip("Skipping permission set test - not a SaaS environment")
    }

    name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]
    description := "Created using Terraform"
    resourceName := "aquasec_permission_set_saas.new"

    resource.Test(t, resource.TestCase{
        PreCheck:     func() { testAccPreCheck(t) },
        Providers:    testAccProviders,
        CheckDestroy: testAccPermissionSetSaasDestroy,
        Steps: []resource.TestStep{
            {
                Config: testAccCheckAquasecPermissionSetSaas(name, description, extendedTestActions),
                Check: resource.ComposeTestCheckFunc(
                    testAccCheckAquasecPermissionSetSaasExists(resourceName),
                    // Verify all attributes match exactly what was set
                    resource.TestCheckResourceAttr(resourceName, "name", name),
                    resource.TestCheckResourceAttr(resourceName, "description", description),
                    // Verify each action in the actions list
                    resource.TestCheckResourceAttr(resourceName, "actions.#", fmt.Sprintf("%d", len(extendedTestActions))),
                    resource.TestCheckResourceAttr(resourceName, "actions.0", extendedTestActions[0]),
                    resource.TestCheckResourceAttr(resourceName, "actions.1", extendedTestActions[1]),
                    resource.TestCheckResourceAttr(resourceName, "actions.2", extendedTestActions[2]),
                    resource.TestCheckResourceAttr(resourceName, "actions.3", extendedTestActions[3]),
                    resource.TestCheckResourceAttr(resourceName, "actions.4", extendedTestActions[4]),
                ),
            },
            {
                ResourceName:      resourceName,
                ImportState:       true,
                ImportStateVerify: true,
            },
        },
    })
}